// SPDX-License-Identifier: Apache-2.0

// Command demo runs the whole containment story from one command.
//
// Each branch declares what it predicts before it runs, and the run either
// matches or does not. Comparing against a prediction written in advance is
// what stops a branch that passes for the wrong reason from being counted as
// a pass.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"arazu/pkg/auditlog"
	"arazu/pkg/tpmseal"
)

type branch struct {
	name      string
	predicted string
	observe   func(*harness) (string, error)
}

type harness struct {
	repo    string
	workdir string
	broken  string
}

func main() {
	workdir := flag.String("workdir", "state/demo", "directory for demo state")
	repo := flag.String("repo", ".", "repository root")
	breakBranch := flag.String("break-branch", "", "deliberately sabotage one branch, to prove the demo can fail")
	flag.Parse()

	abs, err := filepath.Abs(*repo)
	if err != nil {
		fail(err)
	}
	wd, err := filepath.Abs(*workdir)
	if err != nil {
		fail(err)
	}
	if err := os.RemoveAll(wd); err != nil {
		fail(err)
	}
	if err := os.MkdirAll(wd, 0o700); err != nil {
		fail(err)
	}

	h := &harness{repo: abs, workdir: wd, broken: *breakBranch}

	branches := []branch{
		{
			name:      "happy-path",
			predicted: "ACCEPT, contained, no egress, unseal, SIGNED, log CLEAN",
			observe:   happyPath,
		},
		{
			name:      "poisoned-bundle",
			predicted: "REJECT:hash-mismatch, nothing downstream ran",
			observe:   poisonedBundle,
		},
		{
			name:      "tampered-content",
			predicted: "REFUSED:measured-state-mismatch, unsigned, exit non-zero",
			observe:   tamperedContent,
		},
		{
			name:      "gate-in-chain",
			predicted: "ACCEPT recorded, decision under the sealed root, SIGNED, log CLEAN",
			observe:   gateInTheChain,
		},
		{
			// The deck's promise, and the one branch that runs a real gate
			// verdict on a patch that every other acceptance signal accepts.
			// Three minutes: it builds libpng twice and replays 79 inputs.
			name:      "wrong-patch-refused",
			predicted: "REJECT:class-replay-fail, refusal under the sealed root, logged, chain CLEAN",
			observe:   wrongPatchRefused,
		},
		{
			name:      "log-tamper",
			predicted: "BROKEN, chain break reported at the edited entry",
			observe:   logTamper,
		},
	}

	// A -break-branch that silently does nothing would report all-match and
	// look like the harness passing, which is the exact failure this flag
	// exists to rule out.
	if h.broken != "" {
		known := false
		for _, b := range branches {
			if b.name == h.broken {
				known = true
			}
		}
		if !known {
			names := make([]string, 0, len(branches))
			for _, b := range branches {
				names = append(names, b.name)
			}
			fail(fmt.Errorf("-break-branch %q is not a branch; choose one of %s",
				h.broken, strings.Join(names, ", ")))
		}
	}

	header(h)

	rows := make([][4]string, 0, len(branches))
	allMatch := true
	for _, b := range branches {
		observed, err := b.observe(h)
		if err != nil {
			observed = "error: " + err.Error()
		}
		verdict := "MATCH"
		if observed != b.predicted {
			verdict = "MISMATCH"
			allMatch = false
		}
		rows = append(rows, [4]string{b.name, b.predicted, observed, verdict})
	}

	table(rows)
	footer()

	if !allMatch {
		fmt.Println("\nRESULT: at least one branch did not match its prediction.")
		os.Exit(1)
	}
	// Counted, not spelled. It said "all four" while five branches ran, because
	// adding gate-in-chain did not touch this line. A summary that states a
	// number the code does not derive drifts the moment the code does.
	fmt.Printf("\nRESULT: all %d branches matched their predictions.\n", len(branches))
}

func header(h *harness) {
	fmt.Println("Arazu containment spike, end-to-end demonstration")
	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("TPM device      : %s\n", tpmseal.Device())
	fmt.Printf("Measured into   : PCR %d (resettable; production binds to measured-boot PCRs)\n", tpmseal.PCR)
	fmt.Printf("Work directory  : %s\n", h.workdir)
	if h.broken != "" {
		fmt.Printf("Sabotaged branch: %s (proving the demo can fail)\n", h.broken)
	}
	fmt.Println()
}

func footer() {
	fmt.Println()
	fmt.Println(strings.Repeat("-", 78))
	fmt.Println("What this shows: the acceptance bar does not live in the workload. A")
	fmt.Println("poisoned bundle is refused at the door, tampering after the door breaks")
	fmt.Println("the measured-state binding so nothing gets signed, and the record of what")
	fmt.Println("happened cannot be quietly rewritten. None of that depends on how good")
	fmt.Println("the thing inside the envelope is.")
	fmt.Println()
	fmt.Println("What it does not show: see SCOPE.md.")
}

func table(rows [][4]string) {
	fmt.Printf("%-18s %-52s %s\n", "BRANCH", "PREDICTED", "VERDICT")
	fmt.Println(strings.Repeat("-", 78))
	for _, r := range rows {
		fmt.Printf("%-18s %-52s %s\n", r[0], r[1], r[3])
		if r[3] != "MATCH" {
			fmt.Printf("%-18s observed: %s\n", "", r[2])
		}
	}
}

// runTool invokes one of the spike's binaries and returns its JSON decision
// plus the exit code.
func (h *harness) runTool(name string, args ...string) (map[string]any, int, error) {
	cmd := exec.Command(filepath.Join(h.repo, "bin", name), args...)
	cmd.Dir = h.repo
	out, _ := cmd.Output()
	code := cmd.ProcessState.ExitCode()

	var d map[string]any
	if err := json.Unmarshal(out, &d); err != nil {
		return nil, code, fmt.Errorf("%s produced no JSON decision (exit %d): %s", name, code, out)
	}
	return d, code, nil
}

func str(d map[string]any, key string) string {
	if v, ok := d[key].(string); ok {
		return v
	}
	return ""
}

func (h *harness) path(parts ...string) string {
	return filepath.Join(append([]string{h.workdir}, parts...)...)
}

func (h *harness) bundle(name string) string {
	return filepath.Join(h.repo, "testdata", "bundles", name)
}

// happyPath runs the whole accepted flow: gate, measure, seal, contained
// run, unseal, sign, verify the log.
func happyPath(h *harness) (string, error) {
	log := h.path("happy", "audit.jsonl")
	state := h.path("happy", "state")
	seal := h.path("happy", "seal")
	artifact := h.path("happy", "artifact.txt")
	sig := h.path("happy", "artifact.sig")
	os.MkdirAll(filepath.Dir(log), 0o700)

	d, code, err := h.runTool("ingress-verify",
		"-bundle", h.bundle("good"), "-trusted", filepath.Join(h.repo, "testdata/keys/trusted.pub"),
		"-state", state, "-log", log, "-allow", "content/")
	if err != nil {
		return "", err
	}
	if str(d, "decision") != "ACCEPT" || code != 0 {
		return fmt.Sprintf("gate said %s:%s", str(d, "decision"), str(d, "reason")), nil
	}
	root := str(d, "content_root")

	if _, code, err = h.runTool("seal-tool", "provision",
		"-dir", seal, "-content-root", root, "-log", log); err != nil {
		return "", err
	}
	if code != 0 {
		return "seal provisioning failed", nil
	}

	// Sabotage: run without the BPF layer, so the run is not the contained
	// mode the happy path predicts.
	mode := "contained"
	if h.broken == "happy-path" {
		mode = "netns-only"
	}

	run, code, err := h.runTool("contained-run",
		"-mode", mode, "-bundle", h.bundle("good"),
		"-out", artifact, "-log", log,
		"-obj", filepath.Join(h.repo, "bpf/egress_deny.bpf.o"),
		"-probe", filepath.Join(h.repo, "scripts/egress-probe.sh"),
		"-ns", "arazu-demo")
	if err != nil {
		return "", err
	}
	if code != 0 {
		return fmt.Sprintf("contained run failed: %s", str(run, "reason")), nil
	}
	if leaked := reachedProbes(run); len(leaked) > 0 {
		return "egress leaked: " + strings.Join(leaked, ","), nil
	}
	// The happy path claims the kernel layer was enforcing, so check the
	// kernel's own counters rather than inferring it from the mode flag.
	if !bpfEnforced(run) {
		return "contained run produced no kernel-side denials", nil
	}

	d, code, err = h.runTool("seal-tool", "sign",
		"-dir", seal, "-content-root", root,
		"-artifact", artifact, "-sig", sig, "-log", log)
	if err != nil {
		return "", err
	}
	if str(d, "decision") != "SIGNED" || code != 0 {
		return fmt.Sprintf("signing said %s:%s", str(d, "decision"), str(d, "reason")), nil
	}

	if _, err := os.Stat(sig); err != nil {
		return "no signature written", nil
	}

	v, code, err := h.runTool("log-verify", "-log", log)
	if err != nil {
		return "", err
	}
	if str(v, "decision") != "CLEAN" || code != 0 {
		return "log " + str(v, "decision"), nil
	}

	return "ACCEPT, contained, no egress, unseal, SIGNED, log CLEAN", nil
}

// bpfEnforced reads the kernel's own denial counters. Trusting the mode flag
// instead would let a run that never attached anything still be reported as
// contained.
func bpfEnforced(run map[string]any) bool {
	d, _ := run["bpf_denials"].(map[string]any)
	if d == nil {
		return false
	}
	total := 0.0
	for _, k := range []string{"connect_denied", "sendmsg_denied"} {
		if v, ok := d[k].(float64); ok {
			total += v
		}
	}
	return total > 0
}

func reachedProbes(run map[string]any) []string {
	var out []string
	probes, _ := run["probes"].([]any)
	for _, p := range probes {
		m, _ := p.(map[string]any)
		if m == nil {
			continue
		}
		reached, _ := m["reached"].(bool)
		if class, _ := m["class"].(string); class == "REACH" && reached {
			name, _ := m["name"].(string)
			out = append(out, name)
		}
	}
	return out
}

// poisonedBundle shows the gate refusing bad input at the door, and that
// nothing downstream ran.
func poisonedBundle(h *harness) (string, error) {
	log := h.path("poisoned", "audit.jsonl")
	state := h.path("poisoned", "state")
	os.MkdirAll(filepath.Dir(log), 0o700)

	// Sabotage: point at the good bundle, which the gate will accept, so the
	// prediction of a rejection fails.
	bundle := h.bundle("flipped-byte")
	if h.broken == "poisoned-bundle" {
		bundle = h.bundle("good")
	}

	d, code, err := h.runTool("ingress-verify",
		"-bundle", bundle, "-trusted", filepath.Join(h.repo, "testdata/keys/trusted.pub"),
		"-state", state, "-log", log, "-allow", "content/")
	if err != nil {
		return "", err
	}
	if str(d, "decision") != "REJECT" || code == 0 {
		return fmt.Sprintf("gate said %s (exit %d)", str(d, "decision"), code), nil
	}
	if r := str(d, "reason"); r != "hash-mismatch" {
		return "REJECT:" + r, nil
	}
	// Nothing downstream may have run: no content root to measure, so no
	// seal directory and no artifact can exist.
	if str(d, "content_root") != "" {
		return "REJECT but a content root was published", nil
	}
	if _, err := os.Stat(h.path("poisoned", "artifact.txt")); err == nil {
		return "REJECT but an artifact exists", nil
	}

	return "REJECT:hash-mismatch, nothing downstream ran", nil
}

// tamperedContent is the branch that matters. Content is altered after the
// gate accepted it, so the measurement no longer matches and signing is
// refused rather than producing a signature over compromised output.
func tamperedContent(h *harness) (string, error) {
	log := h.path("tampered", "audit.jsonl")
	state := h.path("tampered", "state")
	seal := h.path("tampered", "seal")
	store := h.path("tampered", "store")
	artifact := h.path("tampered", "artifact.txt")
	sig := h.path("tampered", "artifact.sig")
	os.MkdirAll(filepath.Dir(log), 0o700)

	// Copy the accepted bundle into a working store the demo can tamper with.
	if out, err := exec.Command("cp", "-a", h.bundle("good"), store).CombinedOutput(); err != nil {
		return "", fmt.Errorf("cp: %v: %s", err, out)
	}

	d, code, err := h.runTool("ingress-verify",
		"-bundle", store, "-trusted", filepath.Join(h.repo, "testdata/keys/trusted.pub"),
		"-state", state, "-log", log, "-allow", "content/")
	if err != nil {
		return "", err
	}
	if str(d, "decision") != "ACCEPT" || code != 0 {
		return "gate refused the good bundle: " + str(d, "reason"), nil
	}
	acceptedRoot := str(d, "content_root")

	if _, code, err = h.runTool("seal-tool", "provision",
		"-dir", seal, "-content-root", acceptedRoot, "-log", log); err != nil {
		return "", err
	}
	if code != 0 {
		return "seal provisioning failed", nil
	}

	// The tamper. Unless this branch is sabotaged, in which case leave the
	// content alone so the measurement still matches and signing succeeds
	// where a refusal was predicted.
	if h.broken != "tampered-content" {
		body := []byte("TAMPERED after the gate accepted this bundle\n")
		if err := os.WriteFile(filepath.Join(store, "content", "a.txt"), body, 0o644); err != nil {
			return "", err
		}
	}

	// Re-measure the store as it now stands. This is the run-time
	// measurement, and it is what the seal is checked against.
	run, _, err := h.runTool("contained-run",
		"-mode", "control", "-bundle", store,
		"-out", artifact, "-log", log,
		"-probe", filepath.Join(h.repo, "scripts/egress-probe.sh"))
	if err != nil {
		return "", err
	}
	runtimeRoot := str(run, "content_root")

	d, code, err = h.runTool("seal-tool", "sign",
		"-dir", seal, "-content-root", runtimeRoot,
		"-artifact", artifact, "-sig", sig, "-log", log)
	if err != nil {
		return "", err
	}
	if str(d, "decision") != "REFUSED" || code == 0 {
		return fmt.Sprintf("signing said %s (exit %d)", str(d, "decision"), code), nil
	}
	if r := str(d, "reason"); r != "measured-state-mismatch" {
		return "REFUSED:" + r, nil
	}
	if _, err := os.Stat(sig); err == nil {
		return "REFUSED but a signature exists", nil
	}

	return "REFUSED:measured-state-mismatch, unsigned, exit non-zero", nil
}

// logTamper edits one entry and shows the verifier catching it.
func logTamper(h *harness) (string, error) {
	log := h.path("logtamper", "audit.jsonl")
	os.MkdirAll(filepath.Dir(log), 0o700)

	l, err := auditlog.Open(log)
	if err != nil {
		return "", err
	}
	for _, e := range []struct{ event, detail string }{
		{auditlog.EvIngressAccept, "bundle=arazu-spike version=2"},
		{auditlog.EvRunStart, "mode=contained"},
		{auditlog.EvEgressDeny, "probe=tcp-connect errno=EPERM"},
		{auditlog.EvSign, "artifact=artifact.txt"},
	} {
		if _, err := l.Append(e.event, e.detail); err != nil {
			l.Close()
			return "", err
		}
	}
	l.Close()

	if v, code, err := h.runTool("log-verify", "-log", log); err != nil {
		return "", err
	} else if str(v, "decision") != "CLEAN" || code != 0 {
		return "the untouched log did not verify: " + str(v, "reason"), nil
	}

	// Rewrite history: make the denied egress attempt look permitted.
	b, err := os.ReadFile(log)
	if err != nil {
		return "", err
	}
	edited := strings.Replace(string(b), "errno=EPERM", "errno=NONE!", 1)
	if h.broken == "log-tamper" {
		edited = string(b) // sabotage: change nothing, so the chain stays clean
	}
	if err := os.WriteFile(log, []byte(edited), 0o600); err != nil {
		return "", err
	}

	v, code, err := h.runTool("log-verify", "-log", log)
	if err != nil {
		return "", err
	}
	if str(v, "decision") != "BROKEN" || code == 0 {
		return fmt.Sprintf("verifier said %s (exit %d)", str(v, "decision"), code), nil
	}
	if !strings.Contains(str(v, "reason"), "seq 3") {
		return "BROKEN but the reported entry was: " + str(v, "reason"), nil
	}

	return "BROKEN, chain break reported at the edited entry", nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
