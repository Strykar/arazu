// SPDX-License-Identifier: Apache-2.0

// Command contained-run executes the stand-in workload and the egress
// probe under one of three containment modes.
//
// Three modes rather than two. The workbook asks only for containment
// versus a control, but that pair cannot attribute the result to the BPF
// layer: "the contained run reached nothing" is equally well explained by
// the namespace alone. Running netns-only in between isolates the layers,
// and flipping just the BPF layer changes the observed errno from
// ENETUNREACH to EPERM.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"arazu/pkg/auditlog"
	"arazu/pkg/contentstore"
	"arazu/pkg/egress"
)

const (
	modeControl   = "control"
	modeNetnsOnly = "netns-only"
	modeContained = "contained"
)

type probe struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Reached bool   `json:"reached"`
	Errno   string `json:"errno"`
	Detail  string `json:"detail"`
}

type result struct {
	// OK is first so a reader that scans the object top-down meets the verdict
	// before any detail. The run already exits non-zero and prints the reason to
	// stderr, and both were once discarded by a caller using `|| true` and a
	// stderr redirect it never read — so the verdict is also carried IN the
	// object, where a partial read cannot step over it. Reading order is a
	// property of the output, not of the reader's discipline.
	OK          bool            `json:"ok"`
	Mode        string          `json:"mode"`
	NetnsInode  uint32          `json:"netns_inode"`
	BPFAttached bool            `json:"bpf_attached"`
	ContentRoot string          `json:"content_root"`
	Artifact    string          `json:"artifact,omitempty"`
	Probes      []probe         `json:"probes"`
	BPFDenials  egress.Counters `json:"bpf_denials"`
	Reason      string          `json:"reason,omitempty"`
}

func main() {
	mode := flag.String("mode", modeContained, "containment mode: contained, netns-only or control")
	bundle := flag.String("bundle", "", "verified bundle the workload reads and the run re-measures")
	out := flag.String("out", "", "artifact path the workload writes")
	logPath := flag.String("log", "", "audit log path")
	obj := flag.String("obj", "bpf/egress_deny.bpf.o", "compiled BPF object")
	probeScript := flag.String("probe", "scripts/egress-probe.sh", "egress probe script")
	nsName := flag.String("ns", "arazu-run", "network namespace name")
	workloadOnly := flag.Bool("workload-only", false, "internal: run just the workload, used to run it inside the namespace")
	flag.Parse()

	// The workload re-executes this binary inside the namespace so it runs
	// under containment rather than beside it.
	if *workloadOnly {
		if err := workload(*bundle, *out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *bundle == "" || *out == "" || *logPath == "" {
		fatal(result{Mode: *mode, Reason: "need -bundle, -out and -log"})
	}

	r, err := execute(*mode, *bundle, *out, *logPath, *obj, *probeScript, *nsName)
	emit(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func execute(mode, bundle, out, logPath, obj, probeScript, nsName string) (result, error) {
	r := result{Mode: mode}

	// Re-measure the bundle exactly the way the gate measured it. Using the
	// shared helper is what keeps the two from drifting apart, which would
	// make the fail-closed branch pass with nothing tampered.
	_, root, err := contentstore.MeasureBundle(bundle)
	if err != nil {
		r.Reason = "cannot measure the bundle: " + err.Error()
		return r, err
	}
	r.ContentRoot = root

	l, err := auditlog.Open(logPath)
	if err != nil {
		r.Reason = "audit-log-unavailable: " + err.Error()
		return r, err
	}
	defer l.Close()
	l.Append(auditlog.EvRunStart, fmt.Sprintf("mode=%s bundle=%s content_root=%s", mode, bundle, r.ContentRoot))

	var ns *egress.Netns
	var deny *egress.Deny

	if mode == modeNetnsOnly || mode == modeContained {
		egress.CleanupStale(nsName)
		ns, err = egress.CreateNetns(nsName)
		if err != nil {
			r.Reason = "cannot create the namespace: " + err.Error()
			l.Append(auditlog.EvRunEnd, "mode="+mode+" result=setup-failed reason="+r.Reason)
			return r, err
		}
		defer ns.Close()
		r.NetnsInode = ns.Inode
	}

	// Attach before anything runs inside the namespace. Doing it after would
	// leave a window in which the workload is uncontained.
	if mode == modeContained {
		deny, err = egress.AttachDeny(obj, ns.Inode)
		if err != nil {
			// Fail closed. Falling back to netns-only here would silently
			// downgrade the containment while still reporting the contained
			// mode, which is the failure this whole spike argues against.
			r.Reason = "cannot attach egress denial: " + err.Error()
			l.Append(auditlog.EvRunEnd, "mode="+mode+" result=attach-failed reason="+r.Reason)
			return r, fmt.Errorf("refusing to run uncontained: %w", err)
		}
		defer deny.Close()
		r.BPFAttached = true
	}

	if err := runWorkload(ns, bundle, out); err != nil {
		r.Reason = "workload failed: " + err.Error()
		l.Append(auditlog.EvRunEnd, "mode="+mode+" result=workload-failed reason="+r.Reason)
		return r, err
	}
	r.Artifact = out

	r.Probes, err = runProbe(ns, mode, probeScript)
	if err != nil {
		r.Reason = "probe failed to run: " + err.Error()
		l.Append(auditlog.EvRunEnd, "mode="+mode+" result=probe-failed reason="+r.Reason)
		return r, err
	}

	for _, p := range r.Probes {
		l.Append(auditlog.EvEgressRequest, fmt.Sprintf("probe=%s class=%s", p.Name, p.Class))
		if !p.Reached {
			l.Append(auditlog.EvEgressDeny, fmt.Sprintf("probe=%s errno=%s detail=%s", p.Name, p.Errno, p.Detail))
		}
	}

	if deny != nil {
		if r.BPFDenials, err = deny.Counters(); err != nil {
			r.Reason = "cannot read the denial counters: " + err.Error()
			return r, err
		}
	}

	if err := r.checkExpectations(); err != nil {
		r.Reason = err.Error()
		l.Append(auditlog.EvRunEnd, "mode="+mode+" result=expectations-unmet reason="+r.Reason)
		return r, err
	}

	l.Append(auditlog.EvRunEnd, fmt.Sprintf("mode=%s result=ok reach_denied=%d bpf_denials=%d",
		mode, r.countDenied(), r.BPFDenials.ConnectDenied+r.BPFDenials.SendmsgDenied))
	r.OK = true
	return r, nil
}

func (r result) countDenied() int {
	n := 0
	for _, p := range r.Probes {
		if p.Class == classReach && !p.Reached {
			n++
		}
	}
	return n
}

// Probe classes. Only REACH probes bear on whether containment held; a
// LOCAL probe that succeeds has not reached anything.
const (
	classReach  = "REACH"
	classLocal  = "LOCAL"
	classConfig = "CONFIG"
	// A destination the policy deliberately permits, which must be REACHED
	// under containment. Its denial is the failure.
	//
	// This is not LOCAL. Both stay on the box, but their required verdicts are
	// OPPOSITE: raw-packet-loopback must be refused under containment, because
	// that denial is the only one the namespace cannot produce and is what
	// attributes the result to the bpf hook. model-loopback must succeed,
	// because the model server lives inside the boundary and an unreachable
	// model is a broken deployment. Expressing both as LOCAL made the carve-out
	// register as "the bpf hook let a local raw send through".
	classPermitted = "PERMITTED"
	// Exercises a real code path but cannot attribute between the namespace and
	// the bpf hook, so it is reported and excluded from the containment verdict.
	classCoverage = "COVERAGE"
)

// checkExpectations makes the runner assert its own mode's contract, so a
// mode that quietly stops containing anything fails here rather than being
// left for a reader of the JSON to notice.
func (r result) checkExpectations() error {
	var reached, denied, localReached, localDenied, permittedDenied []string
	for _, p := range r.Probes {
		switch p.Class {
		case classReach:
			if p.Reached {
				reached = append(reached, p.Name)
			} else {
				denied = append(denied, p.Name)
			}
		case classLocal:
			if p.Reached {
				localReached = append(localReached, p.Name)
			} else {
				localDenied = append(localDenied, p.Name+"("+p.Errno+")")
			}
		case classPermitted:
			if !p.Reached {
				permittedDenied = append(permittedDenied, p.Name+"("+p.Errno+")")
			}
		}
	}

	switch r.Mode {
	case modeControl:
		if len(reached) == 0 {
			return errors.New("control run reached nothing, so the probe is not exercising real egress " +
				"and no containment result derived from it means anything")
		}
	case modeNetnsOnly, modeContained:
		if len(reached) > 0 {
			return fmt.Errorf("containment leaked: %s reached off the box", strings.Join(reached, ", "))
		}
		if len(denied) == 0 {
			return errors.New("no reach probes ran, so nothing was proven")
		}
	}

	// The namespace cannot refuse a raw send onto its own loopback, so this
	// is where the two layers separate. Under netns-only the local probe is
	// expected to succeed; under containment the bpf hook must refuse it.
	switch r.Mode {
	case modeNetnsOnly:
		if len(localReached) == 0 && len(localDenied) > 0 {
			return fmt.Errorf("netns-only refused a local send (%s), which the namespace alone cannot do; "+
				"something else is enforcing and the layers can no longer be told apart",
				strings.Join(localDenied, ", "))
		}
	case modeContained:
		// The carve-out's matched twin. Off-box must be refused (checked above)
		// AND the permitted destination must be reachable; asserting only the
		// first is satisfied by a policy that denies everything, which would
		// leave the model unreachable and the run still "passing".
		if len(permittedDenied) > 0 {
			return fmt.Errorf("a deliberately permitted destination was refused: %s; "+
				"the model would be unreachable from inside the boundary",
				strings.Join(permittedDenied, ", "))
		}
		if len(localReached) > 0 {
			return fmt.Errorf("the bpf hook let a local raw send through: %s", strings.Join(localReached, ", "))
		}
		if r.BPFDenials.ConnectDenied == 0 && r.BPFDenials.SendmsgDenied == 0 {
			return errors.New("the bpf hooks denied nothing, so the namespace did all the work " +
				"and the defence-in-depth layer is unevidenced")
		}
	}
	return nil
}

// workload is the stand-in. It reads the verified store and writes one
// artifact. It is deliberately trivial: this spike proves the envelope, not
// anything about what runs inside it.
func workload(bundle, out string) error {
	files, _, err := contentstore.MeasureBundle(bundle)
	if err != nil {
		return err
	}
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(bundle, filepath.FromSlash(f.Path)))
		if err != nil {
			return err
		}
		h.Write(b)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	body := fmt.Sprintf("arazu-spike-artifact\nfiles=%d\ndigest=%s\n",
		len(files), hex.EncodeToString(h.Sum(nil)))
	return os.WriteFile(out, []byte(body), 0o600)
}

func runWorkload(ns *egress.Netns, bundle, out string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	argv := []string{self, "-workload-only", "-bundle", bundle, "-out", out}

	if ns == nil {
		return workload(bundle, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, stderr, code, err := ns.Exec(ctx, argv)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("workload exited %d: %s", code, stderr)
	}
	return nil
}

func runProbe(ns *egress.Netns, mode, script string) ([]probe, error) {
	abs, err := filepath.Abs(script)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	var stdout []byte
	if ns == nil {
		// On the host, skip the probes that would reconfigure the operator's
		// own machine.
		os.Setenv("ARAZU_PROBE_SKIP_CONFIG", "1")
		stdout, err = runHost(ctx, abs)
	} else {
		stdout, _, _, err = ns.Exec(ctx, []string{"/usr/bin/env", "bash", abs})
	}
	if err != nil {
		return nil, err
	}

	var probes []probe
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var p probe
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			return nil, fmt.Errorf("unparseable probe line %q: %w", line, err)
		}
		probes = append(probes, p)
	}
	if len(probes) == 0 {
		return nil, fmt.Errorf("probe produced no results: %q", stdout)
	}
	return probes, nil
}

func emit(r result) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot render result: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(b))

	fmt.Fprintf(os.Stderr, "mode=%s netns=%d bpf=%v\n", r.Mode, r.NetnsInode, r.BPFAttached)
	for _, p := range r.Probes {
		verdict := "denied"
		if p.Reached {
			verdict = "REACHED"
		}
		fmt.Fprintf(os.Stderr, "  %-26s %-7s %-8s %s\n", p.Name, p.Class, verdict, p.Errno)
	}
	if r.BPFAttached {
		fmt.Fprintf(os.Stderr, "  kernel denials: connect=%d sendmsg=%d (seen connect=%d sendmsg=%d)\n",
			r.BPFDenials.ConnectDenied, r.BPFDenials.SendmsgDenied,
			r.BPFDenials.ConnectSeen, r.BPFDenials.SendmsgSeen)
	}
}

func fatal(r result) {
	emit(r)
	os.Exit(2)
}
