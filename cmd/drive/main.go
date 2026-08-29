// SPDX-License-Identifier: Apache-2.0

// drive joins a CRS run to the gate.
//
// crsout turns what Buttercup left on disk into a gradable case, the gate
// reaches a verdict, and the envelope binds that verdict to measured state.
//
// It composes the built binaries rather than reimplementing their wiring: the
// stage chain lives in cmd/gate, and a second copy agrees until one changes.
//
// FOUR OUTCOMES, NOT THREE. DECLINE is added for a run that gave the gate
// nothing to grade. Folding that into REJECT would report a bad patch where
// there was none. A decline is still logged, like any other outcome.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"arazu/pkg/auditlog"
	"arazu/pkg/contentstore"
	"arazu/pkg/corpus"
	"arazu/pkg/crsout"
)

type decision struct {
	Decision string   `json:"decision"`
	Reason   string   `json:"reason,omitempty"`
	Task     string   `json:"task_id"`
	Stage    string   `json:"stage,omitempty"`
	Case     string   `json:"case_path,omitempty"`
	Root     string   `json:"content_root,omitempty"`
	Evidence []string `json:"evidence"`
}

func main() {
	run := flag.String("run", "", "a run-data-<ts> directory from the CRS")
	task := flag.String("task", "", "task id under that directory")
	casePath := flag.String("case", "", "the corpus case the task was submitted from")
	out := flag.String("out", "", "where the captured case is written")
	stage := flag.String("stage", "m0", "gate stage: m0, m1, m3")
	dossier := flag.String("dossier", "", "directory the verdict is written into")
	seal := flag.String("seal", "", "seal state directory")
	logPath := flag.String("log", "", "audit log")
	bin := flag.String("bin", "bin", "directory holding gate and seal-tool")
	flag.Parse()

	for _, f := range []struct{ name, v string }{
		{"-run", *run}, {"-task", *task}, {"-case", *casePath},
		{"-out", *out}, {"-dossier", *dossier}, {"-log", *logPath},
	} {
		if f.v == "" {
			fail("usage: drive -run <dir> -task <id> -case <file> -out <dir> -dossier <dir> -log <file>", f.name+" is required")
		}
	}

	d := decision{Task: *task, Stage: *stage}

	c, err := corpus.Load(*casePath)
	if err != nil {
		emit(decision{Decision: "ERROR", Reason: "case-unreadable", Task: *task,
			Evidence: []string{err.Error()}}, 2)
	}

	// Absolute, so the captured case's paths resolve on their own. joinRoot
	// returns an absolute path unchanged, so the gate's -root cannot move them.
	absOut, err := filepath.Abs(*out)
	if err != nil {
		emit(decision{Decision: "ERROR", Reason: "out-unresolvable", Task: *task,
			Evidence: []string{err.Error()}}, 2)
	}

	res, err := crsout.Capture(*run, *task, sourceOf(c), absOut)
	if err != nil {
		emit(decision{Decision: "ERROR", Reason: "capture-failed", Task: *task,
			Evidence: []string{err.Error()}}, 2)
	}
	d.Evidence = append(d.Evidence, res.Evidence...)

	if res.Outcome != crsout.Captured {
		d.Decision, d.Reason = "DECLINE", string(res.Outcome)
		if res.Detail != "" {
			d.Evidence = append(d.Evidence, res.Detail)
		}
		// Logged like any other outcome. A run that produced nothing to grade
		// is a fact about the CRS and belongs in the record.
		logDecline(*logPath, "DECLINE "+string(res.Outcome)+" task="+*task)
		emit(d, 3)
	}
	d.Case = res.CasePath
	d.Evidence = append(d.Evidence, "captured "+res.PatchID+" against pov "+res.PoVID)

	if err := os.MkdirAll(*dossier, 0o700); err != nil {
		emit(decision{Decision: "ERROR", Reason: "dossier-unwritable", Task: *task,
			Evidence: []string{err.Error()}}, 2)
	}

	// The gate writes decision.json into the dossier and appends GATE_* to the
	// log. Its exit code carries the verdict; its stdout carries the reason.
	gd, code := runTool(*bin, "gate",
		"-case", res.CasePath, "-candidate", "crs-"+*task+"-candidate",
		"-stage", *stage, "-root", "", "-repo", ".",
		"-bundle", *dossier, "-log", *logPath)
	d.Decision = strOf(gd, "verdict")
	if d.Decision == "" {
		d.Decision = strOf(gd, "decision")
	}
	d.Reason = strOf(gd, "reason")
	if d.Decision == "" {
		emit(decision{Decision: "ERROR", Reason: "gate-said-nothing", Task: *task,
			Evidence: append(d.Evidence, fmt.Sprintf("exit %d", code))}, 2)
	}

	// Measure the dossier and confirm the verdict is inside it before sealing.
	// Recomputed rather than assumed: a dossier with no decision in it still
	// has a perfectly valid root, and everything downstream signs it happily.
	files, root, err := contentstore.MeasureBundle(*dossier)
	if err != nil {
		emit(decision{Decision: "ERROR", Reason: "dossier-unmeasurable", Task: *task,
			Evidence: []string{err.Error()}}, 2)
	}
	covered := false
	for _, f := range files {
		if filepath.Base(f.Path) == "decision.json" {
			covered = true
		}
	}
	if !covered {
		emit(decision{Decision: "ERROR", Reason: "verdict-not-under-the-root", Task: *task,
			Evidence: append(d.Evidence, "measured root does not cover decision.json")}, 2)
	}
	d.Root = root
	d.Evidence = append(d.Evidence, "decision.json is under the measured root")

	if *seal != "" {
		if _, code := runTool(*bin, "seal-tool", "provision",
			"-dir", *seal, "-content-root", root, "-log", *logPath); code != 0 {
			emit(decision{Decision: "ERROR", Reason: "seal-provision-failed", Task: *task,
				Evidence: d.Evidence}, 2)
		}
		sd, code := runTool(*bin, "seal-tool", "sign",
			"-dir", *seal, "-content-root", root,
			"-artifact", filepath.Join(*dossier, "decision.json"),
			"-sig", filepath.Join(*dossier, "decision.sig"), "-log", *logPath)
		if strOf(sd, "decision") != "SIGNED" || code != 0 {
			emit(decision{Decision: "ERROR", Reason: "signing-failed", Task: *task,
				Evidence: append(d.Evidence, strOf(sd, "reason"))}, 2)
		}
		d.Evidence = append(d.Evidence, "verdict signed against the measured root")
	}

	emit(d, exitFor(d.Decision))
}

func sourceOf(c corpus.Case) crsout.Source {
	return crsout.Source{
		Repo:              c.Source.SrcRepo,
		BaseCommit:        c.Source.BaseCommit,
		HeadCommit:        c.Source.SrcCommit,
		Project:           c.Source.FuzzToolingProject,
		Harness:           c.Harness,
		Sanitizer:         c.PoV.Sanitizer,
		ExpectedSanitizer: c.PoV.ExpectedSanitizer,
		CrashLocation:     c.PoV.CrashLocation,
	}
}

func exitFor(v string) int {
	switch v {
	case "ACCEPT":
		return 0
	case "REJECT":
		return 1
	default:
		return 2
	}
}

func runTool(bin, name string, args ...string) (map[string]any, int) {
	cmd := exec.Command(filepath.Join(bin, name), args...)
	outB, _ := cmd.Output()
	var m map[string]any
	_ = json.Unmarshal(outB, &m)
	return m, cmd.ProcessState.ExitCode()
}

// logDecline records an outcome the gate never saw, into the same chain as
// every other event, so a declined run leaves the same kind of record as one
// that reached a verdict.
func logDecline(logPath, msg string) {
	l, err := auditlog.Open(logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not open the log:", err)
		return
	}
	defer l.Close()
	if _, err := l.Append(auditlog.EvDriveDecline, msg); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not record the decline:", err)
	}
}

func strOf(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func emit(d decision, code int) {
	if d.Evidence == nil {
		d.Evidence = []string{}
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(b))
	os.Exit(code)
}

func fail(usage, why string) {
	fmt.Fprintln(os.Stderr, usage)
	fmt.Fprintln(os.Stderr, "  "+why)
	os.Exit(2)
}
