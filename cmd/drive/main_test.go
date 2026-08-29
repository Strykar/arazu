// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	runs      = "../../testdata/crsout/realrun/run-data-20260819143519"
	withPatch = "0e69cb3f-68e4-4f52-a056-303b63408157"
	noPatch   = "017d6977-ca2e-46cd-ad5c-d8f92495024b"
	caseFile  = "../../corpus/cases/libpng/iccp-keyword.yaml"
)

type observed struct {
	Decision string   `json:"decision"`
	Reason   string   `json:"reason"`
	Root     string   `json:"content_root"`
	Evidence []string `json:"evidence"`
}

// Both fixtures are real Buttercup runs, not constructed ones: one that emitted
// a patch and one that emitted none. The whole point of the driver is what it
// does with each, so the test uses them rather than directories it builds.
func drive(t *testing.T, task string) (observed, int, string) {
	t.Helper()
	bin := binaries(t)
	w := t.TempDir()
	cmd := exec.Command(filepath.Join(bin, "drive"),
		"-run", runs, "-task", task, "-case", caseFile,
		"-out", filepath.Join(w, "captured"),
		"-dossier", filepath.Join(w, "dossier"),
		"-log", filepath.Join(w, "audit.jsonl"),
		"-bin", bin, "-stage", "m0")
	out, _ := cmd.Output()
	var o observed
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("no JSON decision (exit %d): %q", cmd.ProcessState.ExitCode(), out)
	}
	return o, cmd.ProcessState.ExitCode(), w
}

func TestARunWithAPatchReachesAVerdictUnderTheMeasuredRoot(t *testing.T) {
	o, code, _ := drive(t, withPatch)
	if o.Decision != "ACCEPT" || code != 0 {
		t.Fatalf("decision %s:%s exit %d, want ACCEPT exit 0", o.Decision, o.Reason, code)
	}
	if o.Root == "" {
		t.Error("no content root, so nothing was measured")
	}
	var covered bool
	for _, e := range o.Evidence {
		if strings.Contains(e, "decision.json is under the measured root") {
			covered = true
		}
	}
	if !covered {
		t.Error("the verdict was not confirmed to be inside what was measured")
	}
}

// THE FOURTH OUTCOME. A run that produced nothing is not a rejected patch.
// Reporting REJECT here would tell an operator the CRS produced a bad fix when
// it produced no fix, which sends them to the wrong artifact.
func TestARunWithNoPatchDeclinesRatherThanRejecting(t *testing.T) {
	o, code, _ := drive(t, noPatch)
	if o.Decision != "DECLINE" {
		t.Fatalf("decision %s, want DECLINE; REJECT here would blame a patch that does not exist", o.Decision)
	}
	if o.Reason != "crs-no-patch" {
		t.Errorf("reason %q, want crs-no-patch", o.Reason)
	}
	if code != 3 {
		t.Errorf("exit %d, want 3: a decline must be distinguishable from ACCEPT(0), REJECT(1) and ERROR(2)", code)
	}
}

// Absence has to be recorded, not inferred from a missing entry. A declined run
// leaves the same kind of record as one that reached a verdict.
func TestTheDeclineIsLoggedAndTheChainStillVerifies(t *testing.T) {
	o, _, w := drive(t, noPatch)
	if o.Decision != "DECLINE" {
		t.Fatalf("expected a decline, got %s", o.Decision)
	}
	b, err := os.ReadFile(filepath.Join(w, "audit.jsonl"))
	if err != nil {
		t.Fatalf("no audit log written for a declined run: %v", err)
	}
	if !strings.Contains(string(b), "DRIVE_DECLINE") {
		t.Error("the log carries no DRIVE_DECLINE, so a run that produced nothing left no record")
	}
	v := exec.Command(filepath.Join(binaries(t), "log-verify"),
		"-log", filepath.Join(w, "audit.jsonl"))
	out, _ := v.Output()
	if !strings.Contains(string(out), "CLEAN") {
		t.Errorf("log does not verify after a decline: %s", out)
	}
}

var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
)

// binaries builds the tools this test drives, rather than trusting whatever is
// in bin/. A prebuilt binary is indistinguishable from a current one until it
// disagrees with the tree: adding observer: to the corpus schema left a stale
// bin/drive whose strict unmarshalling correctly refused a field it did not
// know, and the test reported case-unreadable, which reads as a broken case
// file rather than a stale build.
func binaries(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		d, err := os.MkdirTemp("", "arazu-drive-bin-")
		if err != nil {
			buildErr = err
			return
		}
		buildDir = d
		out, err := exec.Command("go", "build", "-o", d,
			"../gate", "../seal-tool", "../drive", "../log-verify").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build tools: %w: %s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return buildDir
}
