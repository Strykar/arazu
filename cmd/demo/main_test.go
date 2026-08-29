// SPDX-License-Identifier: Apache-2.0

package main

import (
	"arazu/pkg/hostcap"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The demo runs the whole envelope: namespace creation, LSM attach and TPM
// sealing. Without CAP_SYS_ADMIN it cannot start, which is a property of the
// machine and not a failed prediction.
func requireSysAdmin(t *testing.T) {
	t.Helper()
	if !hostcap.HasSysAdmin() {
		t.Skip("needs CAP_SYS_ADMIN: the demo creates namespaces and seals to the TPM")
	}
}

func runDemo(t *testing.T, breakBranch string) (string, int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for netns creation, LSM attach and TPM access")
	}
	if !hostcap.HasTPM() {
		t.Skip("no TPM device: the happy path seals and unseals")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	args := []string{"-repo", repo, "-workdir", t.TempDir()}
	if breakBranch != "" {
		args = append(args, "-break-branch", breakBranch)
	}
	cmd := exec.Command(filepath.Join(repo, "bin", "demo"), args...)
	out, _ := cmd.CombinedOutput()
	return string(out), cmd.ProcessState.ExitCode()
}

func TestDemoAllBranchesMatchPredictions(t *testing.T) {
	requireSysAdmin(t)
	out, code := runDemo(t, "")

	if code != 0 {
		t.Fatalf("demo exited %d:\n%s", code, out)
	}
	for _, want := range []string{"happy-path", "poisoned-bundle", "tampered-content", "log-tamper"} {
		if !strings.Contains(out, want) {
			t.Errorf("branch %q missing from the demo output", want)
		}
	}
	if strings.Contains(out, "MISMATCH") {
		t.Errorf("a branch did not match its prediction:\n%s", out)
	}
	if n := strings.Count(out, "MATCH"); n < 4 {
		t.Errorf("only %d branches reported MATCH", n)
	}
}

// A harness that cannot fail proves nothing. Every branch must be breakable,
// and breaking it must be caught.
//
// This test earns its place: sabotaging tampered-content originally produced
// no mismatch, which revealed that the branch was refusing to sign because
// the gate and the runner measured different path prefixes, not because
// anything had been tampered with.
func TestDemoCatchesEveryBrokenBranch(t *testing.T) {
	requireSysAdmin(t)
	for _, b := range []string{"happy-path", "poisoned-bundle", "tampered-content", "log-tamper"} {
		t.Run(b, func(t *testing.T) {
			out, code := runDemo(t, b)
			if code == 0 {
				t.Fatalf("demo reported success with %s deliberately broken:\n%s", b, out)
			}
			if !strings.Contains(out, "MISMATCH") {
				t.Errorf("no mismatch reported for the broken branch:\n%s", out)
			}
			if !strings.Contains(out, b) {
				t.Errorf("output does not name the broken branch %s", b)
			}
		})
	}
}

// An unrecognised branch name must be an error. Accepting it silently would
// report all-match and read as the harness passing.
func TestDemoRejectsAnUnknownBrokenBranch(t *testing.T) {
	requireSysAdmin(t)
	out, code := runDemo(t, "no-such-branch")
	if code == 0 {
		t.Fatalf("demo accepted an unknown -break-branch:\n%s", out)
	}
	if strings.Contains(out, "RESULT: all four branches matched") {
		t.Error("demo reported success for an unknown -break-branch")
	}
}

// The honesty note has to be in the output, not only in SCOPE.md. Someone
// watching the demo should not come away thinking this is measured boot.
func TestDemoStatesTheResettablePCRLimit(t *testing.T) {
	requireSysAdmin(t)
	out, _ := runDemo(t, "")
	if !strings.Contains(out, "resettable") {
		t.Error("the demo does not say that PCR 23 is resettable")
	}
	if !strings.Contains(out, "SCOPE.md") {
		t.Error("the demo does not point at SCOPE.md for what it fails to prove")
	}
}
