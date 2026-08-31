// SPDX-License-Identifier: Apache-2.0

package revert

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arazu/pkg/corpus"
)

// challengeAt builds a Challenge over a throwaway tree whose run.sh is the
// script given. The shim is empty because nothing here calls docker.
func challengeAt(t *testing.T, runsh string) Challenge {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "run.sh"), []byte(runsh), 0o755); err != nil {
		t.Fatal(err)
	}
	return Challenge{Root: root}
}

// priorOutput plants a finished run_pov directory, as a previous invocation on
// the same tree would leave behind.
func priorOutput(t *testing.T, root, name, stderr string) {
	t.Helper()
	dir := filepath.Join(root, "out", "output", name+"--run_pov")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stderr.log"), []byte(stderr), 0o644); err != nil {
		t.Fatal(err)
	}
}

var testPoV = corpus.PoV{ExpectedSanitizer: "AddressSanitizer: heap-buffer-overflow"}

// A run that produced no output must not be answered out of the directory a
// previous run left. Both directions are wrong verdicts: a stale clean run reads
// as the vulnerability not reproducing, a stale crashing one rejects a candidate
// that was never measured.
func TestRunThatProducedNoOutputDoesNotReadThePreviousRun(t *testing.T) {
	c := challengeAt(t, "#!/bin/sh\nexit 1\n")
	priorOutput(t, c.Root, "2020-01-01T00-00-00",
		"Running: /blob\n==1==ERROR: AddressSanitizer: heap-buffer-overflow\n")

	_, err := c.RunPoV(context.Background(), "blob", "harness", testPoV)
	if err == nil {
		t.Fatal("a run that produced no output was answered from a previous run's directory")
	}
	if !strings.Contains(err.Error(), "no new") {
		t.Fatalf("error should say no new output appeared, got: %v", err)
	}
}

// The guard must not fire on the run that works. A run.sh that creates its own
// output directory is measured from that directory even when older ones sit
// beside it.
func TestOutputFromThisRunIsPreferredOverOlderOnes(t *testing.T) {
	c := challengeAt(t, "#!/bin/sh\n"+
		"d=out/output/2030-01-01T00-00-00--run_pov\n"+
		"mkdir -p \"$d\"\n"+
		"printf 'Running: /blob\\n==1==ERROR: AddressSanitizer: heap-buffer-overflow\\n' > \"$d/stderr.log\"\n")
	priorOutput(t, c.Root, "2020-01-01T00-00-00", "Running: /blob\nExecuted /blob in 3 ms\n")

	run, err := c.RunPoV(context.Background(), "blob", "harness", testPoV)
	if err != nil {
		t.Fatalf("a run that produced output should be readable: %v", err)
	}
	if !run.SanitizerFired {
		t.Error("read the stale clean directory instead of this run's crashing one")
	}
}

// buildScript fakes one `run.sh build`: it creates the output directory the real
// one creates, records the container's status in exitcode, and exits 0 whatever
// happened inside, as the real one does.
func buildScript(exitcode, stderr string) string {
	return "#!/bin/sh\n" +
		"d=out/output/2030-01-01T00-00-00--build\n" +
		"mkdir -p \"$d\"\n" +
		"printf '" + exitcode + "' > \"$d/exitcode\"\n" +
		"printf '" + stderr + "' > \"$d/stderr.log\"\n" +
		"exit 0\n"
}

func TestBuildFailureIsNotHiddenByRunShExitingZero(t *testing.T) {
	c := challengeAt(t, buildScript("1", "cc: fatal error\\n"))
	if err := c.Build(context.Background()); err == nil {
		t.Fatal("a build that failed inside the container was reported as a success")
	}
}

// The reason has to reach the operator: the exit status alone cannot carry it.
func TestAFailedBuildNamesWhatWentWrong(t *testing.T) {
	c := challengeAt(t, buildScript("1", "cc: fatal error\\n"))
	err := c.Build(context.Background())
	if err == nil {
		t.Fatal("no error at all")
	}
	if !strings.Contains(err.Error(), "cc: fatal error") {
		t.Errorf("the refusal does not carry the build's own diagnostic: %v", err)
	}
}

// The mirror, so the guard cannot be satisfied by refusing everything. A build
// that really succeeded must still pass.
func TestASuccessfulBuildIsNotRefused(t *testing.T) {
	c := challengeAt(t, buildScript("0", "ok\\n"))
	if err := c.Build(context.Background()); err != nil {
		t.Fatalf("a build that succeeded was refused: %v", err)
	}
}

func TestBuildThatProducedNoOutputIsNotAPass(t *testing.T) {
	c := challengeAt(t, "#!/bin/sh\nexit 0\n")
	if err := c.Build(context.Background()); err == nil {
		t.Fatal("a build that recorded nothing was treated as a success")
	}
}

// Unreadable is not zero. Two of the 132 build directories on the staged nginx
// checkout carry no exitcode or a blank one.
func TestABuildWithNoRecordedStatusIsNotAPass(t *testing.T) {
	c := challengeAt(t, "#!/bin/sh\nmkdir -p out/output/2030-01-01T00-00-00--build\nexit 0\n")
	if err := c.Build(context.Background()); err == nil {
		t.Fatal("a build whose status was never recorded was treated as a success")
	}
}
