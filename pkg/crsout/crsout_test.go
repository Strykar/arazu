// SPDX-License-Identifier: Apache-2.0

package crsout

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"arazu/pkg/corpus"
)

func run(t *testing.T) (string, string) {
	t.Helper()
	d := t.TempDir()
	return filepath.Join(d, "run"), filepath.Join(d, "out")
}

func put(t *testing.T, runDir, task, kind, id string, body []byte) {
	t.Helper()
	dir := filepath.Join(runDir, task, kind)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

var diff = []byte("--- a/x.c\n+++ b/x.c\n@@ -1,3 +1,3 @@\n-bad\n+good\n")

func src() Source {
	return Source{
		Repo: "https://github.com/example/thing", BaseCommit: "aaaa", HeadCommit: "bbbb",
		Project: "thing", Harness: "thing_fuzzer", Sanitizer: "address",
		ExpectedSanitizer: "AddressSanitizer: heap-buffer-overflow",
		CrashLocation:     "do_thing thing.c:42",
	}
}

// THE load-bearing test. The whole reason this emits a case rather than a
// bespoke format is that the existing machinery can read it. Load is strict —
// KnownFields(true) — so one wrong field name means the capture produces
// something nothing downstream can open, and every other test here would still
// pass.
func TestACapturedCaseLoads(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "p1.patch", diff)
	put(t, runDir, "t1", "povs", "v1.bin", []byte("\x01\x02"))

	res, err := Capture(runDir, "t1", src(), out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Captured {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Detail)
	}

	c, err := corpus.Load(res.CasePath)
	if err != nil {
		t.Fatalf("the emitted case does not load: %v", err)
	}
	if len(c.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(c.Candidates))
	}
	// A captured case has no answer key. Presuming one would make eval M0
	// grade the capture instead of the patch.
	if c.Candidates[0].ExpectedGateReason != nil {
		t.Errorf("captured case carries an expected_gate_reason: %v", *c.Candidates[0].ExpectedGateReason)
	}
	if c.Source.BaseCommit != "aaaa" || c.Source.SrcCommit != "bbbb" {
		t.Errorf("pins not carried: base=%q src=%q", c.Source.BaseCommit, c.Source.SrcCommit)
	}
}

// The outcome that decides whether "unattended" is real. A run that produced
// nothing must be a named result, not an empty directory the chain walks past.
func TestNoPatchIsANamedOutcome(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "povs", "v1.bin", []byte("x"))

	res, _ := Capture(runDir, "t1", src(), out)
	if res.Outcome != NoPatch {
		t.Fatalf("outcome = %s, want crs-no-patch", res.Outcome)
	}
	if res.Detail == "" {
		t.Error("a named outcome with no detail sends nobody anywhere")
	}
}

func TestEachFailureIsDistinct(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, runDir string)
		want  Outcome
	}{
		{"no task directory", func(*testing.T, string) {}, NoRun},
		{"patch with no pov", func(t *testing.T, r string) {
			put(t, r, "t1", "patches", "p1.patch", diff)
		}, NoPoV},
		{"patch with no hunk", func(t *testing.T, r string) {
			put(t, r, "t1", "patches", "p1.patch", []byte("I fixed it, trust me"))
			put(t, r, "t1", "povs", "v1.bin", []byte("x"))
		}, Malformed},
		{"empty pov", func(t *testing.T, r string) {
			put(t, r, "t1", "patches", "p1.patch", diff)
			put(t, r, "t1", "povs", "v1.bin", nil)
		}, Malformed},
		{"two of each, no bundle", func(t *testing.T, r string) {
			put(t, r, "t1", "patches", "p1.patch", diff)
			put(t, r, "t1", "patches", "p2.patch", diff)
			put(t, r, "t1", "povs", "v1.bin", []byte("x"))
			put(t, r, "t1", "povs", "v2.bin", []byte("y"))
		}, Unpairable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runDir, out := run(t)
			tc.setup(t, runDir)
			res, err := Capture(runDir, "t1", src(), out)
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %s, want %s (%s)", res.Outcome, tc.want, res.Detail)
			}
			if res.CasePath != "" {
				t.Error("a failed capture wrote a case anyway")
			}
		})
	}
}

// Without a sanitizer string, SanitizerFired is strings.Contains(report, ""),
// true of everything, and the case grades every candidate clean. Refuse.
func TestNoSanitizerReportIsRefused(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "p1.patch", diff)
	put(t, runDir, "t1", "povs", "v1.bin", []byte("x"))
	sr := src()
	sr.ExpectedSanitizer = ""

	res, _ := Capture(runDir, "t1", sr, out)
	if res.Outcome != NoSanitizerReport {
		t.Fatalf("outcome = %s, want crs-no-sanitizer-report", res.Outcome)
	}
	if res.CasePath != "" {
		t.Error("wrote a case that would grade everything clean")
	}
}

// A captured case is a question, not an oracle: no reference patch, because a
// novel target has no known-good fix.
func TestACapturedCaseIsMarkedAndCarriesNoReference(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "p1.patch", diff)
	put(t, runDir, "t1", "povs", "v1.bin", []byte("x"))
	res, _ := Capture(runDir, "t1", src(), out)

	c, err := corpus.Load(res.CasePath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != corpus.KindCaptured {
		t.Errorf("kind = %q, want captured", c.Kind)
	}
	if c.ReferencePatch != "" {
		t.Errorf("a captured case invented a reference patch: %q", c.ReferencePatch)
	}
}

// The discriminating test for the join. Alphabetical order and the bundle
// disagree here, so a pairing by filename passes every other test and fails
// this one. That is the whole reason to read the bundle.
func TestTheBundleDecidesThePairing(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "aaa.patch", []byte("--- a\n+++ b\n@@ -1 +1 @@\n-a\n+A\n"))
	put(t, runDir, "t1", "patches", "zzz.patch", diff)
	put(t, runDir, "t1", "povs", "aaa.bin", []byte("first"))
	put(t, runDir, "t1", "povs", "zzz.bin", []byte("second"))
	b, _ := json.Marshal(Bundle{BundleID: "b1", TaskID: "t1", PoVID: "zzz", PatchID: "zzz"})
	put(t, runDir, "t1", "bundles", "b1.json", b)

	res, err := Capture(runDir, "t1", src(), out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Captured {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Detail)
	}
	if res.PatchID != "zzz" || res.PoVID != "zzz" {
		t.Errorf("paired %s/%s, want zzz/zzz: the bundle was not consulted", res.PatchID, res.PoVID)
	}
}

// One of each is unambiguous, so a missing bundle is not a refusal there.
func TestOneOfEachPairsWithoutABundle(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "only.patch", diff)
	put(t, runDir, "t1", "povs", "only.bin", []byte("x"))

	if res, _ := Capture(runDir, "t1", src(), out); res.Outcome != Captured {
		t.Fatalf("outcome = %s (%s)", res.Outcome, res.Detail)
	}
}

// Artifacts are copied, so the case survives the CRS scratch being cleaned.
func TestArtifactsAreCopiedNotReferenced(t *testing.T) {
	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "p1.patch", diff)
	put(t, runDir, "t1", "povs", "v1.bin", []byte("x"))
	res, _ := Capture(runDir, "t1", src(), out)

	if err := os.RemoveAll(runDir); err != nil {
		t.Fatal(err)
	}
	c, err := corpus.Load(res.CasePath)
	if err != nil {
		t.Fatalf("case unreadable after the run dir went away: %v", err)
	}
	if _, err := os.Stat(c.PoV.Input); err != nil {
		t.Errorf("the pov did not survive: %v", err)
	}
}
