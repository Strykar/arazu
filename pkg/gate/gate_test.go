// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arazu/pkg/corpus"
)

func notProven() []string { return []string{"only patch-effect has run"} }

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func input(t *testing.T, patchBody string) Input {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "cand.diff", patchBody)
	return Input{
		Case:      corpus.Case{ID: "nginx-cpv2"},
		Candidate: corpus.Candidate{ID: "cand", Patch: "cand.diff"},
		Root:      dir,
	}
}

// The M0 acceptance criterion: a no-op patch is refused, with a reason, and the
// decision it produces is schema-valid.
func TestNoOpPatchIsRejectedWithAReason(t *testing.T) {
	// Headers and context only. This applies cleanly, builds, and leaves the
	// vulnerability exactly where it was.
	noop := `--- a/src/core/ngx_string.c
+++ b/src/core/ngx_string.c
@@ -1325,7 +1325,7 @@
     ngx_str_t  src;
     ngx_str_t  dst;

`
	d, err := Verify(context.Background(), input(t, noop), []Stage{EffectStage{}}, notProven())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Verdict != VerdictReject {
		t.Errorf("verdict = %s, want REJECT", d.Verdict)
	}
	if d.Reason != corpus.ReasonEmptyPatch {
		t.Errorf("reason = %q, want %q", d.Reason, corpus.ReasonEmptyPatch)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("decision is not schema-valid: %v", err)
	}
}

// The counterpart: a patch that changes a line clears this stage. Without it,
// a stage hard-wired to reject would pass the test above.
func TestPatchThatChangesALinePasses(t *testing.T) {
	real := `--- a/src/core/ngx_string.c
+++ b/src/core/ngx_string.c
@@ -1325,7 +1325,7 @@
-    auth.len = encoded.len;
+    auth.len = ngx_base64_decoded_length(encoded.len);
`
	d, err := Verify(context.Background(), input(t, real), []Stage{EffectStage{}}, notProven())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Verdict != VerdictAccept {
		t.Fatalf("verdict = %s (%s), want ACCEPT", d.Verdict, d.Reason)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("decision is not schema-valid: %v", err)
	}
}

// A file rename with no edits is the same nothing-happened as an empty diff,
// and the +++/--- lines are what a naive line count reads as changes.
func TestHeaderLinesAreNotCountedAsChanges(t *testing.T) {
	headersOnly := "--- a/a.c\n+++ b/a.c\n"
	d, err := Verify(context.Background(), input(t, headersOnly), []Stage{EffectStage{}}, notProven())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Reason != corpus.ReasonEmptyPatch {
		t.Errorf("reason = %q, want %q", d.Reason, corpus.ReasonEmptyPatch)
	}
}

// A stage that cannot run has decided nothing. It must not surface as a REJECT,
// because that would credit the gate with a judgement it never made.
func TestUnreadablePatchIsNotAVerdict(t *testing.T) {
	in := Input{
		Case:      corpus.Case{ID: "nginx-cpv2"},
		Candidate: corpus.Candidate{ID: "cand", Patch: "does-not-exist.diff"},
		Root:      t.TempDir(),
	}
	_, err := Verify(context.Background(), in, []Stage{EffectStage{}}, notProven())
	if err == nil {
		t.Fatal("want an error when the patch cannot be read, got a decision")
	}
}

type stubStage struct {
	name string
	res  StageResult
}

func (s stubStage) Name() string { return s.name }
func (s stubStage) Run(context.Context, Input) (StageResult, error) {
	return s.res, nil
}

// Stages after a failure must be absent, not recorded as passing: a Decision
// that listed them would imply checks that never ran.
func TestVerifyStopsAtTheFirstFailure(t *testing.T) {
	fail := stubStage{"first", StageResult{Outcome: OutcomeFailed, Reason: "boom", Evidence: []string{"ran"}}}
	after := stubStage{"second", StageResult{Outcome: OutcomePassed, Evidence: []string{"ran"}}}

	d, err := Verify(context.Background(), input(t, "x"), []Stage{fail, after}, notProven())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(d.Stages) != 1 {
		t.Fatalf("recorded %d stages, want 1", len(d.Stages))
	}
	if d.Stages[0].Stage != "first" {
		t.Errorf("recorded %q, want the failing stage", d.Stages[0].Stage)
	}
}

func TestDecisionValidateRefusesUnsupportedClaims(t *testing.T) {
	ok := []StageResult{{Stage: "s", Outcome: OutcomePassed, Evidence: []string{"ran"}}}
	bad := []StageResult{{Stage: "s", Outcome: OutcomeFailed, Reason: "r", Evidence: []string{"ran"}}}

	for _, tc := range []struct {
		name string
		d    Decision
		want string
	}{
		{"accept with a failing stage",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictAccept, Stages: bad, NotProven: notProven()},
			"accepted with a failing stage"},
		{"reject with no reason",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictReject, Stages: bad, NotProven: notProven()},
			"rejected without a reason"},
		{"reject for a reason no stage gave",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictReject, Reason: "invented", Stages: bad, NotProven: notProven()},
			"which no stage reported"},
		{"no not-proven section",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictAccept, Stages: ok},
			"not-proven"},
		{"stage with no evidence",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictAccept,
				Stages: []StageResult{{Stage: "s", Outcome: OutcomePassed}}, NotProven: notProven()},
			"records no evidence"},
		{"no stages at all",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictAccept, NotProven: notProven()},
			"no stages ran"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.Validate()
			if err == nil {
				t.Fatal("want a validation error, got none")
			}
			if !errors.Is(err, ErrMalformedDecision) {
				t.Errorf("error is not ErrMalformedDecision: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// An undecided stage is not a rejection. The patch was never tested, so a
// verdict that says it failed would send an operator to debug a sound patch.
func TestUndecidedStageYieldsErrorNotReject(t *testing.T) {
	stage := stubStage{"pov-reproduces", StageResult{
		Outcome: OutcomeUndecided, Reason: corpus.ReasonPoVNotReproduced,
		Evidence: []string{"harness ran the blob and produced no sanitizer output"}}}
	after := stubStage{"class-replay", StageResult{Outcome: OutcomePassed, Evidence: []string{"ran"}}}

	d, err := Verify(context.Background(), input(t, "x"), []Stage{stage, after}, notProven())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Verdict != VerdictError {
		t.Errorf("verdict = %s, want ERROR", d.Verdict)
	}
	if d.Reason != corpus.ReasonPoVNotReproduced {
		t.Errorf("reason = %q, want %q", d.Reason, corpus.ReasonPoVNotReproduced)
	}
	// Downstream stages would each measure nothing and return green.
	if len(d.Stages) != 1 {
		t.Errorf("recorded %d stages, want 1: undecided must short-circuit", len(d.Stages))
	}
	if err := d.Validate(); err != nil {
		t.Errorf("decision is not schema-valid: %v", err)
	}
}

// The two non-passing outcomes must not borrow each other's reasons.
func TestVerdictAndOutcomeMustAgree(t *testing.T) {
	und := []StageResult{{Stage: "s", Outcome: OutcomeUndecided, Reason: "u", Evidence: []string{"ran"}}}
	for _, tc := range []struct {
		name, want string
		d          Decision
	}{
		{"reject on an undecided stage", "no stage reported as a failure",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictReject, Reason: "u", Stages: und, NotProven: notProven()}},
		{"error on a failing stage", "should be REJECT",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictError, Reason: "r",
				Stages:    []StageResult{{Stage: "s", Outcome: OutcomeFailed, Reason: "r", Evidence: []string{"ran"}}},
				NotProven: notProven()}},
		{"accept with an undecided stage", "demonstrates nothing",
			Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictAccept, Stages: und, NotProven: notProven()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.Validate()
			if err == nil {
				t.Fatal("want a validation error, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
