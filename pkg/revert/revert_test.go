// SPDX-License-Identifier: Apache-2.0

package revert

import (
	"context"
	"errors"
	"strings"
	"testing"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

// fakeTarget replays scripted PoV results, so the ordering of the stage's two
// questions is testable without a build. It also records what it was asked to
// do, because "did the stage bother to reset the tree" is exactly the kind of
// thing that silently stops happening.
type fakeTarget struct {
	before, after PoVRun
	calls         []string
	applyErr      error
	resetErr      error
	buildErrOn    int // fail the Nth build call; 0 means never
	builds        int
	sawSignal     string
}

func (f *fakeTarget) ResetToPin(context.Context) error {
	f.calls = append(f.calls, "reset")
	return f.resetErr
}
func (f *fakeTarget) Build(context.Context) error {
	f.calls = append(f.calls, "build")
	f.builds++
	if f.buildErrOn == f.builds {
		return errors.New("compilation failed")
	}
	return nil
}
func (f *fakeTarget) Apply(_ context.Context, p string) error {
	f.calls = append(f.calls, "apply")
	return f.applyErr
}
func (f *fakeTarget) RunPoV(_ context.Context, _, _ string, pov corpus.PoV) (PoVRun, error) {
	f.sawSignal = pov.Signal
	f.calls = append(f.calls, "pov")
	if len(f.calls) > 0 && countPoV(f.calls) == 1 {
		return f.before, nil
	}
	return f.after, nil
}

func countPoV(calls []string) int {
	n := 0
	for _, c := range calls {
		if c == "pov" {
			n++
		}
	}
	return n
}

func testInput() gate.Input {
	return gate.Input{
		Case: corpus.Case{
			ID:      "nginx-cpv2",
			Harness: "pov_harness",
			PoV:     corpus.PoV{ExpectedSanitizer: "AddressSanitizer: heap-buffer-overflow"},
		},
		Candidate: corpus.Candidate{ID: "cand"},
	}
}

func ran(fired bool) PoVRun {
	r := PoVRun{HarnessRan: true, SanitizerFired: fired, Evidence: []string{"executed the blob"}}
	if fired {
		r.Site = corpus.SiteSame
	}
	return r
}

// firedAt is a run where the sanitizer fired somewhere other than the declared
// site, or somewhere the comparison could not resolve.
func firedAt(m corpus.SiteMatch) PoVRun {
	return PoVRun{HarnessRan: true, SanitizerFired: true, Site: m,
		Evidence: []string{"executed the blob"}}
}

// The three Step 8 acceptance cases, one per outcome.
func TestTheThreeAcceptanceCases(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after PoVRun
		wantOutcome   gate.Outcome
		wantReason    string
	}{
		{"reference patch is credited", ran(true), ran(false), gate.OutcomePassed, ""},
		{"nonfunctional patch is refused", ran(true), ran(true),
			gate.OutcomeFailed, corpus.ReasonRevertAttributeFail},
		{"mis-wired case is undecided", ran(false), ran(false),
			gate.OutcomeUndecided, corpus.ReasonPoVNotReproduced},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeTarget{before: tc.before, after: tc.after}
			s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
			res, err := s.Run(context.Background(), testInput())
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if res.Outcome != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q", res.Outcome, tc.wantOutcome)
			}
			if res.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", res.Reason, tc.wantReason)
			}
			if len(res.Evidence) == 0 {
				t.Error("no evidence recorded")
			}
		})
	}
}

// The undecided case must not touch the patch at all. Building and running a
// patched tree for a case that demonstrates nothing produces a green result
// that means nothing, which is the shape this gate exists to refuse.
func TestUndecidedDoesNotApplyThePatch(t *testing.T) {
	f := &fakeTarget{before: ran(false), after: ran(false)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	if _, err := s.Run(context.Background(), testInput()); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, c := range f.calls {
		if c == "apply" {
			t.Fatalf("the patch was applied for a case that demonstrated nothing: %v", f.calls)
		}
	}
}

// The tree must be reset before the pre-patch run. A tree left patched by an
// earlier candidate produces a silent PoV that reads as pov-not-reproduced.
func TestTreeIsResetBeforeMeasuring(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: ran(false)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	if _, err := s.Run(context.Background(), testInput()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.calls) == 0 || f.calls[0] != "reset" {
		t.Errorf("first call was %v, want a reset before anything is measured", f.calls)
	}
}

// A harness that never executed has measured nothing. That is a plumbing
// failure and must not surface as a finding about the case, or a broken
// harness reads as a demonstrated absence of vulnerability.
func TestHarnessThatDidNotRunIsNotAFinding(t *testing.T) {
	f := &fakeTarget{before: PoVRun{HarnessRan: false}, after: ran(false)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	_, err := s.Run(context.Background(), testInput())
	if err == nil {
		t.Fatal("want an error when the harness did not execute, got a result")
	}
	if !strings.Contains(err.Error(), "did not execute") {
		t.Errorf("error %q does not say the harness failed to run", err)
	}
}

// End to end through the gate: the mis-wired case must reach ERROR, not REJECT.
func TestMiswiredCaseReachesErrorThroughTheGate(t *testing.T) {
	f := &fakeTarget{before: ran(false), after: ran(false)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	d, err := gate.Verify(context.Background(), testInput(), []gate.Stage{s},
		[]string{"only revert-to-attribute has run"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Verdict != gate.VerdictError {
		t.Errorf("verdict = %s, want ERROR", d.Verdict)
	}
	if d.Reason != corpus.ReasonPoVNotReproduced {
		t.Errorf("reason = %q, want %q", d.Reason, corpus.ReasonPoVNotReproduced)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("decision is not schema-valid: %v", err)
	}
}

// A candidate that will not apply is a fact about the candidate, not about the
// infrastructure, so it is a REJECT that routes the operator to the patch.
func TestPatchThatDoesNotApplyIsRejected(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: ran(false),
		applyErr: errors.New("hunk #1 FAILED")}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	res, err := s.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("want a verdict, got a plumbing error: %v", err)
	}
	if res.Outcome != gate.OutcomeFailed {
		t.Errorf("outcome = %q, want failed", res.Outcome)
	}
	if res.Reason != corpus.ReasonPatchDoesNotApply {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonPatchDoesNotApply)
	}
}

// The routing boundary. A reset that fails is an infrastructure fault, and it
// must NOT be laundered into patch-does-not-apply by letting the run continue
// against a dirty tree.
func TestResetFailureIsNotLaunderedIntoAPatchVerdict(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: ran(false),
		resetErr: errors.New("worktree is dirty")}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	res, err := s.Run(context.Background(), testInput())
	if err == nil {
		t.Fatalf("want a plumbing error, got verdict %q/%q", res.Outcome, res.Reason)
	}
	if strings.Contains(err.Error(), corpus.ReasonPatchDoesNotApply) {
		t.Errorf("a reset failure was reported as a patch verdict: %v", err)
	}
}

// The fourth state: the pov fires pre-patch, and the PATCHED build never
// produces a run. That is the check failing to complete, not a silent
// sanitizer. Reading it as silent would credit a patch for breaking the build.
func TestPatchedBuildFailureIsNotAPass(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: ran(false), buildErrOn: 2}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	res, err := s.Run(context.Background(), testInput())
	if err == nil {
		t.Fatalf("want a plumbing error, got verdict %q", res.Outcome)
	}
	if !strings.Contains(err.Error(), "build the patched tree") {
		t.Errorf("error %q does not name the patched build", err)
	}
}

// Matched twin of TestHarnessThatDidNotRunIsNotAFinding, on the patched side.
// A harness that dies after the patch is applied is not evidence the patch
// worked.
func TestPatchedHarnessThatDidNotRunIsNotAPass(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: PoVRun{HarnessRan: false}}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	res, err := s.Run(context.Background(), testInput())
	if err == nil {
		t.Fatalf("want a plumbing error, got verdict %q", res.Outcome)
	}
	if !strings.Contains(err.Error(), "patched tree") {
		t.Errorf("error %q does not say which tree", err)
	}
}

// A sanitizer firing after the patch at a DIFFERENT site is not "your patch
// does not work". The original vulnerability is stopped and a second one is
// introduced, and those route an operator to different places.
func TestDifferentCrashSiteIsANewSanitizerFinding(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: firedAt(corpus.SiteDiffer)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	res, err := s.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeFailed {
		t.Errorf("outcome = %q, want failed", res.Outcome)
	}
	if res.Reason != corpus.ReasonNewSanitizerFinding {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonNewSanitizerFinding)
	}
}

// An unresolvable site — an inlined frame — must be undecided. Calling it a new
// finding would manufacture a second bug out of an optimisation setting.
func TestUndeterminedCrashSiteIsUndecidedNotAFinding(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: firedAt(corpus.SiteUndetermined)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	res, err := s.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeUndecided {
		t.Errorf("outcome = %q, want undecided", res.Outcome)
	}
	if res.Reason != corpus.ReasonPoVSiteUndetermined {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonPoVSiteUndetermined)
	}
}

// PoV.Signal must reach the target. A field the gate reads correctly but that
// only ever holds one value is untested in the way that matters: the
// hard-coding could return and nothing would fail.
func TestSignalFromTheCaseReachesTheTarget(t *testing.T) {
	f := &fakeTarget{before: ran(true), after: ran(false)}
	s := Stage{Target: f, BlobPath: "blob", PatchPath: "patch"}
	in := testInput()
	in.Case.PoV.Signal = "some-other-log.txt"
	if _, err := s.Run(context.Background(), in); err != nil {
		t.Fatalf("run: %v", err)
	}
	if f.sawSignal != "some-other-log.txt" {
		t.Errorf("target saw signal %q, want the value the case declares", f.sawSignal)
	}
}
