// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"testing"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

func reason(s string) *string { return &s }

func decision(stage string, o gate.Outcome, r string) gate.Decision {
	return gate.Decision{Stages: []gate.StageResult{
		{Stage: stage, Outcome: o, Reason: r, Evidence: []string{"ran"}},
	}}
}

func find(ms []Matrix, stage string) Matrix {
	for _, m := range ms {
		if m.Stage == stage {
			return m
		}
	}
	return Matrix{}
}

// The finding this package was designed around: M1 accepting the 14 shipped bad
// patches is the layered design working, not 14 leaks. They are answerable to
// the test-delta stage.
func TestOutOfScopeIsNotALeak(t *testing.T) {
	var os []Outcome
	for i := 0; i < 14; i++ {
		os = append(os, Outcome{
			Label:    corpus.LabelRegression,
			Expected: corpus.ReasonNewTestFailure, // M3's reason
			Decision: decision("revert-to-attribute", gate.OutcomePassed, ""),
		})
	}
	m := find(Score(os), corpus.StageM1)
	if m.BadAccepted != 0 {
		t.Errorf("bad_accepted = %d, want 0: these are answerable to another stage", m.BadAccepted)
	}
	if m.OutOfScope != 14 {
		t.Errorf("out_of_scope = %d, want 14", m.OutOfScope)
	}
}

// In-scope and accepted IS a leak, and must still be counted as one.
func TestInScopeAcceptanceIsALeak(t *testing.T) {
	m := find(Score([]Outcome{{
		Label:    corpus.LabelNonfunctional,
		Expected: corpus.ReasonRevertAttributeFail, // M1's own reason
		Decision: decision("revert-to-attribute", gate.OutcomePassed, ""),
	}}), corpus.StageM1)
	if m.BadAccepted != 1 {
		t.Errorf("bad_accepted = %d, want 1", m.BadAccepted)
	}
	if m.OutOfScope != 0 {
		t.Errorf("out_of_scope = %d, want 0", m.OutOfScope)
	}
}

// Right answer for the wrong reason is not a pass.
func TestRejectionForTheWrongReasonIsNotAMatch(t *testing.T) {
	m := find(Score([]Outcome{{
		Label:    corpus.LabelNonfunctional,
		Expected: corpus.ReasonRevertAttributeFail,
		Decision: decision("revert-to-attribute", gate.OutcomeFailed, corpus.ReasonPatchDoesNotApply),
	}}), corpus.StageM1)
	if m.BadRejected != 1 {
		t.Errorf("bad_rejected = %d, want 1", m.BadRejected)
	}
	if m.ReasonMatched != 0 || m.ReasonMismatch != 1 {
		t.Errorf("matched=%d mismatch=%d, want 0 and 1", m.ReasonMatched, m.ReasonMismatch)
	}
}

// Inverse perfection: a stage that refuses everything scores perfect recall and
// must be distinguishable from one that works. The good-accepted cell is what
// does it, so Sound() reports on that and nothing else.
func TestInversePerfectionIsDetectable(t *testing.T) {
	refuseEverything := []Outcome{
		{Label: corpus.LabelGood, Decision: decision("revert-to-attribute", gate.OutcomeFailed, "x")},
		{Label: corpus.LabelNonfunctional, Expected: corpus.ReasonRevertAttributeFail,
			Decision: decision("revert-to-attribute", gate.OutcomeFailed, corpus.ReasonRevertAttributeFail)},
	}
	m := find(Score(refuseEverything), corpus.StageM1)
	if m.BadRejected != 1 || m.ReasonMatched != 1 {
		t.Fatalf("the broken stage should still score perfect recall: %+v", m)
	}
	if m.GoodAccepted != 0 || m.GoodRejected != 1 {
		t.Fatalf("good cells wrong: %+v", m)
	}
	if m.Sound() {
		t.Error("a stage that rejected the good candidate reports Sound(); the trap is undetected")
	}

	working := []Outcome{
		{Label: corpus.LabelGood, Decision: decision("revert-to-attribute", gate.OutcomePassed, "")},
		{Label: corpus.LabelNonfunctional, Expected: corpus.ReasonRevertAttributeFail,
			Decision: decision("revert-to-attribute", gate.OutcomeFailed, corpus.ReasonRevertAttributeFail)},
	}
	if !find(Score(working), corpus.StageM1).Sound() {
		t.Error("a working stage should report Sound()")
	}
}

// A reason no stage claims is a corpus defect and must not hide in out-of-scope.
func TestUnassignedReasonIsReportedSeparately(t *testing.T) {
	m := find(Score([]Outcome{{
		Label:    corpus.LabelWrongBranch,
		Expected: "a-reason-no-stage-emits",
		Decision: decision("revert-to-attribute", gate.OutcomePassed, ""),
	}}), corpus.StageM1)
	if m.Unassigned != 1 || m.OutOfScope != 0 || m.BadAccepted != 0 {
		t.Errorf("unassigned=%d out_of_scope=%d bad_accepted=%d, want 1/0/0",
			m.Unassigned, m.OutOfScope, m.BadAccepted)
	}
}

func TestStageForCoversEveryDeclaredReason(t *testing.T) {
	for _, r := range []string{
		corpus.ReasonEmptyPatch, corpus.ReasonPoVNotReproduced, corpus.ReasonPatchDoesNotApply,
		corpus.ReasonPoVSiteUndetermined, corpus.ReasonRevertAttributeFail,
		corpus.ReasonClassReplayFail, corpus.ReasonNewSanitizerFinding,
		corpus.ReasonNewTestFailure, corpus.ReasonUnadjudicatedBehaviourChange,
		corpus.ReasonNondeterministic,
	} {
		if corpus.StageFor(r) == corpus.StageUnassigned {
			t.Errorf("declared reason %q is answerable to no stage", r)
		}
	}
}
