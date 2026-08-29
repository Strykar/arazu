// SPDX-License-Identifier: Apache-2.0

package gate

import "testing"

// ok builds the smallest Decision that validates, so each test below changes
// exactly one thing and the failure names that thing.
func okReject() Decision {
	return Decision{
		CaseID: "c", CandidateID: "x", Verdict: VerdictReject, Reason: "r",
		Stages:    []StageResult{{Stage: "s", Outcome: OutcomeFailed, Reason: "r", Evidence: []string{"e"}}},
		NotProven: []string{"n"},
	}
}

// Named for what it actually pins. It was written for the ERROR mirror, but
// reverting that guard does not flip it: the short-circuit catches this shape
// first. The missing invariant was the short-circuit, not the mirror, and the
// test that "proved" the mirror was passing for another reason.
func TestRejectWithAnUndecidedStageIsRefused(t *testing.T) {
	d := okReject()
	d.Stages = []StageResult{
		{Stage: "a", Outcome: OutcomeUndecided, Reason: "u", Evidence: []string{"e"}},
		{Stage: "b", Outcome: OutcomeFailed, Reason: "r", Evidence: []string{"e"}},
	}
	if err := d.Validate(); err == nil {
		t.Fatal("validated a REJECT resting beside a stage that demonstrated nothing")
	}
}

// The short-circuit is an invariant Verify enforces on emit and nothing checked
// on read. A dossier claiming checks kept passing after the patch was refused
// could not have been produced by this gate.
func TestStagesRecordedAfterTheDecidingOneAreRefused(t *testing.T) {
	d := okReject()
	d.Stages = append(d.Stages,
		StageResult{Stage: "after", Outcome: OutcomePassed, Evidence: []string{"e"}})
	if err := d.Validate(); err == nil {
		t.Fatal("validated stages recorded after the stage that decided the verdict")
	}
}

// A blank entry is present and asserts nothing: strings.Contains(x, "") in the
// field whose whole purpose is refusing that move.
func TestABlankNotProvenIsNotASection(t *testing.T) {
	d := okReject()
	d.NotProven = []string{"   "}
	if err := d.Validate(); err == nil {
		t.Fatal("a whitespace entry satisfied the mandatory could-not-prove section")
	}
}

func TestBlankEvidenceIsNotEvidence(t *testing.T) {
	d := okReject()
	d.Stages[0].Evidence = []string{""}
	if err := d.Validate(); err == nil {
		t.Fatal("a blank line satisfied the check that tells a stage apart from one that never ran")
	}
}

// The matched twin: the minimal valid Decision must still validate, or the
// guards above are just rejecting everything.
func TestTheMinimalValidDecisionStillValidates(t *testing.T) {
	if err := okReject().Validate(); err != nil {
		t.Fatalf("a well-formed REJECT was refused: %v", err)
	}
	acc := Decision{CaseID: "c", CandidateID: "x", Verdict: VerdictAccept,
		Stages:    []StageResult{{Stage: "s", Outcome: OutcomePassed, Evidence: []string{"e"}}},
		NotProven: []string{"n"}}
	if err := acc.Validate(); err != nil {
		t.Fatalf("a well-formed ACCEPT was refused: %v", err)
	}
}
