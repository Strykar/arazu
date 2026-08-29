// SPDX-License-Identifier: Apache-2.0

package corpus

// Which stage is responsible for emitting each reason.
//
// This exists because a metric must name the subject it is about. "Bad patches
// accepted" is a predicate; "bad patches accepted BY THE STAGE RESPONSIBLE FOR
// CATCHING THEM" is a measurement, and only the second is meaningful over a
// layered gate. All 14 shipped bad patches are accepted by M1 — correctly, since
// they do stop their PoVs and are caught by the test-delta stage — and scored
// without attribution that reads as a 14-case failure in the gate's own
// metrics. The layered design would then be indicted by the numbers meant to
// describe it.
//
// The mapping is already implicit in the vocabulary: a reason names the stage
// that produces it. Making it explicit is what lets an eval score each stage
// over the candidates it is answerable for and treat the rest as out of scope
// rather than as leaks.
const (
	StageM0 = "m0-patch-effect"
	StageM1 = "m1-revert-to-attribute"
	StageM2 = "m2-class-replay"
	StageM3 = "m3-sanitizer-reachability"
	StageM5 = "m5-non-determinism"
	// A reason no stage claims. Distinct from "no reason", and reported rather
	// than silently bucketed: an unclaimed reason means the answer key expects
	// something no stage can produce.
	StageUnassigned = "unassigned"
)

// StageFor returns the stage answerable for a reason.
func StageFor(reason string) string {
	switch reason {
	case ReasonEmptyPatch:
		return StageM0
	case ReasonPoVNotReproduced, ReasonPatchDoesNotApply,
		ReasonRevertAttributeFail, ReasonPoVSiteUndetermined:
		return StageM1
	case ReasonClassReplayFail, ReasonClassNotDefined, ReasonUnadjudicatedBehaviourChange:
		return StageM2
	case ReasonNewSanitizerFinding, ReasonNewTestFailure:
		return StageM3
	case ReasonNondeterministic:
		return StageM5
	}
	return StageUnassigned
}

// ResponsibleStage is the stage a candidate is answerable to, read from the
// reason the answer key expects. A candidate with no expected reason is either
// good — nothing should catch it, so every stage must pass it — or still
// unclassified, and the caller has to tell those apart by label.
func (cand Candidate) ResponsibleStage() string {
	if cand.ExpectedGateReason == nil {
		return ""
	}
	return StageFor(*cand.ExpectedGateReason)
}
