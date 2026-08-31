// SPDX-License-Identifier: Apache-2.0

package corpus

// Which stage is responsible for emitting each reason.
//
// A metric must name its subject. "Bad patches accepted" is a predicate; "bad
// patches accepted BY THE STAGE ANSWERABLE FOR CATCHING THEM" is a measurement.
// Without the attribution, the 14 shipped bad patches that M1 correctly accepts
// and a later stage catches read as 14 failures, indicting the layered design
// with the numbers meant to describe it.
const (
	StageM0 = "m0-patch-effect"
	StageM1 = "m1-revert-to-attribute"
	StageM2 = "m2-class-replay"
	StageM3 = "m3-sanitizer-reachability"
	StageM5 = "m5-non-determinism"
	// A reason no stage claims, reported rather than silently bucketed: it means
	// the answer key expects something no stage can produce.
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
	case ReasonClassReplayFail, ReasonClassNotDefined, ReasonUnadjudicatedBehaviourChange,
		ReasonClassNoReference, ReasonClassTruncated, ReasonClassObserverMissing:
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
