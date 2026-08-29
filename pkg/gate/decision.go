// SPDX-License-Identifier: Apache-2.0

// Package gate is the acceptance bar. It decides whether a candidate patch has
// earned credit for fixing a vulnerability, and records what that decision does
// and does not establish.
//
// The bar does not live in the model. A stage passes because something was run
// and observed, never because a model was confident, so a Decision carries the
// evidence each stage produced and the reason the first failing stage gave.
//
// Two schema rules are load-bearing rather than bookkeeping.
//
// A REJECT must name a reason that some stage actually produced. Grading on
// accept/reject alone would pass a gate that had been broken into rejecting
// everything, so the reason is checked against the stage results rather than
// taken on trust from whoever built the Decision.
//
// An accepted Decision must say what it could not prove. Sanitizer-gated
// reachability is an operational proxy and not an unreachability proof, and a
// semantic change with no sanitizer signal is invisible to every stage here.
// Making that section structurally mandatory is the difference between a gate
// that reports residual uncertainty and one that implies it has none.
package gate

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"arazu/pkg/model"
)

var ErrMalformedDecision = errors.New("decision-malformed")

// Verdict is three-valued, and the third value is not a formality.
//
// REJECT asserts the patch failed a check. ERROR says nothing was demonstrated,
// so there is nothing to accept or refuse — the patch was not tested, it did not
// fail. Collapsing the two would put "your patch is wrong" in front of an
// operator whose patch is fine and whose harness is broken. The ingress gate
// already draws this line: audit-log-unavailable exits 2 as an ERROR rather than
// counting as an eleventh rejection class.
type Verdict string

const (
	VerdictAccept Verdict = "ACCEPT"
	VerdictReject Verdict = "REJECT"
	VerdictError  Verdict = "ERROR"
)

// Outcome is what one stage concluded. Three values for the same reason the
// verdict has three: a stage that could not demonstrate anything has not found
// the patch wanting, and a bool cannot say so.
type Outcome string

const (
	OutcomePassed Outcome = "passed"
	OutcomeFailed Outcome = "failed"
	// The stage ran and established that the case proves nothing. Distinct from
	// a stage that could not run at all, which is a plumbing error and returns
	// no Decision.
	OutcomeUndecided Outcome = "undecided"
)

// StageResult is what one stage observed.
//
// Evidence is what was run and seen, in a form a reviewer can check against the
// artefacts. A stage that passes without evidence is indistinguishable from a
// stage that did not run, which is the failure the whole gate exists to avoid,
// so Validate refuses it.
type StageResult struct {
	Stage    string   `json:"stage"`
	Outcome  Outcome  `json:"outcome"`
	Reason   string   `json:"reason,omitempty"`
	Evidence []string `json:"evidence"`
}

// Decision is the gate's output for one candidate against one case.
// Artifact is a file the decision was reached from, carried inside the dossier.
type Artifact struct {
	// Role says what the file was to this decision: candidate-patch, pov, case.
	Role string `json:"role"`
	// Path is relative to the dossier directory, never absolute.
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Decision struct {
	CaseID      string `json:"case_id"`
	CandidateID string `json:"candidate_id"`

	Verdict Verdict `json:"verdict"`
	// Reason is set iff REJECT, and equals the reason of the first stage that
	// failed. The gate stops at that stage, so later stages are absent rather
	// than recorded as passing.
	Reason string `json:"reason,omitempty"`

	Stages []StageResult `json:"stages"`

	// NotProven is the mandatory "what we could not prove" section. Required on
	// every verdict: a rejection also fails to establish that the rest of the
	// patch is sound, and saying so keeps a REJECT from reading as a full audit.
	NotProven []string `json:"not_proven"`

	// There is deliberately no ContentRoot field here. A root recorded inside
	// the dossier cannot be true: MeasureBundle hashes decision.json along with
	// everything else, so writing the root into that file changes the root.
	// Demonstrated rather than reasoned about -- 0f19271b before recording,
	// b2c9bf07 after. The seal carries the root; the dossier carries what was
	// sealed, and Verify recomputes it and compares against the seal.

	// Artifacts are the files this decision was reached from, each named by a
	// path RELATIVE to the dossier and by the sha256 of the bytes read.
	//
	// Relative because a dossier is meant to be auditable by someone who was not
	// there. The first emitter recorded absolute paths into a session scratch
	// directory, so the evidence resolved for one process on one machine on one
	// day, which is the opposite of the property a dossier exists to have.
	Artifacts []Artifact `json:"artifacts,omitempty"`

	// Usage is per-call rather than summed so cost-per-trusted-patch can be
	// attributed to the stage that spent it. Empty when no stage called a model,
	// which is the case for every stage that decides by execution alone.
	Usage []model.Usage `json:"usage,omitempty"`
}

// Validate refuses a Decision that claims more than its stages support.
//
// This runs on emit and again on read, because the dossier's value is that its
// machine-checkable claims can be re-checked by someone who does not trust the
// process that produced them.
func (d Decision) Validate() error {
	var problems []string

	if d.CaseID == "" {
		problems = append(problems, "no case id")
	}
	if d.CandidateID == "" {
		problems = append(problems, "no candidate id")
	}
	if nonBlank(d.NotProven) == 0 {
		// Counted, not len()'d. []string{""} is present and asserts nothing,
		// which is the vacuous check in the field built to prevent vacuity.
		problems = append(problems, "no not-proven section: every verdict must say what it does not establish")
	}
	if len(d.Stages) == 0 {
		problems = append(problems, "no stages ran, so nothing was observed")
	}

	// Reasons are tracked per outcome, so a REJECT cannot borrow an undecided
	// stage's reason and call it a failure, or the reverse.
	failed, undecided := map[string]bool{}, map[string]bool{}
	for i, s := range d.Stages {
		switch s.Outcome {
		case OutcomePassed:
			if s.Reason != "" {
				problems = append(problems, fmt.Sprintf("%s passed but gives a reason", s.Stage))
			}
		case OutcomeFailed, OutcomeUndecided:
			if s.Reason == "" {
				problems = append(problems, fmt.Sprintf("%s is %s but names no reason", s.Stage, s.Outcome))
			}
		default:
			problems = append(problems, fmt.Sprintf("stage %d has outcome %q", i, s.Outcome))
		}
		if s.Stage == "" {
			problems = append(problems, fmt.Sprintf("stage %d is unnamed", i))
		}
		// A stage with no evidence cannot be told apart from one that never ran,
		// and a blank line is not evidence.
		if nonBlank(s.Evidence) == 0 {
			problems = append(problems, fmt.Sprintf("%s records no evidence", s.Stage))
		}
		switch s.Outcome {
		case OutcomeFailed:
			failed[s.Reason] = true
		case OutcomeUndecided:
			undecided[s.Reason] = true
		}
	}

	// Verify stops at the first stage that is not passed, so nothing can be
	// recorded after it. Decision.Reason's own doc says later stages are absent
	// rather than recorded as passing; nothing enforced it.
	for i, s := range d.Stages {
		if s.Outcome != OutcomePassed && i != len(d.Stages)-1 {
			problems = append(problems, fmt.Sprintf(
				"%s is %s but %d stage(s) are recorded after it; the gate stops at the first",
				s.Stage, s.Outcome, len(d.Stages)-1-i))
			break
		}
	}

	switch d.Verdict {
	case VerdictAccept:
		if d.Reason != "" {
			problems = append(problems, "accepted but carries a reason")
		}
		if len(failed) > 0 {
			problems = append(problems, "accepted with a failing stage")
		}
		if len(undecided) > 0 {
			problems = append(problems, "accepted with an undecided stage, which demonstrates nothing")
		}
	case VerdictReject:
		if len(undecided) > 0 {
			// Subsumed today and kept deliberately. With the short-circuit above
			// enforced, at most one stage is non-passed, so an undecided stage in
			// a REJECT is already caught: either by the short-circuit, or by the
			// reason check below finding no failed stage. Verified by reverting
			// this line, which flips no test. It stays so that relaxing the
			// short-circuit cannot silently reopen this direction, which was open
			// while the ERROR mirror was guarded.
			problems = append(problems, "rejected with an undecided stage, which demonstrates nothing")
		}
		if d.Reason == "" {
			problems = append(problems, "rejected without a reason")
		} else if !failed[d.Reason] {
			// The reason has to come from a stage that actually failed. An
			// undecided stage's reason is not a rejection: it says the patch was
			// never tested, not that it fell short.
			problems = append(problems, fmt.Sprintf("rejected for %q, which no stage reported as a failure", d.Reason))
		}
	case VerdictError:
		if d.Reason == "" {
			problems = append(problems, "errored without a reason")
		} else if !undecided[d.Reason] {
			problems = append(problems, fmt.Sprintf("errored for %q, which no stage reported as undecided", d.Reason))
		}
		if len(failed) > 0 {
			problems = append(problems, "errored with a failing stage, so the verdict should be REJECT")
		}
	default:
		problems = append(problems, fmt.Sprintf("verdict %q is not ACCEPT, REJECT or ERROR", d.Verdict))
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w: %s", ErrMalformedDecision, strings.Join(problems, "; "))
	}
	return nil
}

// nonBlank counts entries that carry something. A slice of empty strings
// satisfies a len() check while asserting nothing.
func nonBlank(ss []string) int {
	n := 0
	for _, x := range ss {
		if strings.TrimSpace(x) != "" {
			n++
		}
	}
	return n
}
