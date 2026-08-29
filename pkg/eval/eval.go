// SPDX-License-Identifier: Apache-2.0

// Package eval scores the gate against the corpus answer key.
//
// The confusion matrix is computed PER STAGE, over the candidates that stage is
// answerable for, and this is a design constraint rather than a refinement.
// Scored without it, M1 shows 14 bad patches accepted — correctly, because they
// stop their PoVs and are caught by the test-delta stage — and the layered
// architecture reads as a 14-case failure in its own metrics. That number would
// end up on a slide.
//
// Two traps are scored against explicitly, and they are the same defect in
// opposite directions:
//
//   - Inverse perfection. A stage broken into rejecting everything scores 100%
//     bad-patch recall. The good-accepted cell is what tells it apart from a
//     working stage, so it is reported and never omitted.
//   - Leak-by-attribution. A stage correctly passing what a later stage catches
//     scores as leaking. Out-of-scope candidates are counted separately and
//     never folded into bad-accepted.
//
// Both come from a metric that does not name its subject.
package eval

import (
	"sort"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

// Outcome pairs what the gate decided with what the key expected.
type Outcome struct {
	CaseID      string
	CandidateID string
	Label       corpus.Label
	// Expected is the reason the key predicts, empty for a good candidate.
	Expected string
	Decision gate.Decision
}

// Matrix is one stage's score over the candidates it is answerable for.
type Matrix struct {
	Stage string `json:"stage"`

	// In scope: the key expects THIS stage to produce the verdict, or the
	// candidate is good and every stage must pass it.
	GoodAccepted int `json:"good_accepted"`
	GoodRejected int `json:"good_rejected"`
	BadRejected  int `json:"bad_rejected"`
	BadAccepted  int `json:"bad_accepted"`

	// Of the bad candidates this stage rejected, how many for the reason the
	// key names. Rejecting for the wrong reason is not a pass: it is the
	// difference between a gate that works and one that refuses on sight.
	ReasonMatched    int `json:"reason_matched"`
	ReasonMismatch   int `json:"reason_mismatch"`
	UndecidedInScope int `json:"undecided_in_scope"`

	// Answerable to a different stage. Never folded into BadAccepted: a stage
	// passing what a later stage catches is the design working.
	OutOfScope int `json:"out_of_scope"`

	// The key expects a reason no stage claims. A corpus defect, reported so it
	// cannot hide inside OutOfScope.
	Unassigned int `json:"unassigned"`
}

// Sound reports whether the matrix distinguishes a working stage from one
// broken into refusing everything. It is not a score; it is the question the
// score cannot answer on its own.
func (m Matrix) Sound() bool { return m.GoodAccepted > 0 || m.GoodRejected == 0 }

// Score builds one matrix per stage that any outcome is answerable to.
func Score(outcomes []Outcome) []Matrix {
	byStage := map[string]*Matrix{}
	get := func(s string) *Matrix {
		if byStage[s] == nil {
			byStage[s] = &Matrix{Stage: s}
		}
		return byStage[s]
	}
	// Every stage that ran, so a stage with only out-of-scope candidates still
	// reports rather than vanishing.
	for _, o := range outcomes {
		for _, s := range o.Decision.Stages {
			get(stageKey(s.Stage))
		}
	}

	for _, o := range outcomes {
		good := o.Label == corpus.LabelGood
		resp := corpus.StageFor(o.Expected)
		if o.Expected == "" {
			resp = "" // good, or unclassified
		}
		for _, sr := range o.Decision.Stages {
			m := get(stageKey(sr.Stage))
			switch {
			case good:
				// A good candidate is in scope for every stage: each one must
				// pass it, and the good-accepted cell is what makes the rest of
				// the row meaningful.
				if sr.Outcome == gate.OutcomePassed {
					m.GoodAccepted++
				} else {
					m.GoodRejected++
				}
			case resp == corpus.StageUnassigned:
				m.Unassigned++
			case resp != stageKey(sr.Stage):
				m.OutOfScope++
			case sr.Outcome == gate.OutcomeFailed:
				m.BadRejected++
				if sr.Reason == o.Expected {
					m.ReasonMatched++
				} else {
					m.ReasonMismatch++
				}
			case sr.Outcome == gate.OutcomeUndecided:
				m.UndecidedInScope++
				if sr.Reason == o.Expected {
					m.ReasonMatched++
				} else {
					m.ReasonMismatch++
				}
			default:
				m.BadAccepted++
			}
		}
	}

	out := make([]Matrix, 0, len(byStage))
	for _, m := range byStage {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stage < out[j].Stage })
	return out
}

// stageKey maps a stage's own name to the key the reason vocabulary uses.
func stageKey(name string) string {
	switch name {
	case "patch-effect":
		return corpus.StageM0
	case "revert-to-attribute":
		return corpus.StageM1
	case "class-replay":
		return corpus.StageM2
	}
	return name
}
