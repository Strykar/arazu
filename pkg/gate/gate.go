// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"fmt"

	"arazu/pkg/corpus"
)

// Input is everything a stage may look at.
//
// A stage must not reach outside this struct for anything: what a stage saw has
// to be exactly what it was given, or the isolation claim cannot be asserted.
type Input struct {
	Case      corpus.Case
	Candidate corpus.Candidate
	Root      string
	// RepoRoot is where candidates we synthesised live. The challenge's own
	// candidates sit under Root; ours are version-controlled here, and the
	// candidate says which tree it belongs to.
	RepoRoot string
}

// Stage is one check. An error means the check could not be run, which is not
// the check failing, and a stage that could not run is never recorded as a pass.
//
// For every check that reads an ABSENCE as evidence, its mirror must exist on
// the other side of the patch boundary. A build failure, a harness that never
// ran, a timeout and a silent sanitizer each have an unpatched and a patched
// form and mean different things; without both, a patch that breaks the build
// is credited with fixing the bug.
type Stage interface {
	Name() string
	Run(ctx context.Context, in Input) (StageResult, error)
}

// Verify runs the stages in order and stops at the first failure, so stages
// after it are absent rather than recorded as passing and the Decision cannot
// imply a check that never ran.
//
// notProven is carried into the Decision and is required: defaulting it would
// be a claim nobody wrote.
func Verify(ctx context.Context, in Input, stages []Stage, notProven []string) (Decision, error) {
	d := Decision{
		CaseID:      in.Case.ID,
		CandidateID: in.Candidate.ID,
		Verdict:     VerdictAccept,
		NotProven:   notProven,
	}

	for _, s := range stages {
		res, err := s.Run(ctx, in)
		if err != nil {
			// A gate that cannot run its own check has decided nothing, so this
			// is a plumbing failure and not a REJECT.
			return Decision{}, fmt.Errorf("%s could not run: %w", s.Name(), err)
		}
		if res.Stage == "" {
			res.Stage = s.Name()
		}
		d.Stages = append(d.Stages, res)

		// Both non-passing outcomes stop the run. Undecided matters most: with
		// nothing demonstrated, every downstream stage measures nothing and
		// returns green, which is the one result shape this gate must not emit.
		switch res.Outcome {
		case OutcomeFailed:
			d.Verdict = VerdictReject
			d.Reason = res.Reason
		case OutcomeUndecided:
			d.Verdict = VerdictError
			d.Reason = res.Reason
		default:
			continue
		}
		break
	}

	if err := d.Validate(); err != nil {
		return Decision{}, err
	}
	return d, nil
}
