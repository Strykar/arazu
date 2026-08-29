// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"fmt"

	"arazu/pkg/corpus"
)

// Input is everything a stage may look at.
//
// Root is where the challenge tree is checked out, because every stage that
// decides by execution needs the real target rather than the case file's
// description of it. A stage that does not need it must not reach outside this
// struct for anything else: what a stage saw has to be exactly what it was
// given, or the red-team stage's isolation claim cannot be asserted later.
type Input struct {
	Case      corpus.Case
	Candidate corpus.Candidate
	Root      string
	// RepoRoot is where candidates we synthesised live. The challenge's own
	// candidates sit under Root; ours are version-controlled here, and the
	// candidate says which tree it belongs to.
	RepoRoot string
}

// Stage is one check. Returning an error means the check could not be run,
// which is not the same as the check failing, and Verify keeps them apart: a
// stage that could not run must never be recorded as a pass.
//
// When writing a new stage, ask this once: for every check that reads an
// ABSENCE as evidence, does its mirror exist on the other side of the patch
// boundary? A build failure, a harness that never ran, a timeout and a silent
// sanitizer each have an unpatched form and a patched form, and they mean
// different things. M1 was written with the unpatched side covered and the
// patched side not, which is how a patch that breaks the build gets credited
// with fixing the bug: it produces no sanitizer output, and nothing distinguishes
// that from a fix. Cheaper to ask the question per stage than to rediscover it.
type Stage interface {
	Name() string
	Run(ctx context.Context, in Input) (StageResult, error)
}

// Verify runs the stages in order and stops at the first failure.
//
// Short-circuiting is deliberate. The later stages cost real compute, and a
// candidate that already failed an earlier one gains nothing by being measured
// against the rest. It also keeps the record honest: stages after the failure
// are absent rather than recorded as passing, so the Decision cannot imply a
// check that never ran.
//
// notProven is the caller's honesty section, carried into the Decision. Verify
// refuses to build a Decision without one rather than defaulting it, because a
// default would be a claim nobody wrote.
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
			// Fail closed, and say so as a plumbing failure rather than as a
			// verdict. A gate that cannot run its own check has not decided
			// anything, and reporting that as a REJECT would credit it with a
			// judgement it never made.
			return Decision{}, fmt.Errorf("%s could not run: %w", s.Name(), err)
		}
		if res.Stage == "" {
			res.Stage = s.Name()
		}
		d.Stages = append(d.Stages, res)

		// Both non-passing outcomes stop the run, for different reasons. A
		// failure means the patch is already refused and the remaining stages
		// would only spend compute on it. Undecided means nothing was
		// demonstrated, so every downstream stage is measuring nothing: class
		// replay has no class, sanitizer gating has no signal to gate on, and
		// each would return green. Green results that mean nothing are the
		// exact shape this project keeps being bitten by, so they are not
		// produced at all.
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
