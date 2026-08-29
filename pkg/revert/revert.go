// SPDX-License-Identifier: Apache-2.0

// Package revert implements Gate M1: credit a patch only if reverting it alone
// re-triggers the proof of vulnerability.
//
// The stage asks two questions in order, and they are about different things:
//
//  1. Did the PoV fire on the PRE-patch build?   — about the case
//  2. Does the patch stop it firing?             — about the patch
//
// A no to the first is ERROR / pov-not-reproduced: the case demonstrates no
// vulnerability, so the fault is in the reproduction and an operator belongs at
// the harness. A no to the second is REJECT / revert-attribute-fail, the "green
// suite proves nothing" case.
//
// ASSUMPTION about this corpus, not a general truth: every candidate is a single
// patch on the tree at its pin, so "revert the patch alone" and "the pinned
// tree" are the same state and the pre-patch run serves as both. A candidate
// stacked on other changes would need the revert performed explicitly.
package revert

import (
	"context"
	"fmt"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

// PoVRun is one execution of the proof of vulnerability.
//
// HarnessRan is separate from SanitizerFired because both look identical in a
// log that records only the absence of a crash. A harness that ran and stayed
// silent is a finding about the case; one that never ran means the check could
// not execute. Collapsed, a broken harness passes as a demonstrated absence.
type PoVRun struct {
	HarnessRan     bool
	SanitizerFired bool
	// Site says whether the sanitizer fired at the location the case declares,
	// somewhere else, or somewhere the comparison cannot resolve. Only
	// meaningful when SanitizerFired.
	Site     corpus.SiteMatch
	Evidence []string
}

// Target is the tree under test, an interface so the ordering of the two
// questions is testable without a build.
type Target interface {
	// ResetToPin returns the tree to the case's pin, discarding any patch a
	// previous run left applied: a tree left patched is the easiest way to get a
	// clean PoV run that looks like a fix.
	//
	// It must VERIFY the tree is clean afterwards rather than assume the reset
	// took. A dirty tree makes a sound candidate fail to apply, which reports as
	// patch-does-not-apply and sends an operator to debug the wrong thing.
	ResetToPin(ctx context.Context) error
	Apply(ctx context.Context, patchPath string) error
	Build(ctx context.Context) error
	RunPoV(ctx context.Context, blob, harness string, pov corpus.PoV) (PoVRun, error)
}

// Stage is Gate M1.
type Stage struct {
	Target Target
	// BlobPath and PatchPath are resolved by the caller, which knows which tree
	// each belongs to.
	BlobPath  string
	PatchPath string
}

func (Stage) Name() string { return "revert-to-attribute" }

func (s Stage) Run(ctx context.Context, in gate.Input) (gate.StageResult, error) {
	pov := in.Case.PoV
	name := s.Name()

	// Question 1, about the case: does the vulnerability reproduce at all?
	if err := s.Target.ResetToPin(ctx); err != nil {
		return gate.StageResult{}, fmt.Errorf("reset to pin: %w", err)
	}
	if err := s.Target.Build(ctx); err != nil {
		return gate.StageResult{}, fmt.Errorf("build the unpatched tree: %w", err)
	}
	before, err := s.Target.RunPoV(ctx, s.BlobPath, in.Case.Harness, pov)
	if err != nil {
		return gate.StageResult{}, fmt.Errorf("run the pov on the unpatched tree: %w", err)
	}
	if !before.HarnessRan {
		// Not a verdict about the case: the check itself did not execute.
		return gate.StageResult{}, fmt.Errorf(
			"the pov harness did not execute on the unpatched tree, so nothing was measured")
	}

	evidence := append([]string{"unpatched tree at the pin: " + verdictOf(before)}, before.Evidence...)

	if !before.SanitizerFired {
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeUndecided,
			Reason:  corpus.ReasonPoVNotReproduced,
			Evidence: append(evidence,
				"the harness ran and produced no "+pov.ExpectedSanitizer,
				"no patch can be credited with fixing a vulnerability the case never demonstrated"),
		}, nil
	}

	if before.Site == corpus.SiteDiffer {
		// The sanitizer fired somewhere else, so what was watched is a different
		// defect and the candidate must not be credited with stopping it.
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeUndecided,
			Reason:  corpus.ReasonPoVNotReproduced,
			Evidence: append(evidence,
				"the unpatched tree crashes somewhere other than the declared crash site",
				"the reproduction demonstrates a different defect, so no patch can be "+
					"attributed to fixing the declared one"),
		}, nil
	}

	// Question 2, about the patch: does it stop what we just watched happen?
	//
	// A patch that will not apply is a REJECT, not a plumbing error, and that is
	// only sound because ResetToPin verified the tree first.
	if err := s.Target.Apply(ctx, s.PatchPath); err != nil {
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeFailed,
			Reason:  corpus.ReasonPatchDoesNotApply,
			Evidence: append(evidence,
				"the candidate does not apply to the verified-clean tree at the pin: "+err.Error(),
				"a patch that cannot be applied cannot be the thing that stopped the pov"),
		}, nil
	}
	if err := s.Target.Build(ctx); err != nil {
		return gate.StageResult{}, fmt.Errorf("build the patched tree: %w", err)
	}
	after, err := s.Target.RunPoV(ctx, s.BlobPath, in.Case.Harness, pov)
	if err != nil {
		return gate.StageResult{}, fmt.Errorf("run the pov on the patched tree: %w", err)
	}
	if !after.HarnessRan {
		return gate.StageResult{}, fmt.Errorf(
			"the pov harness did not execute on the patched tree, so nothing was measured")
	}

	evidence = append(evidence, "patched tree: "+verdictOf(after))
	evidence = append(evidence, after.Evidence...)

	if after.SanitizerFired {
		// The sanitizer string alone cannot tell "does not fix it" from "fixes it
		// and introduces a different bug", and those route to different places.
		switch after.Site {
		case corpus.SiteDiffer:
			return gate.StageResult{
				Stage:   name,
				Outcome: gate.OutcomeFailed,
				Reason:  corpus.ReasonNewSanitizerFinding,
				Evidence: append(evidence,
					"the declared crash site is silent and a sanitizer fires elsewhere, "+
						"so the original vulnerability is stopped and a different one is introduced"),
			}, nil
		case corpus.SiteUndetermined:
			// Cannot resolve declared-versus-observed: an inlined frame, or a
			// report naming no comparable site. Undecided beats guessing, and
			// guessing wrong here invents a new-sanitizer-finding out of an
			// optimisation setting.
			return gate.StageResult{
				Stage:   name,
				Outcome: gate.OutcomeUndecided,
				Reason:  corpus.ReasonPoVSiteUndetermined,
				Evidence: append(evidence,
					"a sanitizer fired after the patch but the report cannot be matched to "+
						"the declared crash site, so whether it is the same vulnerability is undetermined"),
			}, nil
		}
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeFailed,
			Reason:  corpus.ReasonRevertAttributeFail,
			Evidence: append(evidence,
				"the pov fires at the declared crash site with the patch applied, so reverting "+
					"it changes nothing and nothing attributes the fix to this patch"),
		}, nil
	}

	return gate.StageResult{
		Stage:   name,
		Outcome: gate.OutcomePassed,
		Evidence: append(evidence,
			"the pov fires without the patch and stops with it, so the patch is what stopped it"),
	}, nil
}

func verdictOf(r PoVRun) string {
	if r.SanitizerFired {
		return "harness ran, sanitizer fired"
	}
	return "harness ran, sanitizer silent"
}
