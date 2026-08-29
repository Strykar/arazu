// SPDX-License-Identifier: Apache-2.0

// Package revert implements Gate M1: credit a patch only if reverting it alone
// re-triggers the proof of vulnerability.
//
// The stage asks two questions in order, and they are about different things:
//
//  1. Did the PoV fire on the PRE-patch build?   — about the case
//  2. Does the patch stop it firing?             — about the patch
//
// A no to the first is not a rejection. It means the case demonstrates no
// vulnerability, so no patch can be credited with fixing one and the fault is
// in the reproduction. That is ERROR / pov-not-reproduced, and it routes an
// operator to the harness rather than to a patch that is probably fine.
//
// A no to the second is a rejection: the PoV fires with the patch applied, so
// removing the patch changes nothing and nothing attributes the fix to it. That
// is REJECT / revert-attribute-fail, and it is the "green suite proves nothing"
// case.
//
// On reverting. Every candidate in this corpus is a single patch applied to the
// tree at its pinned commit, so "revert the patch alone" and "the pinned tree"
// are the same state, and the pre-patch run serves as both. That equivalence is
// an assumption about the corpus, not a general truth: a candidate stacked on
// other changes would need the revert performed explicitly, because reverting
// it alone would no longer return the tree to the pin.
package revert

import (
	"context"
	"fmt"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

// PoVRun is one execution of the proof of vulnerability.
//
// HarnessRan is separate from SanitizerFired because the two failures look
// identical in a log that only records the absence of a crash: a harness that
// executed and stayed silent is a mis-wired reproduction, a harness that never
// executed is a broken one. The first is a finding about the case; the second
// means this stage could not run its check at all. Collapsing them would let a
// broken harness masquerade as a demonstrated absence of vulnerability.
type PoVRun struct {
	HarnessRan     bool
	SanitizerFired bool
	// Site says whether the sanitizer fired at the location the case declares,
	// somewhere else, or somewhere the comparison cannot resolve. Only
	// meaningful when SanitizerFired.
	Site     corpus.SiteMatch
	Evidence []string
}

// Target is the tree under test. It exists so the stage's decision logic can be
// exercised without a container: the ordering of the two questions is the part
// most worth testing, and it should not require a build to check.
type Target interface {
	// ResetToPin returns the tree to the case's pinned commit, discarding any
	// patch a previous run left applied. A tree left patched is the single
	// easiest way to produce a clean PoV run that looks like a fix.
	//
	// It must VERIFY the tree is clean afterwards and return an error if it is
	// not, rather than assuming the reset took. Everything downstream depends on
	// it: a dirty tree makes a sound candidate fail to apply, and that would be
	// reported as patch-does-not-apply, sending an operator to debug a patch
	// when the fault is here.
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

	// Question 2, about the patch: does it stop what we just watched happen?
	//
	// A patch that will not apply is a fact about the candidate, established by
	// a check that ran correctly, so it is a REJECT and not a plumbing error.
	// This is only sound because ResetToPin verified the tree first: without
	// that, a dirty tree would make a sound candidate fail here and route the
	// operator to the patch instead of to the harness.
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
		// A sanitizer firing after the patch is not automatically the same
		// vulnerability. Comparing only the sanitizer STRING cannot tell "your
		// patch does not fix it" from "your patch fixes it and introduces a
		// different bug", and those route an operator to different places.
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
