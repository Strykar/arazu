// SPDX-License-Identifier: Apache-2.0

// Package sanitizer implements Gate M3: the patched build must not report a
// sanitizer finding the unpatched build did not.
//
// M3 exists because M1 is satisfied by a patch that stops the declared
// vulnerability, and stopping it is not the same as not breaking anything. A
// candidate can remove the original overflow and introduce a different one; M1
// sees the declared PoV stop reproducing and credits it. cpv2-boundary-off-by-one
// is that patch: it fixes the base64 decode overflow and writes one byte past a
// 3021-byte region at ngx_http_core_module.c:1999 instead.
//
// WHAT MAKES THIS REFERENCE-FREE. M2 compares a candidate against a known-good
// fix, which a target nobody prepared does not have. M3 compares the patched
// build against the UNPATCHED one, which every target has by construction. That
// is why it, and not M2, is the stage that widens what runs on a novel target.
//
// WHY THE RECOVERING BUILD IS A PRECONDITION AND NOT A DETAIL. Without
// -fsanitize-recover=address, ASan halts on the first error, so a report naming
// one site says nothing about whether another site is clean: the run may have
// stopped before reaching it. The probe that established cpv2 as a new-finding
// negative had to argue from execution ORDER to get around this, because the new
// bug happened to fire after the original would have. That argument is a
// property of that case, not of the method, and a stage built on it would carry
// "provided the new finding fires later" as an unstated precondition in every
// verdict. On a recovering build both sites report and no such argument is
// needed. The corpus target sets the flag, so this holds today; RequireRecover
// makes the dependency explicit rather than assumed.
package sanitizer

import (
	"context"
	"fmt"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
	"arazu/pkg/revert"
)

// Stage is Gate M3.
type Stage struct {
	Target   revert.Target
	BlobPath string

	// PatchPath is the candidate under test.
	PatchPath string

	// RequireRecover records that the target builds with
	// -fsanitize-recover=address. A stage run against a halting build can
	// mistake "ASan stopped before reaching the second site" for "the second
	// site is clean", so this refuses rather than producing a verdict whose
	// precondition nobody checked.
	RequireRecover bool
}

func (Stage) Name() string { return "sanitizer-gated-reachability" }

func (s Stage) Run(ctx context.Context, in gate.Input) (gate.StageResult, error) {
	name := s.Name()
	pov := in.Case.PoV

	if !s.RequireRecover {
		return gate.StageResult{}, fmt.Errorf(
			"refusing to grade on a build that may halt on the first sanitizer error: " +
				"set RequireRecover once the target builds with -fsanitize-recover=address")
	}

	// The unpatched run is the reference. Not a known-good fix, which a novel
	// target has none of, but the tree as submitted, which it always has.
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
		return gate.StageResult{}, fmt.Errorf(
			"the pov harness did not execute on the unpatched tree, so nothing was measured")
	}

	if err := s.Target.ResetToPin(ctx); err != nil {
		return gate.StageResult{}, fmt.Errorf("reset before applying: %w", err)
	}
	if err := s.Target.Apply(ctx, s.PatchPath); err != nil {
		return gate.StageResult{
			Stage: name, Outcome: gate.OutcomeFailed, Reason: corpus.ReasonPatchDoesNotApply,
			Evidence: []string{"the candidate does not apply at the pin: " + err.Error()},
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

	ev := []string{
		fmt.Sprintf("unpatched: sanitizer fired %t, site %s", before.SanitizerFired, before.Site),
		fmt.Sprintf("patched:   sanitizer fired %t, site %s", after.SanitizerFired, after.Site),
		"recovering build, so both sites report and no execution-order argument is relied on",
	}

	if !after.SanitizerFired {
		return gate.StageResult{Stage: name, Outcome: gate.OutcomePassed,
			Evidence: append(ev, "no sanitizer finding on the patched build")}, nil
	}

	// The declared site still firing is M1's verdict, not M3's. Saying
	// new-sanitizer-finding here would send an operator looking for a second
	// defect when the original one simply survived.
	switch after.Site {
	case corpus.SiteSame:
		return gate.StageResult{Stage: name, Outcome: gate.OutcomePassed,
			Evidence: append(ev,
				"the finding is at the declared site, which is the original vulnerability; "+
					"whether it still reproduces is M1's question, not this one")}, nil

	case corpus.SiteDiffer:
		return gate.StageResult{Stage: name, Outcome: gate.OutcomeFailed,
			Reason: corpus.ReasonNewSanitizerFinding,
			Evidence: append(ev,
				"the patched build reports a sanitizer finding at a site the case does not "+
					"declare, so the candidate introduced a defect while addressing the original")}, nil

	default:
		// Inlining makes some reports uncomparable. Undetermined is a verdict,
		// not a pass: the run happened and cannot be adjudicated.
		return gate.StageResult{Stage: name, Outcome: gate.OutcomeFailed,
			Reason: corpus.ReasonUnadjudicatedBehaviourChange,
			Evidence: append(ev,
				"a sanitizer finding on the patched build could not be placed against the "+
					"declared site, so it can be neither credited nor refused here")}, nil
	}
}
