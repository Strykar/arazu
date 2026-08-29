// SPDX-License-Identifier: Apache-2.0

// Package classreplay implements Gate M2: replay the whole recurring input
// class, not just the input that crashed.
//
// M1 credits a patch when the PoV stops firing, which is what an incomplete fix
// does well. libpng run 2 stopped the crash, passed 29 PoV variants and the full
// suite, and removed iCCP support for every PNG carrying an ICC profile. No
// sanitizer and no single input sees that.
//
// THE ORACLE IS THE REFERENCE PATCH, not the declared discriminator.
// FalsifyingClass.Discriminator is prose for a reviewer and cannot be executed.
// reference_patch is a fix known to be correct, so the comparison is
// differential: any class member the candidate and the reference handle
// differently is a member the candidate gets wrong. This shows the candidate
// differs from the reference, not that the reference is right.
//
// TWO ORACLES, because the strong one is missing where it matters most. The
// organisers' target has no reference patch -- producing the fix IS the exercise
// -- and M2 catches the class M1 and M3 both miss. The fallback is the pre-patch
// build, which October always provides:
//
//	reference available -> compare against the known-good fix; divergence REJECTs.
//	reference absent    -> compare against the UNPATCHED build and partition by
//	  pre-patch behaviour. Crashed before and differs after is the fix working.
//	  Did NOT crash before and differs after is unadjudicated-behaviour-change,
//	  an ERROR: a differential is an oracle for CHANGE, not for correctness, so
//	  the gate surfaces it and does not decide it.
//
// So the stage degrades to undecided rather than to unavailable.
package classreplay

import (
	"context"
	"fmt"
	"strings"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

// Member is one input from the class, with what each build did to it.
type Member struct {
	Name      string
	Reference string // normalised output under the reference patch
	Candidate string // normalised output under the candidate
}

func (m Member) agrees() bool { return m.Reference == m.Candidate }

// Target replays a class against two builds. Split from the run so the stage's
// decision logic is testable without a container, the same seam M1 uses.
type Target interface {
	// Generate runs the case's generator and returns the class members it
	// produced. An empty class is an error, never an empty agreement: a
	// generator that produced nothing would otherwise read as a patch that
	// handles every member correctly.
	// It returns the members it produced AND the size the class is declared to
	// have, which are different numbers whenever a caller bounds the run. The
	// stage needs both: agreement across a subset is not agreement across the
	// class, and only the generator knows how big the class is.
	Generate(ctx context.Context, fc corpus.FalsifyingClass) (members []string, declared int, err error)
	// ReplayAgainst builds the tree with patchPath applied and runs every
	// member, returning normalised output per member.
	ReplayAgainst(ctx context.Context, patchPath string, members []string) (map[string]string, error)
}

// Stage is Gate M2.
type Stage struct {
	Target         Target
	CandidatePatch string
	// ReferencePatch is the known-good fix. Empty on a target that has none,
	// which selects the pre-patch oracle.
	ReferencePatch string
}

func (Stage) Name() string { return "class-replay" }

func (s Stage) Run(ctx context.Context, in gate.Input) (gate.StageResult, error) {
	name := s.Name()
	fc := in.Case.FalsifyingClass
	if fc == nil {
		// The case defines no class, so this stage has nothing to replay. Not a
		// verdict on the patch: undecided, and the schema already treats a
		// missing class as gradable by other stages but not by this one.
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeUndecided,
			Reason:  corpus.ReasonClassNotDefined,
			Evidence: []string{
				"the case defines no falsifying_class, so there is no class to replay",
				"gradable by the stages that do not need one; not by this stage"},
		}, nil
	}

	// No observer, no verdict. Same asymmetry as truncation, one step earlier:
	// a stage that cannot see the discriminator must not conclude with it. See
	// corpus.FalsifyingClass.Observer for why the fallback was removed.
	if fc.Observer == "" {
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeUndecided,
			Reason:  corpus.ReasonClassObserverMissing,
			Evidence: []string{
				"the case declares a falsifying_class with no observer, so nothing produces " +
					"the observation its discriminator names",
				"discriminator: " + fc.Discriminator,
			},
		}, nil
	}

	members, declared, err := s.Target.Generate(ctx, *fc)
	if err != nil {
		return gate.StageResult{}, fmt.Errorf("generate the class: %w", err)
	}
	if len(members) == 0 {
		// An empty class agreeing with itself is the purest false pass
		// available to this stage.
		return gate.StageResult{}, fmt.Errorf(
			"the generator produced no class members, so nothing was replayed")
	}

	oracle, oracleName := s.ReferencePatch, "the reference fix"
	if oracle == "" {
		// No known-good fix exists for this target. The unpatched build is
		// still an oracle, for change rather than for correctness.
		oracleName = "the unpatched build"
	}
	ref, err := s.Target.ReplayAgainst(ctx, oracle, members)
	if err != nil {
		return gate.StageResult{}, fmt.Errorf("replay against %s: %w", oracleName, err)
	}
	cand, err := s.Target.ReplayAgainst(ctx, s.CandidatePatch, members)
	if err != nil {
		return gate.StageResult{}, fmt.Errorf("replay against the candidate: %w", err)
	}

	var disagreed []Member
	for _, m := range members {
		r, okr := ref[m]
		c, okc := cand[m]
		if !okr || !okc {
			// A member missing from either replay was not compared. Silence is
			// not agreement.
			return gate.StageResult{}, fmt.Errorf(
				"class member %q has no result from %s", m,
				map[bool]string{true: "the candidate", false: "the reference"}[okr])
		}
		if r != c {
			disagreed = append(disagreed, Member{Name: m, Reference: r, Candidate: c})
		}
	}

	evidence := []string{
		fmt.Sprintf("class: %s", fc.Description),
		fmt.Sprintf("generator: %s", fc.Generator),
		fmt.Sprintf("oracle: %s", oracleName),
		fmt.Sprintf("%d of %d declared members replayed against %s and the candidate",
			len(members), declared, oracleName),
		fmt.Sprintf("members on which they disagree: %d", len(disagreed)),
	}

	// Pre-patch oracle: a disagreement is only interesting on members the
	// unpatched build did NOT crash on. Where it crashed, the candidate
	// differing is the fix doing its job, and counting those would make every
	// correct patch look like a regression.
	if s.ReferencePatch == "" {
		var unintended []Member
		for _, d := range disagreed {
			if !strings.Contains(d.Reference, in.Case.PoV.ExpectedSanitizer) {
				unintended = append(unintended, d)
			}
		}
		evidence = append(evidence, fmt.Sprintf(
			"of those, %d are on members the unpatched build did not crash on", len(unintended)))
		if len(unintended) == 0 {
			return gate.StageResult{
				Stage:   name,
				Outcome: gate.OutcomePassed,
				Evidence: append(evidence,
					"every divergence is on a member that crashed before the patch, which is the fix working"),
			}, nil
		}
		for i, d := range unintended {
			if i == 3 {
				evidence = append(evidence, fmt.Sprintf("...and %d more", len(unintended)-3))
				break
			}
			evidence = append(evidence,
				fmt.Sprintf("%s: unpatched %q, candidate %q", d.Name, d.Reference, d.Candidate))
		}
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeUndecided,
			Reason:  corpus.ReasonUnadjudicatedBehaviourChange,
			Evidence: append(evidence,
				"these members did not crash before the patch and behave differently after it. "+
					"Whether that is a fault is not something this differential can determine: a "+
					"legitimate fix may tighten validation. Surfaced for a human to adjudicate."),
		}, nil
	}

	if len(disagreed) > 0 {
		for i, d := range disagreed {
			if i == 3 {
				evidence = append(evidence, fmt.Sprintf("...and %d more", len(disagreed)-3))
				break
			}
			evidence = append(evidence,
				fmt.Sprintf("%s: reference %q, candidate %q", d.Name, d.Reference, d.Candidate))
		}
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeFailed,
			Reason:  corpus.ReasonClassReplayFail,
			Evidence: append(evidence,
				"the candidate handles the crashing input but diverges from a known-good "+
					"fix elsewhere in its class, which is what an incomplete fix does"),
		}, nil
	}

	// AGREEMENT ACROSS A SUBSET IS NOT AGREEMENT ACROSS THE CLASS. Refusing here
	// rather than annotating, because a truncated ACCEPT is unsound and reads
	// identically to a sound one. The asymmetry is deliberate: a divergence
	// found in a subset is still a divergence, so the REJECT arm above needs no
	// such guard.
	//
	// Found by running it. -members 3 on the libpng case replayed keyword
	// lengths 1..3 while the injection sits at the boundary near 41, and the
	// stage accepted the known-incomplete fix while reporting agreement "across
	// the whole class".
	if len(members) < declared {
		return gate.StageResult{
			Stage:   name,
			Outcome: gate.OutcomeUndecided,
			Reason:  corpus.ReasonClassTruncated,
			Evidence: append(evidence, fmt.Sprintf(
				"no divergence in %d of %d declared members, which does not establish agreement "+
					"across the class; raise the member bound to conclude", len(members), declared)),
		}, nil
	}

	return gate.StageResult{
		Stage:    name,
		Outcome:  gate.OutcomePassed,
		Evidence: append(evidence, "the candidate agrees with the reference fix across the whole class"),
	}, nil
}
