// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
	"arazu/pkg/revert"
)

// fake is the target with no container behind it. The ordering of the two runs
// and the mapping from site to verdict is the part worth testing, and it should
// not need a build to check.
type fake struct {
	runs      []revert.PoVRun // consumed in order: unpatched, then patched
	applyErr  error
	buildErr  error
	resets    int
	applied   bool
	nextRunIx int
}

func (f *fake) ResetToPin(context.Context) error { f.resets++; return nil }
func (f *fake) Apply(_ context.Context, _ string) error {
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied = true
	return nil
}
func (f *fake) Build(context.Context) error { return f.buildErr }
func (f *fake) RunPoV(context.Context, string, string, corpus.PoV) (revert.PoVRun, error) {
	r := f.runs[f.nextRunIx]
	f.nextRunIx++
	return r, nil
}

func fired(site corpus.SiteMatch) revert.PoVRun {
	return revert.PoVRun{HarnessRan: true, SanitizerFired: true, Site: site}
}
func clean() revert.PoVRun { return revert.PoVRun{HarnessRan: true, SanitizerFired: false} }

func run(t *testing.T, f *fake) gate.StageResult {
	t.Helper()
	s := Stage{Target: f, BlobPath: "b", PatchPath: "p", RequireRecover: true}
	res, err := s.Run(context.Background(), gate.Input{Case: corpus.Case{ID: "c"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// The case the stage exists for: cpv2-boundary-off-by-one fixes the declared
// overflow and introduces a different one.
func TestFindingAtAnotherSiteIsRejected(t *testing.T) {
	res := run(t, &fake{runs: []revert.PoVRun{fired(corpus.SiteSame), fired(corpus.SiteDiffer)}})
	if res.Outcome != gate.OutcomeFailed {
		t.Fatalf("outcome = %s, want failed", res.Outcome)
	}
	if res.Reason != corpus.ReasonNewSanitizerFinding {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonNewSanitizerFinding)
	}
}

// A reference fix leaves nothing firing. This is the other half of the
// acceptance criterion and the one that would catch a stage that always fails.
func TestACleanPatchedBuildPasses(t *testing.T) {
	res := run(t, &fake{runs: []revert.PoVRun{fired(corpus.SiteSame), clean()}})
	if res.Outcome != gate.OutcomePassed {
		t.Fatalf("outcome = %s, want passed: %v", res.Outcome, res.Evidence)
	}
	if res.Reason != "" {
		t.Errorf("a passing stage set a reason: %q", res.Reason)
	}
}

// The original vulnerability surviving is M1's verdict. Reporting it here as a
// new finding sends an operator hunting a second defect that does not exist.
func TestTheDeclaredSiteStillFiringIsNotANewFinding(t *testing.T) {
	res := run(t, &fake{runs: []revert.PoVRun{fired(corpus.SiteSame), fired(corpus.SiteSame)}})
	if res.Outcome != gate.OutcomePassed {
		t.Fatalf("outcome = %s, want passed, M3 does not adjudicate the original", res.Outcome)
	}
}

// Inlining can make a report uncomparable. That is a verdict, not a pass: the
// run happened and could not be adjudicated, which the vocabulary can say.
func TestAnUnplaceableFindingIsUnadjudicated(t *testing.T) {
	res := run(t, &fake{runs: []revert.PoVRun{fired(corpus.SiteSame), fired(corpus.SiteUndetermined)}})
	if res.Reason != corpus.ReasonUnadjudicatedBehaviourChange {
		t.Fatalf("reason = %q, want unadjudicated-behaviour-change", res.Reason)
	}
}

// The precondition that the probe had to argue around. A halting build cannot
// distinguish "the second site is clean" from "ASan stopped before reaching
// it", so the stage must refuse rather than emit a verdict resting on an
// unstated assumption about which bug fires first.
func TestAHaltingBuildIsRefused(t *testing.T) {
	s := Stage{Target: &fake{runs: []revert.PoVRun{clean(), clean()}}, RequireRecover: false}
	_, err := s.Run(context.Background(), gate.Input{Case: corpus.Case{ID: "c"}})
	if err == nil {
		t.Fatal("graded on a build that may halt on the first error")
	}
	if !strings.Contains(err.Error(), "halt") {
		t.Errorf("refusal does not name the reason: %v", err)
	}
}

// A tree left patched by a previous run produces a clean PoV that looks like a
// fix, so the reset before the unpatched run is load-bearing.
func TestItResetsBeforeEachBuild(t *testing.T) {
	f := &fake{runs: []revert.PoVRun{fired(corpus.SiteSame), clean()}}
	run(t, f)
	if f.resets < 2 {
		t.Errorf("reset %d times, want at least 2: once before the unpatched build, once before applying", f.resets)
	}
	if !f.applied {
		t.Error("the candidate was never applied")
	}
}

// A patch that does not apply is a named refusal, not a crash.
func TestAPatchThatDoesNotApplyIsNamed(t *testing.T) {
	f := &fake{runs: []revert.PoVRun{fired(corpus.SiteSame)}, applyErr: errors.New("hunk #1 failed")}
	res := run(t, f)
	if res.Reason != corpus.ReasonPatchDoesNotApply {
		t.Fatalf("reason = %q, want patch-does-not-apply", res.Reason)
	}
}

// A harness that never ran measured nothing. That is a plumbing error, not a
// verdict about the candidate, so it must not come back as a pass.
func TestAHarnessThatDidNotRunIsAnError(t *testing.T) {
	s := Stage{Target: &fake{runs: []revert.PoVRun{{HarnessRan: false}}}, RequireRecover: true}
	if _, err := s.Run(context.Background(), gate.Input{Case: corpus.Case{ID: "c"}}); err == nil {
		t.Fatal("a harness that did not execute produced a verdict")
	}
}

// Every result carries evidence. A stage that passes without it is
// indistinguishable from one that did not run.
func TestEveryOutcomeCarriesEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		runs []revert.PoVRun
	}{
		{"reject", []revert.PoVRun{fired(corpus.SiteSame), fired(corpus.SiteDiffer)}},
		{"pass", []revert.PoVRun{fired(corpus.SiteSame), clean()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if res := run(t, &fake{runs: tc.runs}); len(res.Evidence) == 0 {
				t.Error("no evidence recorded")
			}
		})
	}
}
