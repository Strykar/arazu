// SPDX-License-Identifier: Apache-2.0

package classreplay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"arazu/pkg/corpus"
	"arazu/pkg/gate"
)

type fake struct {
	members []string
	// output per patch path, per member
	byPatch  map[string]map[string]string
	genErr   error
	calls    []string
	declared int // 0 means "as many as members", i.e. a complete class
}

func (f *fake) Generate(context.Context, corpus.FalsifyingClass) ([]string, int, error) {
	f.calls = append(f.calls, "generate")
	// declared defaults to what was produced, so existing tests describe a
	// complete class. A test that wants truncation sets declared explicitly.
	d := f.declared
	if d == 0 {
		d = len(f.members)
	}
	return f.members, d, f.genErr
}
func (f *fake) ReplayAgainst(_ context.Context, patch string, members []string) (map[string]string, error) {
	f.calls = append(f.calls, "replay:"+patch)
	return f.byPatch[patch], nil
}

func input(withClass bool) gate.Input {
	c := corpus.Case{ID: "libpng-iccp-keyword"}
	if withClass {
		c.FalsifyingClass = &corpus.FalsifyingClass{
			Description: "any PNG carrying an iCCP chunk", Generator: "gen.py",
			Discriminator: "whether the keyword is reported",
			// Every case that can be graded by this stage has one; the
			// no-observer path has its own test rather than being the default.
			Observer: "observe.sh",
		}
	}
	return gate.Input{Case: c, Candidate: corpus.Candidate{ID: "cand"}}
}

func stage(f *fake) Stage {
	return Stage{Target: f, CandidatePatch: "cand.patch", ReferencePatch: "ref.patch"}
}

// The witness this stage exists for: a candidate that stops the crash and
// diverges from a known-good fix elsewhere in the class.
func TestDivergenceFromTheReferenceIsClassReplayFail(t *testing.T) {
	f := &fake{members: []string{"a.png", "b.png"}, byPatch: map[string]map[string]string{
		"ref.patch":  {"a.png": "keyword parsed", "b.png": "keyword parsed"},
		"cand.patch": {"a.png": "keyword parsed", "b.png": "rejected"},
	}}
	res, err := stage(f).Run(context.Background(), input(true))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeFailed || res.Reason != corpus.ReasonClassReplayFail {
		t.Errorf("got %q/%q, want failed/%s", res.Outcome, res.Reason, corpus.ReasonClassReplayFail)
	}
}

// The matched twin: agreeing across the class must pass, or a stage hardwired
// to reject would satisfy the test above.
func TestAgreementAcrossTheClassPasses(t *testing.T) {
	f := &fake{members: []string{"a.png", "b.png"}, byPatch: map[string]map[string]string{
		"ref.patch":  {"a.png": "keyword parsed", "b.png": "keyword parsed"},
		"cand.patch": {"a.png": "keyword parsed", "b.png": "keyword parsed"},
	}}
	res, err := stage(f).Run(context.Background(), input(true))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomePassed {
		t.Errorf("got %q/%q, want passed", res.Outcome, res.Reason)
	}
}

// An empty class agreeing with itself is the purest false pass available here.
func TestEmptyClassIsNotAgreement(t *testing.T) {
	f := &fake{members: nil, byPatch: map[string]map[string]string{}}
	_, err := stage(f).Run(context.Background(), input(true))
	if err == nil {
		t.Fatal("an empty class must be an error, not a pass")
	}
	if !strings.Contains(err.Error(), "no class members") {
		t.Errorf("error %q does not say the class was empty", err)
	}
}

// A member missing from either replay was never compared. Silence is not
// agreement.
func TestMissingMemberResultIsNotAgreement(t *testing.T) {
	f := &fake{members: []string{"a.png", "b.png"}, byPatch: map[string]map[string]string{
		"ref.patch":  {"a.png": "x", "b.png": "x"},
		"cand.patch": {"a.png": "x"}, // b.png never ran
	}}
	_, err := stage(f).Run(context.Background(), input(true))
	if err == nil {
		t.Fatal("a member with no candidate result must not count as agreeing")
	}
}

// No class defined is undecided, not a pass and not a rejection.
func TestNoClassDefinedIsUndecided(t *testing.T) {
	f := &fake{}
	res, err := stage(f).Run(context.Background(), input(false))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeUndecided || res.Reason != corpus.ReasonClassNotDefined {
		t.Errorf("got %q/%q, want undecided/%s", res.Outcome, res.Reason, corpus.ReasonClassNotDefined)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "replay") {
			t.Errorf("replayed with no class defined: %v", f.calls)
		}
	}
}

// A generator that fails is a plumbing error, never a verdict on the patch.
func TestGeneratorFailureIsNotAVerdict(t *testing.T) {
	f := &fake{genErr: errors.New("generator exploded")}
	_, err := stage(f).Run(context.Background(), input(true))
	if err == nil {
		t.Fatal("a failing generator must not produce a verdict")
	}
}

// --- the pre-patch oracle, which is the only one October provides ---

func inputWithSanitizer() gate.Input {
	in := input(true)
	in.Case.PoV.ExpectedSanitizer = "runtime error: index"
	return in
}

func prePatchStage(f *fake) Stage {
	return Stage{Target: f, CandidatePatch: "cand.patch"} // no reference
}

// The libpng run-2 shape with no reference available: a member that did NOT
// crash before the patch behaves differently after it. Undecided and surfaced,
// never rejected — the differential is an oracle for change, not correctness.
func TestPrePatchOracleSurfacesUnintendedChange(t *testing.T) {
	f := &fake{members: []string{"crashed.png", "clean.png"}, byPatch: map[string]map[string]string{
		"":           {"crashed.png": "runtime error: index 41 out of bounds", "clean.png": "keyword parsed"},
		"cand.patch": {"crashed.png": "keyword parsed", "clean.png": "rejected"},
	}}
	res, err := prePatchStage(f).Run(context.Background(), inputWithSanitizer())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeUndecided {
		t.Errorf("outcome = %q, want undecided", res.Outcome)
	}
	if res.Reason != corpus.ReasonUnadjudicatedBehaviourChange {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonUnadjudicatedBehaviourChange)
	}
}

// Divergence ONLY on members that crashed before the patch is the fix working.
// Counting those would make every correct patch look like a regression.
func TestPrePatchOracleIgnoresTheFixItself(t *testing.T) {
	f := &fake{members: []string{"crashed.png", "clean.png"}, byPatch: map[string]map[string]string{
		"":           {"crashed.png": "runtime error: index 41 out of bounds", "clean.png": "keyword parsed"},
		"cand.patch": {"crashed.png": "keyword parsed", "clean.png": "keyword parsed"},
	}}
	res, err := prePatchStage(f).Run(context.Background(), inputWithSanitizer())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomePassed {
		t.Errorf("outcome = %q (%s), want passed", res.Outcome, res.Reason)
	}
}

// The two oracles must not be confused: with a reference available, divergence
// is a REJECT, not an undecided surfacing.
func TestReferenceOracleStillRejects(t *testing.T) {
	f := &fake{members: []string{"a.png"}, byPatch: map[string]map[string]string{
		"ref.patch": {"a.png": "keyword parsed"}, "cand.patch": {"a.png": "rejected"},
	}}
	res, err := stage(f).Run(context.Background(), inputWithSanitizer())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeFailed || res.Reason != corpus.ReasonClassReplayFail {
		t.Errorf("got %q/%q, want failed/%s", res.Outcome, res.Reason, corpus.ReasonClassReplayFail)
	}
}

// THE FALSE ACCEPT. Running m2 with -members 3 on the libpng case replayed
// keyword lengths 1..3 while the injected bug sits at the boundary near 41, and
// the stage accepted the known-incomplete fix while its evidence claimed
// agreement "across the whole class".
//
// The member bound reads like a performance knob and is a correctness one: it
// redefines the class. Absence of divergence in a subset establishes nothing
// about the class, so the pass arm refuses rather than annotating.
func TestAgreementAcrossASubsetDoesNotAccept(t *testing.T) {
	agree := map[string]string{"kw01.png": "parsed", "kw02.png": "parsed", "kw03.png": "parsed"}
	f := &fake{
		members: []string{"kw01.png", "kw02.png", "kw03.png"}, declared: 79,
		byPatch: map[string]map[string]string{"ref.patch": agree, "cand.patch": agree},
	}
	res, err := stage(f).Run(context.Background(), input(true))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome == gate.OutcomePassed {
		t.Fatal("accepted on 3 of 79 declared members; a subset that agrees says nothing about the class")
	}
	if res.Reason != corpus.ReasonClassTruncated {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonClassTruncated)
	}
	var named bool
	for _, e := range res.Evidence {
		if strings.Contains(e, "3 of 79") {
			named = true
		}
	}
	if !named {
		t.Errorf("evidence does not say how much of the class was replayed: %q", res.Evidence)
	}
}

// The asymmetry. A divergence found in a subset IS a divergence, so truncation
// must not suppress a rejection.
func TestADivergenceInASubsetStillRejects(t *testing.T) {
	f := &fake{
		members: []string{"kw01.png", "kw02.png"}, declared: 79,
		byPatch: map[string]map[string]string{
			"ref.patch":  {"kw01.png": "parsed", "kw02.png": "parsed"},
			"cand.patch": {"kw01.png": "parsed", "kw02.png": "mangled"},
		},
	}
	res, err := stage(f).Run(context.Background(), input(true))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome != gate.OutcomeFailed {
		t.Fatalf("outcome = %s, want failed: truncation must not suppress a real divergence", res.Outcome)
	}
	if res.Reason != corpus.ReasonClassReplayFail {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonClassReplayFail)
	}
}

// A class with nothing to observe it is not gradable by this stage. The
// fallback it replaces was the fuzz harness, which discards diagnostics and so
// reported every member equal: that is how the corpus's central witness was
// accepted across all 79 members.
func TestAClassWithNoObserverIsRefusedNotFallenBackOn(t *testing.T) {
	in := input(true)
	in.Case.FalsifyingClass.Observer = ""
	f := &fake{members: []string{"a.png"}, byPatch: map[string]map[string]string{
		"ref.patch": {"a.png": "x"}, "cand.patch": {"a.png": "x"},
	}}
	res, err := stage(f).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Outcome == gate.OutcomePassed {
		t.Fatal("passed with no observer; agreement measured through a channel that carries nothing")
	}
	if res.Reason != corpus.ReasonClassObserverMissing {
		t.Errorf("reason = %q, want %q", res.Reason, corpus.ReasonClassObserverMissing)
	}
	for _, c := range f.calls {
		t.Errorf("target was called (%s) before the stage established it could observe anything", c)
	}
}
