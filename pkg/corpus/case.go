// SPDX-License-Identifier: Apache-2.0

// Package corpus loads the labelled cases the gate is measured against.
//
// A case is a vulnerability the corpus can prove it has: a target at a pinned
// commit, an input that fires a named sanitizer, and a reference patch that
// stops it. The generator scripts establish all three by running them, so
// what is loaded here has round-tripped rather than been read off a label.
//
// The candidates attached to a case are the patches the gate is graded on.
// Each carries the reason the gate is expected to give, which is what makes
// the eval "right answer for the right reason" rather than accept/reject.
package corpus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kind separates a hand-authored oracle from a captured question. The default,
// empty, is an oracle: an existing case file gains nothing and keeps its
// answer-key requirement.
type Kind string

const (
	KindOracle   Kind = ""
	KindCaptured Kind = "captured"
)

var (
	ErrIncomplete   = errors.New("case-incomplete")
	ErrUnknownLabel = errors.New("case-unknown-label")
)

// Label classifies a candidate patch. Every label except LabelGood is a way a
// patch can look right and be wrong, and each one exists to exercise a
// specific gate stage.
type Label string

const (
	LabelGood Label = "good"

	// Compiles, looks right, does not stop the proof of vulnerability. The
	// "green suite proves nothing" case.
	LabelNonfunctional Label = "nonfunctional-plausible"

	// Off-by-one or the wrong comparison.
	LabelBoundaryWrong Label = "boundary-wrong"

	// Handles the crashing input but not its class siblings.
	LabelIncompleteFix Label = "incomplete-fix"

	// Fixes the vulnerability and breaks something else.
	LabelRegression Label = "regression-introducing"

	// Guards a path the input does not take.
	LabelWrongBranch Label = "wrong-branch"

	// Shipped by the challenge as deliberately wrong, class not yet
	// established by running it. Carried explicitly so an unclassified
	// candidate cannot be mistaken for a classified one.
	LabelUnclassified Label = "unclassified"
)

// The reasons a gate stage can reject for. These are the answer key's
// vocabulary: grading on accept/reject alone would pass a gate that had been
// broken into rejecting everything, so a candidate names the reason it is
// expected to fall to and the stage that should produce it.
const (
	// M0: the patch changes no source line, so there is nothing to attribute a
	// fix to. The degenerate case of revert-to-attribute, caught before any
	// stage spends compute on it.
	ReasonEmptyPatch = "empty-patch"
	// M1, first question: the PoV did not fire on the PRE-patch build, so the
	// case demonstrates no vulnerability and no patch can be credited with
	// fixing one. This is an ERROR, not a REJECT: the patch was not tested, it
	// did not fail. The fault is in the reproduction — wrong build flags, a
	// sanitizer not enabled, an input that never reaches the sink — so the
	// reason has to route an operator to the harness rather than to the patch.
	// Naming it revert-attribute-fail would be correct only by luck: they would
	// find the real fault eventually, after first satisfying themselves that a
	// sound patch was sound.
	ReasonPoVNotReproduced = "pov-not-reproduced"
	// M1: the candidate does not apply to the tree at the pin. A REJECT rather
	// than an ERROR, because nothing is undecided — a patch that cannot be
	// applied cannot be a fix, and that is a determination. The check ran
	// perfectly; the fact established is about the candidate, so the operator
	// belongs at the patch.
	//
	// Only reachable once the tree is known to be at the pin. "Does not apply
	// because the tree was left dirty" is an infrastructure fault wearing the
	// candidate's clothes, and must surface as a plumbing error instead.
	ReasonPatchDoesNotApply = "patch-does-not-apply"
	// M1: a sanitizer fired after the patch, but the report cannot be matched
	// against the declared crash site — an inlined frame, or a report naming no
	// comparable location. An ERROR reason: whether this is the same
	// vulnerability or a different one is undetermined, and answering either way
	// would invent a verdict. Rejecting for revert-attribute-fail would blame a
	// patch that may have worked; rejecting for new-sanitizer-finding would
	// manufacture a second bug out of an optimisation setting.
	ReasonPoVSiteUndetermined = "pov-site-undetermined"
	// M1, second question: the PoV fires before the patch, but reverting the
	// patch alone does not bring it back, so nothing attributes the fix to it.
	ReasonRevertAttributeFail = "revert-attribute-fail"
	// M2, falsifying-class replay: the crashing input is handled, a sibling
	// in its class is not.
	ReasonClassReplayFail = "class-replay-fail"
	// M2: the case defines no falsifying class, so there is nothing to replay.
	// An ERROR reason and not a rejection — the patch was not tested by this
	// stage, it did not fail it. The schema already treats a missing class as
	// gradable by the other stages, and this makes that visible in the verdict
	// rather than leaving the stage silently absent from the record.
	ReasonClassNotDefined = "class-not-defined"
	// The class was replayed short of its declared size. A divergence found in
	// a subset is still a divergence, so REJECT stands; an absence of
	// divergence in a subset says nothing about the class, so ACCEPT cannot.
	ReasonClassTruncated = "class-truncated"
	// A class with no observer: nothing produces the observation its
	// discriminator names. Refused, not fallen back on. See Observer below.
	ReasonClassObserverMissing = "class-observer-missing"
	// M3, sanitizer-gated reachability: the patched build reports something the
	// unpatched one did not.
	//
	// Reachability is asserted AGAINST THE CONFIGURATION UNDER TEST, never in
	// general, and the dossier must say so. cpv2's sink is reached only because
	// the access log format references $remote_user; drop that one variable and
	// no input reaches it, with no source change. So "no input in the class
	// reaches the sink" describes a deployment, not the code.
	//
	// PRECONDITION, invisible unless stated: ASan halts on the first error unless
	// the target was built with -fsanitize-recover=address. Without it,
	// ASAN_OPTIONS=halt_on_error=0 is accepted and INERT, so a report missing the
	// original site is evidence of nothing.
	//
	// Surviving that once rested on execution order -- the new finding ran after
	// the original, so reaching it proved the original had not fired. That works
	// in one direction only. Build with -fsanitize-recover=address, or make the
	// ordering argument explicitly every time.
	ReasonNewSanitizerFinding = "new-sanitizer-finding"
	// The functional counterpart: a test that passed before the patch fails
	// after it. Both are a set difference against a baseline, and they are kept
	// apart because they are different evidence. A sanitizer finding is a
	// memory-safety claim from instrumentation; this is a behavioural claim from
	// the project's own suite, and a dossier that named the wrong one would send
	// a reviewer looking for sanitizer output that was never produced.
	//
	// This is the reason the challenge's own bad patches actually fall to: all
	// three calibrated so far stop the crash and break a passing test, and none
	// produce a new sanitizer finding. A label of regression-introducing maps to
	// whichever of the two was observed by running it, never to an assumption.
	ReasonNewTestFailure = "new-test-failure"
	// M2, differential against the pre-patch build: an input that did NOT crash
	// before the patch behaves differently after it.
	//
	// An ERROR reason, not a rejection, and the word in the middle is doing the
	// work. The differential is an oracle for CHANGE, not for correctness: a
	// legitimate fix may tighten validation and alter behaviour on inputs that
	// never crashed. libpng run 2 was wrong because removing iCCP support is
	// wrong for libpng, and that judgement came from a human reading the diff,
	// not from the differential noticing a difference.
	//
	// So the gate surfaces it and routes it, and does not decide it. Rejecting
	// would assert a fault it has not established; accepting would discard the
	// most interesting thing in the run. The verdict is undecided, with the
	// differing inputs and their before/after output in the dossier, for a human
	// to adjudicate.
	//
	// This constant is also the guard against a claim drifting upward. As long
	// as the reason is named unadjudicated, "the gate surfaces unintended change
	// for review" cannot quietly become "the gate detects wrong patches",
	// because the code says otherwise.
	ReasonUnadjudicatedBehaviourChange = "unadjudicated-behaviour-change"
	// M4, non-determinism control: the candidate passes on some repeats and
	// fails on others.
	ReasonNondeterministic = "nondeterministic"
)

func (l Label) known() bool {
	switch l {
	case LabelGood, LabelNonfunctional, LabelBoundaryWrong, LabelIncompleteFix,
		LabelRegression, LabelWrongBranch, LabelUnclassified:
		return true
	}
	return false
}

type Source struct {
	CPRepo    string `yaml:"cp_repo"`
	CPCommit  string `yaml:"cp_commit"`
	SrcRepo   string `yaml:"src_repo"`
	SrcRef    string `yaml:"src_ref"`
	SrcCommit string `yaml:"src_commit"`

	// The harness build inputs, for targets whose fuzz tooling lives outside the
	// challenge repo. libpng is the case that forced these: it is a bare source
	// tree, and libpng_read_fuzzer is built from a separate oss-fuzz checkout, so
	// nothing in cp_*/src_* names what actually produces the binary under test.
	//
	// Recorded here rather than in prose so scripts/stage-corpus.sh can DERIVE
	// what to clone instead of carrying its own copy of these facts. A staging
	// script with a hardcoded list is a second source of truth that agrees until
	// a case changes.
	//
	// Empty for challenges that carry their own build, which is the AIxCC CP
	// shape nginx uses.
	// The tree BEFORE the change under test. The CRS diffs base..head to know
	// what changed, so submitting a task with base == head asks it to analyse a
	// diff that is empty. libpng forced this too: its base is recorded in the
	// task the CRS was actually given and was sitting in a comment here, where
	// scripts/buttercup-task.sh could not read it and silently used the head
	// commit for both.
	//
	// Optional: a target with no meaningful "before" (fuzz the whole tree) sets
	// base and head to the same ref deliberately, which is different from
	// defaulting to it by accident.
	BaseCommit string `yaml:"base_commit"`

	FuzzToolingRepo    string `yaml:"fuzz_tooling_repo"`
	FuzzToolingRef     string `yaml:"fuzz_tooling_ref"`
	FuzzToolingCommit  string `yaml:"fuzz_tooling_commit"`
	FuzzToolingProject string `yaml:"fuzz_tooling_project"`
}

// PoV is the proof of vulnerability.
//
// Signal names where the verdict is read from. It is a field rather than a
// constant because the challenge's container exits zero whether or not the
// vulnerability fires, so a gate keyed on the exit code would accept every
// candidate patch. Recording where the truth lives keeps that decision with
// the case instead of hard-coded in the runner.
type PoV struct {
	Input string `yaml:"input"`
	// Sanitizer names the build ExpectedSanitizer belongs to. Without it the
	// expected string is uncheckable rather than merely imprecise: libpng's
	// declared "runtime error: index 41 out of bounds" is a UBSan message and
	// does not appear at all in an ASan build, where the same defect reports as
	// "dynamic-stack-buffer-overflow". The truth of the field depended on a
	// configuration nothing recorded.
	//
	// Optional, and deliberately not added to validate()'s required set: the
	// nginx cases predate it and declaring it required would fail fifteen cases
	// to fix one. Empty means "not recorded", which is honest, rather than
	// defaulting to address and inventing a fact.
	Sanitizer         string `yaml:"sanitizer"`
	ExpectedSanitizer string `yaml:"expected_sanitizer"`
	CrashLocation     string `yaml:"crash_location"`
	Signal            string `yaml:"signal"`

	// InputRoot says which tree Input is relative to, on the same rule as a
	// candidate's PatchRoot: the challenge ships its own blobs, and the inputs
	// we author for deliberately mis-wired cases live in this repository.
	InputRoot string `yaml:"input_root,omitempty"`
}

// resolveRoot picks a tree: the per-path override if given, else the case
// default, else the challenge checkout.
func resolveRoot(override, caseDefault, challengeRoot, repoRoot string) string {
	which := override
	if which == "" {
		which = caseDefault
	}
	if which == PatchRootRepo {
		return repoRoot
	}
	return challengeRoot
}

// InputPath resolves the PoV input against the tree it belongs to.
func (c Case) InputPath(challengeRoot, repoRoot string) string {
	return joinRoot(resolveRoot(c.PoV.InputRoot, c.Root, challengeRoot, repoRoot), c.PoV.Input)
}

// ReferencePatchPath resolves the case's reference fix.
func (c Case) ReferencePatchPath(challengeRoot, repoRoot string) string {
	return joinRoot(resolveRoot("", c.Root, challengeRoot, repoRoot), c.ReferencePatch)
}

// CandidatePatchPath resolves a candidate against its override or the case default.
func (c Case) CandidatePatchPath(cand Candidate, challengeRoot, repoRoot string) string {
	return joinRoot(resolveRoot(cand.PatchRoot, c.Root, challengeRoot, repoRoot), cand.Patch)
}

func joinRoot(root, p string) string {
	if filepath.IsAbs(p) || root == "" {
		return p
	}
	return filepath.Join(root, p)
}

// FalsifyingClass is the set of inputs a fix has to survive, not just the one
// that crashed.
//
// A patch is only credited with fixing a vulnerability if the whole class stops
// reaching the sink, because handling the single crashing input is exactly what
// an incomplete fix does well. Generator runs and reports; a case without one
// can be graded by stages M1 and M3 but not by class replay, so its absence is
// recorded rather than treated as "no class exists".
type FalsifyingClass struct {
	// Description says what varies across the class, in a sentence a reviewer
	// can check against the generator.
	Description string `yaml:"description"`
	// Generator is a runnable path, relative to the repo root.
	Generator string `yaml:"generator"`
	// Discriminator names what separates a correct fix from an incomplete one
	// when the class is replayed, so a green run cannot be read as agreement.
	Discriminator string `yaml:"discriminator"`
	// Observer is a runnable that PRODUCES the observation the discriminator
	// names. A schema that says how to build the class and not what to look at
	// expresses half a contract.
	//
	// It exists because the fuzz harness is silent by construction:
	// libpng_read_fuzzer calls png_image_finish_read and discards diagnostics,
	// so replaying the class through it found zero disagreements across all 79
	// members and ACCEPTED the known-incomplete fix. The channel could not carry
	// the discriminator, which is a blind instrument rather than agreement.
	//
	// Contract: run once per replay as
	//     observer <source-tree> <members-dir>
	// printing one "<member>\t<observation>" line per member. The script owns
	// building and running, the same way generator owns making the class,
	// because only the case knows what its discriminator looks at.
	Observer string `yaml:"observer"`
}

// PatchRoot says which tree a candidate's patch path is relative to. The
// challenge's own candidates live inside its checkout; the ones we synthesise
// live in this repository, under version control where work product belongs.
// Recording which is explicit rather than inferred, because a path that
// resolves against the wrong root either fails to open or, worse, opens a
// different patch and grades it as this one.
const (
	PatchRootChallenge = "challenge"
	PatchRootRepo      = "repo"
)

type Candidate struct {
	ID    string `yaml:"id"`
	Patch string `yaml:"patch"`
	Label Label  `yaml:"label"`

	// PatchRoot defaults to the challenge checkout, which is where every
	// candidate the challenge ships lives.
	PatchRoot string `yaml:"patch_root,omitempty"`

	// ExpectedGateReason is the answer key. A candidate the gate rejects for
	// the wrong reason is not a pass, so this is nil only while the class is
	// still unclassified.
	ExpectedGateReason *string `yaml:"expected_gate_reason"`
}

type Case struct {
	ID       string `yaml:"id"`
	Language string `yaml:"language"`
	CWE      string `yaml:"cwe"`
	CWEName  string `yaml:"cwe_name"`
	Target   string `yaml:"target"`
	Harness  string `yaml:"harness"`

	// Root is the tree this case's paths resolve against by default. The
	// challenge's own cases live in its checkout; the libpng case is entirely
	// ours and lives here. A per-path override exists for the mixed case — an
	// nginx case whose shipped candidates are in the challenge tree and whose
	// synthesised ones are in this repository — but a case that is wholly one
	// or the other says so once rather than on every line.
	Root string `yaml:"root,omitempty"`

	Source         Source      `yaml:"source"`
	PoV            PoV         `yaml:"pov"`
	Kind           Kind        `yaml:"kind,omitempty"`
	ReferencePatch string      `yaml:"reference_patch"`
	Candidates     []Candidate `yaml:"candidates"`

	// FalsifyingClass is optional, because a case is still worth grading on
	// the earlier stages without one.
	FalsifyingClass *FalsifyingClass `yaml:"falsifying_class,omitempty"`

	// Path is where this case was loaded from, so a failure can name a file.
	Path string `yaml:"-"`
}

// Validate refuses a case the gate cannot be graded on.
//
// This is deliberately strict. A case missing its expected sanitizer would
// still run, and every candidate would be judged against an empty string,
// which passes for anything. The corpus is the oracle; an oracle that does
// not know the answer silently grades everything correct.
func (c Case) Validate() error {
	var missing []string
	need := map[string]string{
		"id": c.ID, "language": c.Language, "target": c.Target, "harness": c.Harness,
		"source.src_commit":      c.Source.SrcCommit,
		"pov.input":              c.PoV.Input,
		"pov.expected_sanitizer": c.PoV.ExpectedSanitizer,
	}
	// reference_patch is M2's precondition, not the format's. A hand-authored
	// case is an ORACLE and must carry its answer; a case captured from a CRS
	// run is the QUESTION, and has no known-good fix by construction — that is
	// what makes it a novel target. Requiring one here made reference-free
	// cases unrepresentable, so the reference-free stages had nothing to grade.
	//
	// expected_sanitizer stays required for both. Without it SanitizerFired is
	// strings.Contains(report, ""), which is true of everything, and the case
	// grades every candidate correct. A capture that cannot determine it is
	// refused at capture time rather than written out empty.
	if c.Kind != KindCaptured {
		need["reference_patch"] = c.ReferencePatch
	}
	for k, v := range need {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s is missing %s", ErrIncomplete, c.where(), strings.Join(missing, ", "))
	}

	seen := map[string]bool{}
	for _, cand := range c.Candidates {
		if cand.ID == "" || cand.Patch == "" {
			return fmt.Errorf("%w: %s has a candidate with no id or no patch", ErrIncomplete, c.where())
		}
		if seen[cand.ID] {
			return fmt.Errorf("%w: %s lists candidate %s twice", ErrIncomplete, c.where(), cand.ID)
		}
		seen[cand.ID] = true

		if !cand.Label.known() {
			return fmt.Errorf("%w: %s candidate %s has label %q", ErrUnknownLabel, c.where(), cand.ID, cand.Label)
		}
		switch c.Root {
		case "", PatchRootChallenge, PatchRootRepo:
		default:
			return fmt.Errorf("%w: %s root is %q, want %q or %q",
				ErrUnknownLabel, c.where(), c.Root, PatchRootChallenge, PatchRootRepo)
		}
		switch c.PoV.InputRoot {
		case "", PatchRootChallenge, PatchRootRepo:
		default:
			return fmt.Errorf("%w: %s pov.input_root is %q, want %q or %q",
				ErrUnknownLabel, c.where(), c.PoV.InputRoot, PatchRootChallenge, PatchRootRepo)
		}
		switch cand.PatchRoot {
		case "", PatchRootChallenge, PatchRootRepo:
		default:
			return fmt.Errorf("%w: %s candidate %s has patch_root %q, want %q or %q",
				ErrUnknownLabel, c.where(), cand.ID, cand.PatchRoot, PatchRootChallenge, PatchRootRepo)
		}
		// A classified candidate has to say what the gate should conclude.
		// Without it the eval can only score accept/reject, which a gate
		// broken into rejecting everything would pass.
		if cand.Label != LabelUnclassified && cand.Label != LabelGood && cand.ExpectedGateReason == nil {
			return fmt.Errorf("%w: %s candidate %s is labelled %s but names no expected gate reason",
				ErrIncomplete, c.where(), cand.ID, cand.Label)
		}
		// A candidate the gate is meant to catch by replaying the class needs a
		// class to replay. Without one the stage cannot run, and the candidate
		// would be scored against a check that never executed.
		if cand.ExpectedGateReason != nil && *cand.ExpectedGateReason == ReasonClassReplayFail &&
			c.FalsifyingClass == nil {
			return fmt.Errorf("%w: %s candidate %s expects %s but the case defines no falsifying class",
				ErrIncomplete, c.where(), cand.ID, ReasonClassReplayFail)
		}
	}
	if c.FalsifyingClass != nil {
		f := c.FalsifyingClass
		if strings.TrimSpace(f.Generator) == "" || strings.TrimSpace(f.Discriminator) == "" {
			return fmt.Errorf("%w: %s has a falsifying class with no generator or no discriminator",
				ErrIncomplete, c.where())
		}
	}
	return nil
}

// PatchPath resolves a candidate's patch against the tree it belongs to.
// challengeRoot is the challenge checkout; repoRoot is this repository.
func (cand Candidate) PatchPath(challengeRoot, repoRoot string) string {
	if filepath.IsAbs(cand.Patch) {
		return cand.Patch
	}
	root := challengeRoot
	if cand.PatchRoot == PatchRootRepo {
		root = repoRoot
	}
	if root == "" {
		return cand.Patch
	}
	return filepath.Join(root, cand.Patch)
}

func (c Case) where() string {
	if c.Path != "" {
		return c.Path
	}
	return c.ID
}

func Load(path string) (Case, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Case{}, err
	}
	var c Case
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // an unrecognised field is a case we are misreading
	if err := dec.Decode(&c); err != nil {
		return Case{}, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	return c, c.Validate()
}

// LoadDir loads every case file under dir, in a stable order.
func LoadDir(dir string) ([]Case, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)

	var out []Case
	for _, p := range entries {
		c, err := Load(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no cases in %s", ErrIncomplete, dir)
	}
	return out, nil
}
