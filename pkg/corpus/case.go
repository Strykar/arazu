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
	// M1: the PoV did not demonstrate the declared vulnerability on the
	// pre-patch build, so nothing can be credited with fixing it. ERROR rather
	// than REJECT — the fault is in the reproduction, so it routes an operator
	// to the harness and not to the patch.
	ReasonPoVNotReproduced = "pov-not-reproduced"
	// M1: the candidate does not apply to the tree at the pin. A REJECT, since a
	// patch that cannot be applied cannot be a fix, and that is a determination
	// about the candidate.
	//
	// Only sound once the tree is known to be at the pin: "does not apply
	// because the tree was left dirty" must surface as a plumbing error instead.
	ReasonPatchDoesNotApply = "patch-does-not-apply"
	// M1: a sanitizer fired after the patch but the report cannot be matched
	// against the declared crash site, so whether it is the same vulnerability is
	// undetermined. ERROR: deciding either way would invent a verdict.
	ReasonPoVSiteUndetermined = "pov-site-undetermined"
	// M1, second question: the PoV fires before the patch, but reverting the
	// patch alone does not bring it back, so nothing attributes the fix to it.
	ReasonRevertAttributeFail = "revert-attribute-fail"
	// M2, falsifying-class replay: the crashing input is handled, a sibling
	// in its class is not.
	ReasonClassReplayFail = "class-replay-fail"
	// M2: the case defines no falsifying class, so there is nothing to replay.
	// ERROR, not a rejection, and recorded so the stage is not silently absent
	// from the verdict.
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
	// Reachability is asserted against the configuration under test, never in
	// general: cpv2's sink is reached only because the access log format
	// references $remote_user, so it describes a deployment and not the code.
	//
	// PRECONDITION: the target must be built with -fsanitize-recover=address.
	// Without it ASan halts on the first error, ASAN_OPTIONS=halt_on_error=0 is
	// accepted and inert, and a report missing the original site proves nothing.
	ReasonNewSanitizerFinding = "new-sanitizer-finding"
	// The functional counterpart: a test that passed before the patch fails
	// after it. Kept apart from a sanitizer finding because they are different
	// evidence — instrumentation versus the project's own suite — and a dossier
	// naming the wrong one sends a reviewer looking for output never produced.
	ReasonNewTestFailure = "new-test-failure"
	// M2, differential against the pre-patch build: an input that did NOT crash
	// before the patch behaves differently after it.
	//
	// ERROR, not a rejection: the differential is an oracle for CHANGE, not for
	// correctness, and a legitimate fix may tighten validation on inputs that
	// never crashed. Rejecting would assert a fault it has not established;
	// accepting would discard the most interesting thing in the run.
	//
	// The name is also the guard against the claim drifting upward. While the
	// reason says unadjudicated, "surfaces unintended change for review" cannot
	// quietly become "detects wrong patches".
	ReasonUnadjudicatedBehaviourChange = "unadjudicated-behaviour-change"
	// M2 with no reference fix: the candidate matches the unpatched build
	// everywhere it did not already crash, which a complete and an incomplete fix
	// both do. A change oracle cannot accept.
	ReasonClassNoReference = "class-no-reference"
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

	// The tree BEFORE the change under test. The CRS diffs base..head, so a task
	// with base == head asks it to analyse an empty diff.
	//
	// Optional: a target with no meaningful "before" sets base and head to the
	// same ref deliberately, which differs from defaulting to it by accident.
	BaseCommit string `yaml:"base_commit"`

	// Where the harness is built from, for targets whose fuzz tooling lives
	// outside the challenge repo. libpng is a bare source tree and
	// libpng_read_fuzzer comes from a separate oss-fuzz checkout, so cp_*/src_*
	// name nothing that produces the binary under test. Recorded here so
	// scripts/stage-corpus.sh derives what to clone rather than keeping a second
	// copy. Empty for challenges that carry their own build.
	FuzzToolingRepo    string `yaml:"fuzz_tooling_repo"`
	FuzzToolingRef     string `yaml:"fuzz_tooling_ref"`
	FuzzToolingCommit  string `yaml:"fuzz_tooling_commit"`
	FuzzToolingProject string `yaml:"fuzz_tooling_project"`
}

// PoV is the proof of vulnerability.
//
// Signal names where the verdict is read from. A field rather than a constant
// because the container exits zero whether or not the vulnerability fires, so a
// gate keyed on the exit code would accept everything.
type PoV struct {
	Input string `yaml:"input"`
	// Sanitizer names the build ExpectedSanitizer belongs to, without which the
	// expected string is uncheckable: libpng's "runtime error: index 41 out of
	// bounds" is a UBSan message that never appears in an ASan build, where the
	// same defect reports as "dynamic-stack-buffer-overflow".
	//
	// Optional and deliberately not in validate()'s required set. Empty means
	// "not recorded" rather than defaulting to address and inventing a fact.
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
// A patch earns credit only if the whole class stops reaching the sink, since
// handling the single crashing input is what an incomplete fix does well. A case
// without one is gradable by M1 and M3, so its absence is recorded rather than
// read as "no class exists".
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
	// names, because a fuzz harness is silent by construction: replaying the
	// class through libpng_read_fuzzer found zero disagreements across all 79
	// members and accepted the known-incomplete fix. Zero disagreements on a
	// channel that cannot carry the discriminator is a blind instrument, not
	// agreement.
	//
	// Contract: run once per replay as
	//     observer <source-tree> <members-dir>
	// printing one "<member>\t<observation>" line per member. Only the case
	// knows what its discriminator looks at, so the script owns building and
	// running, as generator owns making the class.
	Observer string `yaml:"observer"`
}

// PatchRoot says which tree a candidate's patch path is relative to. Explicit
// rather than inferred: a path resolved against the wrong root either fails to
// open or, worse, opens a different patch and grades it as this one.
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

	// Root is the tree this case's paths resolve against by default, so a case
	// that is wholly one or the other says so once rather than on every line.
	// Per-path overrides exist for cases that mix the two.
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

// Validate refuses a case the gate cannot be graded on. Deliberately strict:
// the corpus is the oracle, and an oracle that does not know the answer grades
// everything correct.
func (c Case) Validate() error {
	var missing []string
	need := map[string]string{
		"id": c.ID, "language": c.Language, "target": c.Target, "harness": c.Harness,
		"source.src_commit":      c.Source.SrcCommit,
		"pov.input":              c.PoV.Input,
		"pov.expected_sanitizer": c.PoV.ExpectedSanitizer,
	}
	// reference_patch is M2's precondition, not the format's. A hand-authored
	// case is an ORACLE and carries its answer; one captured from a CRS run is
	// the QUESTION and has no known-good fix, which is what makes it novel.
	//
	// expected_sanitizer stays required for both: without it SanitizerFired is
	// strings.Contains(report, ""), true of everything, and the case grades every
	// candidate correct.
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
