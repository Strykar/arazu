// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"arazu/pkg/classreplay"
	"arazu/pkg/corpus"
	"arazu/pkg/gate"
	"arazu/pkg/revert"
	"arazu/pkg/sanitizer"
)

// runSweep grades one candidate through Gate M1 against a real challenge
// checkout. Split from the M0 path because it drives containers and takes
// minutes, where -case/-candidate alone is a file read.
func runSweep(stageID, casePath, candID, root, repoRoot, shim, corpusRoot, workDir string,
	members int, o outputs) {
	c, err := corpus.Load(casePath)
	if err != nil {
		undecided(err)
	}
	var cand corpus.Candidate
	found := false
	for _, x := range c.Candidates {
		if x.ID == candID {
			cand, found = x, true
			break
		}
	}
	if !found {
		undecided(fmt.Errorf("case %s has no candidate %q", c.ID, candID))
	}

	patch := c.CandidatePatchPath(cand, root, repoRoot)

	// resolveTarget is resolved PER ARM, not up front. m1 and m3 need the
	// revert-shaped challenge and its container image; m2 needs neither and
	// uses its own target. Resolving for everyone meant m2 failed on a docker
	// shim it never calls, reporting UNDECIDED for a reason unrelated to the
	// stage that was asked for.
	revertTarget := func() revert.Challenge {
		t, err := resolveTarget(c, root, shim)
		if err != nil {
			undecided(err)
		}
		return t
	}
	blob := func() string { return c.InputPath(root, repoRoot) }

	var st gate.Stage
	var notProven []string
	switch stageID {
	case "m1":
		st = revert.Stage{Target: revertTarget(), BlobPath: blob(), PatchPath: patch}
		notProven = []string{
			"only revert-to-attribute has run; falsifying-class replay, sanitizer-gated " +
				"reachability and the non-determinism control have not",
			"a credited patch has been shown to stop this PoV, not to be correct",
		}
	case "m3":
		// RequireRecover is true because target.go builds every shape with
		// -fsanitize-recover=address. If that ever stops being so, the stage
		// refuses rather than grading against a build that may halt early.
		st = sanitizer.Stage{Target: revertTarget(), BlobPath: blob(), PatchPath: patch, RequireRecover: true}
		notProven = []string{
			"only sanitizer-gated reachability has run; revert-attribution, falsifying-class " +
				"replay and the non-determinism control have not",
			"no NEW sanitizer finding is not a proof of unreachability, which is undecidable in " +
				"general; the bar met here is that no input in the falsifying class reached the " +
				"vulnerable sink under sanitizer",
		}
	case "m2":
		// The only stage that needs a reference. M0, M1 and M3 are
		// reference-free and run against a novel target; this one asks whether
		// the candidate agrees with a KNOWN-GOOD fix across the whole class, so
		// a target with no reference_patch cannot be graded by it.
		if c.ReferencePatch == "" {
			undecided(fmt.Errorf(
				"case %s carries no reference_patch, and falsifying-class replay compares a "+
					"candidate against a known-good fix; there is nothing to compare to", c.ID))
		}
		// A temp dir when unset, rather than mkdir "" failing inside the stage
		// as "class-replay could not run", which reads as the stage being
		// broken rather than a flag being unset.
		if workDir == "" {
			d, err := os.MkdirTemp("", "arazu-m2-")
			if err != nil {
				undecided(err)
			}
			workDir = d
		}
		ct, err := resolveClassTarget(c, corpusRoot, repoRoot, shim, workDir, members)
		if err != nil {
			undecided(err)
		}
		// Absolute, both of them. The stage applies these INSIDE the source
		// checkout, so a path relative to this repository resolves against the
		// wrong tree and fails as "apply ...: exit status 128", which reads as a
		// bad patch rather than a bad path.
		st = classreplay.Stage{
			Target:         ct,
			CandidatePatch: mustAbs(patch),
			ReferencePatch: mustAbs(c.ReferencePatchPath(root, repoRoot)),
		}
		notProven = []string{
			"only falsifying-class replay has run; revert-attribution, sanitizer-gated " +
				"reachability and the non-determinism control have not",
			"agreement with the reference across this class is not correctness in general: " +
				"the class is the one the case describes, not every input the target accepts",
		}

	default:
		undecided(fmt.Errorf("unknown sweep stage %q", stageID))
	}

	d, err := gate.Verify(context.Background(),
		gate.Input{Case: c, Candidate: cand, Root: root, RepoRoot: repoRoot},
		[]gate.Stage{st}, notProven)
	if err != nil {
		undecided(err)
	}
	emitDecision(d, o)
}

// mustAbs resolves a path against this process's working directory before it is
// handed to a stage that will chdir elsewhere.
func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		undecided(err)
	}
	return a
}
