// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"arazu/pkg/corpus"
)

// EffectStage refuses a patch that changes no source line.
//
// This is the degenerate case of revert-to-attribute, and it is worth its own
// stage because it is the one form of nothing-happened that every later stage
// would report as success. A patch that changes nothing builds, leaves the
// proof of vulnerability firing exactly as before, and breaks no test; run it
// against a target whose PoV was already flaky and the sanitizer's silence
// reads as a fix. Catching it first costs one file read instead of a build.
//
// It decides on the diff alone, so it needs no container and no target tree.
type EffectStage struct{}

func (EffectStage) Name() string { return "patch-effect" }

func (s EffectStage) Run(_ context.Context, in Input) (StageResult, error) {
	path := in.Case.CandidatePatchPath(in.Candidate, in.Root, in.RepoRoot)

	f, err := os.Open(path)
	if err != nil {
		// The patch not being readable is a plumbing failure, not a verdict.
		// Reporting it as a rejection would credit the gate with a judgement it
		// never made, and the candidate would be scored on a check that never
		// ran.
		return StageResult{}, fmt.Errorf("candidate patch %s: %w", in.Candidate.Patch, err)
	}
	defer f.Close()

	var added, removed, hunks int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		// File headers open with the same characters as changed lines, so they
		// are excluded before anything is counted. A diff of headers alone
		// changes nothing.
		case strings.HasPrefix(line, "+++ "), strings.HasPrefix(line, "--- "):
		case strings.HasPrefix(line, "@@"):
			hunks++
		case strings.HasPrefix(line, "+"):
			added++
		case strings.HasPrefix(line, "-"):
			removed++
		}
	}
	if err := sc.Err(); err != nil {
		return StageResult{}, fmt.Errorf("reading %s: %w", in.Candidate.Patch, err)
	}

	evidence := []string{
		fmt.Sprintf("read %s", in.Candidate.Patch),
		fmt.Sprintf("%d hunks, %d added lines, %d removed lines", hunks, added, removed),
	}

	if added+removed == 0 {
		return StageResult{
			Stage:    s.Name(),
			Outcome:  OutcomeFailed,
			Reason:   corpus.ReasonEmptyPatch,
			Evidence: append(evidence, "a patch that changes no line cannot be credited with a fix"),
		}, nil
	}

	return StageResult{
		Stage:    s.Name(),
		Outcome:  OutcomePassed,
		Evidence: evidence,
	}, nil
}
