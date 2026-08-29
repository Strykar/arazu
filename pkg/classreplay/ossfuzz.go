// SPDX-License-Identifier: Apache-2.0

package classreplay

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"arazu/pkg/corpus"
)

// OSSFuzzTarget drives a real challenge: it runs the case's generator to build
// the falsifying class, and rebuilds the target under a patch to replay the
// class against it. Everything above it is tested against a fake, so a
// divergence the Stage reports is a real behavioural difference or a bug here.
type OSSFuzzTarget struct {
	// RepoRoot is the arazu checkout; the case's paths are relative to it.
	RepoRoot string
	// Source is the challenge checkout, Ref the vulnerable branch. Ref is
	// restored after every replay: a tree left patched poisons the next one.
	Source string
	Ref    string
	// OSSFuzz is the pinned tooling checkout, Project what it builds. There is no
	// harness here: ReplayAgainst runs the case's observer, and a class with no
	// observer is refused rather than falling back to the fuzz harness, whose
	// silence cannot carry a discriminator.
	OSSFuzz string
	Project string
	// Sanitizer must match the case's pov.sanitizer. A class replay under a
	// different sanitizer compares outputs the case never described.
	Sanitizer string
	// Shim holds the `docker` shim and goes on PATH, so oss-fuzz's helper finds
	// the podman store the gate uses rather than whatever docker is installed.
	Shim string
	// WorkDir holds the generated class members.
	WorkDir string
	// Observer is the case's runnable, absolute. Given the source tree and the
	// members directory, it prints one "<member>\t<observation>" line per member.
	Observer string
	// Members bounds how many class members to generate. Each member costs a
	// container start on every replay, so this is the run's dominant cost.
	Members int
}

func (t *OSSFuzzTarget) env() []string {
	return append(os.Environ(), "PATH="+t.Shim+":"+os.Getenv("PATH"))
}

// Generate runs the case's generator once per class member. The generator is
// mode 644, so it goes through the interpreter: exec'ing it fails with EACCES,
// which reads as a missing generator rather than a permission bit.
func (t *OSSFuzzTarget) Generate(ctx context.Context, fc corpus.FalsifyingClass) ([]string, int, error) {
	gen := filepath.Join(t.RepoRoot, fc.Generator)
	if _, err := os.Stat(gen); err != nil {
		return nil, 0, fmt.Errorf("generator %s: %w", fc.Generator, err)
	}
	if err := os.MkdirAll(t.WorkDir, 0o755); err != nil {
		return nil, 0, err
	}
	// declared is the class the case describes, n how much of it this run
	// replays. The stage refuses to accept on the strength of a subset.
	const declared = 79 // the PNG keyword length limit, i.e. the whole class
	n := t.Members
	if n <= 0 || n > declared {
		n = declared
	}
	var members []string
	for i := 1; i <= n; i++ {
		// The keyword is the varying dimension, so the name records its length:
		// a divergence at "kw41" points straight at the boundary.
		name := fmt.Sprintf("kw%02d.png", i)
		out := filepath.Join(t.WorkDir, name)
		cmd := exec.CommandContext(ctx, "python3", gen, strings.Repeat("A", i), out, "400")
		if b, err := cmd.CombinedOutput(); err != nil {
			return nil, 0, fmt.Errorf("generator at length %d: %w: %s", i, err, b)
		}
		if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
			return nil, 0, fmt.Errorf("generator produced nothing at length %d", i)
		}
		members = append(members, name)
	}
	return members, declared, nil
}

// ReplayAgainst builds the target with patchPath applied and runs the case's
// observer over every member. An empty patchPath means the unpatched tree, the
// Stage's pre-patch oracle.
//
// It runs the observer, not the fuzz harness: the harness discards the
// diagnostics carrying the case's discriminator, so replaying the class through
// it compares silence against silence and accepts an incomplete fix.
func (t *OSSFuzzTarget) ReplayAgainst(ctx context.Context, patchPath string, members []string) (map[string]string, error) {
	if err := t.reset(ctx); err != nil {
		return nil, err
	}
	// Restore the tree whatever happens: a patch left applied makes the next
	// replay compare against the wrong baseline, and nothing notices.
	defer func() { _ = t.reset(context.WithoutCancel(ctx)) }()

	if patchPath != "" {
		p := patchPath
		if !filepath.IsAbs(p) {
			p = filepath.Join(t.RepoRoot, p)
		}
		cmd := exec.CommandContext(ctx, "git", "apply", p)
		cmd.Dir = t.Source
		if b, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("apply %s: %w: %s", patchPath, err, b)
		}
	}

	build := exec.CommandContext(ctx, "python3", "infra/helper.py", "build_fuzzers",
		"--sanitizer", t.Sanitizer, t.Project, t.Source)
	build.Dir = t.OSSFuzz
	build.Env = t.env()
	if b, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build with patch %q: %w: %s", patchPath, err, tail(string(b), 20))
	}

	// One run for the whole member set, because the observer owns the build.
	obs := exec.CommandContext(ctx, t.Observer, t.Source, t.WorkDir)
	obs.Env = t.env()
	b, err := obs.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("observer %s with patch %q: %w: %s",
			t.Observer, patchPath, err, tail(string(b), 20))
	}

	// One "<member>\t<observation>" line per member. An unreported member is
	// absent from the map, which the Stage treats as not-compared, not agreement.
	out := make(map[string]string, len(members))
	for _, ln := range strings.Split(string(b), "\n") {
		name, obsv, ok := strings.Cut(strings.TrimRight(ln, "\r"), "\t")
		if !ok || name == "" {
			continue
		}
		out[name] = normalise(obsv)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"observer %s produced no <member>\\t<observation> lines, so nothing was observed",
			t.Observer)
	}
	return out, nil
}

// reset returns the checkout to the case's ref with no local modifications.
func (t *OSSFuzzTarget) reset(ctx context.Context) error {
	for _, args := range [][]string{
		{"checkout", "-q", "--detach", "origin/" + t.Ref},
		{"reset", "-q", "--hard"},
		{"clean", "-qfd"},
	} {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = t.Source
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %w: %s", args[0], err, b)
		}
	}
	return nil
}

var (
	hexRe   = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	pidRe   = regexp.MustCompile(`==\d+==`)
	pathRe  = regexp.MustCompile(`/[A-Za-z0-9._/-]*/(src|out|work)/`)
	msRe    = regexp.MustCompile(`\b\d+ms\b|\bin \d+ ms\b`)
	ansiRe  = regexp.MustCompile("\x1b\\[[0-9;]*m")
	blankRe = regexp.MustCompile(`\n{2,}`)
)

// normalise strips what varies between two runs of the same build, so what
// remains varies only with the patch: addresses, pids, container paths and
// timings would otherwise make every member disagree with itself. Not reduced
// to a crash-site list, because both the correct and the incomplete fix reject
// the profile and a crash-only summary would collapse the comparison.
func normalise(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	s = hexRe.ReplaceAllString(s, "0xADDR")
	s = pidRe.ReplaceAllString(s, "==PID==")
	s = pathRe.ReplaceAllString(s, "/PATH/")
	s = msRe.ReplaceAllString(s, "TIME")
	var keep []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, " \t")
		// libfuzzer's banner carries seeds and counts the patch does not control.
		if strings.HasPrefix(ln, "INFO: Seed:") || strings.HasPrefix(ln, "INFO: Loaded") ||
			strings.HasPrefix(ln, "INFO: -max_len") || strings.HasPrefix(ln, "Running:") ||
			strings.HasPrefix(ln, "Executed ") {
			continue
		}
		keep = append(keep, ln)
	}
	sort.SliceStable(keep, func(i, j int) bool { return false }) // order preserved; kept explicit
	return strings.TrimSpace(blankRe.ReplaceAllString(strings.Join(keep, "\n"), "\n"))
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
