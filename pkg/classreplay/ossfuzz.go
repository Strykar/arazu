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
// class against it.
//
// Everything above this is already tested against a fake, so this type is the
// ONE new thing a class-replay run exercises. That property is why it is worth
// keeping the seam: a divergence reported by the Stage is either a real
// behavioural difference or a bug in here, and nothing else.
type OSSFuzzTarget struct {
	// RepoRoot is the arazu checkout, used to resolve the case's paths, which
	// are recorded relative to it.
	RepoRoot string
	// Source is the challenge checkout and Ref the branch carrying the
	// vulnerability. Ref is restored after every replay: a class replay that
	// leaves the tree on a patched commit poisons the next one.
	Source string
	Ref    string
	// OSSFuzz is the pinned tooling checkout; Project and Harness name what to
	// build and run inside it.
	OSSFuzz string
	Project string
	Harness string
	// Sanitizer must match the case's pov.sanitizer. A class replay under a
	// different sanitizer compares outputs the case never described.
	Sanitizer string
	// Shim is the directory holding the `docker` shim. It goes on PATH so
	// oss-fuzz's helper finds the podman store the gate uses, rather than
	// whatever docker is installed.
	Shim string
	// WorkDir holds the generated class members.
	WorkDir string
	// Observer is the runnable the case names, resolved to an absolute path. It
	// is given the source tree and the members directory and prints one
	// "<member>\t<observation>" line per member.
	Observer string
	// Members bounds how many class members to generate. The libpng class is
	// "keyword lengths PNG permits", 1..79, and each member costs a container
	// start on every replay, so this is the run's dominant cost.
	Members int
}

func (t *OSSFuzzTarget) env() []string {
	return append(os.Environ(), "PATH="+t.Shim+":"+os.Getenv("PATH"))
}

// Generate runs the case's generator once per class member.
//
// The generator writes ONE file per invocation and takes (keyword, out, size),
// so the class comes from varying its argument rather than from a single call
// returning a set. It is also mode 644, so it is run through the interpreter
// rather than executed: exec'ing it fails with EACCES, which reads as a missing
// generator rather than a permission bit.
func (t *OSSFuzzTarget) Generate(ctx context.Context, fc corpus.FalsifyingClass) ([]string, int, error) {
	gen := filepath.Join(t.RepoRoot, fc.Generator)
	if _, err := os.Stat(gen); err != nil {
		return nil, 0, fmt.Errorf("generator %s: %w", fc.Generator, err)
	}
	if err := os.MkdirAll(t.WorkDir, 0o755); err != nil {
		return nil, 0, err
	}
	// declared is the size of the class the case describes; n is how much of it
	// this run will replay. They differ whenever a caller bounds the run, and
	// the stage refuses to ACCEPT on the strength of a subset.
	const declared = 79 // the PNG keyword length limit, i.e. the whole class
	n := t.Members
	if n <= 0 || n > declared {
		n = declared
	}
	var members []string
	for i := 1; i <= n; i++ {
		// The keyword IS the varying dimension the class describes, so the
		// member's name records its length: a divergence report that says
		// "kw41" points straight at the boundary the injection sits on.
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
// observer over every member.
//
// An empty patchPath means the unpatched tree, which is how the Stage asks for
// its pre-patch oracle.
//
// IT RUNS THE OBSERVER, NOT THE FUZZ HARNESS. libpng_read_fuzzer calls
// png_image_finish_read and discards libpng's warnings, so the output carries no
// trace of this case's discriminator -- whether the parsed keyword is NAMED. A
// real run through it reported 79 members, 0 disagreements, and ACCEPTED the
// known-incomplete run2 patch: a correct comparison over silence. Every part
// worked and nothing in the verdict said the signal was absent, which is worse
// than a wrong answer.
//
// The case names its own observer for that reason. Only it knows what its
// discriminator looks at.
func (t *OSSFuzzTarget) ReplayAgainst(ctx context.Context, patchPath string, members []string) (map[string]string, error) {
	if err := t.reset(ctx); err != nil {
		return nil, err
	}
	// Restore the tree whatever happens. A failed replay that leaves a patch
	// applied makes the NEXT replay compare against the wrong baseline, and the
	// Stage has no way to notice.
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

	// The OBSERVER produces the observation, not the fuzz harness. The harness
	// calls png_image_finish_read and discards diagnostics, so replaying the
	// class through it compared silence against silence: 79 of 79 members
	// equal, and the known-incomplete fix accepted. Only the case knows what
	// its discriminator looks at, so only the case can produce it.
	//
	// Run once for the whole member set, because the observer owns the build.
	obs := exec.CommandContext(ctx, t.Observer, t.Source, t.WorkDir)
	obs.Env = t.env()
	b, err := obs.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("observer %s with patch %q: %w: %s",
			t.Observer, patchPath, err, tail(string(b), 20))
	}

	// One "<member>\t<observation>" line per member. A member the observer did
	// not report is absent from the map, and the Stage already treats a missing
	// member as not-compared rather than as agreement.
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

// normalise strips what varies between two runs of the SAME build so that what
// remains varies only with the patch.
//
// Addresses, pids, container paths and timings all differ run to run; leaving
// them in would make every member disagree with itself and report the whole
// class as divergent. This is the same argument as CrashSite dropping Line and
// Column, applied to a whole report rather than one site.
//
// Deliberately NOT reduced to a crash-site list. The case's discriminator is
// whether libpng names the parsed keyword ("profile '<keyword>'"), and both the
// correct and the incomplete fix end up REJECTING this profile — so a
// crash-only summary would collapse the two sides of the very comparison the
// stage exists to make.
func normalise(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	s = hexRe.ReplaceAllString(s, "0xADDR")
	s = pidRe.ReplaceAllString(s, "==PID==")
	s = pathRe.ReplaceAllString(s, "/PATH/")
	s = msRe.ReplaceAllString(s, "TIME")
	var keep []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, " \t")
		// libfuzzer's per-run banner carries seeds and byte counts that vary
		// with nothing the patch controls.
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
