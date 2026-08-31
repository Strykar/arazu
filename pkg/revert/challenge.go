// SPDX-License-Identifier: Apache-2.0

package revert

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"arazu/pkg/corpus"
)

// Challenge drives an AIxCC challenge checkout through its own run.sh, which is
// the only supported way to build it and run a PoV.
type Challenge struct {
	Root  string // the challenge checkout
	Shim  string // directory holding the docker shim
	Src   string // source subdirectory, relative to Root
	Pin   string // commit the tree is reset to
	Image string // resolved container image

	// ExtraCFlags is appended to the harness build's CFLAGS through the
	// challenge's own CP_HARNESS_EXTRA_CFLAGS hook. It exists so the stage can
	// build with -fsanitize-recover=address: without it ASan halts on the first
	// error, ASAN_OPTIONS=halt_on_error=0 is accepted and INERT, and a report
	// naming one site is indistinguishable from one where the other site is
	// clean. A crash-site comparison on a non-recovering build is not evidence.
	ExtraCFlags string
}

// env puts the shim first on PATH for the CHILDREN of what we launch, which is
// the only thing it can do. exec.Command resolves the command's own name against
// the parent process's PATH and ignores cmd.Env entirely, so this PATH governs
// the docker calls that run.sh makes, not the resolution of run.sh or git.
//
// The invariant that keeps that safe: nothing here may invoke a shimmed binary
// BY NAME. The shim shadows exactly one, docker, and this file calls only git
// (identical under either PATH) and ./run.sh (contains a separator, so it is
// resolved against cmd.Dir rather than looked up). Add a bare docker call here
// and it silently reaches /usr/bin/docker, a different runtime holding different
// images — which is exactly the bug that cost the first M1 sweep. Invoke shimmed
// binaries by explicit path, as cmd/gate/sweep.go does.
func (c Challenge) env() []string {
	e := append(os.Environ(),
		"PATH="+c.Shim+string(os.PathListSeparator)+os.Getenv("PATH"),
		"DOCKER_USER_ARGS=-e LOCAL_USER=0:0",
		"DOCKER_IMAGE_NAME="+c.Image,
	)
	// The build runs inside the container, so the flag has to cross the
	// boundary as a docker -e rather than as a host variable. Setting it on the
	// host would look correct and do nothing.
	if c.ExtraCFlags != "" {
		// BOTH halves are required and they fail differently. The CFLAG makes
		// recovery POSSIBLE; ASAN_OPTIONS=halt_on_error=0 makes it HAPPEN.
		// Compiled-in recovery without the runtime option is inert, and the
		// build log still shows the flag on every compile line — so verifying
		// the artifact alone reports "recovery is in force" when it is not.
		// The observable that settles it is more than one ==ERROR== per run.
		e = append(e,
			"DOCKER_EXTRA_ARGS=-e CP_HARNESS_EXTRA_CFLAGS="+c.ExtraCFlags+
				" -e ASAN_OPTIONS=halt_on_error=0:detect_leaks=0")
	}
	return e
}

func (c Challenge) run(ctx context.Context, name string, arg ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, arg...)
	cmd.Dir = c.Root
	cmd.Env = c.env()
	return cmd.CombinedOutput()
}

func (c Challenge) src() string { return filepath.Join(c.Root, c.Src) }

// ResetToPin discards whatever a previous run left behind, then VERIFIES the
// tree is clean. The verification is the point: everything downstream reads a
// dirty tree as a fact about the candidate.
func (c Challenge) ResetToPin(ctx context.Context) error {
	if out, err := c.run(ctx, "git", "-C", c.src(), "reset", "--hard", c.Pin); err != nil {
		return fmt.Errorf("git reset: %w: %s", err, out)
	}
	if out, err := c.run(ctx, "git", "-C", c.src(), "clean", "-fdx"); err != nil {
		return fmt.Errorf("git clean: %w: %s", err, out)
	}
	out, err := c.run(ctx, "git", "-C", c.src(), "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("git status: %w: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		// Not "probably fine". A candidate applied to this tree would fail for
		// reasons that have nothing to do with the candidate.
		return fmt.Errorf("tree is still dirty after reset to %s:\n%s", c.Pin, out)
	}
	return nil
}

func (c Challenge) Apply(ctx context.Context, patchPath string) error {
	abs, err := filepath.Abs(patchPath)
	if err != nil {
		return err
	}
	if out, err := c.run(ctx, "git", "-C", c.src(), "apply", "--whitespace=nowarn", abs); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Build reads the container's status out of the recorded exitcode, never out of
// run.sh's own: run.sh exits 0 whether or not the build inside it succeeded,
// which is the trap RunPoV is built around, one command earlier.
//
// Trusting the exit status ran the PoV against whatever binary was already in
// out/. Both sides of the patch boundary then measure the same binary, so it
// errs toward REJECT rather than ACCEPT, and it is still a verdict nothing
// supports. Seen on the staged nginx checkout rejecting the case's own good
// candidate.
func (c Challenge) Build(ctx context.Context) error {
	before := c.outputSet("build")
	out, runErr := c.run(ctx, "./run.sh", "build")
	if runErr != nil {
		return fmt.Errorf("%w: %s", runErr, tail(string(out), 400))
	}

	dir, err := c.newestOutput("build", before)
	if err != nil {
		// A build that recorded nothing was not observed, and an unobserved
		// build is not a passed one.
		return err
	}
	status, err := os.ReadFile(filepath.Join(dir, "exitcode"))
	if err != nil {
		return fmt.Errorf("no exitcode in %s, so whether the build succeeded is unknown: %w", dir, err)
	}
	if code := strings.TrimSpace(string(status)); code != "0" {
		stderr, _ := os.ReadFile(filepath.Join(dir, "stderr.log"))
		return fmt.Errorf("the build failed with exit %q: %s",
			code, tail(strings.TrimSpace(string(stderr)), 400))
	}
	return nil
}

// RunPoV runs the blob and reads the verdict out of the recorded stderr, never
// out of an exit status: the container exits 0 whether or not the vulnerability
// fires, which is the trap this whole project is built around.
func (c Challenge) RunPoV(ctx context.Context, blob, harness string, pov corpus.PoV) (PoVRun, error) {
	abs, err := filepath.Abs(blob)
	if err != nil {
		return PoVRun{}, err
	}
	// out/output accumulates across runs, so the verdict must come from a
	// directory this invocation created. run.sh's exit status is not the signal.
	before := c.outputSet("run_pov")
	out, runErr := c.run(ctx, "./run.sh", "run_pov", abs, harness)

	dir, err := c.newestOutput("run_pov", before)
	if err != nil {
		if runErr != nil {
			return PoVRun{}, fmt.Errorf("%w: run.sh: %v: %s", err, runErr, tail(string(out), 400))
		}
		return PoVRun{}, err
	}
	// The case says where the verdict lives; the runner must not decide. A
	// hard-coded "stderr.log" here made PoV.Signal a field the schema declared
	// and nothing read, while its own doc comment claimed the opposite.
	signal := pov.Signal
	if signal == "" {
		signal = "stderr.log"
	}
	stderr, err := os.ReadFile(filepath.Join(dir, signal))
	if err != nil {
		return PoVRun{}, fmt.Errorf("no %s in %s: %w", signal, dir, err)
	}
	s := string(stderr)

	// "Running: <input>" is printed BEFORE the input is executed, so it appears
	// whether or not the run then crashes. "Executed ... in N ms" is printed
	// only on a clean return, so keying on it would report every firing PoV as
	// a harness that never ran — failing hardest on the runs that work.
	run := PoVRun{
		HarnessRan:     strings.Contains(s, "Running: "),
		SanitizerFired: strings.Contains(s, pov.ExpectedSanitizer),
	}
	if run.SanitizerFired {
		run.Site = corpus.MatchSite(corpus.ParseDeclaredSite(pov.CrashLocation), s)
	}
	run.Evidence = []string{
		"run_pov output: " + filepath.Base(dir),
		fmt.Sprintf("harness reached execution: %t (libfuzzer 'Running:' line)", run.HarnessRan),
		fmt.Sprintf("%q present in %s: %t", pov.ExpectedSanitizer, signal, run.SanitizerFired),
	}
	if run.SanitizerFired {
		run.Evidence = append(run.Evidence,
			fmt.Sprintf("crash site versus the declared one: %s", run.Site))
	}
	return run, nil
}

// outputSet records the output directories present before a run.
func (c Challenge) outputSet(kind string) map[string]bool {
	entries, _ := filepath.Glob(filepath.Join(c.Root, "out", "output", "*--"+kind))
	seen := make(map[string]bool, len(entries))
	for _, p := range entries {
		seen[p] = true
	}
	return seen
}

// newestOutput returns the newest output directory not present in before, so a
// run that produced nothing is an error rather than a stale answer.
func (c Challenge) newestOutput(kind string, before map[string]bool) (string, error) {
	entries, err := filepath.Glob(filepath.Join(c.Root, "out", "output", "*--"+kind))
	if err != nil {
		return "", fmt.Errorf("no new %s output directory under %s/out/output: %w", kind, c.Root, err)
	}
	type ent struct {
		path string
		mod  int64
	}
	var es []ent
	for _, p := range entries {
		if before[p] {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		es = append(es, ent{p, fi.ModTime().UnixNano()})
	}
	if len(es) == 0 {
		return "", fmt.Errorf("no new %s output directory under %s/out/output", kind, c.Root)
	}
	sort.Slice(es, func(i, j int) bool { return es[i].mod > es[j].mod })
	return es[0].path, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
