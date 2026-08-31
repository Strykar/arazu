// SPDX-License-Identifier: Apache-2.0

// Command mutation-test breaks each security-relevant check in turn and
// reports which test caught it.
//
// A suite that has never been mutated has unknown evidential value. A check
// with a green test beside it is not known to be tested; it is only known to
// be accompanied by a test that passes. This walks the catalogue, applies one
// edit at a time to a throwaway copy of the tree, and records what failed. A
// mutation nothing catches is a hole, and reporting it is the whole point.
//
// The copy is rebuilt before the tests run. The cmd tests exec binaries out
// of bin/, so a stale bin/ would run unmutated code and every pkg mutation
// would look caught or escaped at random.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Mutation is one deliberate break. Before must occur exactly once in File:
// a catalogue entry that no longer matches is a stale catalogue, which is an
// error rather than something to skip, because skipping it would quietly
// stop testing the check it names.
type Mutation struct {
	ID       string   `json:"id"`
	Check    string   `json:"check"`
	File     string   `json:"file"`
	Before   string   `json:"before"`
	After    string   `json:"after"`
	Packages []string `json:"packages"`
	Expect   string   `json:"expect"`

	// SubsumedBy names another mutation whose check runs first and refuses
	// the same input, making this one defence in depth. Some redundant
	// checks cannot be made to fail on their own: with ScanDir walking the
	// tree before anything is read, no input reaches the per-entry stat
	// check that ScanDir would not already have refused.
	//
	// This is not a way to excuse a hole. The escape is only accepted if the
	// named mutation was itself caught, so the claim "something else catches
	// this" has to be backed by that something else being evidenced.
	SubsumedBy string `json:"subsumedBy,omitempty"`

	// UntestableReason states why no test can catch this mutation on this
	// host: the precondition the check defends against cannot be induced
	// here. A TPM that disagrees with SHA256, or a kernel without the bpf
	// LSM, are real failure modes worth guarding and not reproducible
	// without a simulator or a reboot.
	//
	// This is an escape hatch, so it is deliberately noisy. The run still
	// lists these separately and the reason has to say what would be needed
	// to close it. An empty or vague reason is how a hole gets laundered
	// into a footnote.
	UntestableReason string `json:"untestableReason,omitempty"`
}

type Result struct {
	ID       string   `json:"id"`
	Check    string   `json:"check"`
	File     string   `json:"file"`
	Verdict  string   `json:"verdict"`
	Expect   string   `json:"expect"`
	Catchers []string `json:"catchers"`
	Note     string   `json:"note,omitempty"`
}

// Verdicts. Only "escaped" and "stale" fail the run. A mutation caught by a
// test other than the predicted one is still caught, but the prediction was
// wrong and that is worth seeing.
const (
	caught      = "caught"
	caughtOther = "caught-by-another-test"
	escaped     = "escaped"
	subsumed    = "subsumed"
	untestable  = "untestable-on-this-host"
	buildFail   = "build-fail"
	stale       = "stale-catalogue"
)

// Copied wholesale into each mutant. bin/ is excluded because it is rebuilt,
// and .git because nothing here reads it.
// vendor is here because the build is -mod=vendor with GOPROXY=off. Without it
// every mutant fails with "inconsistent vendoring" before a single test runs,
// which is what happened from the day the tree was vendored: 40 of 40 mutants
// build-failed and the run still reported 0 uncaught.
var treeEntries = []string{"go.mod", "go.sum", "vendor", "pkg", "cmd", "scripts", "testdata", "bpf", "corpus", "Makefile"}

var failLine = regexp.MustCompile(`(?m)^\s*--- FAIL: (\S+)`)

func main() {
	repo := flag.String("repo", ".", "repository to mutate")
	catalogue := flag.String("catalogue", "testdata/mutations.json", "mutation catalogue, relative to -repo")
	work := flag.String("work", "", "directory to build mutants in (default: a temp dir)")
	only := flag.String("only", "", "run just this mutation id")
	flag.Parse()

	root, err := filepath.Abs(*repo)
	if err != nil {
		fatal(err)
	}

	var muts []Mutation
	b, err := os.ReadFile(filepath.Join(root, *catalogue))
	if err != nil {
		fatal(err)
	}
	if err := json.Unmarshal(b, &muts); err != nil {
		fatal(fmt.Errorf("%s: %w", *catalogue, err))
	}

	base := *work
	if base == "" {
		base, err = os.MkdirTemp("", "arazu-mutants-")
		if err != nil {
			fatal(err)
		}
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		fatal(err)
	}

	if pkgs := packagesToRun(muts, *only); len(pkgs) > 0 {
		if err := baseline(root, filepath.Join(base, "_baseline"), pkgs); err != nil {
			fatal(err)
		}
	}

	var results []Result
	for _, m := range muts {
		if *only != "" && m.ID != *only {
			continue
		}
		r := run(root, filepath.Join(base, m.ID), m)
		results = append(results, r)
		fmt.Fprintf(os.Stderr, "%-28s %-22s %s\n", m.ID, r.Verdict, strings.Join(r.Catchers, " "))
	}

	resolveSubsumption(muts, results)
	report(results)
	// A mutant that did not build was never tested, so it is not evidence of
	// anything. It is deliberately NOT folded into untestable: that verdict is a
	// declared, reasoned exemption carrying an UntestableReason, whereas a build
	// failure is the harness breaking. Counting it as neither left a run in which
	// nothing at all was tested exiting 0 and printing "0 uncaught".
	for _, r := range results {
		if r.Verdict == escaped || r.Verdict == stale || r.Verdict == buildFail {
			os.Exit(1)
		}
	}
}

// resolveSubsumption downgrades an escape to "subsumed" when the mutation
// declares a check that catches the same input, and that check was itself
// caught. An escape whose subsuming mutation also escaped stays an escape:
// two redundant checks that both do nothing are not defence in depth.
func resolveSubsumption(muts []Mutation, results []Result) {
	verdict := map[string]string{}
	for _, r := range results {
		verdict[r.ID] = r.Verdict
	}
	byID := map[string]Mutation{}
	for _, m := range muts {
		byID[m.ID] = m
	}

	for i, r := range results {
		if r.Verdict != escaped {
			continue
		}
		m := byID[r.ID]
		if m.UntestableReason != "" {
			results[i].Verdict = untestable
			results[i].Note = m.UntestableReason
			continue
		}
		if m.SubsumedBy == "" {
			continue
		}
		switch verdict[m.SubsumedBy] {
		case caught, caughtOther:
			results[i].Verdict = subsumed
			results[i].Note = "no input reaches this check that " + m.SubsumedBy +
				" does not refuse first, and " + m.SubsumedBy + " is caught"
		case "":
			results[i].Note = "declares subsumedBy " + m.SubsumedBy + ", which is not in the catalogue"
		default:
			results[i].Note = "declares subsumedBy " + m.SubsumedBy +
				", but that mutation also escaped, so neither check is evidenced"
		}
	}
}

// prepare runs the build steps a tree needs before its tests mean anything.
func prepare(dir string) (string, error) {
	if out, err := runIn(dir, "make", "-C", "bpf", "egress_deny.bpf.o"); err != nil {
		return "bpf object: " + firstLines(out, 3), err
	}
	if out, err := goCmd(dir, "build", "-o", "bin/", "./cmd/..."); err != nil {
		return firstLines(out, 3), err
	}
	return "", nil
}

// baseline runs the catalogue's packages against an UNMUTATED copy of the tree.
//
// A mutant is evidence only if the tree it was cut from is green. A test that
// fails for its own reasons fails in every mutant too, and the harness credits
// it as a catcher, so every mutation reports caught and the run proves nothing.
// That is not hypothetical: corpus/ was missing from treeEntries, so
// TestEveryCaseFileLoads hit its own "would pass vacuously" guard in every
// mutant, and 21 corpus mutations looked evidenced when none of them were.
//
// Aborts the run rather than marking results, because no verdict in the run is
// trustworthy once this fails.
func baseline(root, dir string, pkgs []string) error {
	if err := copyTree(root, dir); err != nil {
		return err
	}
	if note, err := prepare(dir); err != nil {
		return fmt.Errorf("the unmutated tree does not build: %s", note)
	}
	out, err := goCmd(dir, append([]string{"test", "-count=1"}, pkgs...)...)
	if err == nil {
		return nil
	}
	if names := uniq(failLine.FindAllStringSubmatch(out, -1)); len(names) > 0 {
		return fmt.Errorf("the unmutated tree already fails %s, so every mutant would "+
			"credit them as catchers", strings.Join(names, " "))
	}
	return fmt.Errorf("the unmutated tree does not pass: %s", firstLines(out, 5))
}

// packagesToRun is every package the mutations selected for this run will test.
func packagesToRun(muts []Mutation, only string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range muts {
		if only != "" && m.ID != only {
			continue
		}
		for _, p := range m.Packages {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func run(root, dir string, m Mutation) Result {
	res := Result{ID: m.ID, Check: m.Check, File: m.File, Expect: m.Expect}

	if err := copyTree(root, dir); err != nil {
		res.Verdict = buildFail
		res.Note = err.Error()
		return res
	}

	target := filepath.Join(dir, m.File)
	src, err := os.ReadFile(target)
	if err != nil {
		res.Verdict = stale
		res.Note = err.Error()
		return res
	}
	if n := strings.Count(string(src), m.Before); n != 1 {
		res.Verdict = stale
		res.Note = fmt.Sprintf("the text to mutate occurs %d times in %s, want exactly 1", n, m.File)
		return res
	}
	mutated := strings.Replace(string(src), m.Before, m.After, 1)
	if err := os.WriteFile(target, []byte(mutated), 0o644); err != nil {
		res.Verdict = stale
		res.Note = err.Error()
		return res
	}

	// A .bpf.c mutation is a no-op unless the object is recompiled. The tests
	// load bpf/egress_deny.bpf.o, which copyTree brought over already built, so
	// without this the edit sat in the source, the unmutated object ran, nothing
	// failed, and the harness reported the check as UNCAUGHT. That is a false
	// hole in the containment layer, which is the one place a false hole is most
	// expensive: it says the eBPF denial is unevidenced when the test for it is
	// correct and does fail once the mutation actually reaches the object.
	//
	// Third time this harness has silently tested something other than the
	// mutant: vendor/ was not copied, the build environment was inherited, and
	// now the object was stale. Rebuild unconditionally; it costs one clang
	// invocation and removes the whole class.
	if note, err := prepare(dir); err != nil {
		res.Verdict = buildFail
		res.Note = note
		return res
	}

	args := append([]string{"test", "-count=1"}, m.Packages...)
	out, err := goCmd(dir, args...)
	res.Catchers = uniq(failLine.FindAllStringSubmatch(out, -1))

	switch {
	case err == nil:
		res.Verdict = escaped
		res.Note = "no test failed with this check broken"
	case len(res.Catchers) == 0:
		// The suite failed without naming a test: a panic, a build error in a
		// test file, or a timeout. That is not evidence the check is tested.
		res.Verdict = escaped
		res.Note = "the suite failed but named no test: " + firstLines(out, 3)
	case m.Expect != "" && !contains(res.Catchers, m.Expect):
		res.Verdict = caughtOther
	default:
		res.Verdict = caught
	}
	return res
}

func goCmd(dir string, args ...string) (string, error) {
	return runIn(dir, "go", args...)
}

func runIn(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range treeEntries {
		from := filepath.Join(src, e)
		if _, err := os.Stat(from); err != nil {
			continue
		}
		cmd := exec.Command("cp", "-a", from, dst+string(os.PathSeparator))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("copy %s: %v: %s", e, err, out)
		}
	}
	return nil
}

func uniq(matches [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		name := m[1]
		// Subtests report as Parent/Child; the parent is what identifies the test.
		if i := strings.Index(name, "/"); i > 0 {
			name = name[:i]
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

func report(results []Result) {
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(b))

	var holes []string
	for _, r := range results {
		if r.Verdict == escaped || r.Verdict == stale {
			holes = append(holes, r.ID+" ("+r.Check+")")
		}
	}
	nSub := 0
	for _, r := range results {
		if r.Verdict == subsumed {
			nSub++
		}
	}
	var untested []string
	for _, r := range results {
		if r.Verdict == untestable {
			untested = append(untested, r.ID+": "+r.Note)
		}
	}
	var broken []string
	for _, r := range results {
		if r.Verdict == buildFail {
			broken = append(broken, r.ID+": "+r.Note)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d mutations, %d uncaught, %d subsumed by an evidenced check, %d untestable here, %d did not build\n",
		len(results), len(holes), nSub, len(untested), len(broken))
	for _, b := range broken {
		fmt.Fprintf(os.Stderr, "  DID NOT BUILD %s\n", b)
	}
	for _, u := range untested {
		fmt.Fprintf(os.Stderr, "  UNTESTABLE %s\n", u)
	}
	for _, h := range holes {
		fmt.Fprintf(os.Stderr, "  UNCAUGHT %s\n", h)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
