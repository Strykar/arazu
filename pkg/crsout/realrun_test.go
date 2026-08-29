// SPDX-License-Identifier: Apache-2.0

package crsout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Three run directories lifted out of a live Buttercup UI pod on 2026-08-19,
// from runs on 8, 9 and 12 August. Committed whole, 68K, because a contract
// read from a writer's source is not the same as one observed in its output,
// and this package had only ever been tested against directories it built
// itself.
const realRuns = "../../testdata/crsout/realrun"

func runDirs(t *testing.T) []string {
	t.Helper()
	d, err := filepath.Glob(filepath.Join(realRuns, "run-data-*"))
	if err != nil || len(d) == 0 {
		t.Fatalf("no real run fixtures under %s", realRuns)
	}
	return d
}

// The layout the contract assumed sat one level too high. get_run_data_dir()
// returns <root>/run-data-<timestamp>, a NEW directory per UI start, and the
// task id is under THAT. Capture takes the run-data dir, so the contract holds
// — but a caller pointed at the root finds nothing, and three historical
// directories sit beside the current one with no marker saying which is live.
func TestTheRunDirIsTimestampedNotTheRoot(t *testing.T) {
	dirs := runDirs(t)
	if len(dirs) < 2 {
		t.Skip("only one run-data dir, the ambiguity this documents needs two")
	}
	for _, d := range dirs {
		if !strings.HasPrefix(filepath.Base(d), "run-data-") {
			t.Errorf("unexpected directory %s", d)
		}
	}
	t.Logf("%d run-data dirs side by side; nothing in the layout says which is current", len(dirs))
}

// THE PREDICTION. Filed as "PROBABLY NOT" before looking: a bundle is a
// competition SUBMISSION artifact, and a local run submits nowhere.
//
// It held. Zero bundles across three real runs. The consequence matters more
// than the fact: the bundle pairing path, and the alphabetical-disagreement
// test that is its only evidence, has never run against real data. A passing
// test on synthetic input is a claim about the test, not about the path.
func TestRealRunsCarryNoBundle(t *testing.T) {
	var withBundles, total int
	for _, d := range runDirs(t) {
		tasks, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, task := range tasks {
			if fi, err := os.Stat(task); err != nil || !fi.IsDir() {
				continue
			}
			total++
			if ents, err := os.ReadDir(filepath.Join(task, "bundles")); err == nil && len(ents) > 0 {
				withBundles++
			}
		}
	}
	if total == 0 {
		t.Fatal("no task directories in the fixtures")
	}
	if withBundles != 0 {
		t.Fatalf("%d of %d real runs carry a bundle: the prediction was wrong and "+
			"the pairing path IS exercised by real data", withBundles, total)
	}
	t.Logf("0 of %d real runs carry a bundle; every real capture takes the "+
		"one-of-each fallback, and the bundle path has only synthetic evidence", total)
}

// Capture against every real directory. Two produce a case; two return
// crs-no-patch, and those two are NOT independent evidence of the same thing.
// See TestNoPatchDoesNotSayWhy.
func TestCaptureAgainstEveryRealRun(t *testing.T) {
	want := map[string]Outcome{
		"a790c3ea-1c89-47e0-82fc-3b5c7cdfb425": Captured,
		"78c4e908-ff7b-403e-b01b-1640e28d1fa7": Captured,
		"88359bc1-8269-4f9e-9c6d-905d3d2a399b": NoPatch,
		"017d6977-ca2e-46cd-ad5c-d8f92495024b": NoPatch,
		// The routing fix, verified end to end. Submitted 20 Aug after the
		// prefill correction; patcher reached the model with no 400 and emitted
		// a patch restoring png_byte keyword[81], libpng's own constant. First
		// capture from a run that completed rather than one that was truncated.
		"0e69cb3f-68e4-4f52-a056-303b63408157": Captured,
	}
	seen := map[string]Outcome{}
	for _, d := range runDirs(t) {
		tasks, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, task := range tasks {
			fi, err := os.Stat(task)
			if err != nil || !fi.IsDir() {
				continue
			}
			id := filepath.Base(task)
			res, err := Capture(d, id, src(), t.TempDir())
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			seen[id] = res.Outcome
		}
	}
	for id, w := range want {
		got, ok := seen[id]
		if !ok {
			t.Errorf("%s missing from the fixtures", id)
			continue
		}
		if got != w {
			t.Errorf("%s: outcome %s, want %s", id, got, w)
		}
	}
	// No decline outside the six. A seventh would mean the vocabulary is
	// incomplete, and the pre-decision says it gets a new name rather than
	// being folded into an existing one.
	for id, o := range seen {
		switch o {
		case Captured, NoRun, NoPatch, NoPoV, Unpairable, Malformed, NoSanitizerReport:
		default:
			t.Errorf("%s produced %q, which is outside the vocabulary", id, o)
		}
	}
}

// Buttercup's own patches are well formed: diff --git, an index line and real
// ranges. That is worth pinning, because it says the looksLikeDiff weakness
// found against raw model output is not what a CRS run exercises — the patcher
// post-processes before writing.
func TestRealPatchesAreWellFormed(t *testing.T) {
	found := 0
	for _, d := range runDirs(t) {
		ps, _ := filepath.Glob(filepath.Join(d, "*", "patches", "*.patch"))
		for _, p := range ps {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			found++
			if !strings.Contains(s, "diff --git ") {
				t.Errorf("%s has no diff --git header", filepath.Base(p))
			}
			if !strings.Contains(s, "@@ -") {
				t.Errorf("%s has a hunk marker with no ranges, the raw-model failure mode", filepath.Base(p))
			}
		}
	}
	if found == 0 {
		t.Fatal("no real patches in the fixtures")
	}
	t.Logf("%d real patches, all with diff --git and ranged hunks", found)
}

// THE LIMIT OF THE DECLINE, found by running a fourth task rather than by
// reading anything.
//
// 88359bc1 and 017d6977 both capture as crs-no-patch. Their causes are
// unrelated: 017d6977's patcher reached its model and got a 400, "This model
// does not support assistant message prefill", because the run was routed to an
// Anthropic model by scripts/buttercup-model.sh while the patcher prefills an
// assistant turn. It never searched for a fix. 88359bc1 has no such record.
//
// The output contract stores artifacts, not reasons an artifact is absent, so
// capture cannot tell the two apart and crs-no-patch is the honest verdict for
// both. This test exists so the decline is never quoted as "the CRS could not
// fix it": it also covers "the CRS never got a usable answer out of its model".
//
// Not a seventh outcome. The pre-decision reserves a new name for a decline the
// six do not cover, and this IS crs-no-patch. Naming it separately would claim
// capture can see something it cannot.
func TestNoPatchDoesNotSayWhy(t *testing.T) {
	for _, d := range runDirs(t) {
		tasks, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, task := range tasks {
			if fi, err := os.Stat(task); err != nil || !fi.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(task, "patches")); err == nil {
				continue
			}
			// A run with no patches directory carries nothing saying why.
			for _, marker := range []string{"error", "reason", "status.json", "log"} {
				if _, err := os.Stat(filepath.Join(task, marker)); err == nil {
					t.Errorf("%s carries %q: the directory DOES record a cause, so "+
						"crs-no-patch could be split and this test is obsolete",
						filepath.Base(task), marker)
				}
			}
		}
	}
	t.Log("no-patch runs carry no cause; the decline covers both " +
		"'searched and found nothing' and 'the model call failed'")
}

// THE EVIDENCE HAS TO MATCH THE ROUTE TAKEN. Capture used to append "paired by
// the CRS's own bundle, not by filename or mtime" unconditionally, after a
// pair() that falls back to one-of-each when no bundle exists. No real run has
// ever carried a bundle, so that line was false on every real capture this
// project has made, in a dossier written to be read by someone deciding whether
// to trust the patch.
//
// A correct verdict with an overstated reason is the defect class this whole
// repository is about, so it gets a test rather than a comment.
func TestPairingEvidenceNamesTheRouteActuallyTaken(t *testing.T) {
	for _, d := range runDirs(t) {
		tasks, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, task := range tasks {
			if fi, err := os.Stat(task); err != nil || !fi.IsDir() {
				continue
			}
			id := filepath.Base(task)
			res, err := Capture(d, id, src(), t.TempDir())
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if res.Outcome != Captured {
				continue
			}
			hasBundle := false
			if ents, err := os.ReadDir(filepath.Join(task, "bundles")); err == nil && len(ents) > 0 {
				hasBundle = true
			}
			var claim string
			for _, e := range res.Evidence {
				if strings.Contains(e, "paired") {
					claim = e
				}
			}
			if claim == "" {
				t.Errorf("%s: capture records no pairing evidence at all", id)
				continue
			}
			if !hasBundle && strings.Contains(claim, "own bundle") {
				t.Errorf("%s: claims %q with no bundle on disk", id, claim)
			}
			if hasBundle && !strings.Contains(claim, "own bundle") {
				t.Errorf("%s: a bundle exists but the evidence says %q", id, claim)
			}
		}
	}
}
