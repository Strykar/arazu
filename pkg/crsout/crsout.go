// SPDX-License-Identifier: Apache-2.0

// Package crsout captures a CRS run's output as a corpus case, in the shape
// the gate, the graders and eval M0 already read. A second format would be a
// second thing to keep true.
//
// The output contract, read from the CRS rather than assumed:
//
//	<run>/<task_id>/patches/<patch_id>.patch    unified diff, plain text
//	<run>/<task_id>/povs/<pov_id>.bin           the reproducer, raw bytes
//	<run>/<task_id>/sarifs/<sarif_id>.sarif     JSON
//	<run>/<task_id>/bundles/<bundle_id>.json    {task_id, pov_id, patch_id, ...}
//
// The bundle ties a PoV to the patch that claims to fix it; pairing by filename
// or mtime would agree with it most of the time, the worst property a join can
// have. Every decline is named and returned: a chain that proceeds against an
// empty directory never reaches the gate and looks downstream like a clean run.
package crsout

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Outcome names what a capture attempt established. Not a bool: "produced
// nothing" and "produced something unusable" go to different places.
type Outcome string

const (
	// Captured means a case was written.
	Captured Outcome = "captured"
	// NoRun means no task directory: the CRS was never asked, or submission failed.
	NoRun Outcome = "crs-no-run"
	// NoPatch means the run exists and produced no patch. A result, not an error.
	NoPatch Outcome = "crs-no-patch"
	// NoPoV means a patch exists with no reproducer, so nothing can attribute it.
	NoPoV Outcome = "crs-no-pov"
	// Unpairable means patches and PoVs exist but no bundle ties them.
	Unpairable Outcome = "crs-unpairable"
	// Malformed means an artifact is present and unreadable: an empty patch, a
	// diff with no hunks, a bundle that does not parse.
	Malformed Outcome = "crs-malformed-artifact"
	// NoSanitizerReport means no sanitizer string to compare against. Written
	// out empty it matches every output, grading every candidate correct.
	NoSanitizerReport Outcome = "crs-no-sanitizer-report"
)

// Result is what one capture attempt established.
type Result struct {
	Outcome  Outcome  `json:"outcome"`
	TaskID   string   `json:"task_id"`
	CasePath string   `json:"case_path,omitempty"`
	PatchID  string   `json:"patch_id,omitempty"`
	PoVID    string   `json:"pov_id,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence"`
}

// Bundle is the CRS's own join between a reproducer and the patch for it.
type Bundle struct {
	BundleID string `json:"bundle_id"`
	TaskID   string `json:"task_id"`
	PoVID    string `json:"pov_id"`
	PatchID  string `json:"patch_id"`
}

// Source is what the case needs that the CRS output does not carry. A run
// directory records what was produced, not what it was produced against.
type Source struct {
	Repo       string
	BaseCommit string
	HeadCommit string
	Project    string
	Harness    string
	Sanitizer  string // which sanitizer built the harness: address, undefined

	// ExpectedSanitizer is the literal report line the PoV produces, from the
	// CRS's own trace. Not optional: see NoSanitizerReport.
	ExpectedSanitizer string
	// CrashLocation is what M3 compares against. Absent, MatchSite is undetermined.
	CrashLocation string
}

// Capture reads one task's output and writes a corpus case for it. outDir gets
// copies of the artifacts, so the case survives the CRS scratch being cleaned.
func Capture(runDir, taskID string, src Source, outDir string) (Result, error) {
	res := Result{TaskID: taskID}
	task := filepath.Join(runDir, taskID)

	if fi, err := os.Stat(task); err != nil || !fi.IsDir() {
		res.Outcome = NoRun
		res.Detail = fmt.Sprintf("no task directory at %s", task)
		res.Evidence = []string{res.Detail}
		return res, nil
	}

	patches, err := artifacts(task, "patches", ".patch")
	if err != nil {
		return res, err
	}
	povs, err := artifacts(task, "povs", ".bin")
	if err != nil {
		return res, err
	}
	res.Evidence = append(res.Evidence,
		fmt.Sprintf("%d patch(es), %d pov(s) under %s", len(patches), len(povs), task))

	// Ordered so the operator is sent to the right place: no patch is about
	// the CRS, no PoV with a patch present is about what can be graded.
	if len(patches) == 0 {
		res.Outcome = NoPatch
		res.Detail = "the run produced no patch, so there is nothing to grade"
		return res, nil
	}
	if len(povs) == 0 {
		res.Outcome = NoPoV
		res.Detail = "a patch exists with no reproducer, so no stage that runs a PoV can attribute it"
		return res, nil
	}

	if strings.TrimSpace(src.ExpectedSanitizer) == "" {
		res.Outcome = NoSanitizerReport
		res.Detail = "no sanitizer report for this run, so every candidate would grade clean"
		return res, nil
	}

	patchID, povID, how, err := pair(task, patches, povs)
	if err != nil {
		res.Outcome = Unpairable
		res.Detail = err.Error()
		return res, nil
	}
	res.PatchID, res.PoVID = patchID, povID
	res.Evidence = append(res.Evidence, how)

	patchPath := filepath.Join(task, "patches", patchID+".patch")
	b, err := os.ReadFile(patchPath)
	if err != nil {
		return res, err
	}
	if !looksLikeDiff(b) {
		res.Outcome = Malformed
		res.Detail = fmt.Sprintf("%s has no unified-diff hunk header with ranges", patchPath)
		return res, nil
	}

	povPath := filepath.Join(task, "povs", povID+".bin")
	pb, err := os.ReadFile(povPath)
	if err != nil {
		return res, err
	}
	if len(pb) == 0 {
		res.Outcome = Malformed
		res.Detail = fmt.Sprintf("%s is empty, so it reproduces nothing", povPath)
		return res, nil
	}

	casePath, err := write(outDir, taskID, src, b, pb)
	if err != nil {
		return res, err
	}
	res.Outcome = Captured
	res.CasePath = casePath
	res.Evidence = append(res.Evidence, "case written to "+casePath)
	return res, nil
}

func artifacts(task, kind, ext string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(task, kind))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ext) {
			out = append(out, strings.TrimSuffix(e.Name(), ext))
		}
	}
	sort.Strings(out)
	return out, nil
}

// pair uses the CRS's bundle. One patch and one PoV needs none; with several,
// a guess that is usually right is worse than a refusal.
func pair(task string, patches, povs []string) (string, string, string, error) {
	bundles, err := artifacts(task, "bundles", ".json")
	if err != nil {
		return "", "", "", err
	}
	for _, id := range bundles {
		b, err := os.ReadFile(filepath.Join(task, "bundles", id+".json"))
		if err != nil {
			continue
		}
		var bu Bundle
		if json.Unmarshal(b, &bu) != nil {
			continue
		}
		if bu.PatchID != "" && bu.PoVID != "" {
			return bu.PatchID, bu.PoVID, "paired by the CRS's own bundle", nil
		}
	}
	if len(patches) == 1 && len(povs) == 1 {
		// Say which route was taken; claiming the bundle overstates provenance.
		return patches[0], povs[0], "paired as the only patch and the only pov; the run carried no bundle", nil
	}
	return "", "", "", fmt.Errorf(
		"no bundle ties a patch to a pov, and there are %d patches and %d povs, so which "+
			"claims to fix which is unknown", len(patches), len(povs))
}

// looksLikeDiff is structural, not an applies check: Capture is given commits
// rather than a checkout, so "does this apply" would mean cloning a tree inside
// a function that reads a directory. Requiring the hunk ranges rejects a bare
// "@@" that git apply refuses; diffs with fabricated context lines need the
// tree and still reach the gate. A structurally broken diff is Malformed.
func looksLikeDiff(b []byte) bool {
	return hunkHeader.Match(b)
}

// @@ -old[,count] +new[,count] @@. The ranges are what git apply needs.
var hunkHeader = regexp.MustCompile(`(?m)^@@ -\d+(,\d+)? \+\d+(,\d+)? @@`)

func write(outDir, taskID string, src Source, patch, pov []byte) (string, error) {
	dir := filepath.Join(outDir, taskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	patchRel := filepath.Join(dir, "candidate.patch")
	povRel := filepath.Join(dir, "pov.bin")
	if err := os.WriteFile(patchRel, patch, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(povRel, pov, 0o644); err != nil {
		return "", err
	}

	// expected_gate_reason is deliberately absent. Whether the candidate is a
	// fix is what the gate is being asked; a guess would grade the capture.
	c := fmt.Sprintf(`# Captured from a CRS run by pkg/crsout. Not hand-authored.
#
# kind: captured means this is a question, not an oracle. It carries no
# reference_patch, because a novel target has no known-good fix, and no
# expected_gate_reason, because whether the candidate is a fix is what the gate
# is being asked. Presuming either would grade the capture instead of the patch.
kind: captured
id: crs-%s
language: c
root: repo
target: %s
harness: %s

source:
  cp_repo: %s
  cp_commit: %s
  src_repo: %s
  src_ref: %s
  src_commit: %s
  base_commit: %s
  fuzz_tooling_project: %s

pov:
  input: %s
  sanitizer: %s
  expected_sanitizer: %q
  crash_location: %q
  signal: stderr

candidates:
  - id: crs-%s-candidate
    patch: %s
    label: unclassified
`, taskID, src.Project, src.Harness,
		src.Repo, src.HeadCommit, src.Repo, src.HeadCommit, src.HeadCommit,
		src.BaseCommit, src.Project,
		povRel, src.Sanitizer, src.ExpectedSanitizer, src.CrashLocation, taskID, patchRel)

	casePath := filepath.Join(dir, "case.yaml")
	return casePath, os.WriteFile(casePath, []byte(c), 0o644)
}
