// SPDX-License-Identifier: Apache-2.0

// Package crsout captures a CRS run's output as a corpus case.
//
// This is Buttercup M2, the output-contract capture: it turns what a real run
// leaves on disk into (target ref, PoV, candidate patch) that the existing
// corpus machinery can grade. Building it as a case emitter rather than a
// bespoke path is the point — the gate, the graders and eval M0 already know
// how to read a case, and a second format would be a second thing to keep true.
//
// THE OUTPUT CONTRACT, read from the CRS rather than assumed:
//
//	<run>/<task_id>/patches/<patch_id>.patch    unified diff, plain text
//	<run>/<task_id>/povs/<pov_id>.bin           the reproducer, raw bytes
//	<run>/<task_id>/sarifs/<sarif_id>.sarif     JSON
//	<run>/<task_id>/bundles/<bundle_id>.json    {task_id, pov_id, patch_id, ...}
//
// The bundle is what ties a PoV to the patch that claims to fix it. Pairing by
// filename or by mtime would agree with the bundle most of the time, which is
// the worst property a join can have.
//
// WHY "NO PATCH" IS A VERDICT AND NOT AN ABSENCE. buttercup-task.sh ends by
// printing a suggestion to a human, so today a run that produces nothing simply
// produces nothing. Automating that turns it silent: the chain proceeds against
// an empty directory and the gate is never reached, which is indistinguishable
// downstream from a clean run. Every way this can decline to produce a case is
// named, and the caller is expected to record it.
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

// Outcome names what a capture attempt established. It is deliberately not a
// bool: "the CRS produced nothing" and "the CRS produced something unusable"
// send an operator to different places.
type Outcome string

const (
	// Captured means a case was written.
	Captured Outcome = "captured"
	// NoRun means the task directory does not exist. The CRS was never asked,
	// or was asked and the submission failed.
	NoRun Outcome = "crs-no-run"
	// NoPatch means the run exists and produced no patch. A real result about
	// the CRS, not an error, and the commonest way an unattended chain would
	// otherwise proceed against nothing.
	NoPatch Outcome = "crs-no-patch"
	// NoPoV means a patch exists with no reproducer, so nothing can attribute
	// it. Ungradable by every stage that runs a PoV.
	NoPoV Outcome = "crs-no-pov"
	// Unpairable means patches and PoVs exist but no bundle ties them, so which
	// patch claims to fix which crash is unknown.
	Unpairable Outcome = "crs-unpairable"
	// Malformed means an artifact is present and unreadable: an empty patch, a
	// diff with no hunks, a bundle that does not parse.
	Malformed Outcome = "crs-malformed-artifact"
	// NoSanitizerReport means the run gave no sanitizer string to compare
	// against. Written out empty it would make SanitizerFired
	// strings.Contains(report, ""), true of everything, and the case would
	// grade every candidate correct. Refused instead.
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
// directory records what was produced, not what it was produced against, so the
// pins come from the task that was submitted.
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
	// CrashLocation is what M3 compares against. Absent is tolerable — MatchSite
	// returns undetermined — but it costs the site comparison.
	CrashLocation string
}

// Capture reads one task's output and writes a corpus case for it.
//
// outDir receives the case file and copies of the artifacts, so the case is
// self-contained and survives the CRS scratch being cleaned.
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

	// Ordered so the operator is sent to the right place. No patch is a
	// statement about the CRS; no PoV with a patch present is a statement about
	// what can be graded.
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

// pair uses the CRS's bundle. With exactly one of each and no bundle the
// pairing is unambiguous and allowed; with several it is a guess, and a guess
// that is usually right is worse than a refusal.
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
		// Unambiguous, but say which route was taken. Claiming the bundle here
		// would overstate the provenance, and no real run has ever carried one:
		// zero bundles across five captures.
		return patches[0], povs[0], "paired as the only patch and the only pov; the run carried no bundle", nil
	}
	return "", "", "", fmt.Errorf(
		"no bundle ties a patch to a pov, and there are %d patches and %d povs, so which "+
			"claims to fix which is unknown", len(patches), len(povs))
}

// looksLikeDiff decides whether a body is a unified diff a patch tool could
// consume. It is a STRUCTURAL check and deliberately not an applies check:
// Capture is given commits rather than a checkout, so "does this apply to the
// tree" cannot be answered here without cloning one, and pretending otherwise
// would put a network fetch inside a function that reads a directory.
//
// What changed and why. This was strings.Contains(b, "@@"), which a bare "@@"
// passes while git apply refuses it with "No valid patches in input", so capture
// accepted patches that could not apply and handed a gradable-looking case to
// the gate. The verdict was still right and it arrived one stage late, blaming
// the candidate at patch-does-not-apply for something capture could have named.
//
// The bound is worth stating because the yield data measured it: of 21 candidate
// diffs the gate refused at apply, most failed on context lines that do not
// exist in the source, which is fabrication and needs the tree to detect. This
// catches the header, not the body. It moves one failure class earlier; it does
// not make capture an oracle for applicability.
//
// No new outcome. A structurally broken diff is Malformed, which already means
// exactly this, and inventing a seventh decline would claim capture can tell
// something apart that it cannot.
func looksLikeDiff(b []byte) bool {
	return hunkHeader.Match(b)
}

// @@ -old[,count] +new[,count] @@ — the ranges are the part that matters, since
// their absence is what git apply rejects.
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

	// expected_gate_reason is deliberately absent. A captured case has no
	// answer key: whether the candidate is a fix is what the gate is being
	// asked, and writing a guess here would make eval M0 grade the capture
	// rather than the patch.
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
