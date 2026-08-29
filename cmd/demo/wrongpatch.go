// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"arazu/pkg/contentstore"
)

// corpusRoot is where stage-corpus.sh clones the checkouts this branch builds
// from. Overridable for a machine that staged elsewhere.
func corpusRoot() string {
	if v := os.Getenv("ARAZU_CORPUS"); v != "" {
		return v
	}
	return "/var/lib/arazu-corpus"
}

// wrongPatchRefused is the demonstration the deck promises: a wrong patch,
// refused, with the reason logged, on a fixed target and with no dependence on
// finding a novel bug live.
//
// WHY THIS CANDIDATE AND NOT A CHEAPER ONE. Any gate rejects an obviously bad
// patch, and demonstrating that proves nothing anyone doubted. run 2 is the
// only artifact here that passes every OTHER acceptance signal: the PoV stops
// reproducing, the build is sanitizer-clean, the suite and 29 variants are
// green, and the CRS's own quality check reported all PoVs fixed. It is wrong
// anyway. Every stage but one would accept it, which is the whole argument in a
// single run, and it is why the branch is worth three minutes.
//
// It builds libpng from source twice and replays 79 generated inputs through
// both, so it needs the staged corpus. That precondition is checked FIRST and
// named, rather than surfacing three minutes in as a container store error.
func wrongPatchRefused(h *harness) (string, error) {
	if why := corpusMissing(); why != "" {
		return "precondition not met: " + why, nil
	}

	log := h.path("wrongpatch", "audit.jsonl")
	dossier := h.path("wrongpatch", "dossier")
	seal := h.path("wrongpatch", "seal")
	work := h.path("wrongpatch", "class")
	for _, d := range []string{dossier, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
	}

	caseFile := filepath.Join(h.repo, "corpus/cases/libpng/iccp-keyword.yaml")
	gd, _, err := h.runTool("gate",
		"-case", caseFile, "-candidate", "libpng-iccp-buttercup-run2",
		"-stage", "m2", "-corpus", corpusRoot(), "-work", work,
		"-repo", h.repo, "-root", h.repo,
		"-bundle", dossier, "-log", log)
	if err != nil {
		return "", err
	}

	verdict, reason := str(gd, "verdict"), str(gd, "reason")
	if verdict != "REJECT" {
		// An ACCEPT here is the failure this branch exists to make visible.
		return fmt.Sprintf("the gate said %s:%s on the known-incomplete fix", verdict, reason), nil
	}

	// The reason has to be the class-replay one. A REJECT for any other reason
	// would be the right verdict reached by the wrong stage, which is the
	// defect class this whole corpus is about.
	if reason != "class-replay-fail" {
		return "refused, but as " + reason + " rather than class-replay-fail", nil
	}

	decision := filepath.Join(dossier, "decision.json")
	if _, err := os.Stat(decision); err != nil {
		return "refused with no decision.json, so the verdict is not an artifact", nil
	}
	// Sabotage: drop the refusal from the record after the gate wrote it. A
	// branch that cannot be made to fail demonstrates nothing, and the half
	// worth breaking is "with the reason logged" -- a refusal nobody can audit
	// is the failure mode, not a wrong verdict.
	if h.broken == "wrong-patch-refused" {
		if err := os.Remove(decision); err != nil {
			return "", err
		}
	}

	root, covered, err := measureDossier(dossier)
	if err != nil {
		return "", err
	}
	if !covered {
		return "the measured root does not cover decision.json", nil
	}

	if _, code, err := h.runTool("seal-tool", "provision",
		"-dir", seal, "-content-root", root, "-log", log); err != nil || code != 0 {
		return "seal provisioning failed", err
	}
	sd, code, err := h.runTool("seal-tool", "sign",
		"-dir", seal, "-content-root", root,
		"-artifact", decision, "-sig", filepath.Join(dossier, "decision.sig"), "-log", log)
	if err != nil {
		return "", err
	}
	if str(sd, "decision") != "SIGNED" || code != 0 {
		return "signing the refusal said " + str(sd, "decision"), nil
	}

	// The refusal must be IN THE RECORD, not only on stdout. "with the reason
	// logged" is half the promise.
	b, err := os.ReadFile(log)
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(b), "GATE_REJECT") {
		return "log carries no GATE_REJECT, so the refusal left no record", nil
	}
	v, code, err := h.runTool("log-verify", "-log", log)
	if err != nil {
		return "", err
	}
	if str(v, "decision") != "CLEAN" || code != 0 {
		return "log " + str(v, "decision"), nil
	}

	return "REJECT:class-replay-fail, refusal under the sealed root, logged, chain CLEAN", nil
}

// corpusMissing names the first missing precondition, or "". Checked before any
// work: a three-minute build that dies on a container store error sends an
// operator to debug the wrong thing.
func corpusMissing() string {
	root := corpusRoot()
	for _, p := range []string{
		filepath.Join(root, "libpng", "example-libpng"),
		filepath.Join(root, "libpng", "oss-fuzz"),
	} {
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			return p + " is not a checkout; run scripts/stage-corpus.sh"
		}
	}
	obs := "corpus/falsifying-class/libpng-iccp/observe.sh"
	if fi, err := os.Stat(obs); err != nil || fi.Mode()&0o111 == 0 {
		return obs + " is missing or not executable"
	}
	return ""
}

var _ = contentstore.MeasureBundle
