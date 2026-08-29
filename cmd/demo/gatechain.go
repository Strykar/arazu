// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"arazu/pkg/contentstore"
)

// gateInTheChain runs the falsification gate INSIDE the envelope rather than
// beside it.
//
// Every other branch exercises the envelope and assumes a verdict. Until this
// existed, the gate stages and the sealing path had never run in one process
// tree, which hid two things: the gate wrote its verdict only to stdout, so
// nothing bound it, and it never appended to the log, so a run produced a hash
// chain that verifies clean over a record with no verdict in it.
//
// WHICH ARTIFACT THE VERDICT BELONGS TO. The first version wrote decision.json
// into the INGRESS bundle and was refused with REJECT:unmanifested-file. Rightly:
// that bundle is what the maintainer signed, and the gate holds no key to
// re-sign it. The verdict belongs to the DOSSIER, which is what Arazu emits
// rather than what it was given.
//
// ORDER IS STILL THE POINT, one artifact along: the decision must be in the
// dossier before the dossier is measured, or the seal binds a tree with no
// verdict while every step passes.
func gateInTheChain(h *harness) (string, error) {
	log := h.path("gatechain", "audit.jsonl")
	state := h.path("gatechain", "state")
	seal := h.path("gatechain", "seal")
	// What gets signed here is the VERDICT, not a produced artifact. The happy
	// path signs what the contained run emitted; this branch is about the
	// decision, so the decision is the thing bound to measured state.
	sig := h.path("gatechain", "decision.sig")
	dossier := h.path("gatechain", "dossier")
	if err := os.MkdirAll(dossier, 0o700); err != nil {
		return "", err
	}

	// 1. The input bundle is verified as given. Untouched: it is the
	//    maintainer's signed artifact and nothing here may add to it.
	in, code, err := h.runTool("ingress-verify",
		"-bundle", h.bundle("good"), "-trusted", filepath.Join(h.repo, "testdata/keys/trusted.pub"),
		"-state", state, "-log", log, "-allow", "content/")
	if err != nil {
		return "", err
	}
	if str(in, "decision") != "ACCEPT" || code != 0 {
		return fmt.Sprintf("ingress said %s:%s", str(in, "decision"), str(in, "reason")), nil
	}

	// 2. The gate reaches a verdict and records it in the dossier.
	caseFile := filepath.Join(h.repo, "corpus/cases/libpng/iccp-keyword.yaml")
	gd, code, err := h.runTool("gate",
		"-case", caseFile, "-candidate", "libpng-iccp-buttercup-run1",
		"-repo", h.repo, "-root", h.repo,
		"-bundle", dossier, "-log", log)
	if err != nil {
		return "", err
	}
	verdict := str(gd, "verdict")
	if verdict == "" {
		return "the gate produced no verdict", nil
	}

	// The verdict must exist as an artifact, not only as a line on stdout.
	decision := filepath.Join(dossier, "decision.json")
	if _, err := os.Stat(decision); err != nil {
		return "the gate reached " + verdict + " and wrote no decision.json", nil
	}

	// Sabotage: remove the decision after the gate wrote it and before the
	// dossier is measured. The seal then binds a tree with no verdict in it and
	// every downstream step still succeeds, which is the failure this branch
	// exists to make visible.
	if h.broken == "gate-in-chain" {
		if err := os.Remove(decision); err != nil {
			return "", err
		}
	}

	// 3. Measure the dossier. The verdict is inside it, so the content root
	//    covers it without the manifest format knowing anything about gates.
	root, covered, err := measureDossier(dossier)
	if err != nil {
		return "", err
	}
	if !covered {
		return "the measured root does not cover decision.json", nil
	}

	if _, code, err = h.runTool("seal-tool", "provision",
		"-dir", seal, "-content-root", root, "-log", log); err != nil {
		return "", err
	}
	if code != 0 {
		return "seal provisioning failed", nil
	}

	sd, code, err := h.runTool("seal-tool", "sign",
		"-dir", seal, "-content-root", root,
		"-artifact", decision, "-sig", sig, "-log", log)
	if err != nil {
		return "", err
	}
	if str(sd, "decision") != "SIGNED" || code != 0 {
		return fmt.Sprintf("signing said %s:%s", str(sd, "decision"), str(sd, "reason")), nil
	}

	// 4. The log must record that a verdict was reached, not only that the
	//    envelope ran. A chain that verifies over an incomplete record is the
	//    failure this branch was written after finding.
	if ok, err := logHasGateEntry(log); err != nil {
		return "", err
	} else if !ok {
		return "log verifies but contains no GATE_ entry", nil
	}

	v, code, err := h.runTool("log-verify", "-log", log)
	if err != nil {
		return "", err
	}
	if str(v, "decision") != "CLEAN" || code != 0 {
		return "log " + str(v, "decision"), nil
	}

	return fmt.Sprintf("%s recorded, decision under the sealed root, SIGNED, log CLEAN", verdict), nil
}

// measureDossier computes the content root over the dossier and reports
// whether decision.json was among the files measured.
//
// Recomputed rather than assumed. If the decision is absent the root is still a
// perfectly valid digest of a tree with no verdict in it, and everything
// downstream signs it happily.
func measureDossier(dir string) (string, bool, error) {
	files, root, err := contentstore.MeasureBundle(dir)
	if err != nil {
		return "", false, err
	}
	for _, f := range files {
		if filepath.Base(f.Path) == "decision.json" {
			return root, true, nil
		}
	}
	return root, false, nil
}

func logHasGateEntry(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return strings.Contains(string(b), "GATE_"), nil
}
