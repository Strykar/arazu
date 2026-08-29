// SPDX-License-Identifier: Apache-2.0

package dossier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"arazu/pkg/contentstore"
	"arazu/pkg/gate"
)

// good builds a real self-contained dossier, so every test below breaks exactly
// one thing and the outcome names that thing.
func good(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	patch := filepath.Join(src, "cand.patch")
	if err := os.WriteFile(patch, []byte("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	d := gate.Decision{
		CaseID: "c", CandidateID: "x", Verdict: gate.VerdictAccept,
		Stages:    []gate.StageResult{{Stage: "s", Outcome: gate.OutcomePassed, Evidence: []string{"e"}}},
		NotProven: []string{"n"},
	}
	if _, err := Emit(dir, d, map[string]string{"candidate-patch": patch}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func verdict(t *testing.T, dir, root string) Report {
	t.Helper()
	r, err := Verify(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The matched twin for everything below: an honest dossier must pass, or the
// negatives are just a verifier that rejects everything.
func TestAnHonestDossierVerifies(t *testing.T) {
	r := verdict(t, good(t), "")
	if r.Outcome != Verified {
		t.Fatalf("outcome %s, problems %v", r.Outcome, r.Problems)
	}
}

// THE FINDING THE VERIFIER EXISTS FOR. Replace an artifact after the fact and
// the decision still describes the bytes that were there when it was written.
// Nothing inside the JSON can notice; only rehashing can.
func TestAnAlteredArtifactIsAnUnsupportedClaim(t *testing.T) {
	dir := good(t)
	p := filepath.Join(dir, ArtifactsDir, "candidate-patch.patch")
	if err := os.WriteFile(p, []byte("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+SOMETHING ELSE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := verdict(t, dir, "")
	if r.Outcome != UnsupportedClaim {
		t.Fatalf("outcome %s, want %s: the dossier describes bytes it no longer carries", r.Outcome, UnsupportedClaim)
	}
}

// A decision naming a file the dossier does not carry is the same defect with
// the artifact removed rather than changed.
func TestAMissingArtifactIsAnUnsupportedClaim(t *testing.T) {
	dir := good(t)
	if err := os.Remove(filepath.Join(dir, ArtifactsDir, "candidate-patch.patch")); err != nil {
		t.Fatal(err)
	}
	if r := verdict(t, dir, ""); r.Outcome != UnsupportedClaim {
		t.Fatalf("outcome %s, want %s", r.Outcome, UnsupportedClaim)
	}
}

// An absolute path is the original defect: evidence that resolved for the
// process that wrote it and for nobody else. It must be refused even when the
// file happens to exist on this machine.
func TestAnAbsolutePathIsRefusedEvenIfItResolves(t *testing.T) {
	dir := good(t)
	real := filepath.Join(dir, ArtifactsDir, "candidate-patch.patch")
	var d gate.Decision
	b, err := os.ReadFile(filepath.Join(dir, DecisionFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	d.Artifacts[0].Path = real // absolute, and present
	nb, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, DecisionFile), append(nb, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := verdict(t, dir, ""); r.Outcome != UnsupportedClaim {
		t.Fatalf("outcome %s, want %s: an absolute path names a file the dossier does not carry, "+
			"even when it resolves here", r.Outcome, UnsupportedClaim)
	}
}

// PRE-CONTRACT, NOT DISHONEST. Every dossier written before this package has no
// artifact list. Reporting those as unsupported claims would read history as
// fraud, so they get their own outcome.
func TestADossierWithNoArtifactsIsRefusedNotFailed(t *testing.T) {
	dir := t.TempDir()
	d := gate.Decision{CaseID: "c", CandidateID: "x", Verdict: gate.VerdictAccept,
		Stages:    []gate.StageResult{{Stage: "s", Outcome: gate.OutcomePassed, Evidence: []string{"e"}}},
		NotProven: []string{"n"}}
	b, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, DecisionFile), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	r := verdict(t, dir, "")
	if r.Outcome != NotSelfContained {
		t.Fatalf("outcome %s, want %s", r.Outcome, NotSelfContained)
	}
	if r.Outcome == UnsupportedClaim {
		t.Fatal("a pre-contract dossier was reported as one that lies")
	}
}

// The seal check. The root cannot live in the dossier, so the caller supplies
// it; a dossier that has moved on since sealing must not pass.
func TestARootThatNoLongerMatchesTheSealFails(t *testing.T) {
	dir := good(t)
	_, root, err := contentstore.MeasureBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := verdict(t, dir, root); r.Outcome != Verified {
		t.Fatalf("the real root was rejected: %v", r.Problems)
	}
	if err := os.WriteFile(filepath.Join(dir, ArtifactsDir, "extra.txt"), []byte("added later"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := verdict(t, dir, root); r.Outcome != UnsupportedClaim {
		t.Fatalf("outcome %s, want %s: the directory changed after the seal was taken", r.Outcome, UnsupportedClaim)
	}
}

// A verdict is about the patch; an outcome is about the record. An honest
// dossier describing a REJECT must verify, or the two are conflated and a
// failed audit reads as a failed patch.
func TestAnHonestRejectionVerifies(t *testing.T) {
	src := t.TempDir()
	patch := filepath.Join(src, "cand.patch")
	os.WriteFile(patch, []byte("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"), 0o644)
	dir := t.TempDir()
	d := gate.Decision{CaseID: "c", CandidateID: "x", Verdict: gate.VerdictReject, Reason: "r",
		Stages:    []gate.StageResult{{Stage: "s", Outcome: gate.OutcomeFailed, Reason: "r", Evidence: []string{"e"}}},
		NotProven: []string{"n"}}
	if _, err := Emit(dir, d, map[string]string{"candidate-patch": patch}); err != nil {
		t.Fatal(err)
	}
	if r := verdict(t, dir, ""); r.Outcome != Verified {
		t.Fatalf("an honest dossier about a rejected patch failed verification: %v", r.Problems)
	}
}
