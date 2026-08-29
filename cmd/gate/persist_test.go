// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arazu/pkg/auditlog"
	"arazu/pkg/contentstore"
	"arazu/pkg/gate"
)

func decision(v gate.Verdict, reason string) gate.Decision {
	return gate.Decision{CaseID: "c1", CandidateID: "cand1", Verdict: v, Reason: reason}
}

// The prediction that was falsified by inspection: nothing bound the verdict,
// so a seal could not cover it. This is the check that it now can — the
// decision is measured into the content root like any other bundle file.
func TestTheDecisionIsUnderTheContentRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "patch.diff"), []byte("@@\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, rootBefore, err := contentstore.MeasureBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeDecision(dir, decision(gate.VerdictAccept, ""), nil); err != nil {
		t.Fatal(err)
	}
	after, rootAfter, err := contentstore.MeasureBundle(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(after) != len(before)+1 {
		t.Fatalf("files %d -> %d, want one more", len(before), len(after))
	}
	// The root MUST move. If it does not, the decision is not covered, and a
	// seal taken over rootBefore would verify against a bundle containing a
	// verdict it never bound.
	if rootAfter == rootBefore {
		t.Fatal("the content root did not change, so the decision is not under it")
	}
	var found bool
	for _, f := range after {
		if filepath.Base(f.Path) == "decision.json" {
			found = true
		}
	}
	if !found {
		t.Error("decision.json is not in the measured file list")
	}
}

// The ordering hazard, stated as a test because nothing in the type system
// prevents it. Measuring first and writing after leaves every individual check
// passing and the verdict outside the root.
func TestMeasuringBeforeWritingLeavesTheVerdictUnbound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "patch.diff"), []byte("@@\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The wrong order.
	_, sealedRoot, err := contentstore.MeasureBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeDecision(dir, decision(gate.VerdictAccept, ""), nil); err != nil {
		t.Fatal(err)
	}
	_, actualRoot, err := contentstore.MeasureBundle(dir)
	if err != nil {
		t.Fatal(err)
	}

	if sealedRoot == actualRoot {
		t.Fatal("wrong order produced the same root, so this hazard cannot be detected at all")
	}
	// Documents the failure: a seal over sealedRoot is self-consistent and
	// binds a tree that does not include the verdict.
	t.Logf("sealed %s but the bundle is now %s: the verdict is outside the seal",
		sealedRoot[:12], actualRoot[:12])
}

// A bundle directory that does not exist is refused rather than silently
// skipped. Skipping is how a verdict goes unrecorded while the run reports fine.
func TestAMissingBundleDirectoryIsRefused(t *testing.T) {
	if _, _, err := writeDecision(filepath.Join(t.TempDir(), "nope"), decision(gate.VerdictAccept, ""), nil); err == nil {
		t.Fatal("a missing bundle directory was accepted")
	}
}

// No bundle requested is not an error: every existing caller passes nothing and
// gets stdout, as before.
func TestNoBundleIsNotAnError(t *testing.T) {
	_, p, err := writeDecision("", decision(gate.VerdictAccept, ""), nil)
	if err != nil || p != "" {
		t.Fatalf("writeDecision(\"\") = %q, %v", p, err)
	}
}

// The other falsified prediction: log-verify passed over a log with no gate
// entry. Each verdict now maps to its own event, so the log records which way
// the decision went rather than only that the envelope ran.
func TestEachVerdictLogsItsOwnEvent(t *testing.T) {
	for _, tc := range []struct {
		verdict gate.Verdict
		want    string
	}{
		{gate.VerdictAccept, auditlog.EvGateAccept},
		{gate.VerdictReject, auditlog.EvGateReject},
		{gate.VerdictError, auditlog.EvGateError},
	} {
		t.Run(string(tc.verdict), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.log")
			if err := logDecision(p, decision(tc.verdict, "some-reason")); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), tc.want) {
				t.Errorf("log has no %s entry:\n%s", tc.want, b)
			}
			// The reason travels with it. An entry saying only REJECT sends
			// nobody anywhere.
			if !strings.Contains(string(b), "some-reason") {
				t.Error("the verdict was logged without its reason")
			}
		})
	}
}

// An unwritable log is reported, not swallowed. The gate is the thing whose
// verdict the log exists to record.
func TestAnUnwritableLogIsReported(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "sub", "audit.log") // parent does not exist
	if err := logDecision(bad, decision(gate.VerdictAccept, "")); err == nil {
		t.Fatal("a log that could not be opened was treated as written")
	}
}
