// SPDX-License-Identifier: Apache-2.0

package crsout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real output from gpt-oss:20b against the libpng iCCP defect, 2026-08-19,
// committed under testdata so this is reproducible without a GPU.
//
// The other tests in this package use a hand-written diff, which is clean in
// ways real output is not. The measured failure distribution says why that
// matters: of 21 apply failures, 14 were fabricated context and 7 were bare @@
// headers carrying no ranges. This file is the second kind.
const emitted = "../../testdata/crsout/gpt-oss-20b-libpng.as-emitted.txt"
const extracted = "../../testdata/crsout/gpt-oss-20b-libpng.extracted.patch"

// What the model actually produced: a fenced ```diff block, a bare @@ with no
// ranges, and a paragraph of prose after the fence. Pinned so a future reader
// does not have to take the description on trust.
func TestTheRealResponseHasTheShapeThisTestsFor(t *testing.T) {
	b, err := os.ReadFile(emitted)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"```diff", "\n@@\n", "This change expands"} {
		if !strings.Contains(s, want) {
			t.Errorf("the fixture no longer contains %q, so it is not the input this tests", want)
		}
	}
	if strings.Contains(s, "@@ -") {
		t.Error("the fixture has ranged hunks, so it is not the bare-@@ case")
	}
}

// THE FINDING, and it has since been fixed. looksLikeDiff was
// strings.Contains(body, "@@") and nothing more, so a bare @@ passed it and
// capture accepted a patch that cannot apply, handing a gradable-looking case to
// a gate that then failed at patch-does-not-apply. The verdict was right and it
// arrived one stage late.
//
// This test asserted that behaviour deliberately and said it should flip if the
// check were ever strengthened. It was, on 2026-08-21, so it has flipped: capture
// now requires a hunk header carrying ranges, which is what git apply needs, and
// declines the rest as Malformed.
//
// The name of the check is doing work: STRUCTURAL, not applies. Capture is given
// commits rather than a checkout, so it cannot answer whether a diff applies to
// the tree, and this catches only the header. The dominant real failure is
// context lines that do not exist in the source, which no header check sees.
// This test therefore proves the header case is closed and says nothing about
// the other one.
func TestCaptureDeclinesAPatchWithNoHunkRanges(t *testing.T) {
	patch, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patch), "@@") {
		t.Fatal("fixture has no hunk marker at all")
	}
	// The thing that makes it unusable: no ranges on the hunk header. git apply
	// rejects this with "No valid patches in input".
	if strings.Contains(string(patch), "@@ -") {
		t.Fatal("fixture gained ranges, so it no longer demonstrates the gap")
	}

	runDir, out := run(t)
	put(t, runDir, "t1", "patches", "p1.patch", patch)
	put(t, runDir, "t1", "povs", "v1.bin", []byte("\x89PNG\r\n\x1a\n"))

	res, err := Capture(runDir, "t1", src(), out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Malformed {
		t.Fatalf("outcome = %s (%s); want %s. A bare @@ carries no ranges and git "+
			"apply refuses it, so capture must decline rather than pass it to the gate",
			res.Outcome, res.Detail, Malformed)
	}
	t.Log("capture declined a patch with a bare @@ header, which git apply refuses: " +
		"the header case is caught here now rather than at the gate one stage later")
}

// Re-anchoring changes the bytes, which is the other half of the prediction. If
// it did not, apply_mode would be recording a distinction that does not exist
// on this input.
func TestReAnchoringChangesTheBytes(t *testing.T) {
	reanchored := filepath.Join("..", "..", "testdata", "crsout",
		"gpt-oss-20b-libpng.reanchored.patch")
	a, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(reanchored)
	if err != nil {
		t.Skip("no re-anchored fixture on disk")
	}
	if string(a) == string(b) {
		t.Fatal("fix-hunks was a no-op, so apply_mode records nothing on this input")
	}
	if !strings.Contains(string(b), "@@ -1419,") {
		t.Errorf("re-anchoring did not produce ranges: %q", firstLine(string(b)))
	}
	// Recorded, not asserted as a pass: re-anchoring gave the hunk ranges and
	// the patch STILL does not apply, because the model's context lines do not
	// match the source. Repair fixes the header, not invented context.
	t.Log("re-anchored to @@ -1419,5 +1419,13 @@ and git apply still refuses: " +
		"range repair does not rescue fabricated context")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
