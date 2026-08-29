// SPDX-License-Identifier: Apache-2.0

package dossier

import (
	"os"
	"path/filepath"
	"testing"

	"arazu/pkg/gate"
)

// A dossier is built or it is not. Half a dossier on disk is a directory that
// looks like evidence and is not, so a failed Emit must leave the bundle as it
// found it.
func TestAFailedEmitLeavesNoPartialDossier(t *testing.T) {
	src := t.TempDir()
	ok := filepath.Join(src, "cand.patch")
	if err := os.WriteFile(ok, []byte("patch bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	d := gate.Decision{CaseID: "c", CandidateID: "x", Verdict: gate.VerdictAccept,
		NotProven: []string{"nothing else"}}
	_, err := Emit(dir, d, map[string]string{
		"candidate-patch": ok,
		"pov":             filepath.Join(src, "absent.bin"),
	})
	if err == nil {
		t.Fatal("emit succeeded with a source that does not exist")
	}

	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		t.Errorf("failed emit left %q behind", e.Name())
	}
}
