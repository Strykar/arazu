// SPDX-License-Identifier: Apache-2.0

package classreplay

import (
	"context"
	"testing"

	"arazu/pkg/corpus"
)

// A constant in the target measures every case against the size of the one it
// was written for.
func TestGenerateTakesTheClassSizeFromTheCase(t *testing.T) {
	tgt := &OSSFuzzTarget{
		RepoRoot: "../..",
		WorkDir:  t.TempDir(),
		Members:  2,
	}
	fc := corpus.FalsifyingClass{
		Generator: "corpus/falsifying-class/libpng-iccp/mkpng.py",
		Size:      3,
	}
	members, declared, err := tgt.Generate(context.Background(), fc)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("generated %d members, want the 2 the bound asked for", len(members))
	}
	if declared != 3 {
		t.Errorf("declared = %d, want 3 from the case; a constant here measures every "+
			"case against the size of the one it was written for", declared)
	}
}

// A class that declares no size cannot say whether a run covered it, and
// defaulting would invent the number the truncation guard depends on.
func TestAClassWithNoDeclaredSizeIsRefused(t *testing.T) {
	tgt := &OSSFuzzTarget{RepoRoot: "../..", WorkDir: t.TempDir(), Members: 1}
	fc := corpus.FalsifyingClass{Generator: "corpus/falsifying-class/libpng-iccp/mkpng.py"}
	if _, _, err := tgt.Generate(context.Background(), fc); err == nil {
		t.Fatal("a class with no declared size was given one")
	}
}
