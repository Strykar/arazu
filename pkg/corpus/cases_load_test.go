// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"path/filepath"
	"testing"
)

// Every real case file must survive Load.
//
// Load has always been strict — KnownFields(true), "an unrecognised field is a
// case we are misreading" — but nothing exercised it against the corpus itself.
// The unit tests build Cases in memory or read testdata fixtures, so a case file
// could carry a key the struct does not have and the suite stayed green: the
// protection existed and was never reached.
//
// That is not hypothetical. A pass at corpus/cases/libpng/iccp-keyword.yaml
// renamed source.cp_repo to source.repo, and a second edit added pov.sanitizer
// before the field existed on PoV. Both were caught by hand-checking the struct.
// This test is what should have caught them, and it costs one Load per case.
func TestEveryCaseFileLoads(t *testing.T) {
	files, err := filepath.Glob("../../corpus/cases/*/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no case files found: this test would pass vacuously")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			if _, err := Load(f); err != nil {
				t.Errorf("%s", err)
			}
		})
	}
	t.Logf("loaded %d case files", len(files))
}
