// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arazu/pkg/corpus"
)

// The AIxCC layout: cp_sources keys are the directories under ./src, and the
// image is pulled rather than built.
const cpProject = `---
cp_name: nginx
language: c
cp_sources:
    nginx:
        address: https://github.com/aixcc-public/challenge-004-nginx-source.git
        ref: hg-asc-v2.0.0
docker_image: ghcr.io/aixcc-public/challenge-004-nginx-cp
`

// Upstream's own oss-fuzz metadata. No docker_image, because oss-fuzz builds
// the image from separate tooling.
const ossFuzzProject = `homepage: "http://www.libpng.org/pub/png/libpng.html"
language: c++
sanitizers:
  - address
`

func writeProject(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(d, "project.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestClassifyDerivesTheChallengeProjectLayout(t *testing.T) {
	root := writeProject(t, cpProject)
	c := corpus.Case{ID: "nginx-x"}

	s, src, img := classify(root, c)
	if s != shapeChallengeProject {
		t.Fatalf("shape = %v, want challenge project", s)
	}
	// Derived from the cp_sources key, not from the target's name appearing
	// anywhere in this package.
	if want := filepath.Join("src", "nginx"); src != want {
		t.Errorf("src = %q, want %q", src, want)
	}
	if img != "ghcr.io/aixcc-public/challenge-004-nginx-cp" {
		t.Errorf("image = %q", img)
	}
}

func TestClassifyDerivesTheOSSFuzzLayout(t *testing.T) {
	root := writeProject(t, ossFuzzProject)
	c := corpus.Case{ID: "libpng-x"}
	c.Source.FuzzToolingProject = "libpng"

	s, src, img := classify(root, c)
	if s != shapeOSSFuzz {
		t.Fatalf("shape = %v, want oss-fuzz", s)
	}
	if src != "." {
		t.Errorf("src = %q, want the checkout root", src)
	}
	if img != "gcr.io/oss-fuzz/libpng" {
		t.Errorf("image = %q", img)
	}
}

// The input class that would falsify "it refuses rather than guesses": a
// project.yaml matching neither packaging, and a case naming no tooling.
// Without this the adapter could default to one layout and grade the wrong
// tree while reporting complete.
func TestUnrecognisedShapeIsRefusedByName(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"no project.yaml at all", ""},
		{"metadata with neither cp_sources nor tooling", ossFuzzProject},
		{"cp_sources but no docker_image", "cp_sources:\n    thing:\n        address: x\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProject(t, tc.body)
			c := corpus.Case{ID: "unknown-x"}
			c.Source.SrcCommit = "deadbeef"

			if s, _, _ := classify(root, c); s != shapeUnknown {
				t.Fatalf("shape = %v, want unknown", s)
			}
			_, err := resolveTarget(c, root, t.TempDir())
			if err == nil {
				t.Fatal("resolveTarget accepted an unrecognised shape")
			}
			if !strings.Contains(err.Error(), "target-shape-unrecognised") {
				t.Errorf("refusal is not named: %v", err)
			}
		})
	}
}

// A case with no pin has no tree to reset to, so the stage cannot mean
// anything. Refuse before touching a container.
func TestMissingPinIsRefused(t *testing.T) {
	c := corpus.Case{ID: "nopin"}
	_, err := resolveTarget(c, writeProject(t, cpProject), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no src_commit") {
		t.Fatalf("want a named refusal for a missing pin, got %v", err)
	}
}

// Every real case in the corpus must classify. A case the adapter cannot place
// is one nobody can grade, and it should show up here rather than in the room.
func TestEveryCorpusCaseClassifies(t *testing.T) {
	paths, err := filepath.Glob("../../corpus/cases/*/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no case files found: %v", err)
	}
	for _, p := range paths {
		c, err := corpus.Load(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		// Only the packaging is under test here, not a checkout on disk, so
		// assert on what the case alone determines: an oss-fuzz case names its
		// tooling, a CP case names a cp_repo.
		if c.Source.FuzzToolingProject == "" && c.Source.CPRepo == "" {
			t.Errorf("%s: names neither fuzz_tooling_project nor cp_repo, so no shape is derivable", p)
		}
	}
}
