// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"arazu/pkg/classreplay"
	"arazu/pkg/corpus"
	"arazu/pkg/revert"
)

// Two packagings exist and neither is the general case.
//
// An AIxCC challenge project carries its own build: project.yaml declares
// cp_sources, whose keys are the directory names under ./src, and a
// docker_image that is pulled rather than built. nginx is this shape.
//
// An oss-fuzz target is a bare upstream checkout. Its project.yaml is
// upstream's own metadata with no docker_image, because oss-fuzz builds the
// image from separate tooling. libpng is this shape, and the case records the
// tooling in fuzz_tooling_*.
//
// Anything matching neither is REFUSED. A driver that guesses a layout still
// grades something, and what it graded is what the verdict does not say.
type shape int

const (
	shapeUnknown shape = iota
	shapeChallengeProject
	shapeOSSFuzz
)

// resolveTarget derives everything revert.Challenge needs from the case and
// the checkout. No target names appear here.
func resolveTarget(c corpus.Case, root, shim string) (revert.Challenge, error) {
	pin := c.Source.SrcCommit
	if pin == "" {
		return revert.Challenge{}, fmt.Errorf(
			"target-shape-unrecognised: case %s records no src_commit, so there is no tree to reset to", c.ID)
	}

	switch s, srcDir, imageBase := classify(root, c); s {
	case shapeChallengeProject:
		image, err := localTag(imageBase, shim)
		if err != nil {
			return revert.Challenge{}, err
		}
		return revert.Challenge{
			Root: root, Shim: shim, Src: srcDir, Pin: pin, Image: image,
			ExtraCFlags: "-fsanitize-recover=address",
		}, nil

	case shapeOSSFuzz:
		image, err := localTag(imageBase, shim)
		if err != nil {
			return revert.Challenge{}, err
		}
		return revert.Challenge{
			Root: root, Shim: shim, Src: srcDir, Pin: pin, Image: image,
			ExtraCFlags: "-fsanitize-recover=address",
		}, nil

	default:
		return revert.Challenge{}, fmt.Errorf(
			"target-shape-unrecognised: %s has no cp_sources in project.yaml and case %s "+
				"names no fuzz_tooling_project, so neither the source directory nor the "+
				"image can be determined", root, c.ID)
	}
}

// classify reads the checkout and the case together. Neither alone is enough:
// project.yaml says how the target is packaged, the case says what tooling
// builds it.
func classify(root string, c corpus.Case) (shape, string, string) {
	y, err := os.ReadFile(filepath.Join(root, "project.yaml"))
	if err == nil {
		if name := firstCPSource(string(y)); name != "" {
			if img := scalar(string(y), "docker_image"); img != "" {
				return shapeChallengeProject, filepath.Join("src", name), img
			}
		}
	}
	// No cp_sources, or one without an image: an oss-fuzz target if the case
	// names the project that builds it. The tree is the source, unnested.
	if p := c.Source.FuzzToolingProject; p != "" {
		return shapeOSSFuzz, ".", "gcr.io/oss-fuzz/" + p
	}
	return shapeUnknown, "", ""
}

// firstCPSource returns the first key under cp_sources, which the AIxCC layout
// says is the directory under ./src holding that repository.
func firstCPSource(y string) string {
	in := false
	for _, ln := range strings.Split(y, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "cp_sources:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		t := strings.TrimRight(ln, " \t")
		if t == "" || strings.HasPrefix(strings.TrimSpace(t), "#") {
			continue
		}
		// Left the block the moment indentation returns to column zero.
		if !strings.HasPrefix(t, " ") && !strings.HasPrefix(t, "\t") {
			return ""
		}
		if k, _, ok := strings.Cut(strings.TrimSpace(t), ":"); ok {
			return strings.Trim(strings.TrimSpace(k), `"'`)
		}
	}
	return ""
}

// scalar pulls a top-level "key: value" out of a small YAML file. Enough for
// two fields in a file this shape; not a parser.
func scalar(y, key string) string {
	for _, ln := range strings.Split(y, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, key+":") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, key+":")), `"'`)
		}
	}
	return ""
}

// localTag finds the tag the shim's runtime actually holds for a base image.
//
// The shim's docker BY EXPLICIT PATH, not by name. exec.Command resolves a bare
// name against the parent's PATH and ignores cmd.Env, so "docker" here finds
// /usr/bin/docker, a different runtime holding different images. That returned
// "no local image" on a host where the image is present, and had the image
// existed under both runtimes it would have graded against the wrong one.
func localTag(base, shim string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("target-shape-unrecognised: no image could be determined")
	}
	dockerBin := filepath.Join(shim, "docker")
	if _, err := os.Stat(dockerBin); err != nil {
		return "", fmt.Errorf("no docker shim at %s: %w", dockerBin, err)
	}
	cmd := exec.Command(dockerBin, "images", "--format", "{{.Repository}}:{{.Tag}}")
	cmd.Env = append(os.Environ(), "PATH="+shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("listing local images with %s: %w", dockerBin, err)
	}
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, base+":") && !strings.HasSuffix(ln, ":<none>") {
			return ln, nil
		}
	}
	return "", fmt.Errorf("no local image for %s", base)
}

// resolveClassTarget builds the target M2 needs. It is a DIFFERENT interface
// from the one above: revert and sanitizer reset-apply-build-run one blob,
// class replay generates a whole input class and replays it against two trees.
//
// Both checkouts are needed, not one. resolveTarget takes a single -root
// because reverting only touches the source; a class replay also runs oss-fuzz
// tooling, which stage-corpus.sh clones separately.
//
// The paths are DERIVED from the case, on stage-corpus.sh's own layout
// ($CORPUS/<target>/<repo name>), rather than carried here as a second copy of
// where things live. A staging script and a resolver with independent lists
// agree until one target changes.
func resolveClassTarget(c corpus.Case, corpusRoot, repoRoot, shim, workDir string,
	members int) (*classreplay.OSSFuzzTarget, error) {

	if c.Source.FuzzToolingProject == "" {
		return nil, fmt.Errorf(
			"target-shape-unrecognised: case %s names no fuzz_tooling_project, so there is "+
				"no tooling checkout to replay the class in", c.ID)
	}
	if c.PoV.Sanitizer == "" {
		return nil, fmt.Errorf(
			"case %s records no pov.sanitizer, and a class replay under a different sanitizer "+
				"compares outputs the case never described", c.ID)
	}

	src := repoDir(corpusRoot, c.Target, c.Source.SrcRepo)
	tooling := repoDir(corpusRoot, c.Target, c.Source.FuzzToolingRepo)
	for _, d := range []string{src, tooling} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf(
				"%s is not a checkout; run scripts/stage-corpus.sh to place it", d)
		}
	}

	// Relative to the repo root, on the same rule as generator.
	obs := c.FalsifyingClass.Observer
	if obs != "" && !filepath.IsAbs(obs) {
		obs = filepath.Join(repoRoot, obs)
	}
	if obs != "" {
		if fi, err := os.Stat(obs); err != nil || fi.Mode()&0o111 == 0 {
			return nil, fmt.Errorf(
				"observer %s is missing or not executable; the stage cannot produce the "+
					"observation the case's discriminator names", obs)
		}
	}

	return &classreplay.OSSFuzzTarget{
		Observer: obs,
		RepoRoot: repoRoot, Source: src, Ref: c.Source.SrcRef,
		OSSFuzz: tooling, Project: c.Source.FuzzToolingProject,
		Harness: c.Harness, Sanitizer: c.PoV.Sanitizer,
		Shim: shim, WorkDir: workDir, Members: members,
	}, nil
}

// repoDir maps a clone URL to where stage-corpus.sh put it.
func repoDir(corpusRoot, target, url string) string {
	name := strings.TrimSuffix(filepath.Base(url), ".git")
	return filepath.Join(corpusRoot, target, name)
}
