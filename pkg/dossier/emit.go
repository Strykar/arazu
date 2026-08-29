// SPDX-License-Identifier: Apache-2.0

// Package dossier writes and re-checks the evidence bundle a verdict is carried
// in.
//
// A dossier is self-contained or it is not a dossier: the artifacts the verdict
// was reached from are copied in, named by a path RELATIVE to the directory and
// by the hash of the bytes, and the whole directory is what gets measured. Move
// it to another machine and it still verifies, or the property did not transfer.
package dossier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"arazu/pkg/gate"
)

// ArtifactsDir is where copied evidence lives inside a dossier.
const ArtifactsDir = "artifacts"

// DecisionFile is the verdict, at the dossier root.
const DecisionFile = "decision.json"

// Emit writes a self-contained dossier into dir and returns the decision as
// recorded, which differs from the one passed in: it carries the artifact list.
//
// sources maps a role ("candidate-patch", "pov", "case") to a path on this
// machine. Each is copied under ArtifactsDir and recorded relative to dir.
//
// ORDER. Artifacts land before decision.json, and decision.json before anything
// measures, because ContentRoot hashes what MeasureBundle scanned. A file
// written after measurement sits outside the root with every check still
// passing. Nothing in the type system enforces this, so it is tested.
func Emit(dir string, d gate.Decision, sources map[string]string) (gate.Decision, error) {
	if dir == "" {
		return d, fmt.Errorf("no dossier directory")
	}
	// Staged, then moved in once complete: a partial dossier is a directory that
	// looks like evidence and is not.
	stage, err := os.MkdirTemp(dir, ".emit-")
	if err != nil {
		return d, err
	}
	defer os.RemoveAll(stage)

	if err := os.MkdirAll(filepath.Join(stage, ArtifactsDir), 0o700); err != nil {
		return d, err
	}

	roles := make([]string, 0, len(sources))
	for r := range sources {
		roles = append(roles, r)
	}
	sort.Strings(roles) // stable order, so two emits of one decision are byte-equal

	d.Artifacts = nil
	for _, role := range roles {
		src := sources[role]
		if src == "" {
			continue
		}
		rel := filepath.Join(ArtifactsDir, role+filepath.Ext(src))
		sum, err := copyAndHash(src, filepath.Join(stage, rel))
		if err != nil {
			return d, fmt.Errorf("artifact %s: %w", role, err)
		}
		d.Artifacts = append(d.Artifacts, gate.Artifact{Role: role, Path: rel, SHA256: sum})
	}

	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return d, err
	}
	if err := os.WriteFile(filepath.Join(stage, DecisionFile), append(b, '\n'), 0o644); err != nil {
		return d, err
	}
	if err := syncDir(stage); err != nil {
		return d, err
	}

	if err := os.Rename(filepath.Join(stage, ArtifactsDir), filepath.Join(dir, ArtifactsDir)); err != nil {
		return d, err
	}
	if err := os.Rename(filepath.Join(stage, DecisionFile), filepath.Join(dir, DecisionFile)); err != nil {
		return d, err
	}
	return d, syncDir(dir)
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func copyAndHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		return "", err
	}
	// The hash is over what was WRITTEN, taken from the same stream, so it
	// cannot describe bytes the dossier does not carry.
	return hex.EncodeToString(h.Sum(nil)), out.Sync()
}
