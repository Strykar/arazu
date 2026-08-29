// SPDX-License-Identifier: Apache-2.0

// Package contentstore verifies an unpacked bundle against its manifest and
// derives the content root that gets measured into the TPM.
//
// The content root is derived from the verified file set, never stored in
// the manifest. Storing it would be self-referential, and deriving it is
// what makes post-gate tampering detectable: re-measuring a modified store
// at run time yields a different root, the PCR no longer matches, and the
// output signing key will not unseal.
package contentstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"arazu/pkg/manifest"
)

// Reason strings the ingress gate reports for content failures.
var (
	ErrHashMismatch       = errors.New("hash-mismatch")
	ErrUnmanifestedFile   = errors.New("unmanifested-file")
	ErrMissingFile        = errors.New("missing-file")
	ErrAllowlistViolation = errors.New("allowlist-violation")
	ErrUnsafePath         = errors.New("unsafe-path")
)

const contentRootDomain = "arazu-content-root-v1\n"

// ContentRoot derives the measured value over a file set.
//
// The domain prefix keeps this hash from colliding with any other SHA256 in
// the system, and the fields are NUL separated so a path containing the
// separator cannot be arranged to look like a different file list.
func ContentRoot(files []manifest.File) string {
	sorted := append([]manifest.File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	h := sha256.New()
	io.WriteString(h, contentRootDomain)
	for _, f := range sorted {
		fmt.Fprintf(h, "%s\x00%s\x00%d\n", f.Path, f.SHA256, f.Size)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ScanDir walks root and returns every regular file, hashed and sized.
//
// Anything that is not a regular file is an error rather than something to
// skip. A symlink in the store could point outside it, so the bytes the
// manifest pins would not be the bytes the workload reads.
func ScanDir(root string) ([]manifest.File, error) {
	var out []manifest.File

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file (%s); the store must contain only regular files",
				ErrUnsafePath, path, d.Type())
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		out = append(out, manifest.File{Path: filepath.ToSlash(rel), SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// checkPath rejects anything that is not a plain relative path under one of
// the allowed prefixes.
//
// Two different failures live here and they report separately. A path that
// is absolute, unclean, or traverses upward is unsafe whatever the allowlist
// says, because it does not denote a location inside the store at all. A
// well-formed relative path that simply sits outside the allowed prefixes is
// an allowlist violation. Reporting both as the latter would have an
// operator widening the allowlist in response to an escape attempt.
func checkPath(p string, allow []string) error {
	if p == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafePath)
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: %q is absolute", ErrUnsafePath, p)
	}
	if filepath.ToSlash(filepath.Clean(p)) != p {
		return fmt.Errorf("%w: %q is not a clean path", ErrUnsafePath, p)
	}
	for _, elem := range strings.Split(p, "/") {
		if elem == ".." {
			return fmt.Errorf("%w: %q traverses upward", ErrUnsafePath, p)
		}
	}
	for _, prefix := range allow {
		if strings.HasPrefix(p, prefix) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q is outside the allowed prefixes %v", ErrAllowlistViolation, p, allow)
}

// VerifyAgainst checks an unpacked store against its manifest.
//
// The order is deliberate. Path safety first, so a path that should never
// have been in the manifest is reported as such rather than as a missing
// file. Then the tree scan, then existence, then content, then anything
// present but unmanifested. Each stage reports the most specific reason for
// the failure, which is what makes the rejection attributable.
//
// The scan has to come before anything reads a file. os.Lstat only refuses a
// symlink in the final component; it resolves the ones before it. So a
// manifest entry "content/sub/file" where "content/sub" is a symlink out of
// the store passes the existence check as a regular file, and hashing it
// reads bytes from wherever the symlink points. The walk refuses any
// non-regular entry anywhere in the tree, which catches the symlinked
// directory itself, so putting it first means the gate never reads through
// one. It used to run last, after the hash loop, purely as the source of the
// unmanifested-file comparison.
func VerifyAgainst(root string, m manifest.Manifest, allow []string) error {
	for _, f := range m.Files {
		if err := checkPath(f.Path, allow); err != nil {
			return err
		}
	}

	present, err := ScanDir(root)
	if err != nil {
		return err
	}

	for _, f := range m.Files {
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		st, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrMissingFile, f.Path)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, f.Path)
		}
	}

	for _, f := range m.Files {
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		sum, size, err := hashFile(full)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrHashMismatch, f.Path, err)
		}
		if sum != f.SHA256 {
			return fmt.Errorf("%w: %s", ErrHashMismatch, f.Path)
		}
		if size != f.Size {
			return fmt.Errorf("%w: %s: size %d, manifest says %d", ErrHashMismatch, f.Path, size, f.Size)
		}
	}

	listed := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		listed[f.Path] = true
	}
	for _, f := range present {
		if isBundleMetadata(f.Path) {
			continue
		}
		if !listed[f.Path] {
			return fmt.Errorf("%w: %s", ErrUnmanifestedFile, f.Path)
		}
	}
	return nil
}

// isBundleMetadata reports whether a path is the manifest or its signatures,
// which live in the bundle but are not payload and cannot describe
// themselves.
func isBundleMetadata(p string) bool {
	return p == "manifest.json" || p == "manifest.sig"
}

// MeasureBundle re-derives a bundle's payload file set and content root
// straight from disk.
//
// This exists so the gate and the run-time re-measurement cannot disagree.
// Both must hash the same paths: the gate hashes what the manifest lists,
// which is relative to the bundle root, so a re-measurement that scanned the
// content subdirectory would hash "a.txt" where the gate hashed
// "content/a.txt" and produce a root that never matches. That failure looks
// exactly like successful tamper detection, which makes it worse than an
// obvious bug: it would let the fail-closed branch pass without any
// tampering having occurred.
func MeasureBundle(dir string) ([]manifest.File, string, error) {
	all, err := ScanDir(dir)
	if err != nil {
		return nil, "", err
	}
	var payload []manifest.File
	for _, f := range all {
		if isBundleMetadata(f.Path) {
			continue
		}
		payload = append(payload, f)
	}
	return payload, ContentRoot(payload), nil
}
