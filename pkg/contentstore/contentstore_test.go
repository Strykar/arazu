// SPDX-License-Identifier: Apache-2.0

package contentstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arazu/pkg/manifest"
)

var allow = []string{"content/"}

func fixture(t *testing.T) (string, manifest.Manifest) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "content", "a.txt"), []byte("alpha"), 0o644)
	os.WriteFile(filepath.Join(root, "content", "b.txt"), []byte("bravo"), 0o644)

	files, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, manifest.Manifest{
		Schema: manifest.Schema, BundleID: "t", Version: 1,
		Created: "2026-08-08T00:00:00Z", Files: files,
	}
}

func TestCleanStoreVerifies(t *testing.T) {
	root, m := fixture(t)
	if err := VerifyAgainst(root, m, allow); err != nil {
		t.Fatalf("clean store rejected: %v", err)
	}
}

func TestContentRootIsOrderIndependent(t *testing.T) {
	_, m := fixture(t)
	a := ContentRoot(m.Files)
	rev := append([]manifest.File(nil), m.Files...)
	rev[0], rev[1] = rev[1], rev[0]
	if b := ContentRoot(rev); a != b {
		t.Fatalf("content root depends on input order: %s vs %s", a, b)
	}
}

func TestContentRootChangesWhenAHashChanges(t *testing.T) {
	_, m := fixture(t)
	before := ContentRoot(m.Files)
	m.Files[0].SHA256 = "deadbeef"
	if after := ContentRoot(m.Files); before == after {
		t.Fatal("content root unchanged after a file hash changed")
	}
}

func TestContentRootChangesWhenAFileIsAdded(t *testing.T) {
	_, m := fixture(t)
	before := ContentRoot(m.Files)
	m.Files = append(m.Files, manifest.File{Path: "content/c.txt", SHA256: "cc", Size: 1})
	if after := ContentRoot(m.Files); before == after {
		t.Fatal("content root unchanged after a file was added")
	}
}

// The NUL separators exist so a crafted path cannot make one file list hash
// the same as a different one.
func TestContentRootResistsFieldConfusion(t *testing.T) {
	a := ContentRoot([]manifest.File{{Path: "x", SHA256: "yy", Size: 1}})
	b := ContentRoot([]manifest.File{{Path: "x\x00yy", SHA256: "", Size: 1}})
	if a == b {
		t.Fatal("a path containing the field separator produced a colliding root")
	}
}

// This is the post-gate tampering path that makes the seal fail closed.
func TestContentRootChangesWhenTheStoreIsModified(t *testing.T) {
	root, m := fixture(t)
	before := ContentRoot(m.Files)

	os.WriteFile(filepath.Join(root, "content", "a.txt"), []byte("alphA"), 0o644)
	after, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if ContentRoot(after) == before {
		t.Fatal("content root unchanged after the store was modified on disk")
	}
}

func TestFlippedByteIsHashMismatch(t *testing.T) {
	root, m := fixture(t)
	os.WriteFile(filepath.Join(root, "content", "a.txt"), []byte("alphA"), 0o644)
	if err := VerifyAgainst(root, m, allow); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("flipped byte not caught as hash-mismatch: %v", err)
	}
}

// A same-length change is the interesting case: a size-only check would
// miss it.
func TestSameLengthEditIsCaught(t *testing.T) {
	root, m := fixture(t)
	os.WriteFile(filepath.Join(root, "content", "a.txt"), []byte("omega"), 0o644)
	if err := VerifyAgainst(root, m, allow); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("same-length edit not caught: %v", err)
	}
}

// The manifest declares a size as well as a hash, and the content root is
// derived from the declared values rather than from the files. So a size that
// disagrees with the file on disk means the measurement would describe
// something the store does not contain, even though the bytes hash correctly.
//
// This test exists because mutation-testing found the size check had none:
// breaking it left the whole suite green.
func TestDeclaredSizeMustMatchTheFile(t *testing.T) {
	root, m := fixture(t)
	if err := VerifyAgainst(root, m, allow); err != nil {
		t.Fatalf("setup: intact fixture rejected: %v", err)
	}

	m.Files[0].Size++
	if err := VerifyAgainst(root, m, allow); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a declared size that disagrees with the file was accepted: %v", err)
	}
}

func TestExtraFileIsUnmanifested(t *testing.T) {
	root, m := fixture(t)
	os.WriteFile(filepath.Join(root, "content", "extra.txt"), []byte("x"), 0o644)
	if err := VerifyAgainst(root, m, allow); !errors.Is(err, ErrUnmanifestedFile) {
		t.Fatalf("extra file not caught: %v", err)
	}
}

func TestMissingFileIsCaught(t *testing.T) {
	root, m := fixture(t)
	os.Remove(filepath.Join(root, "content", "b.txt"))
	if err := VerifyAgainst(root, m, allow); !errors.Is(err, ErrMissingFile) {
		t.Fatalf("missing file not caught: %v", err)
	}
}

func TestPathOutsideAllowlistIsCaught(t *testing.T) {
	root, m := fixture(t)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "evil.conf"), []byte("x"), 0o644)

	files, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	m.Files = files
	if err := VerifyAgainst(root, m, allow); !errors.Is(err, ErrAllowlistViolation) {
		t.Fatalf("path outside the allowlist not caught: %v", err)
	}
}

func TestTraversalPathIsCaught(t *testing.T) {
	root, m := fixture(t)
	for _, bad := range []string{
		"content/../../escape",
		"/etc/passwd",
		"content/./a.txt",
		"../outside",
	} {
		mm := m
		mm.Files = append(append([]manifest.File(nil), m.Files...),
			manifest.File{Path: bad, SHA256: "aa", Size: 1})
		if err := VerifyAgainst(root, mm, allow); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("path %q not caught as unsafe: %v", bad, err)
		}
	}
}

// A traversal and a merely-disallowed location are different failures, and an
// operator who cannot tell them apart might widen the allowlist in response to
// an escape attempt. Both arms run through the same call so neither reason can
// be produced by a check that has stopped discriminating.
func TestUnsafePathAndAllowlistViolationAreDistinct(t *testing.T) {
	root, m := fixture(t)

	traversal := m
	traversal.Files = append(append([]manifest.File(nil), m.Files...),
		manifest.File{Path: "content/../escape", SHA256: "aa", Size: 1})
	if err := VerifyAgainst(root, traversal, allow); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("traversal reported %v, want unsafe-path", err)
	}

	outside := m
	outside.Files = append(append([]manifest.File(nil), m.Files...),
		manifest.File{Path: "etc/evil.conf", SHA256: "aa", Size: 1})
	err := VerifyAgainst(root, outside, allow)
	if !errors.Is(err, ErrAllowlistViolation) {
		t.Errorf("well-formed path outside the prefixes reported %v, want allowlist-violation", err)
	}
	if errors.Is(err, ErrUnsafePath) {
		t.Error("a merely-disallowed path was reported as unsafe")
	}
}

// The regression this file exists for.
//
// os.Lstat refuses a symlink only in the final component and resolves the ones
// before it, so a manifest entry under a symlinked directory used to pass the
// existence check as a regular file and get hashed, reading bytes from outside
// the store. The walk that would have caught the symlink ran afterwards, so the
// bundle was refused, but only as unmanifested-file and only after the read.
//
// The reject arm pins a hash the outside file does not have. That is the
// ordering discriminator, and it is the whole reason the arm is built this way:
// anything that reaches the hash loop reports hash-mismatch, so unsafe-path can
// only have come from the walk that now runs before it. Asserting unsafe-path
// alone would not do it, because the walk reports unsafe-path from either
// position and the test would pass with the scan back where it started.
func TestSymlinkedDirectoryComponentIsRefusedBeforeAnythingIsRead(t *testing.T) {
	outside := t.TempDir()
	secret := []byte("bytes that live outside the bundle\n")
	if err := os.WriteFile(filepath.Join(outside, "file"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(secret)

	// Accept arm: a real directory in the same shape verifies, so the
	// rejection below is attributable to the symlink and not to the shape.
	root, m := fixture(t)
	if err := os.MkdirAll(filepath.Join(root, "content", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "content", "sub", "file"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	m.Files = append(m.Files, manifest.File{
		Path: "content/sub/file", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(secret)),
	})
	if err := VerifyAgainst(root, m, allow); err != nil {
		t.Fatalf("a real directory holding the same bytes was rejected: %v", err)
	}

	// Reject arm: the directory replaced by a symlink pointing out of the store.
	linked, lm := fixture(t)
	if err := os.Symlink(outside, filepath.Join(linked, "content", "sub")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// The escape is real rather than hypothetical: the path resolves out.
	through := filepath.Join(linked, "content", "sub", "file")
	if b, err := os.ReadFile(through); err != nil || !bytes.Equal(b, secret) {
		t.Fatalf("setup: %s does not resolve outside the store: %v", through, err)
	}

	lm.Files = append(lm.Files, manifest.File{
		Path: "content/sub/file", SHA256: strings.Repeat("00", sha256.Size), Size: int64(len(secret)),
	})

	err := VerifyAgainst(linked, lm, allow)
	if errors.Is(err, ErrHashMismatch) {
		t.Fatal("the gate hashed through the symlinked directory before refusing it; " +
			"the tree scan has to run before anything is read")
	}
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlinked directory component reported %v, want unsafe-path", err)
	}
}

// A symlink standing in for a manifested file is unsafe, not missing. The
// accept arm pins that the same manifested path verifies when it is a real
// file, so the rejection is attributable to the symlink.
func TestSymlinkInPlaceOfAManifestedFileIsUnsafeNotMissing(t *testing.T) {
	root, m := fixture(t)
	if err := VerifyAgainst(root, m, allow); err != nil {
		t.Fatalf("setup: intact fixture rejected: %v", err)
	}

	target := filepath.Join(root, "content", "a.txt")
	os.Remove(target)
	if err := os.Symlink("/etc/passwd", target); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	err := VerifyAgainst(root, m, allow)
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink standing in for a manifested file reported %v, want unsafe-path", err)
	}
}

// A symlink could point outside the store, so the bytes the manifest pins
// would not be the bytes the workload reads.
func TestSymlinkIsRejectedByScan(t *testing.T) {
	root, _ := fixture(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "content", "link")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, err := ScanDir(root); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink in the store reported %v, want unsafe-path", err)
	}
}

// The gate measures what the manifest lists, which is relative to the
// bundle root. A run-time re-measurement must land on the same value or the
// seal fails for a reason that has nothing to do with tampering, and the
// fail-closed branch passes while proving nothing.
//
// This is a regression test. The demo's tampered-content branch originally
// passed because the runner scanned the content subdirectory and hashed
// "a.txt" where the gate hashed "content/a.txt", so the roots never matched
// with or without a tamper.
func TestMeasureBundleMatchesTheManifestDerivedRoot(t *testing.T) {
	root, m := fixture(t)
	os.WriteFile(filepath.Join(root, "manifest.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(root, "manifest.sig"), []byte("sig"), 0o644)

	gateRoot := ContentRoot(m.Files)
	files, runtimeRoot, err := MeasureBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeRoot != gateRoot {
		t.Fatalf("run-time root %s does not match the gate's %s; the seal would fail "+
			"with nothing tampered", runtimeRoot, gateRoot)
	}
	if len(files) != len(m.Files) {
		t.Fatalf("measured %d payload files, manifest lists %d", len(files), len(m.Files))
	}
	for i := range files {
		if files[i].Path != m.Files[i].Path {
			t.Errorf("path %d: measured %q, manifest has %q", i, files[i].Path, m.Files[i].Path)
		}
	}
}

// And the value must still move when content actually changes, otherwise
// the test above could be satisfied by a constant.
func TestMeasureBundleChangesWhenContentIsTampered(t *testing.T) {
	root, _ := fixture(t)
	_, before, err := MeasureBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "content", "a.txt"), []byte("TAMPERED"), 0o644)
	_, after, err := MeasureBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("the measured root did not change after the content was tampered")
	}
}

// The manifest and its signatures live in the bundle but are not payload
// and cannot list themselves.
func TestBundleMetadataIsNotUnmanifested(t *testing.T) {
	root, m := fixture(t)
	os.WriteFile(filepath.Join(root, "manifest.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(root, "manifest.sig"), []byte("sig"), 0o644)
	if err := VerifyAgainst(root, m, allow); err != nil {
		t.Fatalf("bundle metadata reported as unmanifested: %v", err)
	}
}

// The content root is pinned to a known digest, so any change to how it is
// derived shows up here rather than silently producing a different measured
// value that the TPM would then seal against.
//
// This test exists because mutation testing found that removing the domain
// separator changed nothing: every other test compares one derived root
// against another derived root, so both sides moved together and the
// comparison still held. A pinned constant is the only thing that catches a
// change to the derivation itself.
func TestContentRootIsPinnedToAKnownDigest(t *testing.T) {
	files := []manifest.File{
		{Path: "content/a.txt", SHA256: "aa", Size: 1},
		{Path: "content/b.txt", SHA256: "bb", Size: 2},
	}
	// Updated once, deliberately, when the project was renamed kavach -> arazu:
	// contentRootDomain went from "kavach-content-root-v1" to
	// "arazu-content-root-v1", which is a change to the DERIVATION and not to
	// this fixture's inputs, which are unchanged. Every measurement sealed under
	// the old separator is invalidated by that, and nothing had been sealed
	// outside this tree when it happened.
	//
	// This test is the only thing that noticed. The rename touched 102 files by
	// pattern, and a versioned cryptographic domain separator looks exactly like
	// prose to a bulk substitution.
	const want = "5ba71ce4e5afafda8903b91a524ae197cfcd998b2a0b6dd0be7eeeda2a23bb31"

	if got := ContentRoot(files); got != want {
		t.Fatalf("content root derivation changed:\n got  %s\n want %s\n"+
			"If this change is intended, every previously sealed measurement is "+
			"invalidated and the constant here must be updated deliberately.", got, want)
	}
}
