// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"errors"
	"testing"
)

func sample() Manifest {
	return Manifest{
		Schema:   Schema,
		BundleID: "spike-fixture",
		Version:  3,
		Created:  "2026-08-08T00:00:00Z",
		Files: []File{
			{Path: "content/b.txt", SHA256: "bb", Size: 2},
			{Path: "content/a.txt", SHA256: "aa", Size: 1},
		},
	}
}

func TestCanonicalSortsFilesByPath(t *testing.T) {
	b, err := sample().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	ai, bi := bytes.Index(b, []byte("a.txt")), bytes.Index(b, []byte("b.txt"))
	if ai < 0 || bi < 0 || ai > bi {
		t.Fatalf("files not sorted by path: %s", b)
	}
}

func TestCanonicalRoundTrips(t *testing.T) {
	b, _ := sample().Canonical()
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := m.Canonical()
	if !bytes.Equal(b, b2) {
		t.Fatalf("round trip changed bytes:\n%s\n%s", b, b2)
	}
}

func TestCanonicalDoesNotMutateTheReceiver(t *testing.T) {
	m := sample()
	first := m.Files[0].Path
	if _, err := m.Canonical(); err != nil {
		t.Fatal(err)
	}
	if m.Files[0].Path != first {
		t.Fatalf("Canonical sorted the caller's slice in place: %s became %s", first, m.Files[0].Path)
	}
}

func TestParseRejectsLeadingWhitespace(t *testing.T) {
	b, _ := sample().Canonical()
	if _, err := Parse(append([]byte("  "), b...)); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("padded manifest accepted, err=%v", err)
	}
}

func TestParseRejectsPrettyPrinted(t *testing.T) {
	raw := []byte("{\n  \"schema\": \"arazu.bundle/v1\",\n  \"bundle_id\": \"spike-fixture\",\n" +
		"  \"version\": 3,\n  \"created\": \"2026-08-08T00:00:00Z\",\n  \"files\": []\n}")
	if _, err := Parse(raw); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("pretty-printed manifest accepted, err=%v", err)
	}
}

func TestParseRejectsReorderedFiles(t *testing.T) {
	raw := []byte(`{"schema":"arazu.bundle/v1","bundle_id":"spike-fixture","version":3,` +
		`"created":"2026-08-08T00:00:00Z","files":[` +
		`{"path":"content/b.txt","sha256":"bb","size":2},` +
		`{"path":"content/a.txt","sha256":"aa","size":1}]}`)
	if _, err := Parse(raw); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("reordered manifest accepted, err=%v", err)
	}
}

func TestParseRejectsTruncated(t *testing.T) {
	b, _ := sample().Canonical()
	if _, err := Parse(b[:len(b)/2]); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("truncated manifest accepted, err=%v", err)
	}
}

func TestParseRejectsWrongSchema(t *testing.T) {
	m := sample()
	m.Schema = "arazu.bundle/v99"
	b, _ := m.Canonical()
	if _, err := Parse(b); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("unknown schema accepted, err=%v", err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{"schema":"arazu.bundle/v1","bundle_id":"x","version":1,` +
		`"created":"2026-08-08T00:00:00Z","files":[],"extra":"smuggled"}`)
	if _, err := Parse(raw); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("manifest with an unknown field accepted, err=%v", err)
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	b, _ := sample().Canonical()
	if _, err := Parse(append(b, []byte(`{"schema":"arazu.bundle/v1"}`)...)); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("trailing document accepted, err=%v", err)
	}
}
