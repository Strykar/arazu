// SPDX-License-Identifier: Apache-2.0

// Package manifest defines the bundle manifest, its canonical byte form,
// and the two-signature policy over it.
//
// Canonical form is what gets signed. Parse therefore re-serialises and
// compares bytes: a manifest that is semantically valid but not
// byte-identical to its canonical form is rejected. That leaves exactly one
// representation of any bundle, so there is no room to vary the encoding
// and smuggle bytes past a signature that was taken over a different
// spelling of the same thing.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Schema is the only manifest schema this gate accepts.
const Schema = "arazu.bundle/v1"

// ErrNotCanonical is the reason string the ingress gate reports for any
// manifest it cannot parse or that is not in canonical form.
var ErrNotCanonical = errors.New("manifest-parse")

// File is one payload file, pinned by hash and size.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the signed description of a bundle. Field order defines the
// canonical encoding, so do not reorder it.
type Manifest struct {
	Schema   string `json:"schema"`
	BundleID string `json:"bundle_id"`
	Version  uint64 `json:"version"`
	Created  string `json:"created"`
	Files    []File `json:"files"`
}

// Canonical renders the one byte form that is signed and hashed.
func (m Manifest) Canonical() ([]byte, error) {
	c := m
	c.Files = append([]File(nil), m.Files...)
	sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Parse decodes a manifest and requires it to already be in canonical form.
func Parse(b []byte) (Manifest, error) {
	var m Manifest

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("%w: trailing data after the manifest", ErrNotCanonical)
	}
	if m.Schema != Schema {
		return Manifest{}, fmt.Errorf("%w: unknown schema %q", ErrNotCanonical, m.Schema)
	}

	c, err := m.Canonical()
	if err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(c, bytes.TrimRight(b, "\n")) {
		return Manifest{}, fmt.Errorf("%w: manifest is not in canonical form", ErrNotCanonical)
	}
	return m, nil
}
