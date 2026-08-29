// SPDX-License-Identifier: Apache-2.0

// Command bundle-sign is the low-side tool that writes a canonical
// manifest over a bundle's content and signs it.
//
// It lives on the low side of the transfer by design: the secret keys never
// exist inside the boundary, and the ingress gate needs only the public keys
// to check what this produced.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"arazu/pkg/contentstore"
	"arazu/pkg/manifest"
)

func main() {
	dir := flag.String("dir", "", "bundle directory to sign")
	bundleID := flag.String("bundle-id", "arazu-spike", "bundle id")
	version := flag.Uint64("version", 1, "bundle version")
	created := flag.String("created", "2026-08-08T00:00:00Z", "creation timestamp, fixed for reproducible fixtures")
	keys := flag.String("keys", "", "comma-separated secret key files to sign with")
	flag.Parse()

	if *dir == "" || *keys == "" {
		fatal(fmt.Errorf("need -dir and -keys"))
	}

	// Scan only the payload. The manifest and its signatures live in the
	// bundle but are not payload and cannot describe themselves.
	files, err := contentstore.ScanDir(*dir)
	if err != nil {
		fatal(err)
	}
	var payload []manifest.File
	for _, f := range files {
		if f.Path == "manifest.json" || f.Path == "manifest.sig" {
			continue
		}
		payload = append(payload, f)
	}

	m := manifest.Manifest{
		Schema:   manifest.Schema,
		BundleID: *bundleID,
		Version:  *version,
		Created:  *created,
		Files:    payload,
	}
	canonical, err := m.Canonical()
	if err != nil {
		fatal(err)
	}

	var sigs strings.Builder
	for _, kp := range strings.Split(*keys, ",") {
		sec, err := loadSecret(strings.TrimSpace(kp))
		if err != nil {
			fatal(err)
		}
		sigs.WriteString(manifest.Sign(sec, canonical) + "\n")
	}

	if err := os.WriteFile(filepath.Join(*dir, "manifest.json"), canonical, 0o644); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "manifest.sig"), []byte(sigs.String()), 0o644); err != nil {
		fatal(err)
	}

	fmt.Printf("signed %s version %d, %d files, content root %s\n",
		*bundleID, *version, len(payload), contentstore.ContentRoot(payload))
}

func loadSecret(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: key is %d bytes, want %d", path, len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
