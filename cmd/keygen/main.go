// SPDX-License-Identifier: Apache-2.0

// Command keygen writes the spike's fixture signing keys.
//
// The keys are derived from fixed seeds so the fixtures are reproducible
// and the acceptance table does not move between runs. They are test
// material and are committed to the repository on purpose. Production key
// handling is out of scope; SCOPE.md says so.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"arazu/pkg/manifest"
)

type signer struct {
	name    string
	seed    byte
	trusted bool
}

func main() {
	out := flag.String("out", "testdata/keys", "directory to write keys into")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o700); err != nil {
		fatal(err)
	}

	signers := []signer{
		{"signer-a", 0x01, true},
		{"signer-b", 0x02, true},
		{"untrusted", 0x09, false},
	}

	var trusted string
	for _, s := range signers {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = s.seed
		}
		sec := ed25519.NewKeyFromSeed(seed)
		pub := sec.Public().(ed25519.PublicKey)

		id := manifest.KeyIDFor(pub)
		pubLine := fmt.Sprintf("%s %s\n", id, base64.StdEncoding.EncodeToString(pub))

		write(filepath.Join(*out, s.name+".sec"), base64.StdEncoding.EncodeToString(sec)+"\n", 0o600)
		write(filepath.Join(*out, s.name+".pub"), pubLine, 0o644)

		if s.trusted {
			trusted += pubLine
		}
		fmt.Printf("%-10s %s trusted=%v\n", s.name, id, s.trusted)
	}

	write(filepath.Join(*out, "trusted.pub"),
		"# public keys provisioned on the high side\n"+trusted, 0o644)
}

func write(path, body string, mode os.FileMode) {
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
