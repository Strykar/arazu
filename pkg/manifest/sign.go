// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Reason strings the ingress gate reports for signature failures.
var (
	ErrUntrustedSigner        = errors.New("untrusted-signer")
	ErrInsufficientSignatures = errors.New("insufficient-signatures")
	ErrBadSignature           = errors.New("bad-signature")
	ErrDuplicateSigner        = errors.New("duplicate-signer")
)

// KeyID identifies a signer by the first 8 bytes of the SHA256 of its
// public key.
type KeyID string

func KeyIDFor(pub ed25519.PublicKey) KeyID {
	sum := sha256.Sum256(pub)
	return KeyID(hex.EncodeToString(sum[:8]))
}

// Sign returns one signature line over the canonical manifest bytes.
func Sign(sec ed25519.PrivateKey, canonical []byte) string {
	pub := sec.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(sec, canonical)
	return fmt.Sprintf("ed25519 %s %s", KeyIDFor(pub), base64.StdEncoding.EncodeToString(sig))
}

// LoadPublicKeys reads a trusted-keys file of "<keyid> <base64 pubkey>"
// lines. The key ID in the file must match the key, so a typo cannot
// silently retarget trust.
func LoadPublicKeys(path string) (map[KeyID]ed25519.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	keys := make(map[KeyID]ed25519.PublicKey)
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want '<keyid> <base64 pubkey>'", path, n)
		}
		raw, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s:%d: public key is %d bytes, want %d",
				path, n, len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		if got := KeyIDFor(pub); string(got) != fields[0] {
			return nil, fmt.Errorf("%s:%d: key id %s does not match the key (%s)", path, n, fields[0], got)
		}
		keys[KeyIDFor(pub)] = pub
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no trusted keys", path)
	}
	return keys, nil
}

// VerifySignatures checks every signature line over canonical and returns
// the distinct trusted signers that verified.
//
// An untrusted signer is a rejection rather than something to skip over. A
// gate that ignored unknown signatures would accept a bundle carrying one
// good signature and any amount of noise, which is not two-person control.
//
// A key signing twice is also a rejection, and gets its own reason. Counting
// the lines rather than the signers is the naive way to defeat two-person
// control: two signatures, both valid, both from a trusted key, count of two.
// Deduplicating silently would refuse it for the right outcome but report
// insufficient-signatures, which reads as an incomplete bundle. One is an
// operator mistake and the other is a single compromised signer trying to
// pass for two, and an operator needs to be able to tell them apart.
func VerifySignatures(canonical, sigFile []byte, trusted map[KeyID]ed25519.PublicKey, minDistinct int) ([]KeyID, error) {
	seen := make(map[KeyID]bool)
	var order []KeyID

	sc := bufio.NewScanner(bytes.NewReader(sigFile))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "ed25519" {
			return nil, fmt.Errorf("%w: line %d: want 'ed25519 <keyid> <base64 sig>'", ErrBadSignature, n)
		}
		id := KeyID(fields[1])
		pub, ok := trusted[id]
		if !ok {
			return nil, fmt.Errorf("%w: key %s is not provisioned on this side", ErrUntrustedSigner, id)
		}
		sig, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrBadSignature, n, err)
		}
		if !ed25519.Verify(pub, canonical, sig) {
			return nil, fmt.Errorf("%w: signature from %s does not verify over the manifest", ErrBadSignature, id)
		}
		if seen[id] {
			return nil, fmt.Errorf("%w: key %s signed the manifest more than once", ErrDuplicateSigner, id)
		}
		seen[id] = true
		order = append(order, id)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if len(order) < minDistinct {
		return nil, fmt.Errorf("%w: %d distinct trusted signers, need %d",
			ErrInsufficientSignatures, len(order), minDistinct)
	}
	return order, nil
}
