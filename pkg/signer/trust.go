// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrUntrustedSigner        = errors.New("untrusted-signer")
	ErrInsufficientSignatures = errors.New("insufficient-signatures")
	ErrDuplicateSigner        = errors.New("duplicate-signer")
)

// TrustStore is the set of keys provisioned on the high side.
type TrustStore struct {
	keys map[KeyID]TrustedKey
}

func (t TrustStore) Len() int { return len(t.keys) }

func (t TrustStore) Get(id KeyID) (TrustedKey, bool) {
	k, ok := t.keys[id]
	return k, ok
}

// UnnamedCount reports how many provisioned keys carry no signer name. Each
// one counts as its own person, so a deployment that wants two-person
// control to mean two people should name them all.
func (t TrustStore) UnnamedCount() int {
	n := 0
	for _, k := range t.keys {
		if !k.NamedSigner {
			n++
		}
	}
	return n
}

// HardwareBackedCount reports how many provisioned keys live on a security
// key. The demo prints it, because "two provisioned signers" and "two
// provisioned signers, both on tokens" are different claims.
func (t TrustStore) HardwareBackedCount() int {
	n := 0
	for _, k := range t.keys {
		if k.HardwareBacked() {
			n++
		}
	}
	return n
}

// LoadTrustStore reads a provisioned-keys file. Three line shapes:
//
//	<keyid> <base64 ed25519 pubkey>          the spike's software format
//	ssh-ed25519 <base64> [comment]           an OpenSSH software key
//	sk-ssh-ed25519@openssh.com <base64> ...  a FIDO2 security key
//
// The SSH shapes are exactly what ssh-keygen writes into a .pub file, so a
// signer can paste theirs in without reformatting, and a reformatting step
// is one more place to make a mistake with a key.
func LoadTrustStore(path string) (TrustStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return TrustStore{}, err
	}
	defer f.Close()

	ts := TrustStore{keys: map[KeyID]TrustedKey{}}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := parseTrustLine(line)
		if err != nil {
			return TrustStore{}, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if _, dup := ts.keys[key.ID]; dup {
			return TrustStore{}, fmt.Errorf("%s:%d: key %s is provisioned twice", path, n, key.ID)
		}
		ts.keys[key.ID] = key
	}
	if err := sc.Err(); err != nil {
		return TrustStore{}, err
	}
	if len(ts.keys) == 0 {
		return TrustStore{}, fmt.Errorf("%s: no trusted keys", path)
	}
	return ts, nil
}

// signerName takes the provisioning comment as the person's name, falling
// back to the key id. The fallback is deliberately not collapsible with any
// other key: an unnamed key cannot be known to belong to the same person as
// another one, so it counts separately and UnnamedCount reports it.
func signerName(rest []string, id KeyID) (string, bool) {
	name := strings.TrimSpace(strings.Join(rest, " "))
	if name == "" {
		return "keyid:" + string(id), false
	}
	return name, true
}

func parseTrustLine(line string) (TrustedKey, error) {
	fields := strings.Fields(line)

	switch {
	case strings.HasPrefix(fields[0], "sk-ssh-ed25519"), strings.HasPrefix(fields[0], "ssh-ed25519"):
		if len(fields) < 2 {
			return TrustedKey{}, fmt.Errorf("%w: ssh key line needs a blob", ErrMalformed)
		}
		id, err := KeyIDForSSH(line)
		if err != nil {
			return TrustedKey{}, err
		}
		alg := AlgSSHEd25519
		if strings.HasPrefix(fields[0], "sk-") {
			alg = AlgSKEd25519
		}
		// Keep only the type and the blob for verification. The comment
		// field names the signer: it is provisioning data the high side
		// wrote, not anything that arrives with a signature.
		k := TrustedKey{ID: id, Alg: alg, SSHLine: fields[0] + " " + fields[1]}
		k.Signer, k.NamedSigner = signerName(fields[2:], id)
		return k, nil

	case len(fields) == 2:
		raw, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return TrustedKey{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return TrustedKey{}, fmt.Errorf("%w: ed25519 key is %d bytes, want %d",
				ErrMalformed, len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		if got := KeyIDForEd25519(pub); string(got) != fields[0] {
			return TrustedKey{}, fmt.Errorf("%w: key id %s does not match the key (%s)",
				ErrMalformed, fields[0], got)
		}
		k := TrustedKey{ID: KeyIDForEd25519(pub), Alg: AlgEd25519, Ed25519: pub}
		k.Signer, k.NamedSigner = signerName(nil, k.ID)
		return k, nil

	case len(fields) == 3:
		raw, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return TrustedKey{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return TrustedKey{}, fmt.Errorf("%w: ed25519 key is %d bytes, want %d",
				ErrMalformed, len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		if got := KeyIDForEd25519(pub); string(got) != fields[0] {
			return TrustedKey{}, fmt.Errorf("%w: key id %s does not match the key (%s)",
				ErrMalformed, fields[0], got)
		}
		k := TrustedKey{ID: KeyIDForEd25519(pub), Alg: AlgEd25519, Ed25519: pub}
		k.Signer, k.NamedSigner = signerName(fields[2:], k.ID)
		return k, nil
	}
	return TrustedKey{}, fmt.Errorf("%w: unrecognised trusted-key line", ErrMalformed)
}

// VerifyAll checks every signature over msg and returns the distinct trusted
// signers that verified.
//
// The two-person rule is over distinct people, not over signature count, not
// per key and not per backend. One person holding a software key and a token
// is still one person, and the provisioning file's signer names are what let
// the gate see that rather than counting two key ids as two people.
//
// It only works for keys the provisioning file names. An unnamed key falls
// back to its own id and so counts as its own person; TrustStore.UnnamedCount
// reports how many are in that state.
func VerifyAll(msg, sigFile []byte, trust TrustStore, minDistinct int) ([]TrustedKey, error) {
	seenKey := map[KeyID]bool{}
	seenSigner := map[string]bool{}
	var signers []TrustedKey

	sc := bufio.NewScanner(bytes.NewReader(sigFile))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sig, err := ParseSignature(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		key, ok := trust.Get(sig.KeyID)
		if !ok {
			return nil, fmt.Errorf("%w: key %s is not provisioned on this side",
				ErrUntrustedSigner, sig.KeyID)
		}
		if err := Verify(msg, sig, key); err != nil {
			return nil, err
		}
		if seenKey[sig.KeyID] {
			return nil, fmt.Errorf("%w: key %s signed the manifest more than once",
				ErrDuplicateSigner, sig.KeyID)
		}
		// Counting keys rather than people would let one person holding two
		// tokens satisfy two-person control alone, which is the whole thing
		// two-person control exists to prevent.
		who := key.SignerIdentity()
		if seenSigner[who] {
			return nil, fmt.Errorf("%w: %s signed the manifest with more than one key",
				ErrDuplicateSigner, who)
		}
		seenKey[sig.KeyID] = true
		seenSigner[who] = true
		signers = append(signers, key)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if len(seenSigner) < minDistinct {
		return nil, fmt.Errorf("%w: %d distinct trusted signers, need %d",
			ErrInsufficientSignatures, len(seenSigner), minDistinct)
	}
	return signers, nil
}
