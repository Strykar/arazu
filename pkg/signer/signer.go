// SPDX-License-Identifier: Apache-2.0

// Package signer verifies manifest signatures across several key backends.
//
// Two-person control is about two people, not two files, so the boundary has
// to accept signatures from whatever the two signers actually hold. Three
// backends are supported:
//
//   - ed25519        a software key, the spike's own minimal format
//   - ssh-ed25519    an OpenSSH signature from a software SSH key
//   - sk-ssh-ed25519 an OpenSSH signature from a FIDO2 security key
//
// The last two verify through exactly the same code path. A FIDO2 signature
// differs only in that the private half lives on a token and signing needed
// a touch, which happens on the low side. That is deliberate: it means the
// verification plumbing the boundary depends on can be tested end to end with
// a software SSH key, with no hardware and no user present, and the hardware
// path adds only the question of who holds the key.
//
// What the boundary gains from a hardware signer is not a better signature.
// It is that the key cannot be copied off the token, so "two signatures"
// becomes closer to "two people", which SCOPE.md otherwise has to disclaim.
package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Algorithms this build accepts. Anything else is refused rather than
// ignored: an unknown algorithm is a signature we cannot check, and a gate
// that skips what it cannot check is not a gate.
const (
	AlgEd25519    = "ed25519"
	AlgSSHEd25519 = "ssh-ed25519"
	AlgSKEd25519  = "sk-ssh-ed25519"
)

var (
	ErrUnknownAlgorithm = errors.New("unknown-algorithm")
	ErrMalformed        = errors.New("malformed-signature")
)

// KeyID identifies a signer by the first 8 bytes of the SHA256 of its public
// key material, hex encoded. The same rule across every backend, so a key ID
// means one thing regardless of where the key lives.
type KeyID string

func KeyIDForBytes(pub []byte) KeyID {
	sum := sha256.Sum256(pub)
	return KeyID(hex.EncodeToString(sum[:8]))
}

func KeyIDForEd25519(pub ed25519.PublicKey) KeyID { return KeyIDForBytes(pub) }

// KeyIDForSSH derives the key ID from an SSH public key's base64 blob, which
// is the wire encoding of the key itself.
func KeyIDForSSH(sshLine string) (KeyID, error) {
	fields := strings.Fields(strings.TrimSpace(sshLine))
	if len(fields) < 2 {
		return "", fmt.Errorf("%w: ssh public key needs a type and a blob", ErrMalformed)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Errorf("%w: ssh key blob: %v", ErrMalformed, err)
	}
	return KeyIDForBytes(raw), nil
}

// Signature is one parsed signature line:
//
//	<algorithm> <keyid> <base64 payload>
//
// For ed25519 the payload is the raw signature. For the SSH algorithms it is
// a base64 of the armoured OpenSSH signature, so the line stays single-line
// and the file format does not change shape between backends.
type Signature struct {
	Alg     string
	KeyID   KeyID
	Payload []byte
}

// ParseSignature reads one line. It is strict about the shape, because a
// line we cannot parse is a signature we cannot check.
func ParseSignature(line string) (Signature, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 3 {
		return Signature{}, fmt.Errorf("%w: want '<alg> <keyid> <base64>', got %d fields",
			ErrMalformed, len(fields))
	}
	switch fields[0] {
	case AlgEd25519, AlgSSHEd25519, AlgSKEd25519:
	default:
		return Signature{}, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, fields[0])
	}
	payload, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return Signature{}, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	return Signature{Alg: fields[0], KeyID: KeyID(fields[1]), Payload: payload}, nil
}

func (s Signature) String() string {
	return fmt.Sprintf("%s %s %s", s.Alg, s.KeyID, base64.StdEncoding.EncodeToString(s.Payload))
}

// IsHardwareBacked reports whether the algorithm requires a security key to
// produce a signature. The boundary records this per signer, because "two
// signatures, both hardware backed" is a materially stronger claim than two
// software keys and the audit log should say which was which.
func (s Signature) IsHardwareBacked() bool { return s.Alg == AlgSKEd25519 }

// TrustedKey is one provisioned public key, whatever its backend.
type TrustedKey struct {
	ID  KeyID
	Alg string
	// Ed25519 is set for the software backend.
	Ed25519 ed25519.PublicKey
	// SSHLine is the authorized_keys-style line for the SSH backends.
	SSHLine string

	// Signer names the person, not the key. Two-person control is over
	// people: one person holding two tokens is still one person, and
	// counting distinct keys would let them satisfy it alone.
	//
	// The name comes from the provisioning file, which the high side
	// controls, so it is trusted input rather than anything an attacker
	// supplies with a signature.
	Signer string
	// NamedSigner records whether the provisioning line said who this is.
	// An unnamed key falls back to its own id, which cannot be collapsed
	// with another key held by the same person, so the store reports how
	// many are unnamed rather than letting the gap pass silently.
	NamedSigner bool
}

func (k TrustedKey) HardwareBacked() bool { return k.Alg == AlgSKEd25519 }

// SignerIdentity is the name two-person control counts over.
//
// An empty Signer falls back to the key id rather than being treated as a
// name. Without this, two keys built programmatically with the field unset
// would share the identity "" and collapse into one person, which turns a
// missing field into a silent weakening of the very property this counts.
// A key whose holder is unknown has to count as its own person.
func (k TrustedKey) SignerIdentity() string {
	if k.Signer == "" {
		return "keyid:" + string(k.ID)
	}
	return k.Signer
}
