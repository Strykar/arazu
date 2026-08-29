// SPDX-License-Identifier: Apache-2.0

// Package signer verifies manifest signatures across several key backends.
//
// Two-person control is about two people, not two files, so the boundary takes
// whatever the signers hold: ed25519 (software), ssh-ed25519 (an OpenSSH
// software key) and sk-ssh-ed25519 (a FIDO2 token). Both SSH algorithms verify
// through one code path, so the plumbing is testable end to end with no
// hardware present. What a token adds is that the key cannot be copied off it,
// so "two signatures" comes closer to "two people".
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
// ignored: an unknown algorithm is a signature we cannot check.
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
// key material, hex encoded. One rule across every backend.
type KeyID string

func KeyIDForBytes(pub []byte) KeyID {
	sum := sha256.Sum256(pub)
	return KeyID(hex.EncodeToString(sum[:8]))
}

func KeyIDForEd25519(pub ed25519.PublicKey) KeyID { return KeyIDForBytes(pub) }

// KeyIDForSSH derives the key ID from an SSH public key's base64 blob.
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

// Signature is one parsed line: <algorithm> <keyid> <base64 payload>. For
// ed25519 the payload is the raw signature, for the SSH algorithms the armoured
// OpenSSH signature, base64'd so the line shape is the same for both.
type Signature struct {
	Alg     string
	KeyID   KeyID
	Payload []byte
}

// ParseSignature reads one line. Strict about the shape: a line we cannot
// parse is a signature we cannot check.
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

// IsHardwareBacked reports whether the algorithm needs a security key. Recorded
// per signer: two hardware-backed signatures is a stronger claim than two
// software ones.
func (s Signature) IsHardwareBacked() bool { return s.Alg == AlgSKEd25519 }

// TrustedKey is one provisioned public key, whatever its backend.
type TrustedKey struct {
	ID  KeyID
	Alg string
	// Ed25519 is set for the software backend.
	Ed25519 ed25519.PublicKey
	// SSHLine is the authorized_keys-style line for the SSH backends.
	SSHLine string

	// Signer names the person, not the key. One person with two tokens is
	// still one person, so counting keys would let them satisfy two-person
	// control alone. The name comes from the provisioning file, not from a
	// signature.
	Signer string
	// NamedSigner records whether the provisioning line said who this is. An
	// unnamed key falls back to its own id and counts as its own person.
	NamedSigner bool
}

func (k TrustedKey) HardwareBacked() bool { return k.Alg == AlgSKEd25519 }

// SignerIdentity is the name two-person control counts over. An empty Signer
// falls back to the key id rather than counting as a name: otherwise keys with
// the field unset share the identity "" and collapse into one person.
func (k TrustedKey) SignerIdentity() string {
	if k.Signer == "" {
		return "keyid:" + string(k.ID)
	}
	return k.Signer
}
