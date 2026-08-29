// SPDX-License-Identifier: Apache-2.0

// Package fido verifies FIDO2 assertions used as manifest signatures.
//
// The software signing path proves that whoever holds a secret key file signed
// the manifest. A hardware assertion proves more: that a specific enrolled
// authenticator was physically present, and under a user-verification policy,
// that the person who enrolled it verified themselves to it. That is the
// difference between two-person control being a property of two files on a
// disk and being a property of two people.
//
// It also has considerably more ways to go wrong than a raw signature, which
// is the reason this package exists as its own thing with its own reason
// codes. A raw ed25519 signature has one failure: it does not verify. An
// assertion additionally carries a relying-party binding, a user-presence
// flag, a user-verification flag, and a signature counter, and each of those
// is a distinct attack that a check of the signature alone would pass.
package fido

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Reason strings the ingress gate reports for assertion failures. Each one is
// a distinct thing an attacker did, not a shade of "signature bad", because an
// operator's response differs: a counter regression means a cloned
// authenticator and every credential it holds is suspect, while a relying-party
// mismatch means a signature was harvested from some other service.
var (
	ErrUnknownCredential  = errors.New("fido-unknown-credential")
	ErrBadSignature       = errors.New("fido-bad-signature")
	ErrRPMismatch         = errors.New("fido-rp-mismatch")
	ErrNoUserPresence     = errors.New("fido-no-user-presence")
	ErrNoUserVerification = errors.New("fido-no-user-verification")
	ErrCounterRegression  = errors.New("fido-counter-regression")
	ErrCounterUnsupported = errors.New("fido-counter-unsupported")
	ErrMalformedAuthData  = errors.New("fido-malformed-authdata")
	ErrAlgorithmMismatch  = errors.New("fido-algorithm-mismatch")

	// Distinctness is over people. These mirror the software-key reasons
	// deliberately: an operator reading a decision should not have to know
	// which signing path produced it to understand what went wrong.
	ErrDuplicateSigner     = errors.New("duplicate-signer")
	ErrInsufficientSigners = errors.New("insufficient-signatures")
)

// Algorithm is the COSE algorithm a credential was enrolled with. It is
// recorded per credential and enforced, so an assertion cannot be presented
// under a different algorithm than the one the public key was registered for.
type Algorithm string

const (
	AlgEd25519 Algorithm = "eddsa"
	AlgES256   Algorithm = "es256"
)

// clientDataDomain separates a manifest signature from every other assertion
// the same authenticator might ever produce. Without it, an assertion the
// token made to log in somewhere could be presented here, provided the
// challenge happened to collide.
const clientDataDomain = "arazu-manifest-sig-v1\n"

// authenticator data flags, from the CTAP2 spec.
const (
	flagUP = 0x01 // user present: someone physically touched the authenticator
	flagUV = 0x04 // user verified: PIN or biometric was satisfied
	flagAT = 0x40 // attested credential data is appended
	flagED = 0x80 // extension data is appended
)

const authDataMinLen = 37 // rpIdHash(32) + flags(1) + signCount(4)

// Credential is one enrolled authenticator, provisioned on the high side.
//
// Signer names the person, not the token. Two-person control is over people:
// if one person enrols two authenticators, signatures from both are still one
// person, and counting credentials rather than signers would let them satisfy
// the threshold alone.
type Credential struct {
	ID        string    `json:"id"`
	Signer    string    `json:"signer"`
	Alg       Algorithm `json:"alg"`
	PublicKey []byte    `json:"public_key"`
	RPID      string    `json:"rpid"`
}

// Policy is what the boundary demands of an assertion.
type Policy struct {
	RPID string `json:"rpid"`

	// RequireUV demands PIN or biometric, not merely a touch. A touch proves
	// the token was present; it does not prove who was holding it. For
	// two-person control the distinction is the entire point.
	RequireUV bool `json:"require_uv"`

	// RequireCounter refuses an authenticator that does not maintain a
	// signature counter. Such a token cannot be checked for cloning, so the
	// choice is between refusing it and accepting that the property is
	// unavailable. Which one is right depends on the deployment, so it is a
	// policy rather than a default, but it is never silently unavailable:
	// Verify reports it either way.
	RequireCounter bool `json:"require_counter"`
}

// Assertion is one signature line's worth of authenticator output.
type Assertion struct {
	CredentialID string
	AuthData     []byte
	Signature    []byte
}

// AuthData is the parsed authenticator data.
type AuthData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
}

func (a AuthData) UserPresent() bool  { return a.Flags&flagUP != 0 }
func (a AuthData) UserVerified() bool { return a.Flags&flagUV != 0 }

// ClientDataHash is the challenge the authenticator signs over. Binding it to
// the canonical manifest is what stops an assertion made over one manifest
// being replayed onto another.
func ClientDataHash(canonical []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(clientDataDomain))
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ParseAuthData reads the fixed header of authenticator data.
//
// The trailing attested-credential-data and extension blocks are not parsed,
// because an assertion has no business carrying them, but their flags are
// still checked against the length so a truncated or padded blob cannot be
// passed off as well-formed.
func ParseAuthData(b []byte) (AuthData, error) {
	if len(b) < authDataMinLen {
		return AuthData{}, fmt.Errorf("%w: %d bytes, need at least %d", ErrMalformedAuthData, len(b), authDataMinLen)
	}
	ad := AuthData{
		RPIDHash:  b[0:32],
		Flags:     b[32],
		SignCount: binary.BigEndian.Uint32(b[33:37]),
	}
	if ad.Flags&(flagAT|flagED) == 0 && len(b) != authDataMinLen {
		return AuthData{}, fmt.Errorf("%w: %d trailing bytes with no attested-credential or extension flag set",
			ErrMalformedAuthData, len(b)-authDataMinLen)
	}
	return ad, nil
}

// Result reports what an accepted assertion did and did not establish.
//
// CounterChecked is not a detail. An authenticator that does not count cannot
// be checked for cloning, and an accepted assertion that quietly skipped that
// check looks identical to one that passed it. The dossier says which.
type Result struct {
	Signer         string `json:"signer"`
	SignCount      uint32 `json:"sign_count"`
	CounterChecked bool   `json:"counter_checked"`
	UserVerified   bool   `json:"user_verified"`
}

// Verify checks one assertion against one credential and the boundary policy.
//
// lastCount is the highest counter previously seen for this credential; zero
// for a credential that has not signed before.
//
// The order is deliberate and runs cheapest-and-most-specific first, so the
// reason reported is the most informative one available rather than whichever
// check happened to run first.
func Verify(a Assertion, c Credential, p Policy, lastCount uint32, canonical []byte) (Result, error) {
	var res Result

	if a.CredentialID != c.ID {
		return res, fmt.Errorf("%w: assertion is for credential %q, checked against %q",
			ErrUnknownCredential, a.CredentialID, c.ID)
	}
	res.Signer = c.Signer

	if c.RPID != p.RPID {
		return res, fmt.Errorf("%w: credential is enrolled for relying party %q, policy is %q",
			ErrRPMismatch, c.RPID, p.RPID)
	}

	ad, err := ParseAuthData(a.AuthData)
	if err != nil {
		return res, err
	}

	want := sha256.Sum256([]byte(p.RPID))
	if !bytes.Equal(ad.RPIDHash, want[:]) {
		return res, fmt.Errorf("%w: assertion was made for a different relying party", ErrRPMismatch)
	}

	// Presence and verification are checked before the signature so that a
	// well-formed assertion made without a human is reported as such rather
	// than passing into the cryptography and being judged only on maths.
	if !ad.UserPresent() {
		return res, fmt.Errorf("%w: the user-presence flag is clear, so nothing was touched", ErrNoUserPresence)
	}
	if p.RequireUV && !ad.UserVerified() {
		return res, fmt.Errorf("%w: policy requires PIN or biometric and the user-verification flag is clear",
			ErrNoUserVerification)
	}
	res.UserVerified = ad.UserVerified()

	cdh := ClientDataHash(canonical)
	signed := append(append([]byte(nil), a.AuthData...), cdh[:]...)
	if err := verifySignature(c, signed, a.Signature); err != nil {
		return res, err
	}

	// Counter last: a regression means a cloned authenticator, and that is
	// only meaningful once the assertion is known to be genuine. Reporting it
	// on a forged assertion would send an operator hunting for a clone that
	// does not exist.
	res.SignCount = ad.SignCount
	switch {
	case ad.SignCount > lastCount:
		res.CounterChecked = true
	case ad.SignCount == 0 && lastCount == 0:
		// The authenticator does not maintain a counter. Cloning cannot be
		// detected for it, which is a fact about the token, not a failure of
		// this assertion.
		if p.RequireCounter {
			return res, fmt.Errorf("%w: this authenticator does not maintain a signature counter",
				ErrCounterUnsupported)
		}
		res.CounterChecked = false
	default:
		return res, fmt.Errorf("%w: counter %d does not exceed the last seen %d, which is what a cloned authenticator looks like",
			ErrCounterRegression, ad.SignCount, lastCount)
	}

	return res, nil
}

func verifySignature(c Credential, signed, sig []byte) error {
	switch c.Alg {
	case AlgEd25519:
		if len(c.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: eddsa credential carries a %d-byte key", ErrAlgorithmMismatch, len(c.PublicKey))
		}
		if !ed25519.Verify(ed25519.PublicKey(c.PublicKey), signed, sig) {
			return fmt.Errorf("%w: eddsa assertion does not verify", ErrBadSignature)
		}
		return nil

	case AlgES256:
		x, y := elliptic.Unmarshal(elliptic.P256(), c.PublicKey)
		if x == nil {
			return fmt.Errorf("%w: es256 credential does not carry a P-256 point", ErrAlgorithmMismatch)
		}
		sum := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, sum[:], sig) {
			return fmt.Errorf("%w: es256 assertion does not verify", ErrBadSignature)
		}
		return nil

	default:
		return fmt.Errorf("%w: credential is enrolled under algorithm %q, which is not supported",
			ErrAlgorithmMismatch, c.Alg)
	}
}
