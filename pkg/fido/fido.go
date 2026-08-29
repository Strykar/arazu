// SPDX-License-Identifier: Apache-2.0

// Package fido verifies FIDO2 assertions used as manifest signatures. An
// assertion proves an enrolled authenticator was physically present, and under
// a user-verification policy that its holder verified themselves to it, so
// two-person control is a property of two people, not of two key files. It
// also carries a relying-party binding, presence and verification flags, and a
// signature counter, each a separate attack a signature check alone passes.
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

// Reason strings the ingress gate reports. Distinct per failure because the
// response differs: a counter regression means a cloned authenticator, an RP
// mismatch a signature harvested elsewhere.
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

	// Mirror the software-key reasons, so a decision reads the same whichever
	// signing path produced it.
	ErrDuplicateSigner     = errors.New("duplicate-signer")
	ErrInsufficientSigners = errors.New("insufficient-signatures")
)

// Algorithm is the COSE algorithm a credential was enrolled with. Enforced per
// credential, so an assertion cannot be presented under a different one.
type Algorithm string

const (
	AlgEd25519 Algorithm = "eddsa"
	AlgES256   Algorithm = "es256"
)

// clientDataDomain separates a manifest signature from every other assertion
// the same token produces, so a login assertion cannot be presented here.
const clientDataDomain = "arazu-manifest-sig-v1\n"

// authenticator data flags, from the CTAP2 spec.
const (
	flagUP = 0x01 // user present: the authenticator was touched
	flagUV = 0x04 // user verified: PIN or biometric satisfied
	flagAT = 0x40 // attested credential data appended
	flagED = 0x80 // extension data appended
)

const authDataMinLen = 37 // rpIdHash(32) + flags(1) + signCount(4)

// Credential is one enrolled authenticator. Signer names the person, not the
// token: counting credentials would let one person holding two of them meet a
// two-signer threshold alone.
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

	// RequireUV demands PIN or biometric. A touch proves the token was
	// present, not who was holding it.
	RequireUV bool `json:"require_uv"`

	// RequireCounter refuses an authenticator with no signature counter, which
	// cannot be checked for cloning. Verify reports which way it went.
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
// the canonical manifest stops an assertion being replayed onto another one.
func ClientDataHash(canonical []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(clientDataDomain))
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ParseAuthData reads the fixed header of authenticator data. The trailing
// blocks are not parsed, but their flags are checked against the length so a
// padded blob cannot pass as well-formed.
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

// Result reports what an accepted assertion did and did not establish. An
// assertion that skipped the cloning check looks identical to one that passed
// it unless CounterChecked says which.
type Result struct {
	Signer         string `json:"signer"`
	SignCount      uint32 `json:"sign_count"`
	CounterChecked bool   `json:"counter_checked"`
	UserVerified   bool   `json:"user_verified"`
}

// Verify checks one assertion against one credential and the boundary policy.
// lastCount is the highest counter seen for this credential, zero if it has not
// signed before. Checks run most-specific first, for the informative reason.
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

	// Presence and verification before the signature, so an assertion made
	// with no human present is reported as such rather than judged on maths.
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

	// Counter last: a regression means a clone only once the signature is
	// known genuine, otherwise the operator hunts a clone that does not exist.
	res.SignCount = ad.SignCount
	switch {
	case ad.SignCount > lastCount:
		res.CounterChecked = true
	case ad.SignCount == 0 && lastCount == 0:
		// No counter on this authenticator. Cloning cannot be detected for it,
		// which is a fact about the token, not a failure of this assertion.
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
