// SPDX-License-Identifier: Apache-2.0

package fido

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// A software authenticator, so every path can be exercised without a human
// touching a token.
//
// This is not a convenience. The hardware can only produce assertions that are
// correct, which means the hardware alone can test exactly one of the paths
// below. Every rejection needs an assertion the real authenticator would never
// make, and the only way to get one is to build it.
type authenticator struct {
	alg   Algorithm
	ed    ed25519.PrivateKey
	ec    *ecdsa.PrivateKey
	rpid  string
	count uint32
}

func newAuth(t *testing.T, alg Algorithm, rpid string) *authenticator {
	t.Helper()
	a := &authenticator{alg: alg, rpid: rpid}
	switch alg {
	case AlgEd25519:
		_, sec, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		a.ed = sec
	case AlgES256:
		sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		a.ec = sec
	}
	return a
}

func (a *authenticator) pub() []byte {
	if a.alg == AlgEd25519 {
		return a.ed.Public().(ed25519.PublicKey)
	}
	return elliptic.Marshal(elliptic.P256(), a.ec.X, a.ec.Y)
}

func (a *authenticator) credential(id, signer string) Credential {
	return Credential{ID: id, Signer: signer, Alg: a.alg, PublicKey: a.pub(), RPID: a.rpid}
}

// authData builds the fixed 37-byte header the authenticator returns.
func authData(rpid string, flags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpid))
	b := make([]byte, 0, authDataMinLen)
	b = append(b, h[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, count)
	return b
}

func (a *authenticator) sign(t *testing.T, ad, canonical []byte) []byte {
	t.Helper()
	cdh := ClientDataHash(canonical)
	signed := append(append([]byte(nil), ad...), cdh[:]...)
	switch a.alg {
	case AlgEd25519:
		return ed25519.Sign(a.ed, signed)
	default:
		sum := sha256.Sum256(signed)
		sig, err := ecdsa.SignASN1(rand.Reader, a.ec, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

// assert produces a well-formed assertion: touched, verified, counter advanced.
func (a *authenticator) assert(t *testing.T, id string, canonical []byte) Assertion {
	t.Helper()
	a.count++
	return a.assertRaw(t, id, canonical, flagUP|flagUV, a.count)
}

// assertRaw produces an assertion with whatever flags and counter are asked
// for, including combinations a real authenticator would refuse to make.
func (a *authenticator) assertRaw(t *testing.T, id string, canonical []byte, flags byte, count uint32) Assertion {
	t.Helper()
	ad := authData(a.rpid, flags, count)
	return Assertion{CredentialID: id, AuthData: ad, Signature: a.sign(t, ad, canonical)}
}

const rp = "arazu.enclave.local"

var canonical = []byte(`{"bundle_id":"arazu-spike","version":2}`)

func strictPolicy() Policy { return Policy{RPID: rp, RequireUV: true, RequireCounter: false} }

// Every rejection below is paired with the accept that differs from it in one
// variable. A rejection on its own cannot distinguish a check that works from
// a verifier that refuses everything.

func TestValidAssertionIsAcceptedAndBadSignatureIsNot(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")

	good := a.assert(t, "cred-1", canonical)
	res, err := Verify(good, c, strictPolicy(), 0, canonical)
	if err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	if res.Signer != "avinash" || !res.UserVerified || !res.CounterChecked {
		t.Fatalf("accepted with the wrong result: %+v", res)
	}

	bad := good
	bad.Signature = append([]byte(nil), good.Signature...)
	bad.Signature[0] ^= 0x01
	if _, err := Verify(bad, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("flipped signature bit reported %v, want fido-bad-signature", err)
	}
}

func TestES256AssertionRoundTrips(t *testing.T) {
	a := newAuth(t, AlgES256, rp)
	c := a.credential("cred-ec", "bhavna")

	good := a.assert(t, "cred-ec", canonical)
	if _, err := Verify(good, c, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("valid es256 assertion rejected: %v", err)
	}

	bad := good
	bad.Signature = append([]byte(nil), good.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 0x01
	if _, err := Verify(bad, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("corrupt es256 signature reported %v, want fido-bad-signature", err)
	}
}

// The assertion is bound to the manifest it was made over. Without that, an
// assertion captured while signing one bundle could be attached to another,
// and every other check in here would still pass: same credential, same
// relying party, presence and verification set, counter fresh.
func TestAnAssertionDoesNotTransferToAnotherManifest(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")
	other := []byte(`{"bundle_id":"arazu-spike","version":3}`)

	sig := a.assert(t, "cred-1", canonical)
	if _, err := Verify(sig, c, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("assertion rejected over its own manifest: %v", err)
	}
	if _, err := Verify(sig, c, strictPolicy(), 0, other); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an assertion made over one manifest verified against another: %v", err)
	}
}

// An assertion the token made for some other relying party must not count
// here. This is the cross-service replay: the signature is genuine, the
// credential is real, the human really did touch the key, but they were
// logging into something else at the time.
func TestAnAssertionForAnotherRelyingPartyIsRefused(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")
	if _, err := Verify(a.assert(t, "cred-1", canonical), c, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("assertion for the right relying party rejected: %v", err)
	}

	elsewhere := newAuth(t, AlgEd25519, "some-other-service.example")
	elsewhere.ed = a.ed // same token, same key material, different service
	stolen := elsewhere.assert(t, "cred-1", canonical)
	if _, err := Verify(stolen, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrRPMismatch) {
		t.Fatalf("assertion from another relying party reported %v, want fido-rp-mismatch", err)
	}
}

// A credential provisioned for a different relying party than the policy is a
// provisioning error, and is caught before any cryptography runs.
//
// The second arm is the one that makes this check load-bearing, and mutation
// testing is what found it missing: with the assertion also made for the wrong
// relying party, the rpIdHash comparison further down catches it anyway, so
// breaking this check left the suite green. The case only this check sees is a
// store entry that records the credential under one relying party while the
// authenticator asserts for another. The signature verifies and the rpIdHash
// matches the policy, so every later check passes, and the boundary would be
// trusting a key its own records say belongs somewhere else.
func TestCredentialEnrolledForAnotherRelyingPartyIsRefused(t *testing.T) {
	a := newAuth(t, AlgEd25519, "wrong-rp.example")
	c := a.credential("cred-1", "avinash")
	if _, err := Verify(a.assert(t, "cred-1", canonical), c, strictPolicy(), 0, canonical); !errors.Is(err, ErrRPMismatch) {
		t.Fatalf("credential enrolled elsewhere reported %v, want fido-rp-mismatch", err)
	}

	// Assertion for the policy's relying party, credential recorded under a
	// different one. Accept arm first, differing only in the recorded value.
	live := newAuth(t, AlgEd25519, rp)
	consistent := live.credential("cred-1", "avinash")
	if _, err := Verify(live.assert(t, "cred-1", canonical), consistent, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("consistent credential rejected: %v", err)
	}

	misprovisioned := consistent
	misprovisioned.RPID = "stale-rp.example"
	if _, err := Verify(live.assert(t, "cred-1", canonical), misprovisioned, strictPolicy(), 0, canonical); !errors.Is(err, ErrRPMismatch) {
		t.Fatalf("credential recorded under another relying party reported %v, want fido-rp-mismatch", err)
	}
}

// Presence is what makes this a human act rather than a computation. An
// assertion with the flag clear was produced without anyone touching anything.
func TestUserPresenceIsRequired(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")

	touched := a.assertRaw(t, "cred-1", canonical, flagUP|flagUV, 1)
	if _, err := Verify(touched, c, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("touched assertion rejected: %v", err)
	}

	untouched := a.assertRaw(t, "cred-1", canonical, flagUV, 2)
	if _, err := Verify(untouched, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrNoUserPresence) {
		t.Fatalf("assertion with no user presence reported %v, want fido-no-user-presence", err)
	}
}

// Presence proves the token was there. Verification proves who was holding it.
// Under a policy that demands the second, the first is not a substitute, and
// the two arms differ only in the policy so the check cannot be passing for
// some other reason.
func TestUserVerificationIsRequiredOnlyWhenPolicySaysSo(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")
	presenceOnly := a.assertRaw(t, "cred-1", canonical, flagUP, 1)

	lax := Policy{RPID: rp, RequireUV: false}
	res, err := Verify(presenceOnly, c, lax, 0, canonical)
	if err != nil {
		t.Fatalf("touch-only assertion rejected under a policy that allows it: %v", err)
	}
	if res.UserVerified {
		t.Fatal("a touch-only assertion was reported as user-verified")
	}

	if _, err := Verify(presenceOnly, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrNoUserVerification) {
		t.Fatalf("touch-only assertion under a strict policy reported %v, want fido-no-user-verification", err)
	}
}

// A counter that does not advance is what a cloned authenticator looks like:
// the clone does not know how many times the original has signed.
func TestCounterMustAdvance(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")

	if _, err := Verify(a.assertRaw(t, "cred-1", canonical, flagUP|flagUV, 8), c, strictPolicy(), 7, canonical); err != nil {
		t.Fatalf("advancing counter rejected: %v", err)
	}
	for _, count := range []uint32{7, 6, 1} {
		got := a.assertRaw(t, "cred-1", canonical, flagUP|flagUV, count)
		if _, err := Verify(got, c, strictPolicy(), 7, canonical); !errors.Is(err, ErrCounterRegression) {
			t.Errorf("counter %d against last-seen 7 reported %v, want fido-counter-regression", count, err)
		}
	}
}

// Some authenticators do not count at all. That is a fact about the token, and
// the honest handling is to say so rather than to let an unchecked counter
// look like a checked one. Both arms of the policy are here because the
// difference between them is the entire point of reporting it.
func TestAnAuthenticatorThatDoesNotCountIsReportedNotHidden(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")
	uncounted := a.assertRaw(t, "cred-1", canonical, flagUP|flagUV, 0)

	res, err := Verify(uncounted, c, Policy{RPID: rp, RequireUV: true, RequireCounter: false}, 0, canonical)
	if err != nil {
		t.Fatalf("uncounted assertion rejected under a policy that allows it: %v", err)
	}
	if res.CounterChecked {
		t.Fatal("an assertion from an authenticator with no counter was reported as counter-checked")
	}

	strict := Policy{RPID: rp, RequireUV: true, RequireCounter: true}
	if _, err := Verify(uncounted, c, strict, 0, canonical); !errors.Is(err, ErrCounterUnsupported) {
		t.Fatalf("uncounted assertion under a counter-requiring policy reported %v, want fido-counter-unsupported", err)
	}
}

// Once a credential has counted, a later zero is a regression rather than a
// token that never counted. Reading it as "no counter support" would let a
// clone reporting zero erase the history of the real token.
func TestZeroCounterAfterACountedAssertionIsARegression(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")
	zero := a.assertRaw(t, "cred-1", canonical, flagUP|flagUV, 0)

	if _, err := Verify(zero, c, strictPolicy(), 5, canonical); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("a zero counter after last-seen 5 reported %v, want fido-counter-regression", err)
	}
}

func TestAssertionForAnotherCredentialIsRefused(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")

	mismatched := a.assert(t, "cred-2", canonical)
	if _, err := Verify(mismatched, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("assertion naming another credential reported %v, want fido-unknown-credential", err)
	}
}

func TestMalformedAuthenticatorDataIsRefused(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	c := a.credential("cred-1", "avinash")
	good := a.assert(t, "cred-1", canonical)

	if _, err := Verify(good, c, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("well-formed authenticator data rejected: %v", err)
	}

	cases := map[string][]byte{
		"empty":     {},
		"truncated": good.AuthData[:authDataMinLen-1],
		// Trailing bytes with neither the attested-credential nor the
		// extension flag set. A verifier that read only the first 37 bytes
		// would ignore whatever was appended.
		"unflagged trailing data": append(append([]byte(nil), good.AuthData...), 0xde, 0xad),
	}
	for name, ad := range cases {
		bad := good
		bad.AuthData = ad
		if _, err := Verify(bad, c, strictPolicy(), 0, canonical); !errors.Is(err, ErrMalformedAuthData) {
			t.Errorf("%s reported %v, want fido-malformed-authdata", name, err)
		}
	}
}

// A credential is pinned to the algorithm it was enrolled under, so an
// assertion cannot be presented under a different one. Without the pin, the
// verifier would pick its interpretation from attacker-supplied data.
func TestAlgorithmIsPinnedToTheCredential(t *testing.T) {
	ed := newAuth(t, AlgEd25519, rp)
	good := ed.credential("cred-1", "avinash")
	if _, err := Verify(ed.assert(t, "cred-1", canonical), good, strictPolicy(), 0, canonical); err != nil {
		t.Fatalf("assertion under its enrolled algorithm rejected: %v", err)
	}

	// The same ed25519 key material, claimed to be an es256 credential.
	confused := good
	confused.Alg = AlgES256
	if _, err := Verify(ed.assert(t, "cred-1", canonical), confused, strictPolicy(), 0, canonical); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("ed25519 key presented as es256 reported %v, want fido-algorithm-mismatch", err)
	}

	unknown := good
	unknown.Alg = "rs256"
	if _, err := Verify(ed.assert(t, "cred-1", canonical), unknown, strictPolicy(), 0, canonical); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("unsupported algorithm reported %v, want fido-algorithm-mismatch", err)
	}

	short := good
	short.PublicKey = good.PublicKey[:16]
	if _, err := Verify(ed.assert(t, "cred-1", canonical), short, strictPolicy(), 0, canonical); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("truncated eddsa key reported %v, want fido-algorithm-mismatch", err)
	}
}
