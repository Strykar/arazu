// SPDX-License-Identifier: Apache-2.0

package fido

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func store(t *testing.T, p Policy, creds ...Credential) *Store {
	t.Helper()
	s := &Store{Policy: p, Credentials: creds, Counters: map[string]uint32{}, byID: map[string]Credential{}}
	for _, c := range creds {
		s.byID[c.ID] = c
	}
	return s
}

func TestTwoDistinctSignersSatisfyTwoPersonControl(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	b := newAuth(t, AlgEd25519, rp)
	s := store(t, strictPolicy(), a.credential("cred-a", "avinash"), b.credential("cred-b", "bhavna"))

	res, err := s.VerifyAll([]Assertion{
		a.assert(t, "cred-a", canonical),
		b.assert(t, "cred-b", canonical),
	}, canonical, 2)
	if err != nil {
		t.Fatalf("two distinct signers rejected: %v", err)
	}
	if len(res) != 2 || res[0].Signer == res[1].Signer {
		t.Fatalf("accepted with signers %+v", res)
	}
}

// The path a naive implementation misses.
//
// Two credentials, two different tokens, two genuine touches, two valid
// assertions, two distinct credential IDs. Everything a per-credential check
// looks at says this is two signers. It is one person with two keys, which is
// exactly as much two-person control as one person with one key.
func TestOnePersonWithTwoTokensIsStillOnePerson(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	b := newAuth(t, AlgEd25519, rp)
	other := newAuth(t, AlgEd25519, rp)

	s := store(t, strictPolicy(),
		a.credential("cred-a1", "avinash"),
		b.credential("cred-a2", "avinash"), // same person, second token
		other.credential("cred-b", "bhavna"),
	)

	// Accept arm: two people.
	if _, err := s.VerifyAll([]Assertion{
		a.assert(t, "cred-a1", canonical),
		other.assert(t, "cred-b", canonical),
	}, canonical, 2); err != nil {
		t.Fatalf("two people rejected: %v", err)
	}

	// Reject arm: one person, both of their tokens.
	_, err := s.VerifyAll([]Assertion{
		a.assert(t, "cred-a1", canonical),
		b.assert(t, "cred-a2", canonical),
	}, canonical, 2)
	if !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("one person using two enrolled tokens reported %v, want duplicate-signer", err)
	}
}

func TestTheSameCredentialTwiceIsADuplicateSigner(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	b := newAuth(t, AlgEd25519, rp)
	s := store(t, strictPolicy(), a.credential("cred-a", "avinash"), b.credential("cred-b", "bhavna"))

	_, err := s.VerifyAll([]Assertion{
		a.assert(t, "cred-a", canonical),
		a.assert(t, "cred-a", canonical),
	}, canonical, 2)
	if !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("the same credential twice reported %v, want duplicate-signer", err)
	}
}

func TestOneSignerIsInsufficient(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	s := store(t, strictPolicy(), a.credential("cred-a", "avinash"))

	if _, err := s.VerifyAll([]Assertion{a.assert(t, "cred-a", canonical)}, canonical, 2); !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("one signer reported %v, want insufficient-signatures", err)
	}
	if _, err := s.VerifyAll([]Assertion{a.assert(t, "cred-a", canonical)}, canonical, 1); err != nil {
		t.Fatalf("one signer rejected against a threshold of one: %v", err)
	}
}

func TestAnUnprovisionedCredentialIsRefused(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	rogue := newAuth(t, AlgEd25519, rp)
	s := store(t, strictPolicy(), a.credential("cred-a", "avinash"))

	_, err := s.VerifyAll([]Assertion{
		a.assert(t, "cred-a", canonical),
		rogue.assert(t, "cred-rogue", canonical),
	}, canonical, 2)
	if !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("unprovisioned credential reported %v, want fido-unknown-credential", err)
	}

	// An assertion naming no credential at all. Mutation testing found this
	// gap: for any non-empty name, dropping the store lookup still refuses the
	// assertion, because the zero-valued credential it falls through with has
	// an ID that cannot match. An empty name is the one input where the zero
	// value does match, and the reason then comes back as a relying-party
	// mismatch, which sends an operator looking for the wrong thing.
	anonymous := rogue.assert(t, "", canonical)
	if _, err := s.VerifyAll([]Assertion{a.assert(t, "cred-a", canonical), anonymous}, canonical, 2); !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("assertion naming no credential reported %v, want fido-unknown-credential", err)
	}
}

// A refused bundle must not burn a counter. If it did, an attacker could
// replay a captured assertion at a high counter value, have it refused for
// some other reason, and leave the real signer unable to sign at all.
func TestCountersAdvanceOnlyOnAcceptance(t *testing.T) {
	a := newAuth(t, AlgEd25519, rp)
	b := newAuth(t, AlgEd25519, rp)
	s := store(t, strictPolicy(), a.credential("cred-a", "avinash"), b.credential("cred-b", "bhavna"))

	// A set that verifies individually but fails the threshold.
	one := []Assertion{a.assert(t, "cred-a", canonical)}
	if _, err := s.VerifyAll(one, canonical, 2); err == nil {
		t.Fatal("setup: expected the threshold to refuse a single signer")
	}
	if got := s.Counters["cred-a"]; got != 0 {
		t.Fatalf("a refused bundle advanced the counter to %d", got)
	}

	pair := []Assertion{a.assert(t, "cred-a", canonical), b.assert(t, "cred-b", canonical)}
	res, err := s.VerifyAll(pair, canonical, 2)
	if err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	s.Commit(res, pair)
	if s.Counters["cred-a"] == 0 || s.Counters["cred-b"] == 0 {
		t.Fatalf("counters not advanced after acceptance: %+v", s.Counters)
	}

	// And a replay of the committed assertions is now a regression.
	if _, err := s.VerifyAll(pair, canonical, 2); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("replaying committed assertions reported %v, want fido-counter-regression", err)
	}
}

func TestLoadStoreRefusesCredentialsItCannotAttribute(t *testing.T) {
	write := func(t *testing.T, v any) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "creds.json")
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(p, b, 0o600)
		return p
	}

	good := Store{
		Policy:      strictPolicy(),
		Credentials: []Credential{{ID: "c1", Signer: "avinash", Alg: AlgEd25519, PublicKey: make([]byte, 32), RPID: rp}},
	}
	if _, err := LoadStore(write(t, good)); err != nil {
		t.Fatalf("a well-formed store was rejected: %v", err)
	}

	bad := map[string]Store{
		"blank signer": {Credentials: []Credential{{ID: "c1", Signer: ""}}},
		"blank id":     {Credentials: []Credential{{ID: "", Signer: "avinash"}}},
		"no credentials": {
			Credentials: nil,
		},
		"credential provisioned twice": {Credentials: []Credential{
			{ID: "c1", Signer: "avinash"}, {ID: "c1", Signer: "bhavna"},
		}},
	}
	for name, s := range bad {
		if _, err := LoadStore(write(t, s)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
