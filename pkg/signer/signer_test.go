// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var msg = []byte(`{"schema":"arazu.bundle/v1","bundle_id":"t","version":1}`)

func softKey(t *testing.T, seed byte) (ed25519.PrivateKey, TrustedKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	sec := ed25519.NewKeyFromSeed(s)
	pub := sec.Public().(ed25519.PublicKey)
	return sec, TrustedKey{ID: KeyIDForEd25519(pub), Alg: AlgEd25519, Ed25519: pub,
		Signer: fmt.Sprintf("signer-%d", seed), NamedSigner: true}
}

func softSig(sec ed25519.PrivateKey) Signature {
	pub := sec.Public().(ed25519.PublicKey)
	return Signature{Alg: AlgEd25519, KeyID: KeyIDForEd25519(pub), Payload: ed25519.Sign(sec, msg)}
}

// newSSHKey makes a software OpenSSH ed25519 key.
//
// This is the same key type and the same signature format a FIDO2 sk key
// produces, and it verifies through the identical code path. Testing with it
// exercises everything the boundary does with a hardware signature, without
// needing a token present or a human to touch it.
func newSSHKey(t *testing.T, name string) (keyPath string, key TrustedKey) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	keyPath = filepath.Join(dir, name)

	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	k, err := parseTrustLine(strings.TrimSpace(string(pub)))
	if err != nil {
		t.Fatal(err)
	}
	return keyPath, k
}

func store(t *testing.T, keys ...TrustedKey) TrustStore {
	t.Helper()
	ts := TrustStore{keys: map[KeyID]TrustedKey{}}
	for _, k := range keys {
		ts.keys[k.ID] = k
	}
	return ts
}

func sigLines(sigs ...Signature) []byte {
	var b strings.Builder
	for _, s := range sigs {
		b.WriteString(s.String() + "\n")
	}
	return []byte(b.String())
}

// --- the software path -------------------------------------------------

func TestSoftwareEd25519RoundTrip(t *testing.T) {
	secA, keyA := softKey(t, 1)
	secB, keyB := softKey(t, 2)

	signers, err := VerifyAll(msg, sigLines(softSig(secA), softSig(secB)), store(t, keyA, keyB), 2)
	if err != nil {
		t.Fatalf("two software signatures rejected: %v", err)
	}
	if len(signers) != 2 {
		t.Fatalf("got %d signers, want 2", len(signers))
	}
}

func TestSoftwareTamperedMessageFails(t *testing.T) {
	secA, keyA := softKey(t, 1)
	secB, keyB := softKey(t, 2)
	sigs := sigLines(softSig(secA), softSig(secB))

	if _, err := VerifyAll([]byte("different"), sigs, store(t, keyA, keyB), 2); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("signatures verified over a different message, err=%v", err)
	}
}

// --- the SSH path, which is the FIDO2 path with the key in software ----

func TestSSHSignatureRoundTrip(t *testing.T) {
	keyPath, key := newSSHKey(t, "signer-a")

	sig, err := SignSSH(keyPath, msg)
	if err != nil {
		t.Fatalf("SignSSH: %v", err)
	}
	if sig.Alg != AlgSSHEd25519 {
		t.Fatalf("algorithm = %s, want %s", sig.Alg, AlgSSHEd25519)
	}
	if sig.KeyID != key.ID {
		t.Fatalf("key id %s does not match the public key %s", sig.KeyID, key.ID)
	}
	if err := Verify(msg, sig, key); err != nil {
		t.Fatalf("a freshly made ssh signature did not verify: %v", err)
	}
}

// The matched twin. A rejection test alone cannot tell a working verifier
// from one broken into refusing everything.
func TestSSHSignatureRejectsATamperedMessage(t *testing.T) {
	keyPath, key := newSSHKey(t, "signer-a")

	sig, err := SignSSH(keyPath, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(msg, sig, key); err != nil {
		t.Fatalf("accept arm failed, so the reject arm below proves nothing: %v", err)
	}
	if err := Verify([]byte("tampered manifest"), sig, key); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("ssh signature verified over a different message, err=%v", err)
	}
}

func TestSSHSignatureFromAnotherKeyIsRejected(t *testing.T) {
	keyPathA, _ := newSSHKey(t, "signer-a")
	_, keyB := newSSHKey(t, "signer-b")

	sig, err := SignSSH(keyPathA, msg)
	if err != nil {
		t.Fatal(err)
	}
	// Present A's signature as though it were B's.
	sig.KeyID = keyB.ID
	if err := Verify(msg, sig, keyB); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("a signature from a different key verified, err=%v", err)
	}
}

// A signature made for another purpose must not count as a manifest
// approval, or any SSH signature the signer ever produced becomes one.
func TestSignatureFromAnotherNamespaceIsRejected(t *testing.T) {
	keyPath, key := newSSHKey(t, "signer-a")
	dir := t.TempDir()
	msgPath := filepath.Join(dir, "m")
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", keyPath, "-n", "some-other-purpose", msgPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen sign: %v: %s", err, out)
	}
	armoured, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}

	sig := Signature{Alg: AlgSSHEd25519, KeyID: key.ID, Payload: armoured}
	if err := Verify(msg, sig, key); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("a signature from another namespace was accepted, err=%v", err)
	}
}

// --- mixing backends ---------------------------------------------------

// Two-person control is about two signers, not two of the same kind of key.
// A software signer and a token holder together must satisfy it.
func TestMixedSoftwareAndSSHSatisfyTwoPersonControl(t *testing.T) {
	secA, keyA := softKey(t, 1)
	keyPathB, keyB := newSSHKey(t, "signer-b")

	sshSig, err := SignSSH(keyPathB, msg)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := VerifyAll(msg, sigLines(softSig(secA), sshSig), store(t, keyA, keyB), 2)
	if err != nil {
		t.Fatalf("mixed-backend two-person control rejected: %v", err)
	}
	if len(signers) != 2 {
		t.Fatalf("got %d signers, want 2", len(signers))
	}
}

// A key provisioned as hardware backed must not be satisfiable by a software
// signature carrying the same key id. Otherwise requiring a token buys
// nothing: an attacker who extracted or forged the key material could
// present it through the cheaper backend.
func TestASoftwareSignatureCannotSatisfyAHardwareProvisionedKey(t *testing.T) {
	keyPath, key := newSSHKey(t, "pretend-token")
	sig, err := SignSSH(keyPath, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Provision the very same key as though it lived on a security key.
	hardware := key
	hardware.Alg = AlgSKEd25519

	if err := Verify(msg, sig, hardware); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("a software signature satisfied a hardware-provisioned signer, err=%v", err)
	}
}

func TestDuplicateSignerAcrossBackendsIsRefused(t *testing.T) {
	keyPath, key := newSSHKey(t, "signer-a")
	sig, err := SignSSH(keyPath, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAll(msg, sigLines(sig, sig), store(t, key), 2); !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("the same key signing twice was accepted, err=%v", err)
	}
}

// --- parsing and trust -------------------------------------------------

func TestUnknownAlgorithmIsRefusedNotIgnored(t *testing.T) {
	line := fmt.Sprintf("rsa-sha2-512 %s %s", "deadbeefdeadbeef",
		base64.StdEncoding.EncodeToString([]byte("x")))
	if _, err := ParseSignature(line); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("unknown algorithm accepted, err=%v", err)
	}
}

func TestTrustStoreReadsEveryBackend(t *testing.T) {
	_, keyA := softKey(t, 1)
	_, sshKey := newSSHKey(t, "signer-b")
	_, tokenKey := newSSHKey(t, "token-c")

	// Stand in for a security key by relabelling a distinct key's blob. The
	// type field is what marks a key as hardware backed, and the blob has to
	// be a different key or it is the same signer twice.
	body := fmt.Sprintf("# provisioned signers\n%s %s\n%s\nsk-ssh-ed25519@openssh.com %s token-c\n",
		keyA.ID, base64.StdEncoding.EncodeToString(keyA.Ed25519),
		sshKey.SSHLine, strings.Fields(tokenKey.SSHLine)[1])

	p := filepath.Join(t.TempDir(), "trusted.pub")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ts, err := LoadTrustStore(p)
	if err != nil {
		t.Fatalf("LoadTrustStore: %v", err)
	}
	if ts.Len() != 3 {
		t.Fatalf("loaded %d keys, want 3", ts.Len())
	}
	if n := ts.HardwareBackedCount(); n != 1 {
		t.Fatalf("hardware-backed count = %d, want 1", n)
	}
}

// Provisioning the same key material under two algorithms must be refused.
//
// The key id covers the key blob, so both lines name the same signer. Left
// alone it would let one person hold two of the provisioned slots and
// satisfy two-person control alone, which is the failure the duplicate-signer
// check exists to prevent, moved from the signature file into the trust
// store where it is easier to miss.
//
// This test exists because writing the fixture above the wrong way produced
// exactly that line, and the store caught it.
func TestSameKeyMaterialUnderTwoAlgorithmsIsRefused(t *testing.T) {
	_, sshKey := newSSHKey(t, "signer-b")
	blob := strings.Fields(sshKey.SSHLine)[1]

	body := fmt.Sprintf("%s\nsk-ssh-ed25519@openssh.com %s same-key-relabelled\n", sshKey.SSHLine, blob)
	p := filepath.Join(t.TempDir(), "trusted.pub")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTrustStore(p)
	if err == nil {
		t.Fatal("the same key material was provisioned twice under two algorithms")
	}
	if !strings.Contains(err.Error(), "provisioned twice") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestTrustStoreRejectsAMismatchedKeyID(t *testing.T) {
	_, keyA := softKey(t, 1)
	_, keyB := softKey(t, 2)

	p := filepath.Join(t.TempDir(), "trusted.pub")
	body := fmt.Sprintf("%s %s\n", keyA.ID, base64.StdEncoding.EncodeToString(keyB.Ed25519))
	os.WriteFile(p, []byte(body), 0o600)

	if _, err := LoadTrustStore(p); err == nil {
		t.Fatal("a line whose key id does not match its key was accepted")
	}
}

func TestUntrustedSignerIsRefused(t *testing.T) {
	secA, keyA := softKey(t, 1)
	_, keyB := softKey(t, 2)
	// Only B is provisioned; A signs.
	if _, err := VerifyAll(msg, sigLines(softSig(secA)), store(t, keyB), 1); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("an unprovisioned signer was accepted, err=%v", err)
	}
	_ = keyA
}

// Two-person control is over people. One person holding two keys is still one
// person, and counting keys would let them satisfy it alone.
//
// This models the peer session's insight: the provisioning file names the
// signer, so the gate can collapse two keys onto one person instead of
// disclaiming the case in SCOPE.md.
func TestOnePersonWithTwoKeysCannotSatisfyTwoPersonControl(t *testing.T) {
	secA, keyA := softKey(t, 1)
	secB, keyB := softKey(t, 2)

	// Both keys belong to the same person.
	keyA.Signer, keyA.NamedSigner = "avinash", true
	keyB.Signer, keyB.NamedSigner = "avinash", true

	_, err := VerifyAll(msg, sigLines(softSig(secA), softSig(secB)), store(t, keyA, keyB), 2)
	if !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("one person with two keys satisfied two-person control, err=%v", err)
	}

	// The matched twin: two different people with the same two keys pass, so
	// the rejection above is about who holds them and not about the keys.
	keyB.Signer = "second-reviewer"
	if _, err := VerifyAll(msg, sigLines(softSig(secA), softSig(secB)), store(t, keyA, keyB), 2); err != nil {
		t.Fatalf("two distinct people were rejected: %v", err)
	}
}

func TestUnnamedKeysAreCountedAndReported(t *testing.T) {
	_, keyA := softKey(t, 1)
	_, keyB := softKey(t, 2)
	p := filepath.Join(t.TempDir(), "trusted.pub")

	body := fmt.Sprintf("%s %s\n%s %s second-reviewer\n",
		keyA.ID, base64.StdEncoding.EncodeToString(keyA.Ed25519),
		keyB.ID, base64.StdEncoding.EncodeToString(keyB.Ed25519))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ts, err := LoadTrustStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := ts.UnnamedCount(); n != 1 {
		t.Fatalf("unnamed count = %d, want 1", n)
	}
	named, _ := ts.Get(keyB.ID)
	if named.Signer != "second-reviewer" || !named.NamedSigner {
		t.Fatalf("signer name not read from the provisioning line: %+v", named)
	}
}

// A TrustedKey built without a Signer must not share an identity with any
// other such key. Treating the empty string as a name would collapse every
// unnamed key onto one person and silently weaken the count.
func TestEmptySignerFallsBackToTheKeyIDNotAnEmptyName(t *testing.T) {
	_, keyA := softKey(t, 1)
	_, keyB := softKey(t, 2)
	keyA.Signer, keyA.NamedSigner = "", false
	keyB.Signer, keyB.NamedSigner = "", false

	if keyA.SignerIdentity() == keyB.SignerIdentity() {
		t.Fatal("two unnamed keys share a signer identity")
	}
	secA, _ := softKey(t, 1)
	secB, _ := softKey(t, 2)
	if _, err := VerifyAll(msg, sigLines(softSig(secA), softSig(secB)), store(t, keyA, keyB), 2); err != nil {
		t.Fatalf("two unnamed keys were treated as one person: %v", err)
	}
}
