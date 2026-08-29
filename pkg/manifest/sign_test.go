// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func keypair(t *testing.T, seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	sec := ed25519.NewKeyFromSeed(seed)
	return sec, sec.Public().(ed25519.PublicKey)
}

func TestTwoDistinctTrustedSignaturesVerify(t *testing.T) {
	secA, pubA := keypair(t, 1)
	secB, pubB := keypair(t, 2)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA, KeyIDFor(pubB): pubB}
	msg := []byte("canonical")

	sigs := []byte(Sign(secA, msg) + "\n" + Sign(secB, msg) + "\n")
	ids, err := VerifySignatures(msg, sigs, trusted, 2)
	if err != nil {
		t.Fatalf("valid two-key signature rejected: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d distinct signers, want 2", len(ids))
	}
}

func TestSingleSignatureIsInsufficient(t *testing.T) {
	secA, pubA := keypair(t, 1)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA}
	msg := []byte("canonical")

	if _, err := VerifySignatures(msg, []byte(Sign(secA, msg)+"\n"), trusted, 2); !errors.Is(err, ErrInsufficientSignatures) {
		t.Fatalf("single signature accepted, err=%v", err)
	}
}

// Two-person control means two people. The same key signing twice must not
// satisfy it, and must not be reported as a short count either.
//
// Both arms are here on purpose. The rejection alone would still pass if
// VerifySignatures were broken into refusing everything, so the accept arm
// through the same call is what makes the rejection mean something.
func TestSameKeyTwiceIsADuplicateSignerNotAShortCount(t *testing.T) {
	secA, pubA := keypair(t, 1)
	secB, pubB := keypair(t, 2)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA, KeyIDFor(pubB): pubB}
	msg := []byte("canonical")

	ids, err := VerifySignatures(msg, []byte(Sign(secA, msg)+"\n"+Sign(secB, msg)+"\n"), trusted, 2)
	if err != nil || len(ids) != 2 {
		t.Fatalf("two distinct signers rejected: ids=%v err=%v", ids, err)
	}

	sigs := []byte(Sign(secA, msg) + "\n" + Sign(secA, msg) + "\n")
	_, err = VerifySignatures(msg, sigs, trusted, 2)
	if !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("one key signing twice reported %v, want duplicate-signer", err)
	}
	if errors.Is(err, ErrInsufficientSignatures) {
		t.Fatal("a duplicate signer was reported as an incomplete bundle")
	}
}

// A duplicate is refused even when enough distinct signers are present. There
// is no legitimate reason for a key to sign the same bytes twice, so the
// padding is treated as the anomaly it is rather than tolerated because the
// count happens to work out.
func TestDuplicateIsRefusedEvenWhenTheThresholdIsOtherwiseMet(t *testing.T) {
	secA, pubA := keypair(t, 1)
	secB, pubB := keypair(t, 2)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA, KeyIDFor(pubB): pubB}
	msg := []byte("canonical")

	sigs := []byte(Sign(secA, msg) + "\n" + Sign(secB, msg) + "\n" + Sign(secA, msg) + "\n")
	if _, err := VerifySignatures(msg, sigs, trusted, 2); !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("padded signature file accepted, err=%v", err)
	}
}

func TestUntrustedSignerRejected(t *testing.T) {
	secA, pubA := keypair(t, 1)
	secX, _ := keypair(t, 9)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA}
	msg := []byte("canonical")

	sigs := []byte(Sign(secA, msg) + "\n" + Sign(secX, msg) + "\n")
	if _, err := VerifySignatures(msg, sigs, trusted, 2); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("untrusted signer accepted, err=%v", err)
	}
}

// An untrusted signature must not be silently skipped. If it were, a bundle
// with one good signature plus noise would pass as two-person control only
// when the count happened to work out, and would report the wrong reason.
func TestUntrustedSignerIsRejectedNotIgnored(t *testing.T) {
	secA, pubA := keypair(t, 1)
	secB, pubB := keypair(t, 2)
	secX, _ := keypair(t, 9)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA, KeyIDFor(pubB): pubB}
	msg := []byte("canonical")

	sigs := []byte(Sign(secA, msg) + "\n" + Sign(secX, msg) + "\n" + Sign(secB, msg) + "\n")
	if _, err := VerifySignatures(msg, sigs, trusted, 2); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("untrusted line ignored because the trusted count was met, err=%v", err)
	}
}

func TestTamperedMessageFailsVerification(t *testing.T) {
	secA, pubA := keypair(t, 1)
	secB, pubB := keypair(t, 2)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA, KeyIDFor(pubB): pubB}

	sigs := []byte(Sign(secA, []byte("canonical")) + "\n" + Sign(secB, []byte("canonical")) + "\n")
	if _, err := VerifySignatures([]byte("CANONICAL"), sigs, trusted, 2); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signatures verified over a different message, err=%v", err)
	}
}

func TestMalformedSignatureLineRejected(t *testing.T) {
	_, pubA := keypair(t, 1)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA}

	for _, bad := range []string{"garbage\n", "rsa abc def\n", "ed25519 onlytwo\n"} {
		if _, err := VerifySignatures([]byte("m"), []byte(bad), trusted, 2); err == nil {
			t.Errorf("malformed signature line %q accepted", bad)
		}
	}
}

func TestEmptySignatureFileIsInsufficient(t *testing.T) {
	_, pubA := keypair(t, 1)
	trusted := map[KeyID]ed25519.PublicKey{KeyIDFor(pubA): pubA}

	if _, err := VerifySignatures([]byte("m"), nil, trusted, 2); !errors.Is(err, ErrInsufficientSignatures) {
		t.Fatalf("empty signature file accepted, err=%v", err)
	}
}

func TestLoadPublicKeysRejectsMismatchedKeyID(t *testing.T) {
	_, pubA := keypair(t, 1)
	_, pubB := keypair(t, 2)
	p := filepath.Join(t.TempDir(), "trusted.pub")

	// The line claims key A's id but carries key B's material.
	line := fmt.Sprintf("%s %s\n", KeyIDFor(pubA), base64.StdEncoding.EncodeToString(pubB))
	os.WriteFile(p, []byte(line), 0o600)

	if _, err := LoadPublicKeys(p); err == nil {
		t.Fatal("trusted-keys file with a mismatched key id accepted")
	}
}

func TestLoadPublicKeysRoundTrip(t *testing.T) {
	_, pubA := keypair(t, 1)
	_, pubB := keypair(t, 2)
	p := filepath.Join(t.TempDir(), "trusted.pub")

	body := fmt.Sprintf("# comment\n%s %s\n\n%s %s\n",
		KeyIDFor(pubA), base64.StdEncoding.EncodeToString(pubA),
		KeyIDFor(pubB), base64.StdEncoding.EncodeToString(pubB))
	os.WriteFile(p, []byte(body), 0o600)

	keys, err := LoadPublicKeys(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("loaded %d keys, want 2", len(keys))
	}
}
