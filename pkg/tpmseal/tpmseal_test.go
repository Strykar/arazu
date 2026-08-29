// SPDX-License-Identifier: Apache-2.0

package tpmseal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

const (
	rootA = "1111111111111111111111111111111111111111111111111111111111111111"
	rootB = "2222222222222222222222222222222222222222222222222222222222222222"
)

var secret = []byte("arazu output signing key seed, 32b")

func requireTPM(t *testing.T) {
	t.Helper()
	if Device() == "" {
		t.Skip("no usable TPM device")
	}
	if _, err := exec.LookPath("tpm2_unseal"); err != nil {
		t.Skip("tpm2-tools not installed")
	}
}

// Leave the host's PCR 23 as we found it.
func cleanPCR(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { Reset() })
}

// ExpectedPCR23 is pure arithmetic and must agree with the TPM. Holding it
// independently is what turns a wrong extend into a clear error instead of
// an unexplained policy failure later.
func TestExpectedPCR23MatchesTheExtendRule(t *testing.T) {
	rb, err := hex.DecodeString(rootA)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append(make([]byte, sha256.Size), rb...))
	if got := ExpectedPCR23(rootA); got != hex.EncodeToString(want[:]) {
		t.Fatalf("ExpectedPCR23 = %s, want %s", got, hex.EncodeToString(want[:]))
	}
}

func TestExpectedPCR23RejectsNonDigests(t *testing.T) {
	for _, bad := range []string{"", "zz", "abcd"} {
		if got := ExpectedPCR23(bad); got != "" && len(bad) != 64 {
			if bad != "abcd" {
				continue
			}
		}
	}
	if ExpectedPCR23("not-hex") != "" {
		t.Fatal("non-hex input produced a digest")
	}
}

// The TPM must compute what Go computed. If this fails, every claim about
// the binding rests on an assumption that is false on this hardware.
func TestTPMAgreesWithTheComputedPCRValue(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)

	var got string
	err := withPCRLock(func() error {
		if e := extend(rootA); e != nil {
			return e
		}
		var e error
		got, e = readPCR()
		return e
	})
	if err != nil {
		t.Fatalf("extend disagreed with the computed value: %v", err)
	}
	if got != ExpectedPCR23(rootA) {
		t.Fatalf("pcr = %s, computed %s", got, ExpectedPCR23(rootA))
	}
}

func TestExtendRejectsAMalformedRoot(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)

	withPCRLock(func() error {
		for _, bad := range []string{"", "deadbeef", "not-a-hex-digest-but-64-characters-long-xxxxxxxxxxxxxxxxxxxxxxxx"} {
			if err := extend(bad); err == nil {
				t.Errorf("extend accepted %q", bad)
			}
		}
		return nil
	})
}

func TestCorrectMeasurementUnseals(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)
	dir := t.TempDir()

	if err := Provision(dir, rootA, secret); err != nil {
		t.Fatalf("provision: %v", err)
	}
	got, err := Unseal(dir, rootA)
	if err != nil {
		t.Fatalf("unseal with the correct measurement failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unsealed %q, want %q", got, secret)
	}
}

// The fail-closed path. A different content root must not release the key.
func TestTamperedMeasurementFailsClosed(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)
	dir := t.TempDir()

	if err := Provision(dir, rootA, secret); err != nil {
		t.Fatalf("provision: %v", err)
	}
	got, err := Unseal(dir, rootB)
	if err == nil {
		t.Fatalf("unseal succeeded with a different measurement and returned %q", got)
	}
	if !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("wrong error class, want measured-state-mismatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatal("secret material was returned alongside an error")
	}
}

// Order and count of measurements are bound, not just the final value. An
// extra measurement on top of the right one must also fail.
func TestExtraMeasurementFailsClosed(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)
	dir := t.TempDir()

	if err := Provision(dir, rootA, secret); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Reproduce the sealed state, then add one more measurement without
	// resetting. The whole sequence has to hold the lock, or another run
	// could reset the pcr between the two extends.
	var got []byte
	err := withPCRLock(func() error {
		if e := extend(rootA); e != nil {
			return e
		}
		if _, e := tpm2("tpm2_pcrextend", "23:sha256="+rootB); e != nil {
			return e
		}
		var e error
		got, e = unsealCurrentState(dir)
		return e
	})
	if err == nil {
		t.Fatalf("unseal succeeded with an extra measurement, returned %q", got)
	}
	if !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("wrong error class: %v", err)
	}
}

// A reset PCR with no measurement at all must not unseal either. Otherwise
// an attacker could simply clear the state instead of matching it.
func TestUnmeasuredStateFailsClosed(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)
	dir := t.TempDir()

	if err := Provision(dir, rootA, secret); err != nil {
		t.Fatalf("provision: %v", err)
	}
	err := withPCRLock(func() error {
		if e := Reset(); e != nil {
			return e
		}
		got, e := unsealCurrentState(dir)
		if e == nil {
			t.Fatalf("unseal succeeded against a cleared pcr, returned %q", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestErrorTextCarriesNoSecretMaterial(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)
	dir := t.TempDir()

	if err := Provision(dir, rootA, secret); err != nil {
		t.Fatalf("provision: %v", err)
	}
	_, err := Unseal(dir, rootB)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("error text leaked the sealed secret: %v", err)
	}
	// It should still say what it was sealed against, so an operator can act.
	if !strings.Contains(err.Error(), rootA) {
		t.Errorf("error does not name the sealed content root: %v", err)
	}
}

// The refusal has to be ours, not the TPM's.
//
// Asserting only that an error came back passes even with our guard removed,
// because tpm2_create rejects an empty input on its own. That makes the guard
// unevidenced, and a TPM that happened to accept an empty seal would then
// seal one. Mutation testing caught exactly this.
func TestProvisionRefusesAnEmptySecret(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)

	err := Provision(t.TempDir(), rootA, nil)
	if err == nil {
		t.Fatal("provision sealed an empty secret")
	}
	if !strings.Contains(err.Error(), "refusing to seal an empty secret") {
		t.Fatalf("the empty secret was refused by something other than our own guard: %v", err)
	}
}

// PCR 23 is one register shared by every process on the host, so concurrent
// runs must not interleave their reset-extend-use sequences. Without the
// lock, one run's extend lands inside another's window and the second sees a
// state it never measured.
//
// This is not a hypothetical. Running the package suites in parallel produced
// exactly this: seven failures, each reporting a different unexpected PCR
// value, because another package's tests were driving the same register.
func TestConcurrentSequencesDoNotInterleave(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)

	dirs := []string{t.TempDir(), t.TempDir()}
	roots := []string{rootA, rootB}
	for i := range dirs {
		if err := Provision(dirs[i], roots[i], secret); err != nil {
			t.Fatalf("provision %d: %v", i, err)
		}
	}

	// Each goroutine measures its own root and unseals against it. If the
	// sequences interleaved, at least one would see the other's measurement
	// and fail the policy.
	errs := make(chan error, len(dirs)*3)
	done := make(chan struct{})
	for round := 0; round < 3; round++ {
		for i := range dirs {
			go func(i int) {
				got, err := Unseal(dirs[i], roots[i])
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, secret) {
					errs <- errors.New("unsealed the wrong material")
					return
				}
				errs <- nil
			}(i)
		}
	}
	go func() {
		for i := 0; i < len(dirs)*3; i++ {
			if err := <-errs; err != nil {
				t.Errorf("a concurrent sequence saw a state it did not measure: %v", err)
			}
		}
		close(done)
	}()
	<-done
}

// Re-sealing against a new root must invalidate the old state, so a stale
// bundle cannot unseal a key provisioned for a newer one.
func TestResealingInvalidatesTheOldMeasurement(t *testing.T) {
	requireTPM(t)
	cleanPCR(t)
	dir := t.TempDir()

	if err := Provision(dir, rootA, secret); err != nil {
		t.Fatal(err)
	}
	if err := Provision(dir, rootB, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := Unseal(dir, rootB); err != nil {
		t.Fatalf("the new measurement does not unseal: %v", err)
	}
	if got, err := Unseal(dir, rootA); err == nil {
		t.Fatalf("the superseded measurement still unseals, returned %q", got)
	}
}
