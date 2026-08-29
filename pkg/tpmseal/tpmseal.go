// SPDX-License-Identifier: Apache-2.0

// Package tpmseal binds the output signing key to a measured state.
//
// The content root of the accepted bundle is extended into PCR 23, and the
// signing secret is sealed under a policy over that PCR. Unsealing therefore
// succeeds only when the runtime measurement reproduces the one sealing was
// done against. Tampering with the content after the gate changes the root,
// the policy stops matching, and signing is refused rather than producing a
// signature over compromised output.
//
// What this proves is measurement equality: "this is the reviewed thing". It
// is not a judgement that the thing is good, and it is not remote
// attestation. PCR 23 is resettable, which is what makes it usable for a
// spike and also what limits the claim; production binds to non-resettable
// measured-boot PCRs established by firmware. SCOPE.md says so.
package tpmseal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// PCR is the index the spike measures into. 23 is the conventional
// application PCR and is resettable from locality 0, which is what lets a
// run reproduce a measurement.
const PCR = 23

// ErrPolicyMismatch is returned when the runtime measurement does not
// reproduce the sealed one.
var ErrPolicyMismatch = errors.New("measured-state-mismatch")

// tpmRCPolicyFail is TPM2_RC_POLICY_FAIL as tpm2-tools reports it.
const tpmRCPolicyFail = "0x99d"

// PCR 23 is one register on one TPM, so a reset-extend-use sequence is only
// meaningful if nothing else touches it in between. Two concurrent runs would
// otherwise interleave their measurements and each would see a state neither
// intended, which surfaces as an unexplained policy failure or, worse, as one
// run unsealing against another's measurement.
//
// The lock covers the whole sequence, not the individual commands: holding it
// per command would serialise the calls while still letting the sequences
// interleave.
func lockPath() string {
	for _, dir := range []string{"/run", os.TempDir()} {
		if f, err := os.OpenFile(filepath.Join(dir, ".arazu-pcr23.lock"),
			os.O_CREATE|os.O_RDWR, 0o600); err == nil {
			f.Close()
			return filepath.Join(dir, ".arazu-pcr23.lock")
		}
	}
	return ""
}

// withPCRLock runs fn holding an exclusive lock on the PCR.
func withPCRLock(fn func() error) error {
	p := lockPath()
	if p == "" {
		return errors.New("cannot create a pcr lock file; refusing to race another run")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("cannot lock the pcr: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	return fn()
}

// Device returns the TPM device to talk to, preferring the kernel resource
// manager so we do not race it on the raw device.
func Device() string {
	for _, d := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if f, err := os.OpenFile(d, os.O_RDWR, 0); err == nil {
			f.Close()
			return d
		}
	}
	return ""
}

func tpm2(args ...string) ([]byte, error) {
	dev := Device()
	if dev == "" {
		return nil, errors.New("no usable TPM device")
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=device:"+dev)

	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// ExpectedPCR23 is the value a reset-then-extend produces, computed without
// the TPM.
//
// Holding this independently means a wrong extend is caught at the extend,
// where the cause is obvious, instead of surfacing later as an unexplained
// policy failure.
func ExpectedPCR23(contentRoot string) string {
	digest, err := hex.DecodeString(contentRoot)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append(make([]byte, sha256.Size), digest...))
	return hex.EncodeToString(sum[:])
}

func readPCR() (string, error) {
	out, err := tpm2("tpm2_pcrread", fmt.Sprintf("sha256:%d", PCR))
	if err != nil {
		return "", err
	}
	// Output looks like "  sha256:\n    23: 0xAB...\n".
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "0x"); i >= 0 && strings.Contains(line, fmt.Sprintf("%d", PCR)) {
			return strings.ToLower(strings.TrimSpace(line[i+2:])), nil
		}
	}
	return "", fmt.Errorf("cannot parse pcr %d from: %s", PCR, out)
}

// extend resets the PCR and extends it with one measurement, then confirms
// the TPM produced the value we expected.
func extend(contentRoot string) error {
	if _, err := hex.DecodeString(contentRoot); err != nil || len(contentRoot) != 64 {
		return fmt.Errorf("content root %q is not a sha256 hex digest", contentRoot)
	}
	if _, err := tpm2("tpm2_pcrreset", fmt.Sprintf("%d", PCR)); err != nil {
		return err
	}
	if _, err := tpm2("tpm2_pcrextend", fmt.Sprintf("%d:sha256=%s", PCR, contentRoot)); err != nil {
		return err
	}

	got, err := readPCR()
	if err != nil {
		return err
	}
	if want := ExpectedPCR23(contentRoot); got != want {
		return fmt.Errorf("pcr %d is %s after extending %s, expected %s", PCR, got, contentRoot, want)
	}
	return nil
}

func flush(ctx string) {
	if ctx == "" {
		return
	}
	_, _ = tpm2("tpm2_flushcontext", ctx)
}

// Provision measures contentRoot into the PCR and seals secret under a
// policy over the resulting state.
func Provision(dir, contentRoot string, secret []byte) error {
	return withPCRLock(func() error { return provision(dir, contentRoot, secret) })
}

func provision(dir, contentRoot string, secret []byte) error {
	if len(secret) == 0 {
		return errors.New("refusing to seal an empty secret")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := func(name string) string { return filepath.Join(dir, name) }

	if err := extend(contentRoot); err != nil {
		return err
	}

	// A trial session computes the policy digest for the state we just
	// measured, without authorising anything.
	trial := p("trial.ctx")
	if _, err := tpm2("tpm2_startauthsession", "-S", trial); err != nil {
		return err
	}
	_, err := tpm2("tpm2_policypcr", "-S", trial, "-l", fmt.Sprintf("sha256:%d", PCR), "-L", p("policy.digest"))
	flush(trial)
	if err != nil {
		return err
	}

	if _, err := tpm2("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", p("primary.ctx")); err != nil {
		return err
	}
	if err := os.WriteFile(p("secret.in"), secret, 0o600); err != nil {
		return err
	}
	defer os.Remove(p("secret.in"))

	if _, err := tpm2("tpm2_create", "-C", p("primary.ctx"),
		"-u", p("seal.pub"), "-r", p("seal.priv"),
		"-L", p("policy.digest"), "-i", p("secret.in")); err != nil {
		return err
	}

	// Record what was sealed against, so a later mismatch can be reported
	// with both values rather than just "policy failed".
	return os.WriteFile(p("sealed-root"), []byte(contentRoot+"\n"), 0o600)
}

// Unseal re-measures contentRoot and releases the secret only if the policy
// is satisfied.
func Unseal(dir, contentRoot string) ([]byte, error) {
	var out []byte
	err := withPCRLock(func() error {
		if err := extend(contentRoot); err != nil {
			return err
		}
		var err error
		out, err = unsealCurrentState(dir)
		return err
	})
	return out, err
}

// unsealCurrentState attempts the unseal against whatever the PCR currently
// holds. Tests use it to prove that an extra measurement also fails, not
// only a different one.
func unsealCurrentState(dir string) ([]byte, error) {
	p := func(name string) string { return filepath.Join(dir, name) }

	if _, err := tpm2("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", p("primary.ctx")); err != nil {
		return nil, err
	}
	if _, err := tpm2("tpm2_load", "-C", p("primary.ctx"),
		"-u", p("seal.pub"), "-r", p("seal.priv"), "-c", p("seal.ctx")); err != nil {
		return nil, err
	}

	session := p("policy.ctx")
	if _, err := tpm2("tpm2_startauthsession", "--policy-session", "-S", session); err != nil {
		return nil, err
	}
	defer flush(session)

	if _, err := tpm2("tpm2_policypcr", "-S", session, "-l", fmt.Sprintf("sha256:%d", PCR)); err != nil {
		return nil, err
	}

	out, err := tpm2("tpm2_unseal", "-c", p("seal.ctx"), "-p", "session:"+session)
	if err != nil {
		// A policy failure is the expected fail-closed path, not a fault. It
		// gets its own error class so callers can tell "the state does not
		// match" from "the TPM is broken".
		if strings.Contains(strings.ToLower(err.Error()), tpmRCPolicyFail) ||
			strings.Contains(strings.ToLower(err.Error()), "policy check failed") {
			return nil, fmt.Errorf("%w: %s", ErrPolicyMismatch, sealedRootNote(dir))
		}
		return nil, err
	}
	if len(out) == 0 {
		// Never treat an empty success as a released secret.
		return nil, fmt.Errorf("%w: unseal produced no material", ErrPolicyMismatch)
	}
	return out, nil
}

// sealedRootNote describes what the seal was made against, without ever
// including secret material.
func sealedRootNote(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "sealed-root"))
	if err != nil {
		return "the current pcr state does not satisfy the sealing policy"
	}
	return fmt.Sprintf("the current pcr state does not satisfy the policy sealed against content root %s",
		strings.TrimSpace(string(b)))
}

// Reset returns PCR 23 to zeros, so a run leaves no measurement behind on
// the host's TPM.
func Reset() error {
	_, err := tpm2("tpm2_pcrreset", fmt.Sprintf("%d", PCR))
	return err
}
