// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Namespace is the ssh-keygen signature namespace. Signatures do not verify
// across namespaces, so one made elsewhere cannot be replayed as an approval.
const Namespace = "arazu-manifest"

// ErrVerifyFailed is one error for every backend, so a caller cannot treat a
// hardware failure as softer than a software one.
var ErrVerifyFailed = fmt.Errorf("bad-signature")

// Verify checks one signature over msg against a provisioned key. Dispatch is
// on the signature's algorithm, but the trusted key's has to agree: otherwise a
// signer provisioned as a hardware key could be satisfied by a software
// signature carrying the same key ID.
func Verify(msg []byte, sig Signature, key TrustedKey) error {
	if sig.KeyID != key.ID {
		return fmt.Errorf("%w: signature key id %s does not match the trusted key %s",
			ErrVerifyFailed, sig.KeyID, key.ID)
	}
	if sig.Alg != key.Alg {
		return fmt.Errorf("%w: key %s is provisioned as %s but the signature claims %s",
			ErrVerifyFailed, key.ID, key.Alg, sig.Alg)
	}

	switch sig.Alg {
	case AlgEd25519:
		if len(key.Ed25519) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: key %s has no ed25519 material", ErrVerifyFailed, key.ID)
		}
		if !ed25519.Verify(key.Ed25519, msg, sig.Payload) {
			return fmt.Errorf("%w: ed25519 signature from %s does not verify", ErrVerifyFailed, key.ID)
		}
		return nil

	case AlgSSHEd25519, AlgSKEd25519:
		return verifySSH(msg, sig, key)
	}
	return fmt.Errorf("%w: %q", ErrUnknownAlgorithm, sig.Alg)
}

// verifySSH shells out to ssh-keygen -Y verify. An sk signature wraps the
// message and carries a flags byte and a counter; OpenSSH has the canonical
// implementation and a second one here would be subtly wrong for years.
func verifySSH(msg []byte, sig Signature, key TrustedKey) error {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return fmt.Errorf("%w: ssh-keygen is needed to verify %s signatures: %v",
			ErrVerifyFailed, sig.Alg, err)
	}

	dir, err := os.MkdirTemp("", "arazu-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// The key ID is both the allowed-signers principal and -I, so the identity
	// ssh-keygen matches is the one the manifest names.
	allowed := filepath.Join(dir, "allowed_signers")
	line := fmt.Sprintf("%s %s\n", key.ID, strings.TrimSpace(key.SSHLine))
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
		return err
	}

	sigPath := filepath.Join(dir, "manifest.sig")
	if err := os.WriteFile(sigPath, sig.Payload, 0o600); err != nil {
		return err
	}

	cmd := exec.Command("ssh-keygen", "-Y", "verify",
		"-f", allowed,
		"-I", string(key.ID),
		"-n", Namespace,
		"-s", sigPath)
	cmd.Stdin = bytes.NewReader(msg)

	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s signature from %s did not verify: %s",
			ErrVerifyFailed, sig.Alg, key.ID, strings.TrimSpace(out.String()))
	}
	return nil
}

// SignSSH produces a signature with an SSH private key. Runs on the low side,
// never in the boundary. An sk key blocks until the token is touched.
func SignSSH(keyPath string, msg []byte) (Signature, error) {
	dir, err := os.MkdirTemp("", "arazu-sign-")
	if err != nil {
		return Signature{}, err
	}
	defer os.RemoveAll(dir)

	msgPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		return Signature{}, err
	}

	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", keyPath, "-n", Namespace, msgPath)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return Signature{}, fmt.Errorf("ssh-keygen sign: %v: %s", err, strings.TrimSpace(errb.String()))
	}

	armoured, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		return Signature{}, err
	}

	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return Signature{}, err
	}
	id, err := KeyIDForSSH(string(pub))
	if err != nil {
		return Signature{}, err
	}

	alg := AlgSSHEd25519
	if strings.HasPrefix(strings.TrimSpace(string(pub)), "sk-ssh-ed25519") {
		alg = AlgSKEd25519
	}
	return Signature{Alg: alg, KeyID: id, Payload: armoured}, nil
}
