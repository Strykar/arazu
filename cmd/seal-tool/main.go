// SPDX-License-Identifier: Apache-2.0

// Command seal-tool binds the output signing key to a measured state and
// signs artifacts with it.
//
// The sign subcommand unseals and signs in one process so the released
// secret never reaches disk. If the measurement does not match, signing is
// refused and nothing is written.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"arazu/pkg/auditlog"
	"arazu/pkg/tpmseal"
)

type decision struct {
	Decision    string `json:"decision"`
	Action      string `json:"action"`
	Reason      string `json:"reason,omitempty"`
	ContentRoot string `json:"content_root,omitempty"`
	ExpectedPCR string `json:"expected_pcr23,omitempty"`
	TPMDevice   string `json:"tpm_device,omitempty"`
	Signature   string `json:"signature,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	// Resettable records that this binding rests on a resettable PCR, so a
	// reader of the output cannot mistake it for a measured-boot claim.
	Resettable bool `json:"pcr_resettable"`
}

func main() {
	if len(os.Args) < 2 {
		emit(decision{Decision: "ERROR", Action: "none",
			Reason: "usage: seal-tool provision|unseal|sign [flags]"}, 2)
	}
	action := os.Args[1]
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	dir := fs.String("dir", "", "directory holding the sealed object")
	contentRoot := fs.String("content-root", "", "content root to measure")
	logPath := fs.String("log", "", "audit log path")
	secretFile := fs.String("secret-file", "", "provision: secret to seal, or empty to generate one")
	artifact := fs.String("artifact", "", "sign: artifact to sign")
	sigPath := fs.String("sig", "", "sign: signature output path")
	fs.Parse(os.Args[2:])

	if *dir == "" || *contentRoot == "" {
		emit(decision{Decision: "ERROR", Action: action, Reason: "need -dir and -content-root"}, 2)
	}

	d := decision{
		Action:      action,
		ContentRoot: *contentRoot,
		ExpectedPCR: tpmseal.ExpectedPCR23(*contentRoot),
		TPMDevice:   tpmseal.Device(),
		Resettable:  true,
	}
	if d.TPMDevice == "" {
		d.Decision, d.Reason = "ERROR", "no usable TPM device"
		emit(d, 2)
	}

	switch action {
	case "provision":
		doProvision(d, *dir, *contentRoot, *secretFile, *logPath)
	case "unseal":
		doUnseal(d, *dir, *contentRoot, *logPath)
	case "sign":
		doSign(d, *dir, *contentRoot, *artifact, *sigPath, *logPath)
	default:
		d.Decision, d.Reason = "ERROR", "unknown action "+action
		emit(d, 2)
	}
}

func doProvision(d decision, dir, root, secretFile, logPath string) {
	seed := make([]byte, ed25519.SeedSize)
	if secretFile != "" {
		b, err := os.ReadFile(secretFile)
		if err != nil {
			d.Decision, d.Reason = "ERROR", err.Error()
			emit(d, 2)
		}
		// Fold whatever was supplied down to a seed so the sealed material is
		// always a usable signing seed.
		sum := sha256.Sum256(b)
		copy(seed, sum[:])
	} else if _, err := rand.Read(seed); err != nil {
		d.Decision, d.Reason = "ERROR", err.Error()
		emit(d, 2)
	}

	if err := tpmseal.Provision(dir, root, seed); err != nil {
		d.Decision, d.Reason = "REFUSED", err.Error()
		appendLog(logPath, auditlog.EvSignRefused, "provision failed: "+err.Error())
		emit(d, 1)
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	d.PublicKey = base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(dir, "signing.pub"), []byte(d.PublicKey+"\n"), 0o644); err != nil {
		d.Decision, d.Reason = "ERROR", err.Error()
		emit(d, 2)
	}

	d.Decision = "SEALED"
	appendLog(logPath, auditlog.EvSeal,
		fmt.Sprintf("content_root=%s expected_pcr23=%s device=%s pcr_resettable=true",
			root, d.ExpectedPCR, d.TPMDevice))
	emit(d, 0)
}

func doUnseal(d decision, dir, root, logPath string) {
	secret, err := tpmseal.Unseal(dir, root)
	if err != nil {
		d.Decision, d.Reason = "REFUSED", err.Error()
		if errors.Is(err, tpmseal.ErrPolicyMismatch) {
			d.Reason = tpmseal.ErrPolicyMismatch.Error()
		}
		appendLog(logPath, auditlog.EvSignRefused, "unseal refused: "+err.Error())
		emit(d, 1)
	}
	// Report that it unsealed, never what unsealed.
	d.Decision = "UNSEALED"
	pub := ed25519.NewKeyFromSeed(secret[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
	d.PublicKey = base64.StdEncoding.EncodeToString(pub)
	emit(d, 0)
}

func doSign(d decision, dir, root, artifact, sigPath, logPath string) {
	if artifact == "" || sigPath == "" {
		d.Decision, d.Reason = "ERROR", "need -artifact and -sig"
		emit(d, 2)
	}

	body, err := os.ReadFile(artifact)
	if err != nil {
		d.Decision, d.Reason = "ERROR", err.Error()
		emit(d, 2)
	}

	// Unseal and sign in one process. The released secret never reaches disk.
	secret, err := tpmseal.Unseal(dir, root)
	if err != nil {
		d.Decision = "REFUSED"
		d.Reason = err.Error()
		if errors.Is(err, tpmseal.ErrPolicyMismatch) {
			d.Reason = tpmseal.ErrPolicyMismatch.Error()
		}
		appendLog(logPath, auditlog.EvSignRefused,
			fmt.Sprintf("artifact=%s reason=%s content_root=%s", artifact, d.Reason, root))
		// Refusing means producing nothing. Leaving a stale signature behind
		// would let a later reader treat unsigned output as signed.
		os.Remove(sigPath)
		emit(d, 1)
	}

	sec := ed25519.NewKeyFromSeed(secret[:ed25519.SeedSize])
	sig := ed25519.Sign(sec, body)
	pub := sec.Public().(ed25519.PublicKey)

	d.Signature = base64.StdEncoding.EncodeToString(sig)
	d.PublicKey = base64.StdEncoding.EncodeToString(pub)

	line := fmt.Sprintf("ed25519 %s %s\n", d.PublicKey, d.Signature)
	if err := os.WriteFile(sigPath, []byte(line), 0o644); err != nil {
		d.Decision, d.Reason = "ERROR", err.Error()
		emit(d, 2)
	}

	sum := sha256.Sum256(body)
	d.Decision = "SIGNED"
	appendLog(logPath, auditlog.EvSign,
		fmt.Sprintf("artifact=%s digest=%s content_root=%s", artifact, hex.EncodeToString(sum[:]), root))
	emit(d, 0)
}

func appendLog(path, event, detail string) {
	if path == "" {
		return
	}
	l, err := auditlog.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open audit log: %v\n", err)
		return
	}
	defer l.Close()
	if _, err := l.Append(event, detail); err != nil {
		fmt.Fprintf(os.Stderr, "cannot append to audit log: %v\n", err)
	}
}

func emit(d decision, code int) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot render decision: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(b))

	fmt.Fprintf(os.Stderr, "%s %s", d.Action, d.Decision)
	if d.Reason != "" {
		fmt.Fprintf(os.Stderr, ": %s", d.Reason)
	}
	fmt.Fprintln(os.Stderr)
	if d.Decision == "SEALED" || d.Decision == "SIGNED" {
		fmt.Fprintf(os.Stderr, "  bound to pcr %d on %s, which is resettable; "+
			"production binds to non-resettable measured-boot pcrs\n", tpmseal.PCR, d.TPMDevice)
	}
	os.Exit(code)
}
