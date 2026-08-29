// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"arazu/pkg/auditlog"
)

type observed struct {
	Decision    string   `json:"decision"`
	Reason      string   `json:"reason"`
	BundleID    string   `json:"bundle_id"`
	Version     uint64   `json:"version"`
	ContentRoot string   `json:"content_root"`
	Signers     []string `json:"signers"`
}

type env struct {
	state string
	log   string
}

func newEnv(t *testing.T) env {
	t.Helper()
	d := t.TempDir()
	return env{state: d, log: filepath.Join(d, "audit.jsonl")}
}

// run invokes the built gate against a generated fixture bundle.
func run(t *testing.T, e env, variant string) (observed, int) {
	t.Helper()
	bundle := filepath.Join("..", "..", "testdata", "bundles", variant)
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("fixture %s missing; run scripts/make-adversarial.sh: %v", variant, err)
	}

	cmd := exec.Command("../../bin/ingress-verify",
		"-bundle", bundle,
		"-trusted", "../../testdata/keys/trusted.pub",
		"-state", e.state,
		"-log", e.log,
		"-allow", "content/")
	out, _ := cmd.Output()
	code := cmd.ProcessState.ExitCode()

	var o observed
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("variant %s: no JSON decision on stdout (exit %d): %q", variant, code, out)
	}
	return o, code
}

// The workbook's acceptance table, verbatim.
func TestAcceptanceTable(t *testing.T) {
	cases := []struct {
		variant  string
		decision string
		reason   string
		zeroExit bool
	}{
		{"good", "ACCEPT", "", true},
		{"flipped-byte", "REJECT", "hash-mismatch", false},
		{"one-signature", "REJECT", "insufficient-signatures", false},
		{"untrusted-signer", "REJECT", "untrusted-signer", false},
		{"extra-file", "REJECT", "unmanifested-file", false},
		{"missing-file", "REJECT", "missing-file", false},
		{"outside-allowlist", "REJECT", "allowlist-violation", false},
		{"truncated-manifest", "REJECT", "manifest-parse", false},
		{"duplicate-signer", "REJECT", "duplicate-signer", false},
		{"symlinked-dir", "REJECT", "unsafe-path", false},
	}
	for _, c := range cases {
		t.Run(c.variant, func(t *testing.T) {
			o, code := run(t, newEnv(t), c.variant)
			if o.Decision != c.decision {
				t.Errorf("decision = %q, want %q (reason %q)", o.Decision, c.decision, o.Reason)
			}
			if o.Reason != c.reason {
				t.Errorf("reason = %q, want %q", o.Reason, c.reason)
			}
			if (code == 0) != c.zeroExit {
				t.Errorf("exit = %d, want zero=%v", code, c.zeroExit)
			}
		})
	}
}

// Rollback needs prior state: the gate must know a newer version was
// already accepted before an older one can be a rollback.
func TestRollbackRejectedAfterANewerVersionWasAccepted(t *testing.T) {
	e := newEnv(t)

	if o, code := run(t, e, "good"); o.Decision != "ACCEPT" || code != 0 {
		t.Fatalf("setup: good bundle not accepted: %+v exit=%d", o, code)
	}
	o, code := run(t, e, "rollback")
	if o.Decision != "REJECT" || o.Reason != "version-rollback" {
		t.Errorf("decision=%q reason=%q, want REJECT/version-rollback", o.Decision, o.Reason)
	}
	if code == 0 {
		t.Error("rollback exited zero")
	}
}

// Without prior state the same bundle is simply a first acceptance. This
// pins that the rejection comes from the recorded version and not from
// something intrinsic to the rollback fixture.
func TestRollbackBundleIsAcceptableOnAFreshState(t *testing.T) {
	o, code := run(t, newEnv(t), "rollback")
	if o.Decision != "ACCEPT" || code != 0 {
		t.Fatalf("version 1 on fresh state should be accepted, got %+v exit=%d", o, code)
	}
}

func TestAcceptPersistsTheVersionAndRejectDoesNot(t *testing.T) {
	e := newEnv(t)
	run(t, e, "good")

	readVersion := func() string {
		b, err := os.ReadFile(filepath.Join(e.state, "last-accepted-arazu-spike"))
		if err != nil {
			t.Fatalf("state file missing after ACCEPT: %v", err)
		}
		return strings.TrimSpace(string(b))
	}
	if v := readVersion(); v != "2" {
		t.Fatalf("last-accepted = %q, want 2", v)
	}

	run(t, e, "flipped-byte")
	if v := readVersion(); v != "2" {
		t.Fatalf("a rejected bundle advanced the accepted version to %q", v)
	}
}

func TestEveryDecisionAppendsExactlyOneLogEntry(t *testing.T) {
	// Fresh version state per variant, one shared log. The variants all
	// carry version 2, so sharing state would make everything after the
	// first decision a version-rollback and the log would record that
	// instead of the reason under test.
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, v := range []string{"good", "flipped-byte", "one-signature", "missing-file"} {
		run(t, env{state: t.TempDir(), log: log}, v)
	}
	e := env{log: log}

	n, err := auditlog.Verify(e.log)
	if err != nil {
		t.Fatalf("audit log does not verify: %v", err)
	}
	if n != 4 {
		t.Fatalf("logged %d entries for 4 decisions", n)
	}

	b, _ := os.ReadFile(e.log)
	body := string(b)
	if !strings.Contains(body, auditlog.EvIngressAccept) {
		t.Error("no INGRESS_ACCEPT entry")
	}
	if strings.Count(body, auditlog.EvIngressReject) != 3 {
		t.Errorf("want 3 INGRESS_REJECT entries, log was:\n%s", body)
	}
	if !strings.Contains(body, "reason=hash-mismatch") {
		t.Error("reject entry does not record the reason")
	}
}

// The gate asks in protocol order: is this authentic, is it fresh, is it
// intact. A bundle failing more than one check reports the earliest, so the
// reason an operator sees is stable rather than depending on which check
// happened to run first.
func TestCheckOrderIsAuthenticityThenFreshnessThenIntegrity(t *testing.T) {
	e := newEnv(t)
	if o, _ := run(t, e, "good"); o.Decision != "ACCEPT" {
		t.Fatalf("setup: %+v", o)
	}

	// flipped-byte is corrupt and, against this state, also a replay of
	// version 2. Freshness is checked first, so that is what is reported.
	if o, _ := run(t, e, "flipped-byte"); o.Reason != "version-rollback" {
		t.Errorf("corrupt replay reported %q, want version-rollback", o.Reason)
	}
	// one-signature is both a replay and unsigned. Authenticity comes
	// first.
	if o, _ := run(t, e, "one-signature"); o.Reason != "insufficient-signatures" {
		t.Errorf("unsigned replay reported %q, want insufficient-signatures", o.Reason)
	}
}

func TestAcceptReportsAStableContentRoot(t *testing.T) {
	first, _ := run(t, newEnv(t), "good")
	if len(first.ContentRoot) != 64 {
		t.Fatalf("content root %q is not a sha256 hex digest", first.ContentRoot)
	}
	second, _ := run(t, newEnv(t), "good")
	if first.ContentRoot != second.ContentRoot {
		t.Fatalf("content root is not deterministic: %s vs %s", first.ContentRoot, second.ContentRoot)
	}
}

// A tampered bundle must not merely be reported as rejected, it must not
// yield a content root at all. Emitting one would invite a caller to
// measure and seal against content that failed the gate.
func TestRejectYieldsNoContentRoot(t *testing.T) {
	o, _ := run(t, newEnv(t), "flipped-byte")
	if o.ContentRoot != "" {
		t.Fatalf("a rejected bundle reported content root %q", o.ContentRoot)
	}
}

func TestAcceptNamesBothSigners(t *testing.T) {
	o, _ := run(t, newEnv(t), "good")
	if len(o.Signers) != 2 {
		t.Fatalf("accepted with %d named signers, want 2: %v", len(o.Signers), o.Signers)
	}
	if o.Signers[0] == o.Signers[1] {
		t.Fatal("the two named signers are the same key")
	}
}

// One compromised signer padding the file to a count of two is a different
// failure from a bundle that is simply missing a signature, and the gate has
// to say which. Both arms run here so neither reason can come from a check
// that has stopped telling them apart.
func TestDuplicateSignerIsDistinguishedFromAShortCount(t *testing.T) {
	if o, _ := run(t, newEnv(t), "duplicate-signer"); o.Reason != "duplicate-signer" {
		t.Errorf("same key twice reported %q, want duplicate-signer", o.Reason)
	}
	if o, _ := run(t, newEnv(t), "one-signature"); o.Reason != "insufficient-signatures" {
		t.Errorf("one signature reported %q, want insufficient-signatures", o.Reason)
	}
	if o, _ := run(t, newEnv(t), "good"); o.Decision != "ACCEPT" {
		t.Errorf("two distinct signers reported %q/%q, want ACCEPT", o.Decision, o.Reason)
	}
}

// The symlinked-dir fixture carries a manifest that is honest and correctly
// signed: every check except path safety passes. So the rejection is
// attributable to the symlink alone, and the content root must not be
// reported, because a caller that measured it would be sealing against bytes
// that were never reviewed.
func TestSymlinkedDirectoryIsRefusedWithNoContentRoot(t *testing.T) {
	o, code := run(t, newEnv(t), "symlinked-dir")
	if o.Reason != "unsafe-path" {
		t.Fatalf("symlinked directory component reported %q, want unsafe-path", o.Reason)
	}
	if code == 0 {
		t.Error("symlinked directory component exited zero")
	}
	if o.ContentRoot != "" {
		t.Errorf("a refused bundle reported content root %q", o.ContentRoot)
	}
}

// The gate refuses rather than proceeding unrecorded when the log is
// unusable. An boundary that runs without an audit trail has lost the
// property the trail exists to provide.
func TestGateRefusesWhenTheAuditLogIsBroken(t *testing.T) {
	e := newEnv(t)
	run(t, e, "good")

	b, _ := os.ReadFile(e.log)
	os.WriteFile(e.log, []byte(strings.Replace(string(b), "INGRESS_ACCEPT", "INGRESS_REJECT", 1)), 0o600)

	o, code := run(t, e, "good")
	if code != 2 || o.Decision != "ERROR" {
		t.Fatalf("gate proceeded with a broken audit log: decision=%q exit=%d", o.Decision, code)
	}
}

func TestVersionMonotonicityAcrossSeveralAccepts(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()

	for _, v := range []uint64{1, 2, 5} {
		bundle := filepath.Join(dir, "b"+strconv.FormatUint(v, 10))
		cmd := exec.Command("../../scripts/make-bundle.sh", bundle, strconv.FormatUint(v, 10))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("make-bundle: %v\n%s", err, out)
		}
		o := runPath(t, e, bundle)
		if o.Decision != "ACCEPT" {
			t.Fatalf("version %d rejected: %s", v, o.Reason)
		}
	}
	// Replaying version 5 is no longer newer than itself.
	bundle := filepath.Join(dir, "b5")
	if o := runPath(t, e, bundle); o.Decision != "REJECT" || o.Reason != "version-rollback" {
		t.Fatalf("replay of the same version accepted: %+v", o)
	}
}

func runPath(t *testing.T, e env, bundle string) observed {
	t.Helper()
	cmd := exec.Command("../../bin/ingress-verify",
		"-bundle", bundle, "-trusted", "../../testdata/keys/trusted.pub",
		"-state", e.state, "-log", e.log, "-allow", "content/")
	out, _ := cmd.Output()
	var o observed
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("no JSON decision: %q", out)
	}
	return o
}

// THE MAPPING, not the detection. pkg/manifest already catches a signature that
// does not verify (TestTamperedMessageFailsVerification). What nothing checked
// is that reasonOf turns it into an emitted REJECT:bad-signature. Drop
// ErrBadSignature from that sentinel list and every other test still passes:
// the error falls through to "unverifiable", the bundle is still refused, and
// the operator is told the wrong thing about why.
//
// Found by counting the rejection classes rather than by reading them. Ten
// reasons are asserted at this level and bad-signature was not one of them.
func TestASignatureThatParsesButDoesNotVerifyIsBadSignature(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "b")
	if err := os.CopyFS(bundle, os.DirFS(filepath.Join("..", "..", "testdata", "bundles", "good"))); err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(bundle, "manifest.sig")
	b, err := os.ReadFile(sig)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	f := strings.Fields(lines[0])
	if len(f) != 3 {
		t.Fatalf("unexpected signature line %q", lines[0])
	}
	raw, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil {
		t.Fatal(err)
	}
	// One bit. The line still parses and the signature is still the right
	// length, so this reaches the verify step and not the decode step, which
	// returns the same sentinel for a different reason.
	raw[0] ^= 0x01
	lines[0] = f[0] + " " + f[1] + " " + base64.StdEncoding.EncodeToString(raw)
	if err := os.Chmod(sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sig, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	o := runPath(t, newEnv(t), bundle)
	if o.Decision != "REJECT" || o.Reason != "bad-signature" {
		t.Fatalf("decision %s:%s, want REJECT:bad-signature", o.Decision, o.Reason)
	}
}

// The fallback, which is not a rejection class and should not be counted as
// one. An error reasonOf does not recognise still has to refuse, and has to
// name itself rather than emit an empty reason. Untested until now, so a new
// sentinel added in pkg/manifest without a matching reasonOf entry would reject
// as "unverifiable" with nothing to notice the class went missing.
func TestAnUnrecognisedErrorIsUnverifiable(t *testing.T) {
	if got := reasonOf(errors.New("a failure nothing maps")); got != "unverifiable" {
		t.Fatalf("reasonOf = %q, want unverifiable", got)
	}
}
