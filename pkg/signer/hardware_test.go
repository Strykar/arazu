// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The hardware tests are opt-in and never run by default.
//
// Signing with a FIDO2 key needs a physical touch, and on a token with a PIN
// set it needs the PIN too. Neither can be supplied by a test runner, so a
// suite that tried would hang rather than fail, which is worse. Set
// ARAZU_SK_KEY to the path of an enrolled sk private key to run them:
//
//	ssh-keygen -t ed25519-sk -O resident -O verify-required \
//	    -C arazu-signer-a -f ~/.ssh/arazu_signer_a
//	ARAZU_SK_KEY=~/.ssh/arazu_signer_a go test ./pkg/signer/ -run Hardware -v
//
// Every non-hardware property of this path is already covered without a
// token, because an sk signature verifies through the same code as a
// software SSH signature. What these add is the part that cannot be faked:
// that the token really produces a signature this build accepts, and that
// the algorithm really comes through as hardware backed.
func skKeyPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv("ARAZU_SK_KEY")
	if p == "" {
		t.Skip("set ARAZU_SK_KEY to an enrolled ed25519-sk key to run the hardware tests")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("ARAZU_SK_KEY=%s: %v", p, err)
	}
	return p
}

func TestHardwareTokenIsPresent(t *testing.T) {
	if os.Getenv("ARAZU_SK_KEY") == "" {
		t.Skip("hardware tests are opt-in")
	}
	out, err := exec.Command("fido2-token", "-L").Output()
	if err != nil {
		t.Fatalf("fido2-token -L: %v", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatal("no FIDO2 token found; plug it in")
	}
	t.Logf("token: %s", strings.TrimSpace(string(out)))
}

// The enrolled key must be provisioned as hardware backed. A key enrolled as
// ed25519-sk that presented itself as a plain ssh-ed25519 would satisfy a
// software signer slot, and the point of the token is that it cannot.
func TestHardwareKeyIsProvisionedAsHardwareBacked(t *testing.T) {
	path := skKeyPath(t)

	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseTrustLine(strings.TrimSpace(string(pub)))
	if err != nil {
		t.Fatal(err)
	}
	if key.Alg != AlgSKEd25519 {
		t.Fatalf("key at %s is %s, not a security key; enrol with -t ed25519-sk", path, key.Alg)
	}
	if !key.HardwareBacked() {
		t.Fatal("an sk key did not report itself as hardware backed")
	}
}

// The full round trip on real hardware. This blocks on a touch.
func TestHardwareSignAndVerifyRoundTrip(t *testing.T) {
	path := skKeyPath(t)

	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseTrustLine(strings.TrimSpace(string(pub)))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("touch the security key when it blinks")
	sig, err := SignSSH(path, msg)
	if err != nil {
		t.Fatalf("signing with the token failed: %v", err)
	}
	if sig.Alg != AlgSKEd25519 {
		t.Fatalf("signature algorithm = %s, want %s", sig.Alg, AlgSKEd25519)
	}
	if !sig.IsHardwareBacked() {
		t.Fatal("a token signature did not report itself as hardware backed")
	}

	if err := Verify(msg, sig, key); err != nil {
		t.Fatalf("a genuine token signature did not verify: %v", err)
	}
	// The matched twin, so the accept above is not the only observation.
	if err := Verify([]byte("tampered"), sig, key); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("a token signature verified over a different message: %v", err)
	}
}
