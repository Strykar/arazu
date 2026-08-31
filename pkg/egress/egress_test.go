// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"arazu/pkg/hostcap"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const objPath = "../../bpf/egress_deny.bpf.o"

func requireRoot(t *testing.T) {
	t.Helper()
	if !hostcap.HasSysAdmin() {
		t.Skip("needs CAP_SYS_ADMIN for netns creation and LSM attach")
	}
}

func newNS(t *testing.T, name string) *Netns {
	t.Helper()
	requireRoot(t)
	CleanupStale(name)
	ns, err := CreateNetns(name)
	if err != nil {
		t.Fatalf("CreateNetns: %v", err)
	}
	t.Cleanup(func() { ns.Close() })
	return ns
}

func TestNetnsInodeIsNonZeroAndDiffersFromHost(t *testing.T) {
	ns := newNS(t, "arazu-test-a")
	if ns.Inode == 0 {
		t.Fatal("netns inode is zero, which the BPF program treats as deny-nothing")
	}
	host, err := HostNetnsInode()
	if err != nil {
		t.Fatal(err)
	}
	if ns.Inode == host {
		t.Fatalf("the new namespace has the host's inode (%d); nothing is isolated", host)
	}
}

// A fresh namespace has lo and nothing else. Seeing the host's interfaces
// would mean Exec ran outside it and every containment result below would
// be meaningless.
func TestExecRunsInsideTheNamespace(t *testing.T) {
	ns := newNS(t, "arazu-test-b")

	out, _, code, err := ns.Exec(context.Background(), []string{"ip", "-o", "link", "show"})
	if err != nil || code != 0 {
		t.Fatalf("exec failed: code=%d err=%v", code, err)
	}
	links := strings.TrimSpace(string(out))
	if strings.Count(links, "\n") != 0 || !strings.Contains(links, "lo:") {
		t.Fatalf("namespace is not isolated, links were:\n%s", links)
	}
}

// The namespace alone must already have no route out, before any BPF is
// involved. This is the primary control.
func TestNamespaceHasNoDefaultRoute(t *testing.T) {
	ns := newNS(t, "arazu-test-c")

	out, _, _, err := ns.Exec(context.Background(), []string{"ip", "route", "show"})
	if err != nil {
		t.Fatal(err)
	}
	if r := strings.TrimSpace(string(out)); r != "" {
		t.Fatalf("fresh namespace already has routes:\n%s", r)
	}
}

func TestAttachDenyLoadsAndCountersStartAtZero(t *testing.T) {
	ns := newNS(t, "arazu-test-d")

	d, err := AttachDeny(objPath, ns.Inode)
	if err != nil {
		t.Fatalf("attach failed: %v", err)
	}
	defer d.Close()

	c, err := d.Counters()
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnectDenied != 0 || c.SendmsgDenied != 0 {
		t.Fatalf("denial counters not zero at attach: %+v", c)
	}
}

// A zero inode would match no namespace and deny nothing, so attaching with
// one is a silent no-op dressed as a working gate.
func TestAttachRefusesAZeroInode(t *testing.T) {
	requireRoot(t)
	if _, err := AttachDeny(objPath, 0); err == nil {
		t.Fatal("attach accepted a zero namespace inode")
	}
}

func TestAttachFailsOnAMissingObject(t *testing.T) {
	requireRoot(t)
	if _, err := AttachDeny("../../bpf/does-not-exist.bpf.o", 4242); err == nil {
		t.Fatal("attach succeeded with no object file")
	}
}

func TestRequireBPFLSMAgreesWithTheKernel(t *testing.T) {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Skipf("cannot read the LSM list: %v", err)
	}
	active := strings.Contains(","+strings.TrimSpace(string(b))+",", ",bpf,")
	if err := RequireBPFLSM(); (err == nil) != active {
		t.Fatalf("RequireBPFLSM err=%v but the kernel list is %q", err, strings.TrimSpace(string(b)))
	}
}

// Denial must be scoped to the contained namespace. If attaching leaked to
// the host, the host's own egress would break, which is both a bug and a
// very disruptive one.
func TestHostEgressSurvivesAttach(t *testing.T) {
	ns := newNS(t, "arazu-test-e")

	d, err := AttachDeny(objPath, ns.Inode)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer d.Close()

	// A host-side connect to a socket that always exists locally.
	out, err := hostConnectProbe()
	if err != nil {
		t.Fatalf("host egress broke while the deny program was attached: %v (%s)", err, out)
	}

	c, err := d.Counters()
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnectSeen == 0 {
		t.Error("the connect hook never fired, so the attach is not actually enforcing anything")
	}
	if c.ConnectDenied != 0 {
		t.Errorf("host traffic was denied: %+v", c)
	}
}

// lsmChildEnv marks the re-executed half of the test below.
const lsmChildEnv = "ARAZU_LSM_ABSENT_CHILD"

// A missing bpf LSM is the silent-failure case AttachDeny guards against: the
// program loads and links, the hook never fires, and that is indistinguishable
// from a gate permitting everything. The guard only means something if attach
// refuses before reaching that state.
//
// The active list is fixed at boot, so it cannot be changed at runtime. It can
// be MASKED: a private mount namespace with a fake file bind mounted over
// /sys/kernel/security/lsm gives this process a list with no bpf and leaves the
// host's own view untouched. No reboot, and nothing in shipped code has to grow
// a seam for the test to reach.
//
// The child half drives AttachDeny rather than RequireBPFLSM, because what is
// under test is that attach CONSULTS the check. Asserting on the error text is
// what keeps an unrelated failure (a missing object, no privilege) from passing
// as evidence.
func TestAttachRefusesWhenTheBPFLSMIsAbsent(t *testing.T) {
	if os.Getenv(lsmChildEnv) == "1" {
		d, err := AttachDeny(objPath, 4242)
		if err == nil {
			d.Close()
			fmt.Fprintln(os.Stderr, "AttachDeny succeeded with the bpf LSM absent from the list")
			os.Exit(1)
		}
		if !strings.Contains(err.Error(), "bpf LSM is not active") {
			fmt.Fprintf(os.Stderr, "attach failed for the wrong reason: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	requireRoot(t)
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("needs unshare(1) to mask the LSM list")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "lsm")
	if err := os.WriteFile(fake, []byte("capability,landlock,lockdown,yama\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("unshare", "--mount", "sh", "-c",
		`mount --bind "$1" /sys/kernel/security/lsm && exec "$2" -test.run='^TestAttachRefusesWhenTheBPFLSMIsAbsent$'`,
		"sh", fake, self)
	cmd.Env = append(os.Environ(), lsmChildEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("attach was not refused with the bpf LSM absent: %v\n%s", err, out)
	}
}
