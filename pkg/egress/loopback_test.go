// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// R1.1(d): a model server lives INSIDE the contained namespace, reached over
// loopback, so nothing outside the boundary is reachable and no relay exists to
// trust. These tests are the acceptance for that, not a report about it.

// The three assertions that make (d) what it claims to be. If any pair matches
// but not the third, the model sits in a different namespace from the policy
// and the workload — which produces exactly the same observation as containment
// working, because nothing reaches out either way.
func TestModelAndWorkloadShareThePolicysNetnsInode(t *testing.T) {
	requireRoot(t)
	const name = "arazu-r11-inode"
	CleanupStale(name)

	ns, err := OpenOrCreate(name)
	if err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	defer func() { ns.Close(); CleanupStale(name) }()

	// 1. the inode the policy is attached to
	d, err := AttachDeny(objPath, ns.Inode)
	if err != nil {
		t.Fatalf("AttachDeny: %v", err)
	}
	defer d.Close()
	policyInode := ns.Inode

	// 2. and 3. two separate processes joining the namespace, standing in for
	// the model server and the analysis workload. Each reports the inode it is
	// actually in, read from the kernel rather than assumed from the name.
	readInode := func(role string) uint32 {
		t.Helper()
		out, _, _, err := ns.Exec(context.Background(),
			[]string{"/usr/bin/env", "sh", "-c", "readlink /proc/self/ns/net"})
		if err != nil {
			t.Fatalf("%s: exec: %v", role, err)
		}
		s := strings.TrimSpace(string(out)) // net:[4026532...]
		i, j := strings.Index(s, "["), strings.Index(s, "]")
		if i < 0 || j < 0 {
			t.Fatalf("%s: cannot parse %q", role, s)
		}
		n, err := strconv.ParseUint(s[i+1:j], 10, 32)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		return uint32(n)
	}

	model := readInode("model server")
	workload := readInode("analysis workload")

	if model != policyInode {
		t.Errorf("model server is in netns %d, policy is attached to %d", model, policyInode)
	}
	if workload != policyInode {
		t.Errorf("analysis workload is in netns %d, policy is attached to %d", workload, policyInode)
	}
	if model != workload {
		t.Errorf("model server (%d) and workload (%d) are in different namespaces", model, workload)
	}
}

// A persistent namespace must survive Close, or the model server dies with the
// run that started it and the next run gets a different inode.
func TestPersistentNamespaceSurvivesClose(t *testing.T) {
	requireRoot(t)
	const name = "arazu-r11-persist"
	CleanupStale(name)

	first, err := OpenOrCreate(name)
	if err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	inode := first.Inode
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat("/var/run/netns/" + name); err != nil {
		t.Fatalf("persistent namespace was deleted on Close: %v", err)
	}

	second, err := OpenOrCreate(name)
	if err != nil {
		t.Fatalf("OpenOrCreate (rejoin): %v", err)
	}
	defer func() { second.Close(); CleanupStale(name) }()
	if second.Inode != inode {
		t.Errorf("rejoined inode %d, first run had %d: the policy would be attached to the wrong namespace",
			second.Inode, inode)
	}
}

// The carve-out itself: loopback reachable, everything else still refused.
// Both arms are required. Without the second this test passes on a program that
// permits everything.
func TestLoopbackReachableAndOffboxStillDenied(t *testing.T) {
	requireRoot(t)
	const name = "arazu-r11-carveout"
	CleanupStale(name)
	ns, err := OpenOrCreate(name)
	if err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	defer func() { ns.Close(); CleanupStale(name) }()

	d, err := AttachDeny(objPath, ns.Inode)
	if err != nil {
		t.Fatalf("AttachDeny: %v", err)
	}
	defer d.Close()

	// A connect to 127.0.0.1 must not be refused by the LSM. Nothing is
	// listening, so the honest assertion is "not EPERM" — ECONNREFUSED means
	// the policy allowed it and the kernel found no listener, which is the
	// permitted case.
	py := `import socket,errno,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3)
try:
    s.connect((sys.argv[1],11434)); print("OK")
except OSError as e: print(errno.errorcode.get(e.errno,"ERR"))`

	loop, _, _, err := ns.Exec(context.Background(),
		[]string{"/usr/bin/env", "python3", "-c", py, "127.0.0.1"})
	if err != nil {
		t.Fatalf("loopback probe: %v", err)
	}
	if got := strings.TrimSpace(string(loop)); got == "EPERM" {
		t.Errorf("loopback was refused by the policy (%s); the model would be unreachable", got)
	}

	off, _, _, err := ns.Exec(context.Background(),
		[]string{"/usr/bin/env", "python3", "-c", py, "1.1.1.1"})
	if err != nil {
		t.Fatalf("offbox probe: %v", err)
	}
	if got := strings.TrimSpace(string(off)); got != "EPERM" {
		t.Errorf("off-box connect returned %q, want EPERM: the carve-out leaks", got)
	}

	c, err := d.Counters()
	if err != nil {
		t.Fatalf("Counters: %v", err)
	}
	if c.LoopbackAllowed == 0 {
		t.Error("loopback_allowed is 0: the permit path never ran, so the loopback result " +
			"cannot be attributed to the carve-out")
	}
	if c.ConnectDenied == 0 {
		t.Error("connect_denied is 0: the deny path never ran")
	}
}

// The model-fetch negative test, with its matched twin.
//
// Under (d) the model server lives inside the boundary, so it inherits the
// boundary: it cannot fetch weights either. `ollama pull` must fail inside.
//
// The twin is what makes that mean anything. A pull that fails because the
// daemon is down, the model name is wrong, or DNS is broken reads identically
// to one denied by containment — so the SAME command must succeed outside. Only
// the pair distinguishes "the boundary refused it" from "it was never going to
// work".
func TestModelFetchDeniedInsideAndReachableOutside(t *testing.T) {
	requireRoot(t)
	const name = "arazu-r11-pull"
	CleanupStale(name)
	ns, err := OpenOrCreate(name)
	if err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	defer func() { ns.Close(); CleanupStale(name) }()

	d, err := AttachDeny(objPath, ns.Inode)
	if err != nil {
		t.Fatalf("AttachDeny: %v", err)
	}
	defer d.Close()

	// Reaching the model registry is the operation under test, not downloading
	// a model: a TCP connect to registry.ollama.ai:443 is what `ollama pull`
	// must do first, and it is bounded in time and bytes.
	//
	// The socket family is derived from the literal rather than fixed to
	// AF_INET. LookupHost returns both families and RFC 6724 sorting puts v6
	// first on a host holding a global v6 address, so the fixed-AF_INET version
	// handed an AAAA record to an IPv4 socket and got EAI_ADDRFAMILY (-9) on
	// both sides. That is an address-family error, not a policy denial, and it
	// failed the first cold boot on a machine with working IPv6. Either family
	// is a valid probe: the LSM filters AF_INET and AF_INET6 alike and the
	// loopback carve-out is deliberately v4-only.
	probe := `import socket,errno,sys
ip=sys.argv[1]
fam=socket.AF_INET6 if ":" in ip else socket.AF_INET
s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(8)
try:
    s.connect((ip,443)); print("OK")
except TimeoutError: print("TIMEOUT")
except OSError as e: print(errno.errorcode.get(e.errno) or "E?%s"%(e.errno,))`

	// Resolve outside the namespace: name resolution is not what is being
	// tested, and letting it fail inside would confuse a DNS failure with a
	// policy denial.
	addrs, err := net.LookupHost("registry.ollama.ai")
	if err != nil || len(addrs) == 0 {
		t.Skipf("cannot resolve the model registry, so the twin cannot be run: %v", err)
	}

	// THE TWIN RUNS FIRST, because it is the control. It establishes that this
	// address is reachable at all, so that a denial inside means the boundary
	// refused it rather than that nothing was ever going to connect.
	//
	// Asserting first and skipping afterwards does not work: t.Skip after
	// t.Errorf leaves the test FAILED, so an unreachable registry was reported
	// as a containment failure instead of as a machine that could not run the
	// check. The pair was already the right idea; only the order was wrong.
	//
	// Every address is tried, not just the first. A dual-stack host whose v6
	// route is dead sorts the AAAA record first and would skip a check it is
	// perfectly able to run; the boundary denies both families, so any address
	// the host can reach is a valid probe.
	var ip, why string
	for _, a := range addrs {
		out, err := exec.Command("/usr/bin/env", "python3", "-c", probe, a).CombinedOutput()
		if err != nil {
			t.Fatalf("outside(%s): %v", a, err)
		}
		if o := strings.TrimSpace(string(out)); o == "OK" {
			ip = a
			break
		} else {
			why = a + "=" + o
		}
	}
	if ip == "" {
		t.Skipf("the registry is unreachable from the host (%s), so an inside denial "+
			"could not be attributed to containment", why)
	}

	inside, _, _, err := ns.Exec(context.Background(),
		[]string{"/usr/bin/env", "python3", "-c", probe, ip})
	if err != nil {
		t.Fatalf("inside: %v", err)
	}
	if got := strings.TrimSpace(string(inside)); got != "EPERM" {
		t.Errorf("model fetch inside the boundary returned %q, want EPERM", got)
	}
}
