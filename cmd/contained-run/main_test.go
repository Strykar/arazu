// SPDX-License-Identifier: Apache-2.0

package main

import (
	"arazu/pkg/hostcap"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"arazu/pkg/auditlog"
	"arazu/pkg/egress"
)

// Every test below drives a network namespace, a raw socket or an LSM attach,
// so each needs CAP_SYS_ADMIN. None of them checked: they assumed root, and a
// container running as uid 0 without the capability therefore FAILED them
// rather than skipping. Someone evaluating this repo saw eight red tests where
// the honest answer is "this machine cannot run these".
//
// euid is the wrong question, which is why this asks the kernel for the
// effective capability set instead.
func requireSysAdmin(t *testing.T) {
	t.Helper()
	if !hostcap.HasSysAdmin() {
		t.Skip("needs CAP_SYS_ADMIN: netns creation, raw sockets and LSM attach")
	}
}

const bundleDir = "../../testdata/bundles/good"

var (
	once    sync.Once
	results = map[string]result{}
	codes   = map[string]int{}
)

// runAllModes executes each mode once and caches the outcome. Each run
// creates a namespace and drives real network timeouts, so doing it once per
// mode keeps the suite honest without making it slow.
func runAllModes(t *testing.T) {
	t.Helper()
	if !hostcap.HasSysAdmin() {
		t.Skip("needs CAP_SYS_ADMIN for netns creation and LSM attach")
	}
	once.Do(func() {
		dir, err := os.MkdirTemp("", "arazu-run-*")
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{modeControl, modeNetnsOnly, modeContained} {
			cmd := exec.Command("../../bin/contained-run",
				"-mode", mode,
				"-bundle", bundleDir,
				"-out", filepath.Join(dir, "artifact-"+mode+".txt"),
				"-log", filepath.Join(dir, "audit-"+mode+".jsonl"),
				"-obj", "../../bpf/egress_deny.bpf.o",
				"-probe", "../../scripts/egress-probe.sh",
				"-ns", "arazu-t-"+mode)
			out, _ := cmd.Output()
			codes[mode] = cmd.ProcessState.ExitCode()

			var r result
			if err := json.Unmarshal(out, &r); err != nil {
				t.Fatalf("mode %s: no JSON result (exit %d): %q", mode, codes[mode], out)
			}
			results[mode] = r
		}
	})
}

func probeByName(t *testing.T, r result, name string) probe {
	t.Helper()
	for _, p := range r.Probes {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("probe %q not present in mode %s", name, r.Mode)
	return probe{}
}

// The control run is load-bearing. If it cannot reach the network then the
// probe is not exercising real egress and every containment result below is
// vacuous.
func TestControlRunReachesTheNetwork(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)
	r := results[modeControl]

	if codes[modeControl] != 0 {
		t.Fatalf("control run failed: %s", r.Reason)
	}
	for _, name := range []string{"tcp-connect", "dns-udp", "icmp-echo", "raw-packet-offbox"} {
		if p := probeByName(t, r, name); !p.Reached {
			t.Errorf("control probe %s did not reach the network (errno %s); "+
				"the containment result is unproven until it does", name, p.Errno)
		}
	}
}

func TestContainedRunReachesNothingOffBox(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)
	r := results[modeContained]

	if codes[modeContained] != 0 {
		t.Fatalf("contained run failed: %s", r.Reason)
	}
	for _, p := range r.Probes {
		if p.Class == classReach && p.Reached {
			t.Errorf("probe %s reached off the box under containment", p.Name)
		}
	}
}

func TestNetnsOnlyRunReachesNothingOffBox(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)
	r := results[modeNetnsOnly]

	if codes[modeNetnsOnly] != 0 {
		t.Fatalf("netns-only run failed: %s", r.Reason)
	}
	for _, p := range r.Probes {
		if p.Class == classReach && p.Reached {
			t.Errorf("probe %s reached off the box with only the namespace", p.Name)
		}
	}
}

// Flipping only the BPF layer must change the observed errno. If both
// contained modes reported the same errno, the namespace would explain the
// whole result and the BPF layer would be unevidenced.
func TestLayerAttributionByErrno(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)

	nsOnly := probeByName(t, results[modeNetnsOnly], "tcp-connect")
	contained := probeByName(t, results[modeContained], "tcp-connect")

	if nsOnly.Errno == contained.Errno {
		t.Fatalf("both contained modes failed with %s, so the bpf layer is unevidenced", contained.Errno)
	}
	if contained.Errno != "EPERM" {
		t.Errorf("contained tcp-connect errno = %s, want EPERM from the bpf hook", contained.Errno)
	}
	if nsOnly.Errno != "ENETUNREACH" && nsOnly.Errno != "EHOSTUNREACH" {
		t.Errorf("netns-only tcp-connect errno = %s, want ENETUNREACH from the missing route", nsOnly.Errno)
	}
}

// The namespace cannot refuse a raw send onto its own loopback, so this
// probe isolates the BPF layer completely: netns-only lets it through and
// containment refuses it.
func TestLocalRawSendIsolatesTheBPFLayer(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)

	nsOnly := probeByName(t, results[modeNetnsOnly], "raw-packet-loopback")
	contained := probeByName(t, results[modeContained], "raw-packet-loopback")

	if !nsOnly.Reached {
		t.Fatalf("the namespace refused a loopback raw send (errno %s), which it cannot do; "+
			"the layers can no longer be told apart", nsOnly.Errno)
	}
	if contained.Reached {
		t.Fatal("the bpf hook let a loopback raw send through")
	}
	if contained.Errno != "EPERM" {
		t.Errorf("contained loopback raw send errno = %s, want EPERM", contained.Errno)
	}
}

// Second, independent witness: the kernel's own counters. A userspace errno
// could in principle come from somewhere else; the map cannot.
func TestKernelCountersWitnessTheDenials(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)
	c := results[modeContained].BPFDenials

	if c.ConnectDenied == 0 {
		t.Error("the connect hook denied nothing, so it did not fire")
	}
	if c.SendmsgDenied == 0 {
		t.Error("the sendmsg hook denied nothing; connect alone would miss UDP and raw sockets")
	}
	if c.ConnectSeen < c.ConnectDenied {
		t.Errorf("denied %d connects but only saw %d", c.ConnectDenied, c.ConnectSeen)
	}
	// Traffic outside the namespace passes through the hook untouched, which
	// is what keeps the denial scoped to the contained workload.
	if results[modeNetnsOnly].BPFDenials.ConnectDenied != 0 {
		t.Error("netns-only reported bpf denials with nothing attached")
	}
}

func TestContainedRunStillProducesTheArtifact(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)
	r := results[modeContained]

	if r.Artifact == "" {
		t.Fatal("no artifact recorded")
	}
	b, err := os.ReadFile(r.Artifact)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if !strings.Contains(string(b), "arazu-spike-artifact") {
		t.Fatalf("artifact does not look like the workload's output:\n%s", b)
	}
	if r.ContentRoot == "" || len(r.ContentRoot) != 64 {
		t.Errorf("content root %q is not a sha256 digest", r.ContentRoot)
	}
}

func TestEveryProbeIsLogged(t *testing.T) {
	requireSysAdmin(t)
	runAllModes(t)
	r := results[modeContained]

	logPath := strings.Replace(r.Artifact, "artifact-contained.txt", "audit-contained.jsonl", 1)
	if _, err := auditlog.Verify(logPath); err != nil {
		t.Fatalf("run log does not verify: %v", err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)

	for _, want := range []string{auditlog.EvRunStart, auditlog.EvRunEnd, auditlog.EvEgressRequest, auditlog.EvEgressDeny} {
		if !strings.Contains(body, want) {
			t.Errorf("log has no %s entry", want)
		}
	}
	for _, p := range r.Probes {
		if !strings.Contains(body, "probe="+p.Name) {
			t.Errorf("probe %s was not logged", p.Name)
		}
	}
	if !strings.Contains(body, "errno=EPERM") {
		t.Error("the log does not record the errno that attributes the denial")
	}
}

// Containment must fail closed. Pointing the runner at an object that
// cannot attach must refuse the run, not quietly downgrade to netns-only.
func TestContainedModeRefusesWhenAttachFails(t *testing.T) {
	if !hostcap.HasSysAdmin() {
		t.Skip("needs CAP_SYS_ADMIN")
	}
	dir := t.TempDir()
	cmd := exec.Command("../../bin/contained-run",
		"-mode", modeContained,
		"-bundle", bundleDir,
		"-out", filepath.Join(dir, "artifact.txt"),
		"-log", filepath.Join(dir, "audit.jsonl"),
		"-obj", "../../bpf/nonexistent.bpf.o",
		"-probe", "../../scripts/egress-probe.sh",
		"-ns", "arazu-t-failclosed")
	out, _ := cmd.Output()
	code := cmd.ProcessState.ExitCode()

	if code == 0 {
		t.Fatalf("run succeeded with no attachable object:\n%s", out)
	}
	var r result
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("no JSON result: %q", out)
	}
	if r.BPFAttached {
		t.Error("reported bpf attached when it was not")
	}
	if !strings.Contains(r.Reason, "attach") {
		t.Errorf("reason does not name the attach failure: %q", r.Reason)
	}
	if _, err := os.Stat(filepath.Join(dir, "artifact.txt")); err == nil {
		t.Error("an artifact was produced by a run that refused to contain")
	}
}

// checkExpectations is where a mode asserts its own contract, and every branch
// in it guards a state a healthy run never produces. Driving the method with
// synthetic results is what makes those branches reachable at all: a real run
// that leaked would be a broken boundary, not a test.
func healthyContained() result {
	return result{
		Mode: modeContained,
		Probes: []probe{
			{Name: "offbox-tcp", Class: classReach, Reached: false, Errno: "EPERM"},
			{Name: "raw-packet-loopback", Class: classLocal, Reached: false, Errno: "EPERM"},
			{Name: "model-loopback", Class: classPermitted, Reached: true},
		},
		BPFDenials: egress.Counters{ConnectDenied: 1, SendmsgDenied: 1},
	}
}

// The matched twin for every refusal below. Without it a method rewritten to
// reject everything would satisfy all of them.
func TestAHealthyContainedRunIsAccepted(t *testing.T) {
	if err := healthyContained().checkExpectations(); err != nil {
		t.Fatalf("a sound contained run was refused: %v", err)
	}
}

func TestCheckExpectationsRefusesEachUnsoundShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() result
		want  string
	}{
		{"control that reached nothing proves nothing", func() result {
			r := healthyContained()
			r.Mode = modeControl
			return r
		}, "control run reached nothing"},

		{"a reach probe that got off the box is a leak", func() result {
			r := healthyContained()
			r.Probes[0].Reached = true
			return r
		}, "containment leaked"},

		{"no reach probes means nothing was proven", func() result {
			r := healthyContained()
			r.Probes = r.Probes[1:]
			return r
		}, "no reach probes ran"},

		{"netns-only cannot refuse a local send on its own", func() result {
			r := healthyContained()
			r.Mode = modeNetnsOnly
			return r
		}, "which the namespace alone cannot do"},

		{"a permitted destination that was refused breaks the deployment", func() result {
			r := healthyContained()
			r.Probes[2].Reached = false
			return r
		}, "deliberately permitted destination was refused"},

		{"a local raw send that got through is the bpf hook failing", func() result {
			r := healthyContained()
			r.Probes[1].Reached = true
			return r
		}, "let a local raw send through"},

		{"counters at zero leave the bpf layer unevidenced", func() result {
			r := healthyContained()
			r.BPFDenials = egress.Counters{}
			return r
		}, "denied nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.build().checkExpectations()
			if err == nil {
				t.Fatal("accepted a run this mode's contract forbids")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}
