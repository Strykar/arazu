// SPDX-License-Identifier: Apache-2.0

package hostcap

import (
	"strings"
	"testing"
)

func TestLSMListParsingDetectsBPF(t *testing.T) {
	if !lsmListHasBPF("capability,landlock,lockdown,yama,apparmor,bpf") {
		t.Fatal("bpf present in list but not detected")
	}
	if lsmListHasBPF("capability,landlock,yama,apparmor") {
		t.Fatal("bpf absent from list but reported present")
	}
	// A name that merely contains "bpf" is not the bpf LSM. A substring
	// match here would report a gate that is not running.
	if lsmListHasBPF("capability,bpfmisc") {
		t.Fatal("substring match wrongly detected bpf LSM")
	}
	if lsmListHasBPF("") {
		t.Fatal("empty list reported bpf present")
	}
	// Real /sys/kernel/security/lsm has no trailing newline on some kernels
	// and one on others.
	if !lsmListHasBPF("capability,bpf\n") {
		t.Fatal("trailing newline defeated detection")
	}
}

func TestReportNotOKWhenAnyRequiredCheckFails(t *testing.T) {
	r := Report{Checks: []Check{
		{Name: "a", OK: true, Required: true},
		{Name: "b", OK: false, Required: true, Remedy: "do the thing"},
	}}
	r.finalise()
	if r.OK {
		t.Fatal("report OK despite a failed required check")
	}
}

func TestReportOKWhenOnlyOptionalCheckFails(t *testing.T) {
	r := Report{Checks: []Check{
		{Name: "a", OK: true, Required: true},
		{Name: "b", OK: false, Required: false},
	}}
	r.finalise()
	if !r.OK {
		t.Fatal("report not OK despite only an optional check failing")
	}
}

// The privilege row must ask for the capability, not the uid. Both directions
// are wrong answers a human acts on: a container root has uid 0 without
// CAP_SYS_ADMIN and would be told the host is ready, and a process holding the
// capability without uid 0 would be told to re-run under sudo.
func TestPrivilegeRowAsksForTheCapabilityNotTheUID(t *testing.T) {
	if ok, detail := privilege(false, 0); ok {
		t.Errorf("uid 0 without CAP_SYS_ADMIN reported as privileged (%s)", detail)
	}
	if ok, detail := privilege(true, 1000); !ok {
		t.Errorf("CAP_SYS_ADMIN without uid 0 reported as unprivileged (%s)", detail)
	}
	if _, detail := privilege(false, 0); !strings.Contains(detail, "cap_sys_admin=false") {
		t.Errorf("evidence does not say what was observed: %q", detail)
	}
}
