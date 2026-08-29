// SPDX-License-Identifier: Apache-2.0

package hostcap

import (
	"os"
	"strconv"
	"strings"
)

// CAP_SYS_ADMIN is bit 21 of the capability bitmask. Creating a network
// namespace and attaching an LSM program both need it.
const capSysAdmin = 21

// HasSysAdmin reports whether this process can actually create a namespace,
// rather than whether it merely looks like it can.
//
// euid == 0 is NOT the same question and was the guard the tests used. A
// container running as root has uid 0 and no CAP_SYS_ADMIN, so the guard
// passed, the test proceeded, and `ip netns add` failed with "Operation not
// permitted" — reported as a failure rather than a skip. Someone evaluating
// this repo in a container therefore sees red where the honest answer is "this
// machine cannot run that test".
//
// Reads the effective set from /proc/self/status, which is the kernel's own
// answer. Falls back to the euid check where that is unreadable, because being
// wrong in the direction of "attempt it" is better than skipping silently on a
// machine that would have worked.
func HasSysAdmin() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return os.Geteuid() == 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return os.Geteuid() == 0
		}
		return v&(1<<capSysAdmin) != 0
	}
	return os.Geteuid() == 0
}

// HasTPM reports whether a TPM character device is present and openable.
//
// The same question as HasSysAdmin, asked about hardware instead of privilege,
// and it was the half nobody asked. The demo test guarded on CAP_SYS_ADMIN and
// root and then sealed anyway, so on a machine with the privilege and no device
// it did not skip: it ran, "seal provisioning failed", and the happy path was
// reported as MISMATCH — an absent TPM presented as a wrong prediction. That is
// what a cold boot in any VM without a vTPM shows.
//
// This does not weaken the TPM signal. check-env reports tpm-device on its own
// row and the self-check prints it, so a machine that should have a TPM and
// does not still fails loudly, in the place that is about the machine.
func HasTPM() bool {
	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if f, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
			f.Close()
			return true
		}
	}
	return false
}
