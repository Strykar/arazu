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

// HasSysAdmin reports whether this process can create a network namespace.
//
// euid == 0 is a different question: a container root has uid 0 and no
// CAP_SYS_ADMIN, so guarding on it turns "this machine cannot run the test"
// into a failed test. Reads the effective set from /proc/self/status, falling
// back to euid where that is unreadable, since attempting beats skipping on a
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
// HasSysAdmin's question asked about hardware: sealing on a machine with the
// privilege and no device reports MISMATCH where the honest answer is a skip.
// check-env still fails tpm-device loudly on its own row.
func HasTPM() bool {
	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if f, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
			f.Close()
			return true
		}
	}
	return false
}
