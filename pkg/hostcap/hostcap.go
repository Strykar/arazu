// SPDX-License-Identifier: Apache-2.0

// Package hostcap probes the host for the capabilities the containment
// spike needs and refuses to proceed when one is missing.
//
// The point of probing rather than assuming is the BPF LSM silent-failure
// trap: if the bpf LSM is compiled in but absent from the runtime lsm= list,
// programs load, the verifier accepts them, attach returns success, and the
// hooks never fire. A gate that is not running looks exactly like a gate
// that permits everything.
package hostcap

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Check is one probed capability.
type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
	Remedy   string `json:"remedy,omitempty"`
}

// Report is the full capability matrix and the choices derived from it.
type Report struct {
	Checks        []Check `json:"checks"`
	EgressBackend string  `json:"egress_backend"`
	TPMDevice     string  `json:"tpm_device"`
	OK            bool    `json:"ok"`
}

func (r *Report) finalise() {
	r.OK = true
	for _, c := range r.Checks {
		if c.Required && !c.OK {
			r.OK = false
			return
		}
	}
}

func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// lsmListHasBPF reports whether the bpf LSM is in the active list.
//
// The comparison is per element and exact. A substring match would accept a
// hypothetical "bpfmisc" and report a gate that is not there.
func lsmListHasBPF(list string) bool {
	for _, name := range strings.Split(strings.TrimSpace(list), ",") {
		if strings.TrimSpace(name) == "bpf" {
			return true
		}
	}
	return false
}

func (r *Report) add(name string, required bool, ok bool, detail, remedy string) {
	c := Check{Name: name, OK: ok, Required: required, Detail: detail}
	if !ok {
		c.Remedy = remedy
	}
	r.Checks = append(r.Checks, c)
}

func haveAll(names ...string) (string, bool) {
	var missing []string
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return "missing: " + strings.Join(missing, ", "), false
	}
	return "all present", true
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func isMountpoint(path string) bool {
	var st, parent syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	if err := syscall.Stat(path+"/..", &parent); err != nil {
		return false
	}
	return st.Dev != parent.Dev
}

// Probe runs every capability check and derives the egress backend and TPM
// device from the results.
func Probe() Report {
	var r Report

	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	switch {
	case err != nil:
		r.add("kernel-bpf-lsm", true, false, "cannot read /sys/kernel/security/lsm: "+err.Error(),
			"mount securityfs, or the kernel lacks LSM support")
	case lsmListHasBPF(string(lsm)):
		r.add("kernel-bpf-lsm", true, true, "active LSMs: "+strings.TrimSpace(string(lsm)), "")
		r.EgressBackend = "bpf-lsm"
	default:
		r.EgressBackend = "cgroup-connect"
		r.add("kernel-bpf-lsm", true, false, "bpf absent from active LSMs: "+strings.TrimSpace(string(lsm)),
			"add bpf to the kernel lsm= cmdline and reboot; this spike implements only the bpf-lsm backend")
	}

	r.add("bpffs", true, isMountpoint("/sys/fs/bpf"), "/sys/fs/bpf",
		"mount -t bpf bpf /sys/fs/bpf")

	d, ok := haveAll("ip", "unshare")
	r.add("netns-tools", true, ok, d, "install iproute2 and util-linux")

	d, ok = haveAll("clang")
	r.add("clang", true, ok, d, "install clang")

	d, ok = haveAll("bpftool")
	r.add("bpftool", true, ok, d, "install bpftool")

	if f, err := os.Open("/sys/kernel/btf/vmlinux"); err == nil {
		f.Close()
		r.add("btf", true, true, "/sys/kernel/btf/vmlinux readable", "")
	} else {
		r.add("btf", true, false, err.Error(), "kernel needs CONFIG_DEBUG_INFO_BTF=y")
	}

	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if f, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
			f.Close()
			r.TPMDevice = dev
			break
		}
	}
	r.add("tpm-device", true, r.TPMDevice != "", "device: "+r.TPMDevice,
		"no usable TPM; add the user to group tss or run as root")

	d, ok = haveAll("tpm2_pcrread", "tpm2_pcrextend", "tpm2_pcrreset", "tpm2_createprimary",
		"tpm2_create", "tpm2_load", "tpm2_unseal", "tpm2_startauthsession",
		"tpm2_policypcr", "tpm2_flushcontext")
	r.add("tpm2-tools", true, ok, d, "install tpm2-tools")

	// Read PCR 23 rather than resetting it. This confirms the whole path to
	// the TPM works, not merely that the device node opens and the binaries
	// exist, and a capability probe has no business mutating host state to
	// answer a question. seal-tool does the reset when it means to.
	if r.TPMDevice != "" && ok {
		cmd := exec.Command("tpm2_pcrread", "sha256:23")
		cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=device:"+r.TPMDevice)
		out, err := cmd.CombinedOutput()
		r.add("tpm-pcr23-readable", true, err == nil,
			strings.TrimSpace(lastLine(string(out))),
			"the TPM did not answer a PCR read; check permissions on "+r.TPMDevice)
	} else {
		r.add("tpm-pcr23-readable", true, false, "skipped: no TPM device or tpm2-tools",
			"resolve the tpm-device and tpm2-tools checks first")
	}

	d, ok = haveAll("python3")
	r.add("python3", true, ok, d, "install python3 (used by the egress probe)")

	// Everything above is REQUIRED: without it the containment envelope cannot
	// be built or attached, which is what this repository is.
	//
	// Everything below is OPTIONAL and grouped by the tier it unlocks. A
	// reviewer who only wants to build the gate and watch the containment demo
	// should not be told they are missing minikube. Reporting them as required
	// would make a working checkout look broken, and a checker that cries wolf
	// gets ignored the first time it is right.
	// git sits under the optional comment above but is required: a host without
	// it fails check-env and is told to stop, which is the "working checkout
	// looks broken" outcome that comment argues against. Kept required because
	// nothing here works without it, and moved so the grouping reads true.
	d, ok = haveAll("git")
	r.add("git", true, ok, d, "install git (needed to stage the corpus)")

	d, ok = haveAll("podman")
	r.add("grade:podman", false, ok, d,
		"install podman — needed to build and run challenge targets")

	d, ok = haveAll("prove")
	r.add("grade:prove", false, ok, d,
		"install perl TAP::Harness — the nginx suite the grader diffs against baseline")

	// grade-patch.sh hard-requires both. Without them check-env reported the
	// grading tier green on a host where grading exits 2.
	d, ok = haveAll("yq")
	r.add("grade:yq", false, ok, d, "install yq — grade-patch.sh reads project.yaml with it")

	d, ok = haveAll("jq")
	r.add("grade:jq", false, ok, d, "install jq — the grader builds its JSON verdict with it")

	d, ok = haveAll("jq", "xxd")
	r.add("model:jq-xxd", false, ok, d,
		"install jq and xxd — used by corpus/local-model-yield.sh")

	d, ok = haveAll("ollama")
	r.add("model:ollama", false, ok, d,
		"install ollama and pull a model — only for the local-model tier")

	d, ok = haveAll("minikube", "kubectl", "helm")
	r.add("crs:cluster", false, ok, d,
		"install minikube, kubectl and helm — only to run the Buttercup CRS")

	r.add("root", true, os.Geteuid() == 0, fmt.Sprintf("euid=%d", os.Geteuid()),
		"run under sudo: netns creation and LSM attach need CAP_SYS_ADMIN")

	r.finalise()
	return r
}

// Text renders the matrix for a human reader.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-16s %-8s %s\n", "CHECK", "STATUS", "DETAIL")
	for _, c := range r.Checks {
		status := "ok"
		if !c.OK {
			status = "MISSING"
			if !c.Required {
				status = "absent"
			}
		}
		fmt.Fprintf(&b, "%-16s %-8s %s\n", c.Name, status, c.Detail)
		if c.Remedy != "" {
			fmt.Fprintf(&b, "%-16s %-8s remedy: %s\n", "", "", c.Remedy)
		}
	}
	fmt.Fprintf(&b, "\negress backend: %s\nTPM device:     %s\n", r.EgressBackend, r.TPMDevice)
	return b.String()
}
