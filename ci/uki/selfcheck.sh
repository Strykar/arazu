#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Arazu bare-metal self-check. Runs at boot in the UKI, prints ONE screen, stops.
#
# WHY THIS EXISTS. Three of the claims in this repository cannot be tested in a
# container, because they are about the kernel: that the BPF LSM attaches and
# denies, that a network namespace with no route is the primary control, and
# that a signing key can be sealed against measured state in a real TPM. A
# container shares the host kernel and cannot hold CAP_SYS_ADMIN, so those tests
# skip there — correctly, and uninformatively.
#
# The output is designed to be PHOTOGRAPHED. There is no persistent storage in
# this image, so a verdict that scrolls is a verdict that is lost: every check
# is one line, the summary is the last thing printed, and nothing is emitted
# after it. Detail for a failing check is printed above the summary, not below.
set -uo pipefail

ARAZU=/usr/local/arazu
PASS=0; FAIL=0; SKIP=0
declare -a FAILED=()
declare -a DETAIL=()

ok()   { printf '    %-26s \033[32mOK\033[0m   %s\n' "$1" "${2:-}"; PASS=$((PASS+1)); }
bad()  { printf '    %-26s \033[31mFAIL\033[0m %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
skip() { printf '    %-26s \033[33mSKIP\033[0m %s\n' "$1" "${2:-}"; SKIP=$((SKIP+1)); }
hdr()  { printf '\n  \033[1m%s\033[0m\n' "$1"; }

clear 2>/dev/null || true
printf '\033[1m'
printf '================================================================\n'
printf '  ARAZU SELF-CHECK   %s\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
printf '  kernel %s\n' "$(uname -r)"
printf '================================================================\033[0m\n'

# ---------------------------------------------------------------- environment
hdr "ENVIRONMENT"
lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)
case "$lsm" in
    *bpf*) ok "bpf LSM active" ;;
    "")    bad "bpf LSM active" "securityfs not mounted" ;;
    *)     bad "bpf LSM active" "active: $lsm" ;;
esac
mountpoint -q /sys/fs/bpf && ok "bpffs mounted" || bad "bpffs mounted" "/sys/fs/bpf"
[ -r /sys/kernel/btf/vmlinux ] && ok "BTF available" || bad "BTF available" "CONFIG_DEBUG_INFO_BTF"

# A hardware TPM is assumed, not optional: the trust story is a key sealed under
# a policy over measured state, and an emulator cannot make that claim.
if [ -c /dev/tpmrm0 ]; then
    ver=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null)
    if [ "$ver" = "2" ]; then ok "TPM 2.0 device" "/dev/tpmrm0"; else bad "TPM 2.0 device" "version $ver"; fi
else
    bad "TPM 2.0 device" "no /dev/tpmrm0"
fi
command -v tpm2_pcrread >/dev/null && ok "tpm2-tools" || bad "tpm2-tools" "not installed"

# ---------------------------------------------------------------------- build
hdr "BUILD"
cd "$ARAZU" || { bad "repo present" "$ARAZU missing"; }
if [ -x "$ARAZU/bin/gate" ]; then
    ok "binaries prebuilt" "$(ls "$ARAZU/bin" | wc -l) in bin/"
else
    bad "binaries prebuilt" "image did not ship them"
fi
[ -s "$ARAZU/bpf/egress_deny.bpf.o" ] && ok "bpf object" || bad "bpf object" "not built into the image"

# ----------------------------------------------------------------- capability
hdr "CAPABILITY"
# check-env answers "can this machine BUILD and RUN arazu". This image is
# runtime-only by design — clang, bpftool, make and git are build-time and were
# dropped so the UKI fits beside the existing kernels in /boot/EFI/Linux — so
# their absence here is the intended configuration, not a defect. Failing on
# them would make a correct image report itself broken, which is the same error
# as reporting a skipped test as a failure.
#
# The runtime-relevant checks are the ones the ENVIRONMENT section above already
# makes individually. This reports the rest for information.
"$ARAZU/bin/arazu-env" >/tmp/env.out 2>/dev/null || true
miss=$(sed -n '/^{/,$p' /tmp/env.out | python3 -c '
import json,sys
BUILD_ONLY={"clang","bpftool","make","git"}
try: r=json.load(sys.stdin)
except Exception: print("PARSE|"); raise SystemExit
bad=[c["name"] for c in r.get("checks",[]) if c.get("required") and not c.get("ok")]
rt=[n for n in bad if n not in BUILD_ONLY]
print("|".join([",".join(rt), ",".join(n for n in bad if n in BUILD_ONLY)]))
' 2>/dev/null)
rt_missing=${miss%%|*}; build_missing=${miss#*|}
if [ "$rt_missing" = "PARSE" ]; then
    bad "check-env" "could not parse arazu-env output"
elif [ -n "$rt_missing" ]; then
    bad "check-env runtime" "$rt_missing"
else
    ok "check-env runtime" "${build_missing:+build-only absent by design: $build_missing}"
fi

# --------------------------------------------------------------- containment
# The three-run table is the containment claim's whole evidence base. Two runs
# cannot separate the layers: "the contained run reached nothing" is explained
# just as well by the namespace alone, which would leave the BPF hook unevidenced.
hdr "CONTAINMENT (three-run attribution)"
# -bundle is REQUIRED: contained-run refuses without it, and the workload reads
# the bundle and the run re-measures it. The image ships generated fixtures.
BUNDLE="${ARAZU}/testdata/bundles/good"
run_mode() {
    timeout 300 "$ARAZU/bin/contained-run" -mode "$1" \
        -bundle "$BUNDLE" \
        -obj "$ARAZU/bpf/egress_deny.bpf.o" \
        -probe "$ARAZU/scripts/egress-probe.sh" \
        -out "/tmp/out-$1" -log "/tmp/log-$1" 2>"/tmp/err-$1"
}

# contained-run emits ONE indented JSON object, not a stream of lines, and `ok`
# is its first field so a top-down reader meets the verdict before the detail.
# The first version of this script parsed it line by line and would have
# reported every containment check as unknown.
verdict_for() { python3 - "$1" "$2" <<'PYEOF'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception:
    print("unparseable"); raise SystemExit
if not r.get("ok"):
    print("run-failed:" + (r.get("reason") or "?")); raise SystemExit
for p in r.get("probes", []):
    if p.get("name") == sys.argv[2]:
        print("REACHED" if p.get("reached") else (p.get("errno") or "?")); raise SystemExit
print("absent")
PYEOF
}

# The kernel's own denial counters, a second witness that does not depend on
# reading a userspace errno.
counters_for() { python3 - "$1" <<'PYEOF'
import json, sys
try: r = json.load(open(sys.argv[1]))
except Exception: print(""); raise SystemExit
d = r.get("bpf_denials") or {}
print(" ".join(f"{k}={v}" for k, v in d.items() if v))
PYEOF
}

if run_mode control >/tmp/control.json 2>&1; then
    v=$(verdict_for /tmp/control.json tcp-connect)
    [ "$v" = REACHED ] && ok "control reaches network" "$v" \
        || bad "control reaches network" "$v — nothing below means anything"
else
    why=$(python3 -c '
import json
try: print(json.load(open("/tmp/control.json")).get("reason") or "")
except Exception: print("")' 2>/dev/null)
    bad "control run" "did not complete: ${why:-no reason recorded}"
    DETAIL+=("control stderr: $(tail -3 /tmp/err-control 2>/dev/null)")
fi
if run_mode netns-only >/tmp/netns.json 2>&1; then
    v=$(verdict_for /tmp/netns.json tcp-connect)
    [ "$v" = ENETUNREACH ] && ok "netns-only denies" "$v" || bad "netns-only denies" "$v"
else
    why=$(python3 -c '
import json
try: print(json.load(open("/tmp/netnsonly.json")).get("reason") or "")
except Exception: print("")' 2>/dev/null)
    bad "netns-only run" "did not complete: ${why:-no reason recorded}"
    DETAIL+=("netns-only stderr: $(tail -3 /tmp/err-netns-only 2>/dev/null)")
fi
if run_mode contained >/tmp/contained.json 2>&1; then
    v=$(verdict_for /tmp/contained.json tcp-connect)
    [ "$v" = EPERM ] && ok "contained denies" "$v (bpf hook)" || bad "contained denies" "$v"
    # The load-bearing row: a raw send onto the namespace's own loopback reaches
    # nothing, so it is never a leak, but the namespace cannot refuse it either.
    # A denial there is the BPF hook's work alone.
    r=$(verdict_for /tmp/contained.json raw-packet-loopback)
    [ "$r" = EPERM ] && ok "loopback raw denied" "$r — attributable to bpf only" \
        || bad "loopback raw denied" "$r"
    c=$(counters_for /tmp/contained.json)
    [ -n "$c" ] && ok "kernel counters witness" "$c" \
        || bad "kernel counters witness" "all zero — the hook never fired"
else
    # Print WHY. The reason is in the json (contained-run puts it there so a
    # partial read cannot step over it) and the detail is in the captured
    # stderr. Reporting only "did not complete" means the next diagnosis costs
    # a reboot, and this image has no persistent storage to come back to.
    why=$(python3 -c '
import json,sys
try: r=json.load(open("/tmp/contained.json"))
except Exception: print(""); raise SystemExit
print(r.get("reason") or "")' 2>/dev/null)
    bad "contained run" "did not complete: ${why:-no reason recorded}"
    DETAIL+=("contained-run stderr:")
    DETAIL+=("$(tail -6 /tmp/err-contained 2>/dev/null)")
    DETAIL+=("bpf_attached=$(python3 -c '
import json
try: print(json.load(open("/tmp/contained.json")).get("bpf_attached"))
except Exception: print("?")' 2>/dev/null)")
fi

# ----------------------------------------------------------------------- tpm
hdr "TPM"
if [ -c /dev/tpmrm0 ]; then
    export TPM2TOOLS_TCTI=device:/dev/tpmrm0
    if tpm2_pcrread sha256:23 >/tmp/pcr23 2>/dev/null; then
        ok "PCR 23 readable" "$(awk '/23:/{print substr($2,1,18)"..."}' /tmp/pcr23)"
    else
        bad "PCR 23 readable" "tpm2_pcrread failed"
    fi
else
    skip "PCR 23 readable" "no TPM"
fi

# --------------------------------------------------------------------- suite
hdr "SUITE"
if command -v go >/dev/null; then
    out=$(cd "$ARAZU" && timeout 900 go test ./... -count=1 2>&1)
    # Count PACKAGE lines, not every line starting with FAIL. Go prints a bare
    # "FAIL" after a failing package's output and another at the end, so one
    # failed package counted as three. It inflates, which is why it went
    # unchallenged: nobody argues with a check claiming more damage than there is.
    nfail=$(grep -cE '^FAIL[[:space:]]+[^[:space:]]' <<<"$out")
    if [ "$nfail" -eq 0 ]; then
        ok "go test ./..." "all packages pass"
    else
        bad "go test ./..." "$nfail package(s) failed"
        DETAIL+=("$(grep -E '^(FAIL|\s+---)' <<<"$out" | head -6)")
    fi
else
    skip "go test ./..." "toolchain not in image"
fi

# ------------------------------------------------------------------- verdict
if [ "${#DETAIL[@]}" -gt 0 ]; then
    printf '\n  \033[1mDETAIL\033[0m\n'
    printf '%s\n' "${DETAIL[@]}" | head -12 | sed 's/^/    /'
fi

printf '\n\033[1m================================================================\033[0m\n'
if [ "$FAIL" -eq 0 ]; then
    printf '  \033[1;32mRESULT: ALL CHECKS PASSED\033[0m   %d ok, %d skipped\n' "$PASS" "$SKIP"
    # Name what was actually verified, not what the image would have liked to
    # verify. The Go toolchain is deliberately absent so the UKI fits beside the
    # installed kernels, so the suite SKIPS here — and a summary claiming "the
    # full suite" while the line above it reads SKIP is exactly the kind of
    # over-claim a reviewer catches and everything else in the screen then pays
    # for. The suite is covered on a build host; this image covers the kernel.
    printf '  containment and TPM verified on bare metal (%d checks).\n' "$PASS"
    if [ "$SKIP" -gt 0 ]; then
        printf '  %d skipped, listed above: not run here, not claimed.\n' "$SKIP"
    fi
else
    printf '  \033[1;31mRESULT: %d FAILED\033[0m   %d ok, %d skipped\n' "$FAIL" "$PASS" "$SKIP"
    printf '  failed: %s\n' "${FAILED[*]}"
fi
printf '\033[1m================================================================\033[0m\n'
printf '\n  photograph this screen. there is no persistent storage.\n'
printf '  power off when done.\n\n'
