#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The demonstration for a box with no TPM.
#
# On hardware that cannot measure, signing must be refused. That refusal IS the
# claim, so it is worth a rehearsed command rather than an improvisation in
# front of a judge. This asserts the refusal happens and names it, and exits
# non-zero because the pipeline did not sign.
#
# Exit codes are the point: 1 means the boundary held and refused, which is the
# expected outcome here. 2 means something else went wrong, including a refusal
# for the wrong reason or a signature produced anyway.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${ARAZU_DEGRADED_WORK:-$REPO/state/demo-degraded}"
BIN="$REPO/bin"

say() { printf '  %s\n' "$*"; }
rule() { printf '%s\n' "================================================================"; }

rule
printf '  ARAZU DEGRADED-MODE DEMONSTRATION\n'
printf '  a host with no TPM must refuse to sign, and say so\n'
rule
echo

[ -x "$BIN/seal-tool" ] || { say "build first: make build"; exit 2; }

# State the hardware, so the run is interpretable without knowing the host.
dev=""
for d in /dev/tpmrm0 /dev/tpm0; do [ -e "$d" ] && dev="$d" && break; done
if [ -n "$dev" ]; then
    say "a TPM IS present at $dev."
    say "this demonstration is for hosts without one. On this box run: make demo"
    exit 2
fi
say "TPM device      : none"
say "expected        : provisioning refuses, nothing is signed, exit non-zero"
echo

rm -rf "$WORK"; mkdir -p "$WORK"

# A content root is just a digest to bind against; any fixed value shows the
# refusal, because the refusal happens before the value is ever used.
root="0000000000000000000000000000000000000000000000000000000000000000"

out=$("$BIN/seal-tool" provision -dir "$WORK/seal" -content-root "$root" \
        -log "$WORK/audit.log" 2>&1)
code=$?

say "seal-tool provision exited $code"
printf '%s\n' "$out" | sed 's/^/      /'
echo

if [ "$code" -eq 0 ]; then
    rule
    say "FAILED: provisioning SUCCEEDED with no TPM."
    say "The measured-state binding is not fail-closed on this host."
    rule
    exit 2
fi

# A refusal is only the right refusal if it names the missing hardware. An
# unrelated error that happens to be non-zero would otherwise read as success.
if ! printf '%s' "$out" | grep -qiE 'tpm|tcti|device|no such file'; then
    rule
    say "FAILED: it refused, but not for a reason naming the TPM:"
    say "$(printf '%s' "$out" | head -1)"
    rule
    exit 2
fi

if [ -e "$WORK/seal/signing.key" ] || [ -e "$WORK/seal/sealed.blob" ]; then
    rule
    say "FAILED: refused, but left sealed material behind."
    rule
    exit 2
fi

rule
say "RESULT: REFUSED, as designed."
say "No signing key was provisioned and nothing was signed."
say "The pipeline degrades to no output rather than to unmeasured output."
rule
echo
say "This is the fail-closed demonstration, not a broken run."
say "With a TPM present the same command provisions and signs: make demo"
exit 1
