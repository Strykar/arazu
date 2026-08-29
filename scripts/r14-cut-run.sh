#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# R1.4 cut run: the same libpng task with the cluster's egress DENIED, and the
# denial recorded BY DESTINATION.
#
# WHY THE RULE RECORDS RATHER THAN JUST DROPS. A silent black hole makes a
# missing dependency and a slow model produce the same observable — a run that
# does not finish — so the probe could not attribute the one thing it exists to
# attribute. A drop that records every destination it refuses makes the verdict
# readable from WHAT WAS REACHED FOR rather than from whether the run completed,
# and a ZERO reach-set is then as informative as a populated one.
#
# WHY BY DESTINATION, not just a count. "It reached for something" fires R1.4's
# pre-decision and abandons the air-gapped Buttercup path. "It reached for
# ghcr.io and nothing else" may be closed by one more pre-pull. Those lead to
# opposite decisions, and only the destination list separates them.
#
# The cut is in the FORWARD chain, keyed on the minikube bridge. Traffic to the
# host itself (the ollama listener on 192.168.49.1) traverses INPUT, not FORWARD,
# so the local model stays reachable by construction rather than by an exception
# — the boundary being tested is "off this box", and that is exactly the chain
# that carries it.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/as-user.sh"

BRIDGE_IF="${ARAZU_MINIKUBE_IF:-$(ip -o -4 addr show | awk '/192.168.49.1\//{print $2; exit}')}"
SUBNET="${ARAZU_MINIKUBE_SUBNET:-192.168.49.0/24}"
BUTTERCUP="${ARAZU_BUTTERCUP_DIR:-/mnt/4TB1/arazu-corpus/buttercup}"
OUT="${ARAZU_CUT_OUT:-$HERE/../logs/r14/cut}"
BUDGET_SEC="${ARAZU_T2_BUDGET:-5400}"
mkdir -p "$OUT"

[ "$(id -u)" -eq 0 ] || { echo "needs root: inserts a forward-chain drop" >&2; exit 2; }

added=0
restore() {
    if [ "$added" -eq 1 ]; then
        # Read the evidence out BEFORE tearing the table down; it lives in kernel
        # state that the delete destroys.
        nft list table inet arazu > "$OUT/table-final.txt" 2>&1 || true
    fi
    # One atomic delete of OUR OWN table. The host's inet filter ruleset is never
    # edited, so a failed revert cannot leave a stray rule in it — the failure
    # mode that makes a disposable rule quietly permanent.
    nft delete table inet arazu 2>/dev/null || true
    if nft list table inet arazu >/dev/null 2>&1; then
        echo "REVERT INCOMPLETE: table inet arazu still exists" >&2
    else
        echo "reverted: table inet arazu removed; host filter ruleset never touched"
    fi
    # Prove the cluster has its egress back, or say so. A cut left in place would
    # look like a broken cluster to whoever touches it next.
    if as_user minikube ssh -- "curl -sf -m 8 https://ghcr.io >/dev/null 2>&1 || curl -sf -m 8 http://1.1.1.1 >/dev/null 2>&1"; then
        echo "confirmed: the cluster can reach off-box again"
    else
        echo "WARNING: the cluster still cannot reach off-box — check by hand" >&2
    fi
}
trap restore EXIT

started=$(date +%s)
stamp() { echo "[$(date -u +%H:%M:%S) +$(( ($(date +%s) - started) / 60 ))m]"; }

# The cut lives in its OWN table at a priority ahead of the host's filter table,
# so a drop here is decided before `iifname "br-*" accept` (handle 43) can permit
# the minikube bridge. Insert-versus-append does not arise: a separate hook
# cannot be short-circuited by the other table's rule order.
#
# The reach-set comes from a DYNAMIC SET. This is not a preference: `log` was
# tried against this kernel and REFUSED — "Could not process rule: No such file
# or directory" with the caret on `log`, because nf_log_syslog is CONFIG=m and
# not installed. The rule containing it cannot be added at all. Had the reach-set
# been built on log parsing, as the first draft was, the cut run would have died
# at its first statement.
#
# A dynamic set accumulates destinations in kernel memory and is read back with
# `nft list set`, needing no logging backend, no kmsg path and no loglevel. The
# self-test below then proves the set RECORDS before anything depends on it, so a
# final empty set means "nothing reached out" and not "the instrument failed" —
# the distinction the whole criterion rests on.
nft -f - <<EOF
table inet arazu {
    set cut_dst {
        type ipv4_addr
        flags dynamic
        timeout 7d
    }
    chain cut {
        type filter hook forward priority filter - 10; policy accept;
        iifname "$BRIDGE_IF" ip saddr $SUBNET \
            update @cut_dst { ip daddr } counter drop
    }
}
EOF
added=1
echo "$(stamp) egress CUT for $SUBNET on $BRIDGE_IF (table inet arazu, priority filter-10)"

# --- self-test, both directions ----------------------------------------------
# The cut must actually deny, AND the local model must still be reachable.
# Either failing alone makes the whole run uninterpretable, in opposite ways.
if as_user minikube ssh -- "curl -sf -m 8 http://1.1.1.1" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: the cluster still reaches off-box. The cut is not in effect." >&2
    exit 1
fi
echo "$(stamp) self-test: the cluster cannot reach off-box"

# The same probe proves the RECORDING works, not just the dropping. If 1.1.1.1
# does not appear in the set now, then an empty set at the end would mean
# "the instrument is broken", not "nothing reached out" — and those two readings
# lead to opposite conclusions about R1.4. Verify the instrument on traffic whose
# existence is certain, before the run depends on it.
if ! nft list set inet arazu cut_dst 2>/dev/null | grep -q '1\.1\.1\.1'; then
    echo "SELF-TEST FAILED: the drop worked but 1.1.1.1 is not in cut_dst." >&2
    echo "The reach-set cannot record, so a zero result would be unreadable." >&2
    exit 1
fi
echo "$(stamp) self-test: the reach-set records a known-denied destination"
if ! as_user minikube ssh -- "curl -sf -m 8 http://192.168.49.1:11434/api/version" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: the local model is unreachable, so a stall would be" >&2
    echo "the cut hitting the model rather than a missing dependency." >&2
    exit 1
fi
echo "$(stamp) self-test: the local model is still reachable"

echo "$(stamp) submitting the task"
( cd "$BUTTERCUP" && as_user make send-libpng-task ) > "$OUT/submit.log" 2>&1

while :; do
    elapsed=$(( $(date +%s) - started ))
    [ "$elapsed" -ge "$BUDGET_SEC" ] && { echo "$(stamp) BUDGET REACHED"; break; }
    if [ $(( elapsed % 300 )) -lt 21 ]; then
        # Read OUR table, not the host's filter table the first draft pointed at.
        pkts=$(nft list chain inet arazu cut 2>/dev/null \
               | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | tail -1)
        seen=$(nft list set inet arazu cut_dst 2>/dev/null \
               | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l)
        echo "$(stamp) drops: ${pkts:-0}, distinct destinations: ${seen:-0}"
    fi
    sleep 20
done

# --- the deliverable ----------------------------------------------------------
# Read from the sources that actually carry the facts. The T2 run's analysis
# greped the litellm log for finish_reason/prompt_tokens/POST paths and got
# nothing on all four: that log holds only health checks and the endpoint has no
# /v1 prefix. These three sources were verified to carry the data before use.
echo
echo "=== THE REACH-SET, by destination — the point of the whole run ==="
# PRIMARY: the kernel set. Verified to record during the self-test, so an empty
# result here means "nothing reached out" and not "the instrument failed".
nft list set inet arazu cut_dst 2>/dev/null | tee "$OUT/cut_dst.txt" \
  | tr ',' '\n' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$OUT/reach-set.txt"
n=$(wc -l < "$OUT/reach-set.txt")
echo "  distinct destinations reached for: $n  (1.1.1.1 is the self-test's own, discount it)"
nft list chain inet arazu cut 2>/dev/null | grep -oE 'packets [0-9]+ bytes [0-9]+' | sed 's/^/  totals: /'
if [ "$n" -le 1 ]; then
    echo "  Nothing beyond the self-test reached for the network."
    echo "  Read with the task outcome below: advanced = ran egress-free (clean pass);"
    echo "  stalled = CAPABILITY, not egress. The zero is meaningful because the"
    echo "  self-test proved this set can record."
else
    # Resolve each to a name, because a decision needs to know WHOSE address it is.
    # One more pre-pull may close a registry; a telemetry endpoint may just be cut.
    while read -r ip; do
        printf "    %-16s %s\n" "$ip" "$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' || true)"
    done < "$OUT/reach-set.txt"
    echo
    echo "  Each entry is a dependency. Decide PER ENTRY whether a pre-pull or a"
    echo "  pre-staged mirror closes it — that is what separates 'the pre-decision"
    echo "  fires' from 'one more pre-pull and Buttercup runs air-gapped'."
fi
echo
echo "  NOTE: there is no second source. nf_log is unavailable on this kernel, so"
echo "  per-port detail is not recoverable and only the destination set is. Stated"
echo "  because a single source is a real limitation, not because it is fine."

echo
echo "=== the local model, over the run (ollama's own slot log) ==="
J=$(journalctl -u ollama --since "@$started" --no-pager 2>/dev/null)
echo "$J" | grep -c 'chat/completions' | sed 's/^/  completions served : /'
echo "$J" | grep -oE 'truncated = [0-9]+' | sort | uniq -c | sed 's/^/  /'
echo "$J" | grep -oE 'task\.n_tokens = [0-9]+' | grep -oE '[0-9]+$' | python3 -c "
import sys
v=[int(x) for x in sys.stdin]
print(f'  prompt sizes       : n={len(v)} min={min(v)} max={max(v)}') if v else print('  none')"

echo
echo "=== did the pipeline advance on model output? (the T2 bar, restated) ==="
as_user kubectl logs -n crs deploy/buttercup-patcher --since="${BUDGET_SEC}s" 2>/dev/null > "$OUT/patcher.log"
for p in "Analyzing the vulnerability" "Selecting a patch strategy" "Creating a patch for" "No valid patches generated"; do
    printf "  %-32s %s\n" "$p" "$(grep -cF "$p" "$OUT/patcher.log")"
done
echo
echo "$(stamp) cut run done. Artifacts in $OUT"
