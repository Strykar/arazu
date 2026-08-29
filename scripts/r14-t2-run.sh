#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# R1.4 T2: run the libpng task against the LOCAL model and record, per model
# call, the fields that decide what a failure means.
#
# Runs under r14-probe.sh, so the exposure is already up and comes down when
# this exits either way. Invoked as root; user-context tools go through as_user.
#
# The whole design principle: this script does not decide whether Buttercup
# "worked". It records the observations that make the verdict decidable later —
# finish_reason (budget vs incapacity), prompt_tokens (truncation vs incapacity),
# and the upstream each call actually went to (local vs off-box). A run that
# ends without those recorded has to be repeated to answer questions it already
# had the data for.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib/as-user.sh"

BUTTERCUP="${ARAZU_BUTTERCUP_DIR:-/mnt/4TB1/arazu-corpus/buttercup}"
OUT="${ARAZU_T2_OUT:-$HERE/../logs/r14/t2}"
BUDGET_SEC="${ARAZU_T2_BUDGET:-5400}"   # 90 minutes, fixed before the run
mkdir -p "$OUT"

started=$(date +%s)
stamp() { echo "[$(date -u +%H:%M:%S) +$(( ($(date +%s) - started) / 60 ))m]"; }

echo "$(stamp) T2 control: libpng against gpt-oss:20b, egress UP, budget ${BUDGET_SEC}s"

# Capture the litellm log for the whole run. This is the primary artifact: the
# verdict is read from it, not from whether the task appeared to finish.
as_user kubectl logs -n crs deploy/buttercup-litellm --tail=0 -f > "$OUT/litellm.log" 2>&1 &
LOGPID=$!
trap 'kill $LOGPID 2>/dev/null' EXIT

echo "$(stamp) submitting the task"
( cd "$BUTTERCUP" && as_user make send-libpng-task ) > "$OUT/submit.log" 2>&1
echo "$(stamp) submit exit=$? (see submit.log)"

# --- the watch loop -----------------------------------------------------------
# Polls rather than waits, because the interesting outcome is often visible long
# before the task ends, and a run that can be abandoned early on a decided
# criterion is worth more than one that can only be read at the end.
last_report=0
while :; do
    now=$(date +%s); elapsed=$(( now - started ))
    [ "$elapsed" -ge "$BUDGET_SEC" ] && { echo "$(stamp) BUDGET REACHED"; break; }

    if [ $(( elapsed - last_report )) -ge 120 ]; then
        last_report=$elapsed
        calls=$(grep -c 'POST /v1/chat/completions\|selected model' "$OUT/litellm.log" 2>/dev/null || echo 0)
        errs=$(grep -ci 'error\|exception\|timeout' "$OUT/litellm.log" 2>/dev/null || echo 0)
        echo "$(stamp) litellm lines=$(wc -l < "$OUT/litellm.log") calls~$calls errs~$errs"
    fi

    # Task finished? The orchestrator marks tasks done in redis; the cheap
    # observable is a patch appearing or the pipeline going quiet.
    if as_user kubectl logs -n crs deploy/buttercup-patcher --tail=200 2>/dev/null \
         | grep -qiE 'patch (submitted|accepted|found)|task .* (done|complete)'; then
        echo "$(stamp) patcher reports a terminal state"
        break
    fi
    sleep 20
done

# --- what the run actually showed ---------------------------------------------
echo
echo "=== per-call facts, which are the deliverable ==="
as_user kubectl logs -n crs deploy/buttercup-litellm --tail=100000 2>/dev/null > "$OUT/litellm-full.log"
python3 - "$OUT/litellm-full.log" <<'PY'
import re, sys, collections
txt = open(sys.argv[1], errors='replace').read()
def counts(pat):
    return collections.Counter(re.findall(pat, txt))
print("  upstream host seen   :", dict(counts(r'(192\.168\.49\.1|api\.anthropic\.com|api\.openai\.com)')) or "none logged")
print("  finish_reason        :", dict(counts(r"'finish_reason':\s*'(\w+)'")) or "none logged")
pt = [int(x) for x in re.findall(r"'prompt_tokens':\s*(\d+)", txt)]
if pt:
    print(f"  prompt_tokens        : n={len(pt)} min={min(pt)} max={max(pt)} "
          f"(n_ctx=32768; a max pinned near it means SILENT TRUNCATION, not incapacity)")
else:
    print("  prompt_tokens        : none logged")
print("  errors               :", dict(counts(r'(RateLimitError|AuthenticationError|APIConnectionError|Timeout)')) or "none")
PY
echo
echo "=== task outcome ==="
as_user kubectl logs -n crs deploy/buttercup-patcher --tail=40 2>/dev/null | tail -20
echo
echo "$(stamp) T2 done. Artifacts in $OUT"
