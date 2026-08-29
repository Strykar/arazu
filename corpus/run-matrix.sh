#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The yield matrix: every GPU-resident local model against three bug classes,
# three attempts each, plus one frontier control per class.
#
# Three attempts because a single run is an existence proof and the deck needs a
# rate. Three bug classes because cpv2 alone cannot say whether a model handles
# heap overflows or handles nginx.
#
# Only models that hold every layer on the 4090 at a 90k context are here:
# gpt-oss:20b, qwen3-coder:30b, devstral:24b. deepseek-r1:32b and
# qwen3.5:35b-a3b spill to CPU at this context and took 692s and 254s for one
# attempt; including them would add hours and measure the spill, not the model.
#
# The control is one Claude Opus 5 call per CPV. It exists to separate "this
# model cannot do it" from "this prompt cannot be answered" — on cpv2 it
# returned the challenge's reference fix in 9 seconds, which is what made the
# local failures interpretable as findings rather than harness artefacts.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/reports"
RESULTS="${RESULTS:-$OUT/matrix.jsonl}"
LOG="${LOG:-$OUT/matrix.log}"

MODELS=(gpt-oss:20b qwen3-coder:30b devstral:24b)
# Overridable so one CPV can be re-run into its own results file without
# truncating a completed matrix.
read -ra CPVS <<< "${CPVS:-cpv2 cpv9 cpv5}"
ATTEMPTS="${ATTEMPTS:-3}"
CONTROL="${CONTROL:-claude-opus-5}"
RUN_CONTROL="${RUN_CONTROL:-1}"

: > "$RESULTS"
say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
: > "$LOG"

say "matrix start: ${#MODELS[@]} models x ${#CPVS[@]} cpvs x $ATTEMPTS attempts, control=$CONTROL"

for cpv in "${CPVS[@]}"; do
    say "=== $cpv ==="

    # One control per CPV, first: if the frontier model cannot produce an
    # applicable patch for this bug class either, the local zeros that follow
    # say nothing about the models.
    if [ "$RUN_CONTROL" = "1" ]; then
        say "  control $CONTROL"
        MAX_TOKENS=64000 TIER=control "$HERE/local-model-yield.sh" \
            "$CONTROL" "$cpv" 1 >> "$RESULTS" 2>>"$LOG" \
            || say "  control failed on $cpv (continuing)"
    fi

    for model in "${MODELS[@]}"; do
        for a in $(seq 1 "$ATTEMPTS"); do
            say "  $model attempt $a"
            NUM_CTX=90112 TIER=A "$HERE/local-model-yield.sh" \
                "$model" "$cpv" "$a" >> "$RESULTS" 2>>"$LOG" \
                || say "  $model attempt $a failed (continuing)"
        done
        # Unload before the next model loads: two 20GB models resident at once
        # is what hard-locked this host twice.
        ollama stop "$model" >/dev/null 2>&1 || true
    done
done

say "matrix complete: $(wc -l < "$RESULTS") results -> $RESULTS"

# Summary by model: acceptance is level 3; the ladder shows where the rest died.
if command -v jq >/dev/null; then
    say "--- summary ---"
    jq -rs '
      group_by(.model)[] |
      { model: .[0].model,
        n: length,
        accepted: [.[] | select(.level==3)] | length,
        reached_pov_clean: [.[] | select(.level>=2)] | length,
        applied: [.[] | select(.applied==true)] | length,
        no_diff: [.[] | select(.level==-1 and (.note|test("no unified diff")))] | length }
      | "\(.model): \(.accepted)/\(.n) accepted, \(.reached_pov_clean) stopped the sanitizer, \(.applied) applied, \(.no_diff) emitted no diff"
    ' "$RESULTS" | tee -a "$LOG"
fi
