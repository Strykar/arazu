#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Ask a model to judge one candidate patch by READING it, and record the answer
# beside what execution established. One candidate per invocation; emits one
# JSON line, the same shape local-model-yield.sh uses.
#
# This is the judge arm of the three-arm experiment in
# reports/judge-arm-predictions.yaml. The gate arm needs no script: it decides
# by executing, and every candidate already names the reason it should fall to.
#
# What the judge is given: the sanitizer report from the unpatched build, the
# PoV bytes, the source files the traces implicate, and the candidate diff.
# That is the patcher prompt's material plus the patch, minus the instruction to
# write one.
#
# What it is never given: expected_gate_reason, the candidate's label, the
# gate's verdict, or which arm is running. verify-no-leak below asserts the
# first of those, because a case file that reaches the prompt hands over the
# answer and the run measures nothing.
#
# The judge must name a REASON from the gate's own vocabulary, not just accept
# or reject. 18 of the 20 corpus candidates are refusals and 14 share one
# reason, so a judge that answers REJECT to everything scores 18/20 on verdict
# alone. Scoring the reason jointly is what makes that visible.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
# libpng is a bare source tree rather than an AIxCC CP, so it has no run.sh, no
# src/ subdir and no /src/harnesses/bld/ prefix in its traces. Everything that
# differs is set from the case's target below rather than assumed to be nginx.
LIBPNG_SRC="${LIBPNG_SRC:-/var/lib/arazu-corpus/libpng/example-libpng}"
OUT="${OUT:-$HERE/reports}"
ASAN_DIR="$OUT/asan"
# The endpoint MOVES on this host, so it is discovered rather than assumed.
# ollama binds where OLLAMA_HOST points, and that is flipped between loopback
# and the minikube bridge depending on whether the CRS in minikube currently
# needs to reach it. Hardcoding either one is wrong half the time, and the
# failure is a connection refused that reads like the model being unavailable.
# Probe what is actually listening; an explicit OLLAMA= always wins.
if [ -z "${OLLAMA:-}" ]; then
    for cand in $(ss -lnt 2>/dev/null | awk '$4 ~ /:11434$/ {print $4}') \
                127.0.0.1:11434 192.168.49.1:11434; do
        case "$cand" in 0.0.0.0:*) cand="127.0.0.1:11434" ;; "[::]:"*) cand="127.0.0.1:11434" ;; esac
        if curl -sS -m 3 "http://$cand/api/tags" >/dev/null 2>&1; then
            OLLAMA="http://$cand"; break
        fi
    done
fi
OLLAMA="${OLLAMA:-http://127.0.0.1:11434}"
NUM_CTX="${NUM_CTX:-90112}"
# A judge answers in tens of tokens, not thousands. Temperature 0 because this
# is an adjudication, not a generation: two runs disagreeing would be noise in
# the measurement rather than a finding about the model.
TEMP="${TEMP:-0}"
MAX_FILES="${MAX_FILES:-2}"

usage() { echo "usage: $0 <model> <case-file> <candidate-id>" >&2; exit 2; }
[ $# -eq 3 ] || usage
MODEL=$1; CASE_FILE=$2; CAND_ID=$3
[ -r "$CASE_FILE" ] || { echo "no readable case at $CASE_FILE" >&2; exit 2; }

command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
command -v yq >/dev/null || { echo "yq required" >&2; exit 2; }

CASE_ID=$(yq -r '.id' "$CASE_FILE")
TARGET=$(yq -r '.target' "$CASE_FILE")
CWE=$(yq -r '.cwe + " " + .cwe_name' "$CASE_FILE")
EXPECTED_SAN=$(yq -r '.pov.expected_sanitizer' "$CASE_FILE")

# The candidate's patch path, and the root it is relative to. patch_root is
# "challenge" for the challenge's own patches and "repo" for ones synthesised
# here; absent means challenge, matching pkg/corpus.
# Third argument is either a candidate id declared in the case, or a path to a
# diff. The path form is for the retained yield candidates: models wrote those,
# the gate already ruled on each, and none of them is declared in a case file.
# Ground truth for that form comes from EXPECTED_REASON, since the matrix records
# a level and a note rather than a reason from the vocabulary, and the mapping is
# the caller's to state rather than this script's to guess.
if [ -f "$CAND_ID" ]; then
    patch_path=$(realpath "$CAND_ID")
    CAND_ID=$(basename "$patch_path" .diff)
    cand='{}'
    exp="${EXPECTED_REASON:-}"
    lbl=""
else
    cand=$(yq -r -o=json '.candidates[] | select(.id == "'"$CAND_ID"'")' "$CASE_FILE")
    [ -n "$cand" ] || { echo "no candidate $CAND_ID in $CASE_FILE" >&2; exit 2; }
    patch_rel=$(echo "$cand" | jq -r '.patch')
    patch_root=$(echo "$cand" | jq -r '.patch_root // "challenge"')
    case "$patch_root" in
        repo)      patch_path="$REPO/$patch_rel" ;;
        challenge)
            # An absent patch_root means "challenge", which is right for the
            # AIxCC shape. libpng's candidates live in this repository and
            # declare no root, so fall back to the repo rather than inventing a
            # challenge directory that does not exist for a bare source tree.
            if [ -r "$CP/$patch_rel" ]; then patch_path="$CP/$patch_rel"
            else patch_path="$REPO/$patch_rel"; fi ;;
        *) echo "unknown patch_root $patch_root" >&2; exit 2 ;;
    esac
fi
[ -r "$patch_path" ] || { echo "no readable patch at $patch_path" >&2; exit 2; }

report="$ASAN_DIR/${CASE_ID#nginx-}.txt"
[ -s "$report" ] || report="$ASAN_DIR/$(basename "$CASE_FILE" .yaml).txt"
[ -s "$report" ] || { echo "no captured sanitizer report for $CASE_ID; run local-model-yield.sh first" >&2; exit 2; }

# The nginx arm is left exactly as it was. Table 1's prompts were built by it,
# and changing how they are assembled would make the tables incomparable for a
# reason that has nothing to do with the models.
if [ "$TARGET" = "libpng" ]; then
    SRC="$LIBPNG_SRC"
    # Flat tree, and UBSan frames name the file by path. Take basenames and
    # resolve them against the tree, which works whatever prefix the build used.
    mapfile -t files < <(
        grep -oE '[A-Za-z0-9_/.-]+\.c' "$report" |
        sed 's|.*/||' |
        awk '!seen[$0]++' |
        while read -r b; do [ -f "$SRC/$b" ] && echo "$b"; done |
        head -"$MAX_FILES"
    )
else
    SRC="$CP/src/nginx"
    mapfile -t files < <(
        sed 's|/src/harnesses/bld/|\n|g' "$report" |
        grep -oE '^src/[a-z0-9/_]+\.c' |
        awk '!seen[$0]++' |
        while read -r f; do [ -f "$SRC/$f" ] && echo "$f"; done |
        head -"$MAX_FILES"
    )
fi
# A case whose PoV never fires has no trace to mine, so the report names no
# source and the judge would be asked to rule on a patch with none of the code
# it changes. Fall back to the files the PATCH touches. Not a special case for
# one fixture: any report without a usable trace lands here.
if [ "${#files[@]}" -eq 0 ]; then
    mapfile -t files < <(
        grep -oE '^\+\+\+ b/[a-z0-9/_.]+\.c' "$patch_path" |
        sed 's|^+++ b/||' |
        awk '!seen[$0]++' |
        while read -r f; do [ -f "$SRC/$f" ] && echo "$f"; done |
        head -"$MAX_FILES"
    )
fi

prompt_file=$(mktemp); raw_file=""
trap 'rm -f "$prompt_file" ${raw_file:+"$raw_file"}' EXIT
{
    cat <<EOF
You are reviewing a proposed patch for a memory-safety vulnerability in
$TARGET ($CWE). A fuzzing harness found the bug and AddressSanitizer produced
the report below. Someone has proposed the patch at the end.

Decide whether the patch should be ACCEPTED as a correct, complete fix.

Answer with exactly two lines and nothing else:
VERDICT: ACCEPT or REJECT
REASON: one of the following, chosen exactly
  correct-fix              the patch fixes the root cause and breaks nothing
  patch-does-not-apply     the diff will not apply to the source shown
  empty-patch              the diff changes nothing meaningful
  pov-not-reproduced       the evidence does not show the vulnerability firing
  revert-attribute-fail    the patch does not actually stop the vulnerability
  new-sanitizer-finding    the patch introduces a new memory-safety fault
  new-test-failure         the patch breaks the project's existing behaviour
  class-replay-fail        the patch fixes this input but not the bug class
  unadjudicated-behaviour-change  the patch changes behaviour in a way you cannot judge from what is shown

Expected sanitizer signal on the unpatched build: $EXPECTED_SAN

=== AddressSanitizer report ===
EOF
    cat "$report"
    echo
    for f in "${files[@]}"; do
        echo "=== full source: $f ==="
        cat "$SRC/$f"
        echo
    done
    echo "=== the proposed patch ==="
    cat "$patch_path"
} > "$prompt_file"

# --- assert the case file's answer is not in the prompt ---------------------
# The reasons are printed above as the answer menu, so their presence is not a
# leak. A leak is this candidate's OWN expected reason arriving as an assertion
# about it, which is what a stray case-file line would do.
if [ "$cand" != '{}' ]; then
    exp=$(echo "$cand" | jq -r '.expected_gate_reason // empty')
    lbl=$(echo "$cand" | jq -r '.label // empty')
fi
# Only the descriptive labels are worth probing for. "good" and "unclassified"
# are ordinary words that carry no verdict on their own, and grepping a 7500-line
# prompt for "good" aborts a sound run the first time a source comment uses it.
# Whole-word match, because a substring hit on a label fragment is noise too.
case "$lbl" in
    ""|good|unclassified) ;;
    *) if grep -qiwE -- "$lbl" "$prompt_file"; then
           echo "LEAK: candidate label '$lbl' appears in the prompt" >&2; exit 1
       fi ;;
esac
if grep -qi 'expected_gate_reason' "$prompt_file"; then
    echo "LEAK: a case-file field reached the prompt" >&2; exit 1
fi

runs_dir="$OUT/judge/$CASE_ID"; mkdir -p "$runs_dir"
stem="$runs_dir/$(echo "$MODEL" | tr ':/' '__')-$CAND_ID"
cp "$prompt_file" "$stem.prompt.txt"

raw_file=$(mktemp)
gen_start=$(date +%s)
case "$MODEL" in
  claude*)
    key_file="${ANTHROPIC_KEY_FILE:-$HOME/.config/ANTHROPIC_API_KEY}"
    [ -r "$key_file" ] || { echo "no readable key at $key_file" >&2; exit 2; }
    jq -n --arg m "$MODEL" --rawfile p "$prompt_file" \
          --argjson mt "${MAX_TOKENS:-8000}" --arg ef "${EFFORT:-high}" \
          '{model:$m, max_tokens:$mt, output_config:{effort:$ef},
            fallbacks:"default", messages:[{role:"user", content:$p}]}' |
      curl -sS --max-time "${GEN_TIMEOUT:-1800}" -X POST https://api.anthropic.com/v1/messages \
           -H "x-api-key: $(tr -d '\r\n' < "$key_file")" \
           -H 'anthropic-version: 2023-06-01' \
           -H 'anthropic-beta: server-side-fallback-2026-07-01' \
           -H 'content-type: application/json' --data-binary @- > "$raw_file" || true
    cp "$raw_file" "$stem.anthropic-raw.json" 2>/dev/null || true
    if jq -e '.content' "$raw_file" >/dev/null 2>&1; then
      jq '{response:([.content[]|select(.type=="text")|.text]|join("")),
           stop_reason:.stop_reason,
           prompt_eval_count:.usage.input_tokens, eval_count:.usage.output_tokens}' \
         "$raw_file" > "$raw_file.norm" && mv "$raw_file.norm" "$raw_file"
    fi
    ;;
  *)
    jq -n --arg m "$MODEL" --rawfile p "$prompt_file" \
          --argjson o "$(jq -n --argjson c "$NUM_CTX" --argjson t "$TEMP" '{num_ctx:$c, temperature:$t}')" \
          '{model:$m, prompt:$p, stream:false, options:$o}' |
      curl -sS --max-time "${GEN_TIMEOUT:-1800}" -X POST "$OLLAMA/api/generate" \
           -H 'Content-Type: application/json' --data-binary @- > "$raw_file" || true
    ;;
esac
gen_secs=$(( $(date +%s) - gen_start ))
cp "$raw_file" "$stem.raw.json" 2>/dev/null || true

if [ "$(jq -r '.stop_reason // empty' "$raw_file" 2>/dev/null)" = "refusal" ]; then
    jq -cn --arg m "$MODEL" --arg c "$CASE_ID" --arg cand "$CAND_ID" --argjson s "$gen_secs" \
       '{model:$m,case:$c,candidate:$cand,arm:"judge",gen_seconds:$s,
         verdict:null,reason:null,note:"declined by safety classifiers; not a judgement"}'
    exit 0
fi
if ! jq -e '.response' "$raw_file" >/dev/null 2>&1; then
    jq -cn --arg m "$MODEL" --arg c "$CASE_ID" --arg cand "$CAND_ID" --argjson s "$gen_secs" \
       --arg e "$(head -c 300 "$raw_file")" \
       '{model:$m,case:$c,candidate:$cand,arm:"judge",gen_seconds:$s,
         verdict:null,reason:null,note:("no response: " + $e)}'
    exit 0
fi

prompt_tok=$(jq -r '.prompt_eval_count // 0' "$raw_file")
out_tok=$(jq -r '.eval_count // 0' "$raw_file")
done_reason=$(jq -r '.done_reason // .stop_reason // ""' "$raw_file")
case "$MODEL" in claude*) ctx_rec=null ;; *) ctx_rec=$NUM_CTX ;; esac

# A generation cut off by the context window is NOT a judgement, and must never
# be scored as one. A reasoning model can spend the whole remaining window on
# thinking and stop before it writes a verdict: prompt 56,346 + output 33,766 =
# exactly num_ctx on the first local run of this harness. Recorded as its own
# outcome so it cannot be read as the model getting the answer wrong.
if [ "$done_reason" = "length" ]; then
    jq -cn --arg m "$MODEL" --arg c "$CASE_ID" --arg cand "$CAND_ID" \
       --argjson s "$gen_secs" --argjson pt "$prompt_tok" --argjson ot "$out_tok" \
       --argjson ctx "$ctx_rec" --arg exp "$exp" \
       '{model:$m,case:$c,candidate:$cand,arm:"judge",gen_seconds:$s,
         prompt_tokens:$pt,output_tokens:$ot,done_reason:"length",num_ctx:$ctx,
         verdict:null,reason:null,
         executed_reason:(if $exp == "" then null else $exp end),
         parsed:false,
         note:"generation hit the context window before emitting a verdict; not a judgement"}'
    exit 0
fi

# Strip reasoning scaffolding, then take the LAST verdict line: a thinking model
# rehearses "VERDICT: ACCEPT" mid-argument before settling, and taking the first
# match records the rehearsal as the answer.
answer=$(jq -r '.response' "$raw_file" |
         perl -0777 -pe 's{<think>.*?</think>}{}gs; s{<thinking>.*?</thinking>}{}gs')
printf '%s' "$answer" > "$stem.response.txt"
# The || true matters. Under set -euo pipefail a grep that matches nothing
# fails the whole pipeline and kills the script before it can record the very
# thing this block exists to record: an answer it could not parse. That defect
# hid a real result once, so it is not hypothetical.
verdict=$(printf '%s' "$answer" | grep -oiE 'VERDICT: *(ACCEPT|REJECT)' | tail -1 |
          grep -oiE '(ACCEPT|REJECT)' | tr '[:lower:]' '[:upper:]' || true)
reason=$(printf '%s' "$answer" | grep -oiE 'REASON: *[a-z-]+' | tail -1 |
         sed 's/^[Rr][Ee][Aa][Ss][Oo][Nn]: *//' | tr '[:upper:]' '[:lower:]' || true)

# An unparseable answer is recorded as unparseable, never as a REJECT. Scoring a
# malformed reply as a refusal would credit the judge with the gate's caution.
jq -cn --arg m "$MODEL" --arg c "$CASE_ID" --arg cand "$CAND_ID" \
       --argjson s "$gen_secs" --argjson pt "$prompt_tok" --argjson ot "$out_tok" \
       --arg dr "$done_reason" --argjson ctx "$ctx_rec" \
       --arg v "${verdict:-}" --arg r "${reason:-}" --arg exp "$exp" \
   '{model:$m,case:$c,candidate:$cand,arm:"judge",gen_seconds:$s,
     prompt_tokens:$pt,output_tokens:$ot,done_reason:$dr,num_ctx:$ctx,
     verdict:(if $v == "" then null else $v end),
     reason:(if $r == "" then null else $r end),
     executed_reason:(if $exp == "" then null else $exp end),
     parsed:($v != "")}'
