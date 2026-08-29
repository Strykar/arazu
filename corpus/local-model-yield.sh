#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Ask a locally-hosted model to patch one nginx CPV, then grade the answer by
# execution with grade-patch.sh. One attempt per invocation; emits one JSON line.
#
# What the model is given, and why:
#
#   - The full AddressSanitizer report from the unpatched build. Not just the
#     innermost frame. For cpv2 the crash fires in ngx_string.c but the fix
#     belongs in the caller, ngx_http_auth_basic_user(), which only appears at
#     frame #1 of the crash trace and frame #3 of the allocation trace. A prompt
#     built from crash_location alone makes the correct patch unreachable, and
#     would measure the harness rather than the model.
#   - The whole text of the distinct nginx source files named in those traces,
#     capped at the first two. No windowing, so no localisation is done for the
#     model that a real system would have to do itself.
#   - The proof-of-vulnerability input bytes, as a hexdump. The boundary design
#     has these: they arrive through the ingress gate inside the signed bundle.
#
# What it is never given: reference_patch, anything under .internal_only/*/patches,
# or a diff against a clean tree. Otherwise this measures recall of a supplied
# answer. verify-no-leak below asserts that.
#
# ollama defaults num_ctx to 4096, which would silently truncate a ~48k-token
# prompt and turn a context failure into what looks like a model failure. num_ctx
# is set explicitly and prompt_eval_count is recorded so truncation is visible in
# the result rather than assumed away.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
SHIM="${SHIM:-/var/lib/arazu-corpus/shim}"
OUT="${OUT:-$HERE/reports}"
ASAN_DIR="$OUT/asan"
OLLAMA="${OLLAMA:-http://localhost:11434}"
# ollama truncates the input to roughly num_ctx/2, reserving the rest for output,
# and it truncates from the FRONT with keep=4. A two-file nginx prompt is ~68k
# tokens, so num_ctx=65536 silently discarded the instructions and the ASan
# report and left the model staring at trailing source with no task. That came
# back as "no unified diff" and looked exactly like a model failure. num_ctx is
# therefore sized for twice the prompt, and truncation is detected below rather
# than trusted not to happen.
NUM_CTX="${NUM_CTX:-90112}"
TEMP="${TEMP:-0.2}"
MAX_FILES="${MAX_FILES:-2}"
export PATH="$SHIM:$PATH"
export DOCKER_USER_ARGS="-e LOCAL_USER=0:0"

usage() { echo "usage: $0 [model] <cpv-id> <attempt-n> [--cpu]" >&2; exit 2; }
# gpt-oss:20b is the default because it is the only local model that cleared the
# bar more than once: 4 of 9 against devstral's 1 and qwen3-coder's 0. A default
# that has to be looked up is a default nobody uses under time pressure.
DEFAULT_MODEL="${ARAZU_LOCAL_MODEL:-gpt-oss:20b}"
if [ $# -eq 2 ]; then
    MODEL="$DEFAULT_MODEL"; CPV=$1; ATTEMPT=$2; CPU=""
else
    [ $# -ge 3 ] || usage
    MODEL=$1; CPV=$2; ATTEMPT=$3; CPU=${4:-}
fi
NUM_GPU=""; [ "$CPU" = "--cpu" ] && NUM_GPU=0

command -v jq >/dev/null || { echo "jq required" >&2; exit 2; }
command -v xxd >/dev/null || { echo "xxd required" >&2; exit 2; }
mkdir -p "$ASAN_DIR"
INT="$CP/.internal_only/$CPV"
SRC="$CP/src/nginx"

# --- the unpatched ASan report, captured once per CPV -----------------------
report="$ASAN_DIR/$CPV.txt"
if [ ! -s "$report" ]; then
    echo "capturing unpatched ASan report for $CPV" >&2
    "$HERE/grade-patch.sh" "$CPV" --none "asan-capture-$CPV" >/dev/null
    d=$(find "$CP/out/output" -maxdepth 1 -name '*--run_pov' -printf '%T@ %p\n' |
        sort -rn | head -1 | cut -d' ' -f2-)
    sed -n '/ERROR: AddressSanitizer/,/^SUMMARY/p' "$d/stderr.log" > "$report"
    [ -s "$report" ] || { echo "no ASan report captured for $CPV" >&2; exit 1; }
fi

# --- which files the traces implicate --------------------------------------
# Frames read "/src/harnesses/bld/src/core/ngx_string.c:1330:14", so the build
# prefix has to come off before the path means anything relative to the nginx
# tree. Membership is then decided by the file existing, not by a pattern:
# libfuzzer and libc frames name paths too, and a regex that merely looks right
# silently selected nothing on the first run.
mapfile -t files < <(
    sed 's|/src/harnesses/bld/|\n|g' "$report" |
    grep -oE '^src/[a-z0-9/_]+\.c' |
    awk '!seen[$0]++' |
    while read -r f; do [ -f "$SRC/$f" ] && echo "$f"; done |
    head -"$MAX_FILES"
)
[ "${#files[@]}" -gt 0 ] || {
    echo "no nginx source files in the trace; first frames were:" >&2
    grep -m3 -oE '#[0-9]+ .*' "$report" >&2
    exit 1
}

expected_san=$(sed 's/^[^,]*, *//' "$INT/pov_pou_info")
blob=$(find "$INT/blobs" -type f | head -1)

# Reset to the pin BEFORE reading any source into the prompt.
#
# grade-patch.sh resets at the start of a run and leaves the tree patched at the
# end, so without this the prompt is built from whatever the previous grading
# left behind. That is exactly what happened: three Claude runs were shown
# ngx_http_core_module.c with gpt-oss:20b's fix already applied, asked to fix a
# bug that was no longer there, and produced diffs against the patched text.
# Claude Opus 5's answer was the challenge's own reference fix, and the grader
# scored it "does not apply" because it had reset the tree back to the pin.
#
# A prompt must always describe the pinned state, and the run that reads it must
# be the one that guarantees it.
pin=$(cd "$CP" && yq -r '.cp_sources.nginx.ref' project.yaml)
want=$(git -C "$SRC" rev-parse "$pin^{commit}")
git -C "$SRC" reset --hard "$want" >/dev/null 2>&1
git -C "$SRC" clean -fdx >/dev/null 2>&1
[ -z "$(git -C "$SRC" status --porcelain)" ] || {
    echo "source tree is not clean at $pin after reset; refusing to build a prompt" >&2
    exit 1
}

# All three are declared before the trap: under `set -u` a trap that names a
# variable assigned later dies on any early exit, and takes the script's real
# result with it.
prompt_file=$(mktemp); raw_file=""; patch_file=""
trap 'rm -f "$prompt_file" ${raw_file:+"$raw_file"} ${patch_file:+"$patch_file" "$patch_file.clean"}' EXIT
{
    cat <<EOF
You are fixing a memory-safety vulnerability in nginx. A fuzzing harness found it
and AddressSanitizer produced the report below. Your job is to emit a minimal
patch that fixes the underlying bug.

Rules:
- Reply with ONE unified diff and nothing else. Use \`diff --git a/<path> b/<path>\`
  headers with paths relative to the nginx source root, exactly as they appear in
  the report (for example a/src/core/ngx_string.c).
- Fix the root cause. Do not delete or disable the feature, do not stub the
  function out, and do not merely suppress the sanitizer. A patch that removes
  the functionality will be rejected by the project's own test suite.
- Change as little as possible.

Expected sanitizer signal on the unpatched build: $expected_san

=== AddressSanitizer report ===
EOF
    cat "$report"
    echo
    echo "=== proof-of-vulnerability input ($(stat -c%s "$blob") bytes) ==="
    xxd "$blob" | head -80
    echo
    for f in "${files[@]}"; do
        echo "=== full source: $f ==="
        cat "$SRC/$f"
        echo
    done
} > "$prompt_file"

# --- assert the answer is not in the prompt --------------------------------
leak=""
for p in "$INT"/patches/nginx/*.diff; do
    [ -e "$p" ] || continue
    while IFS= read -r line; do
        case "$line" in
            +++*|---*|@@*|"") continue ;;
            +*) probe=${line#+} ;;
            *) continue ;;
        esac
        probe=$(echo "$probe" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ ${#probe} -ge 25 ] || continue
        # A patch line that ALREADY occurs in the pinned source is not a leak,
        # it is ordinary source the prompt is supposed to contain. cpv9's fix
        # adds `ngx_double_link_remove(reader);`, which also sits at line 1670
        # of the same clean file — matching on the prompt alone aborted all nine
        # cpv9 runs as leaks. Only flag a probe the pinned source does not have.
        pre_existing=false
        for f in "${files[@]}"; do
            if grep -qF "$probe" "$SRC/$f"; then pre_existing=true; break; fi
        done
        $pre_existing && continue
        if grep -qF "$probe" "$prompt_file"; then leak="$probe"; break; fi
    done < "$p"
    [ -n "$leak" ] && break
done
if [ -n "$leak" ]; then
    echo "PROMPT LEAK: a line from a shipped patch appears in the prompt: $leak" >&2
    exit 1
fi

# --- generate --------------------------------------------------------------
raw_file=$(mktemp); patch_file=$(mktemp)
opts=$(jq -n --argjson ctx "$NUM_CTX" --argjson t "$TEMP" \
        '{num_ctx:$ctx, temperature:$t}')
[ -n "$NUM_GPU" ] && opts=$(echo "$opts" | jq --argjson g "$NUM_GPU" '. + {num_gpu:$g}')

runs_dir="$OUT/runs/$CPV"; mkdir -p "$runs_dir"
stem="$runs_dir/$(echo "$MODEL" | tr ':/' '__')-$ATTEMPT"
cp "$prompt_file" "$stem.prompt.txt"

# Anthropic is the frontier control, not a candidate deployment model: an
# air-gapped boundary cannot call it. It exists to tell us whether a failure to
# emit an applicable diff is a small-model limitation or a defect in what this
# prompt asks for. Same prompt, same grading, different provider.
gen_start=$(date +%s)
case "$MODEL" in
  claude*)
    key_file="${ANTHROPIC_KEY_FILE:-$HOME/.config/ANTHROPIC_API_KEY}"
    [ -r "$key_file" ] || { echo "no readable key at $key_file" >&2; exit 2; }
    # max_tokens caps thinking AND response text together. Claude Opus 5 has
    # thinking on by default, so a ceiling sized for the answer alone gets spent
    # entirely on reasoning: the first control run returned 32000 output tokens,
    # 31997 of them thinking, stop_reason max_tokens, and an empty text block.
    #
    # fallbacks:"default" is the skill's standing recommendation for Opus 5:
    # its cyber classifiers can decline at HTTP 200 with stop_reason "refusal",
    # and this prompt (ASan report + exploit bytes + "write a patch") sits next
    # to that boundary. A cyber-category decline reroutes to Opus 4.8 rather
    # than coming back empty.
    jq -n --arg m "$MODEL" --rawfile p "$prompt_file" \
          --argjson mt "${MAX_TOKENS:-64000}" --arg ef "${EFFORT:-high}" \
          '{model:$m, max_tokens:$mt, output_config:{effort:$ef},
            fallbacks:"default", messages:[{role:"user", content:$p}]}' |
      curl -sS --max-time "${GEN_TIMEOUT:-3600}" -X POST https://api.anthropic.com/v1/messages \
           -H "x-api-key: $(tr -d '\r\n' < "$key_file")" \
           -H 'anthropic-version: 2023-06-01' \
           -H 'anthropic-beta: server-side-fallback-2026-07-01' \
           -H 'content-type: application/json' --data-binary @- > "$raw_file" || true
    # Keep the untouched provider response before reshaping it. Normalising in
    # place destroyed the evidence for why the first control run came back with
    # 16000 output tokens and an empty string: stop_reason and the block types
    # were gone by the time anyone looked.
    cp "$raw_file" "$stem.anthropic-raw.json" 2>/dev/null || true
    if jq -e '.content' "$raw_file" >/dev/null 2>&1; then
      # Take text blocks; if there are none, fall back to thinking blocks so a
      # reasoning-only reply is visible rather than silently empty.
      jq '{response:(([.content[]|select(.type=="text")|.text]|join(""))
                     | if . == "" then ([$c[]|select(.type=="thinking")|.thinking]|join("")) else . end),
           stop_reason:.stop_reason,
           prompt_eval_count:.usage.input_tokens, eval_count:.usage.output_tokens}' \
         --argjson c "$(jq -c '.content' "$raw_file")" \
         "$raw_file" > "$raw_file.norm" && mv "$raw_file.norm" "$raw_file"
    fi
    ;;
  *)
    jq -n --arg m "$MODEL" --rawfile p "$prompt_file" --argjson o "$opts" \
          '{model:$m, prompt:$p, stream:false, options:$o}' |
      curl -sS --max-time "${GEN_TIMEOUT:-3600}" -X POST "$OLLAMA/api/generate" \
           -H 'Content-Type: application/json' --data-binary @- > "$raw_file" || true
    ;;
esac
gen_secs=$(( $(date +%s) - gen_start ))
cp "$raw_file" "$stem.raw.json" 2>/dev/null || true

# A safety-classifier decline arrives as HTTP 200 with stop_reason "refusal",
# so it must be read before the content, or an empty content array looks like a
# model that had nothing to say.
if [ "$(jq -r '.stop_reason // empty' "$raw_file" 2>/dev/null)" = "refusal" ]; then
    jq -cn --arg m "$MODEL" --arg c "$CPV" --argjson a "$ATTEMPT" --argjson s "$gen_secs" \
       --arg cat "$(jq -r '.stop_details.category // "unknown"' "$stem.anthropic-raw.json" 2>/dev/null)" \
       '{model:$m,cpv:$c,attempt:$a,tier:(env.TIER//"?"),gen_seconds:$s,level:-4,accepted:false,
         refusal_category:$cat,note:"declined by safety classifiers; not a model capability result"}'
    exit 0
fi

if ! jq -e '.response' "$raw_file" >/dev/null 2>&1; then
    jq -cn --arg m "$MODEL" --arg c "$CPV" --argjson a "$ATTEMPT" --argjson s "$gen_secs" \
       --arg e "$(head -c 300 "$raw_file")" \
       '{model:$m,cpv:$c,attempt:$a,tier:(env.TIER//"?"),gen_seconds:$s,level:-2,accepted:false,note:("generation failed: "+$e)}'
    exit 0
fi

prompt_tok=$(jq -r '.prompt_eval_count // 0' "$raw_file")
out_tok=$(jq -r '.eval_count // 0' "$raw_file")
# done_reason separates a natural stop from a completion cut by the window,
# which otherwise dies at the diff gate looking like model incapability.
# num_ctx is the request, recorded as corroboration only; the server's own
# account is prompt_eval_count above. Anthropic is sent no window, so null.
done_reason=$(jq -r '.done_reason // .stop_reason // ""' "$raw_file")
case "$MODEL" in claude*) ctx_rec=null ;; *) ctx_rec=$NUM_CTX ;; esac
# Which population the row belongs to, stated rather than inferred. num_ctx=null
# already implies "no window applied", but that asks a reader to know null means
# API. One matrix mixed a claude row whose prompt+output exceeded NUM_CTX by 9727
# tokens with ollama rows the ceiling did govern, and nothing in the record said
# so. Any claim about token budget has to name which rows the ceiling covered.
case "$MODEL" in claude*) backend=anthropic ;; *) backend=ollama ;; esac

# Truncation check, read from the server rather than inferred.
#
# An earlier version compared prompt_eval_count against num_ctx/2 and called
# anything above it truncated. That is wrong twice over: the cap is not half the
# window, and token counts are not comparable across models anyway, because each
# tokenizer sees the same bytes differently. The identical prompt is 67,708
# tokens to qwen3.5 and 61,931 to deepseek-r1. The check fired on a perfectly
# good 11.5-minute deepseek run and discarded it.
#
# ollama logs "truncating input prompt" when and only when it actually cuts, so
# ask the journal about this run's window instead of guessing from arithmetic.
if journalctl -u ollama --since "-$(( gen_secs + 30 )) seconds" --no-pager 2>/dev/null |
     grep -q 'truncating input prompt'; then
    lim=$(journalctl -u ollama --since "-$(( gen_secs + 30 )) seconds" --no-pager 2>/dev/null |
          grep -o 'limit=[0-9]*' | tail -1)
    jq -cn --arg m "$MODEL" --arg c "$CPV" --argjson a "$ATTEMPT" \
       --argjson s "$gen_secs" --argjson pt "$prompt_tok" --argjson ctx "$NUM_CTX" \
       --arg lim "$lim" \
       '{model:$m,cpv:$c,attempt:$a,tier:(env.TIER//"?"),gen_seconds:$s,
         prompt_tokens:$pt,num_ctx:$ctx,server_limit:$lim,level:-3,accepted:false,
         note:"prompt truncated by the server, so the model never saw the instructions. Raise NUM_CTX."}'
    exit 0
fi

# Strip reasoning scaffolding before looking for a diff, so a thinking model is
# not penalised for thinking.
jq -r '.response' "$raw_file" |
  perl -0777 -pe 's{<think>.*?</think>}{}gs; s{<thinking>.*?</thinking>}{}gs' > "$patch_file.clean"
cp "$patch_file.clean" "$stem.response.txt" 2>/dev/null || true

# extract-diff.py picks the candidate region that actually looks like a unified
# diff, rather than the first fenced block. qwen3-coder opens with an
# explanatory ```c snippet and puts the real patch unfenced below it; taking the
# first fence read the snippet as the answer and reported no patch at all.
emitted=false
if python3 "$HERE/extract-diff.py" "$patch_file.clean" > "$patch_file" 2>/dev/null; then
    emitted=true
fi

if ! $emitted; then
    jq -cn --arg m "$MODEL" --arg c "$CPV" --argjson a "$ATTEMPT" \
       --argjson s "$gen_secs" --argjson pt "$prompt_tok" --argjson ot "$out_tok" \
       --arg dr "$done_reason" --argjson ctx "$ctx_rec" --arg be "$backend" \
       '{model:$m,cpv:$c,attempt:$a,tier:(env.TIER//"?"),gen_seconds:$s,
         prompt_tokens:$pt,output_tokens:$ot,done_reason:$dr,num_ctx:$ctx,backend:$be,
         level:-1,accepted:false,
         note:"no unified diff in the response"}'
    exit 0
fi

keep="$OUT/candidates/$CPV/$(echo "$MODEL" | tr ':/' '__')-$ATTEMPT.diff"
mkdir -p "$(dirname "$keep")"; cp "$patch_file" "$keep"

# Hunk repair, ON by default. Local models emit correct edits with wrong @@
# ranges often enough that raw yield understates them: 1 of 27 as emitted
# against 5 of 27 after re-anchoring. hunks-reanchored means the RANGES were
# repaired, not that the patch applies: re-anchoring rewrites the @@ header and
# cannot rescue invented context. gpt-oss:20b produced both faults in one patch
# on 2026-08-19, pinned in testdata/crsout. That is a patch-format failure, not a
# repair failure, and grading it as the latter measures the wrong thing.
#
# The unrepaired diff is kept beside it, so the two are separable afterwards
# and this cannot quietly flatter a run. Set ARAZU_FIX_HUNKS=0 to disable.
apply_mode=as-emitted
if [ "${ARAZU_FIX_HUNKS:-1}" = "1" ] && [ -x "$HERE/fix-hunks.py" ]; then
    git -C "$SRC" reset --hard >/dev/null 2>&1 || true
    if "$HERE/fix-hunks.py" "$patch_file" "$SRC" > "$patch_file.fixed" 2>/dev/null &&
       [ -s "$patch_file.fixed" ]; then
        cp "$patch_file" "$keep.as-emitted"
        mv "$patch_file.fixed" "$patch_file"
        cp "$patch_file" "$keep"
        apply_mode=hunks-reanchored
    else
        rm -f "$patch_file.fixed"
        apply_mode=reanchor-failed
    fi
fi

# Unload before grading. ollama holds the model resident for a keep-alive window
# after generation, so without this the containerised nginx build and prove -jN
# start while 19-23GB of weights are still pinned. Generation and grading are
# sequential in this script but were not sequential in memory, and that overlap
# hard-locked the host twice: no swap, so reclaim has nowhere to go, and the box
# wedges before the OOM killer can act. Nothing is logged when that happens.
ollama stop "$MODEL" >/dev/null 2>&1 || true

grade=$("$HERE/grade-patch.sh" "$CPV" "$patch_file" "$MODEL#$ATTEMPT")
jq -cn --arg m "$MODEL" --argjson a "$ATTEMPT" --argjson s "$gen_secs" \
       --argjson pt "$prompt_tok" --argjson ot "$out_tok" \
       --arg dr "$done_reason" --argjson ctx "$ctx_rec" --arg be "$backend" \
       --argjson files "$(printf '%s\n' "${files[@]}" | jq -R . | jq -s .)" \
       --arg keep "$keep" --arg am "$apply_mode" --argjson g "$grade" \
   '$g + {model:$m,attempt:$a,tier:(env.TIER//"?"),gen_seconds:$s,
          prompt_tokens:$pt,output_tokens:$ot,done_reason:$dr,num_ctx:$ctx,backend:$be,
          context_files:$files,candidate:$keep,apply_mode:$am}'
