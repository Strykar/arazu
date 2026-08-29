#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Re-grade every attempt that died at the apply gate, after mechanically
# rebuilding its hunk headers.
#
# 13 of the first 18 matrix results scored -1 as "patch does not apply". That
# number read as a capability finding until the control failed the same way:
# Claude Opus 5 on cpv5 emitted a correct NULL guard on the real deref, and lost
# it to a hunk header written as "@@ static ngx_int_t" with no line ranges. The
# model that solves cpv2 in nine seconds does not suddenly not understand cpv5.
# So the apply gate is measuring diff syntax, and reporting that as though it
# measured repair ability would overstate the gap by whatever share of those 13
# are correct fixes in malformed envelopes.
#
# fix-hunks.py recomputes the ranges by anchoring each hunk's context in the
# pinned source. It cannot invent a fix: if the context does not exist in the
# file it fails, and a wrong edit stays wrong and still has to clear the PoV and
# the tests. So this measures the same repair ability with the formatting
# obstacle removed, which is what a real CRS would do rather than discard the
# answer.
#
# Recorded as its own apply_mode. Reconstructed acceptances are NOT merged into
# the strict number: "emitted an applicable patch" and "emitted a correct fix
# that needed repair" are different claims and the deck needs both.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
OUT="$HERE/reports"
IN="${IN:-$OUT/matrix.jsonl}"
RESULTS="${RESULTS:-$OUT/matrix-reconstructed.jsonl}"
SRC="$CP/src/nginx"

pin=$(cd "$CP" && yq -r '.cp_sources.nginx.ref' project.yaml)
want=$(git -C "$SRC" rev-parse "$pin^{commit}")

: > "$RESULTS"
mkdir -p "$OUT/candidates/reconstructed"

# Every attempt that failed to apply, across whichever result files were passed.
while IFS= read -r rec; do
    cpv=$(jq -r '.cpv' <<<"$rec")
    model=$(jq -r '.model' <<<"$rec")
    attempt=$(jq -r '.attempt' <<<"$rec")
    cand=$(jq -r '.candidate' <<<"$rec")
    [ -f "$cand" ] || continue

    # fix-hunks anchors against the source, so the tree must be at the pin.
    git -C "$SRC" reset --hard "$want" >/dev/null 2>&1
    git -C "$SRC" clean -fdx >/dev/null 2>&1

    fixed="$OUT/candidates/reconstructed/${cpv}-${model//[:\/]/_}-${attempt}.diff"
    if ! "$HERE/fix-hunks.py" "$cand" "$SRC" > "$fixed" 2>/dev/null; then
        jq -nc --argjson r "$rec" \
            '$r + {apply_mode:"reconstruct-failed", level:-1, accepted:false,
                   note:"hunk context does not match the pinned source"}' >> "$RESULTS"
        continue
    fi

    graded=$("$HERE/grade-patch.sh" "$cpv" "$fixed" "${model}#${attempt}-recon" 2>/dev/null)
    if [ -z "$graded" ]; then
        jq -nc --argjson r "$rec" \
            '$r + {apply_mode:"reconstructed", level:-1, accepted:false,
                   note:"grader produced no result"}' >> "$RESULTS"
        continue
    fi
    # Keep the original run's provenance, overlay the new grade, and mark that
    # this landing required repair.
    jq -nc --argjson r "$rec" --argjson g "$graded" \
        '$r + $g + {apply_mode:"reconstructed", reconstructed:true}' >> "$RESULTS"
done < <(jq -c 'select(.level==-1)' "$IN")

echo "wrote $RESULTS"
jq -rs '
  "reconstructed: \([.[]|select(.level==3)]|length)/\(length) now accepted, " +
  "\([.[]|select(.level>=2)]|length) stopped the sanitizer, " +
  "\([.[]|select(.applied==true)]|length) applied after repair, " +
  "\([.[]|select(.apply_mode=="reconstruct-failed")]|length) could not be anchored"
' "$RESULTS"
