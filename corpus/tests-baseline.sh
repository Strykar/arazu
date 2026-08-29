#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Capture which of the challenge's functionality tests fail on THIS host for
# reasons that have nothing to do with any patch.
#
# Two tests need NET_ADMIN and NET_RAW and fail without them on a known-good
# build; reproduce-nginx.sh records the same thing. So "did run_tests pass" is
# useless as a grading signal in both directions: it is already non-zero for a
# correct patch, and ./run.sh exits 0 regardless of what prove reported, exactly
# as run_pov does. grade-patch.sh therefore grades on the SET DIFFERENCE between
# the tests failing under a candidate patch and the set recorded here.
#
# The baseline is taken on the unpatched tree at the pin. That is only a valid
# stand-in for "environmental" if the vulnerable build fails nothing else, so the
# run asserts the set is exactly the two IP_TRANSPARENT files and refuses to
# write a baseline it cannot vouch for. A baseline that quietly absorbed a real
# failure would hide precisely the regressions the gate exists to catch.
#
# With a CPV argument it instead takes a per-CPV baseline with that CPV's private
# tests mounted, on a tree with the challenge's own good_patch applied. Both
# halves are required. The private test has to be present or it never runs, and
# it has to run against a WORKING tree: on the vulnerable tree the private test
# fails by design, and a baseline recording that failure would excuse it in every
# later comparison, which is the one regression the private test exists to catch.
# Using good_patch here is grader-side only and never reaches a model prompt.
set -euo pipefail

CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
SHIM="${SHIM:-/var/lib/arazu-corpus/shim}"
# Absolute: this script cds into $CP, so a relative sibling path would resolve
# against the challenge tree instead of here.
HERE="$(cd "$(dirname "$0")" && pwd)"
# Absolute: this script cds into $CP, so a relative path would resolve there.
OUT="${OUT:-$(cd "$(dirname "$0")" && pwd)/reports}"
export PATH="$SHIM:$PATH"
export DOCKER_USER_ARGS="-e LOCAL_USER=0:0"

# prove takes every core by default. The box has no swap, and a full-parallel
# suite alongside a resident model is what took it down once already.
export NPROC_VAL="${NPROC_VAL:-8}"

EXPECTED_BASELINE="proxy_bind_transparent.t proxy_bind_transparent_capability.t"

# Optional: take the baseline for one CPV, with its private tests in play.
CPV="${1:-}"
if [ -n "$CPV" ]; then
    INT="$CP/.internal_only/$CPV"
    [ -d "$INT/private_tests" ] || { echo "no private_tests for $CPV" >&2; exit 2; }
    GOOD="$INT/patches/nginx/good_patch.diff"
    [ -f "$GOOD" ] || { echo "no good_patch.diff for $CPV" >&2; exit 2; }
    OUTFILE="$OUT/tests-baseline-$CPV.json"
    export DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS:-} -v $INT/private_tests:/.internal_only:ro"
else
    OUTFILE="$OUT/tests-baseline.json"
fi

command -v docker >/dev/null || { echo "no docker shim on PATH ($SHIM)" >&2; exit 2; }
command -v yq >/dev/null || { echo "yq is required" >&2; exit 2; }
mkdir -p "$OUT"
cd "$CP"

if [ -z "${DOCKER_IMAGE_NAME:-}" ]; then
    base=$(yq -r '.docker_image' project.yaml)
    DOCKER_IMAGE_NAME=$(docker images --format '{{.Repository}}:{{.Tag}}' |
                        grep "^${base}:" | grep -v ':<none>$' | head -1)
    [ -n "$DOCKER_IMAGE_NAME" ] || { echo "no local image for $base" >&2; exit 2; }
    export DOCKER_IMAGE_NAME
fi

pin=$(yq -r '.cp_sources.nginx.ref' project.yaml)
src=src/nginx
want=$(git -C "$src" rev-parse "$pin^{commit}")
echo "resetting $src to $pin ($want)"
git -C "$src" reset --hard "$want" >/dev/null
git -C "$src" clean -fdx >/dev/null

if [ -n "$CPV" ]; then
    echo "applying the challenge's good_patch for $CPV"
    git -C "$src" apply --whitespace=nowarn "$GOOD" ||
        { echo "good_patch.diff does not apply at the pin" >&2; exit 1; }
fi

echo "building"
./run.sh build >/dev/null 2>&1 || { echo "build failed" >&2; exit 1; }

echo "running functionality tests (prove -j$NPROC_VAL)"
# cp_tests copies the mounted private tests over the public suite, and src is a
# bind mount, so the copy persists on the host. Restore on both sides or this
# CPV's private test silently joins every later CPV's test set.
"$HERE/restore-test-suite.sh" >/dev/null || exit 2
./run.sh run_tests >/dev/null 2>&1 || true
"$HERE/restore-test-suite.sh" >/dev/null || exit 2

d=$(find "$CP/out/output" -maxdepth 1 -name '*--run_tests' -printf '%T@ %p\n' |
    sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$d" ] || { echo "no run_tests output directory" >&2; exit 1; }
grep -q 'Test Summary Report' "$d/stdout.log" 2>/dev/null || {
    echo "no Test Summary Report in $d/stdout.log; prove did not run to completion" >&2
    exit 1
}

observed=$(awk '/Test Summary Report/,/^Files=/' "$d/stdout.log" |
           grep -oE '[a-z0-9_]+\.t' | sort -u | tr '\n' ' ')
# Unquoted echo collapses whitespace; that is the point.
# shellcheck disable=SC2086
observed=$(echo $observed)
expected=$(echo $EXPECTED_BASELINE | tr ' ' '\n' | sort -u | tr '\n' ' ')
expected=$(echo $expected)

echo "baseline failures: ${observed:-<none>}"

if [ "$observed" != "$expected" ]; then
    cat >&2 <<EOF
BASELINE MISMATCH
  expected: $expected
  observed: ${observed:-<none>}
This host no longer matches the environment the grader assumes. Do not grade any
candidate against this baseline until the difference is understood: an extra file
here silently becomes a test the grader can never hold a patch responsible for.
EOF
    exit 1
fi

caps=$(capsh --print 2>/dev/null | sed -n 's/^Current: //p' | head -1)
jq -n --arg src "$d" --arg caps "${caps:-unknown}" --arg nproc "$NPROC_VAL" \
      --arg cpv "${CPV:-all}" --arg tree "$([ -n "$CPV" ] && echo good_patch || echo unpatched)" \
      --argjson files "$(printf '%s\n' $observed | jq -R . | jq -s .)" \
      '{taken_from:$src, cpv:$cpv, tree:$tree, private_tests:($cpv!="all"),
        nproc_val:$nproc, host_caps:$caps, baseline_failures:$files}' \
      > "$OUTFILE"

echo "wrote $OUTFILE"
