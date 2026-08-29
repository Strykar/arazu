#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Grade one candidate patch for one nginx CPV, by execution.
#
# The ladder, in order. An attempt is recorded at the level it reached, so the
# drop-off is visible rather than collapsing to pass/fail:
#
#   0 applied     the diff applies to a clean tree at the pin
#   1 built       the patched tree builds under the challenge's sanitizer config
#   2 pov_clean   the PoV no longer produces the sanitizer string it declares
#   3 tests_pass  no functionality test fails that was not already failing
#
# Level 3 is acceptance. Levels 2 and 3 together separate a fix from a revert:
# the CP ships a bad_patch that guts ngx_http_auth_basic_user() to `return
# NGX_DECLINED;`, which reaches level 2 (no crash, because the decode never
# happens) and must fail level 3 on auth_basic.t.
#
# Neither step may be graded on an exit status, and for different reasons.
#
#   run_pov:   the container exits 0 whether or not the vulnerability fires, so
#              the sanitizer string in stderr.log is the only signal.
#   run_tests: ./run.sh also exits 0 regardless of what prove reported, AND the
#              recorded exitcode is already 2 on a known-good build because two
#              IP_TRANSPARENT tests need NET_ADMIN/NET_RAW. So an absolute
#              pass/fail is wrong in both directions: exit status accepts a
#              revert, recorded exitcode rejects a correct patch. The signal is
#              the SET DIFFERENCE against corpus/reports/tests-baseline.json.
#
# An earlier version of this script graded level 3 with `if ./run.sh run_tests`
# and accepted the challenge's own bad_patch. That is the whole reason the
# calibration controls below are run before any model result is believed.
#
# The tree is reset to the pin before every attempt. A tree left patched by an
# earlier attempt produces a clean PoV run indistinguishable from a real fix.
set -euo pipefail

CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
SHIM="${SHIM:-/var/lib/arazu-corpus/shim}"
REPORTS="$(cd "$(dirname "$0")" && pwd)/reports"
export PATH="$SHIM:$PATH"
export DOCKER_USER_ARGS="-e LOCAL_USER=0:0"
export NPROC_VAL="${NPROC_VAL:-8}"

usage() { echo "usage: $0 <cpv-id> <patch-file|--none> [label]" >&2; exit 2; }
[ $# -ge 2 ] || usage
CPV=$1; PATCH=$2; LABEL=${3:-$(basename "$PATCH")}

# Per-CPV baseline when one exists, because the private tests differ per CPV and
# so does the set of tests that pass on a correct tree. Absolute, since this
# script cds into $CP and a relative path would resolve there.
BASELINE="${BASELINE:-$REPORTS/tests-baseline-$CPV.json}"
[ -f "$BASELINE" ] || BASELINE="$REPORTS/tests-baseline.json"
# Resolved before the cd into $CP below, or a relative patch path silently
# resolves against the challenge tree instead of the caller's directory.
[ "$PATCH" = "--none" ] || PATCH=$(realpath "$PATCH")

command -v docker >/dev/null || { echo "no docker shim on PATH ($SHIM)" >&2; exit 2; }
command -v yq >/dev/null || { echo "yq is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
[ -f "$BASELINE" ] || { echo "no baseline at $BASELINE; run tests-baseline.sh first" >&2; exit 2; }
INT="$CP/.internal_only/$CPV"
[ -d "$INT" ] || { echo "no such CPV: $CPV" >&2; exit 2; }

cd "$CP"
if [ -z "${DOCKER_IMAGE_NAME:-}" ]; then
    base=$(yq -r '.docker_image' project.yaml)
    DOCKER_IMAGE_NAME=$(docker images --format '{{.Repository}}:{{.Tag}}' |
                        grep "^${base}:" | grep -v ':<none>$' | head -1)
    [ -n "$DOCKER_IMAGE_NAME" ] || { echo "no local image for $base" >&2; exit 2; }
    export DOCKER_IMAGE_NAME
fi

harness=$(cut -d, -f1 "$INT/pov_pou_info" | tr -d ' ')
expected=$(sed 's/^[^,]*, *//' "$INT/pov_pou_info")
blob=$(find "$INT/blobs" -type f | head -1)
pin=$(yq -r '.cp_sources.nginx.ref' project.yaml)
src=src/nginx
want=$(git -C "$src" rev-parse "$pin^{commit}")
baseline=$(jq -r '.baseline_failures[]' "$BASELINE" | sort -u)

newest() {
    find "$CP/out/output" -maxdepth 1 -name "*--$1" -printf '%T@ %p\n' 2>/dev/null |
        sort -rn | head -1 | cut -d' ' -f2-
}

applied=false; built=false; pov_clean=false; tests_pass=false; level=-1; note=""
new_failures=""; recorded_exit=""
start=$(date +%s)

# 0 — clean tree at the pin, then apply
git -C "$src" reset --hard "$want" >/dev/null 2>&1
git -C "$src" clean -fdx >/dev/null 2>&1

# Two apply modes, recorded rather than blended. Strict is the honest measure of
# whether a model can emit an applicable unified diff, which is a real capability
# and a hard gate: a perfect fix in a malformed diff patches nothing. But the
# first observed failure was only wrong hunk line counts, which --recount exists
# to repair and which says nothing about whether the fix is right. Reporting both
# separates "cannot format a diff" from "cannot fix the bug"; collapsing them
# would let a formatting failure masquerade as a reasoning one.
apply_mode=none
if [ "$PATCH" = "--none" ]; then
    applied=true; level=0; note="unpatched control"; apply_mode=n/a
elif git -C "$src" apply --whitespace=nowarn "$PATCH" >/dev/null 2>&1; then
    applied=true; level=0; apply_mode=strict
elif git -C "$src" apply --recount --whitespace=nowarn "$PATCH" >/dev/null 2>&1; then
    applied=true; level=0; apply_mode=recount
    note="applied only after --recount: hunk line counts were wrong"
else
    note="patch does not apply, even with --recount"
fi

# 1 — build
if $applied; then
    if ./run.sh build >/dev/null 2>&1; then built=true; level=1
    else note="build failed"; fi
fi

# 2 — does the declared sanitizer string still fire
if $built; then
    ./run.sh run_pov "$blob" "$harness" >/dev/null 2>&1 || true
    d=$(newest run_pov)
    if [ -z "$d" ] || [ ! -f "$d/stderr.log" ]; then
        note="no run_pov output; treated as unproven, not as a pass"
    elif grep -qF "$expected" "$d/stderr.log"; then
        note="pov still fires"
    else
        pov_clean=true; level=2
    fi
fi

# 3 — functionality, graded as new failures against the baseline
#
# The CPV's private test is mounted in. container_scripts/cp_tests already copies
# /.internal_only/**.t over the public suite, but run.sh never mounts anything
# there, so without this the private test simply never runs. That is not a
# cosmetic gap: cpv2's private auth_basic.t is byte-identical to the public one,
# so cpv2 graded correctly by luck, while cpv5's private http_variables.t is the
# ONLY test that reads $last_ip. Grading cpv5 without it cannot tell a fix from a
# patch that just switches the variable off. Only this CPV's tests are mounted;
# mounting all fourteen would import unrelated failures.
if $pov_clean; then
    # The mount lands on the host through the src bind mount, so the suite is
    # restored on both sides of the run: before, so a crashed earlier run cannot
    # leave another CPV's private test in this one's test set, and after, so this
    # CPV does not do it to the next.
    "$REPORTS/../restore-test-suite.sh" >/dev/null || exit 2
    if [ -d "$INT/private_tests" ]; then
        export DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS:-} -v $INT/private_tests:/.internal_only:ro"
    fi
    ./run.sh run_tests >/dev/null 2>&1 || true
    "$REPORTS/../restore-test-suite.sh" >/dev/null || exit 2
    t=$(newest run_tests)
    if [ -z "$t" ] || [ ! -f "$t/stdout.log" ]; then
        note="no run_tests output; treated as unproven, not as a pass"
    elif ! grep -q 'Test Summary Report' "$t/stdout.log"; then
        # prove prints no summary when every file passes, so distinguish that
        # from a run that died before reporting.
        if grep -qE '^Result: PASS|^All tests successful' "$t/stdout.log"; then
            tests_pass=true; level=3
        else
            note="prove produced no summary and no pass line; unproven"
        fi
    else
        recorded_exit=$(cat "$t/exitcode" 2>/dev/null || echo "")
        observed=$(awk '/Test Summary Report/,/^Files=/' "$t/stdout.log" |
                   grep -oE '[a-z0-9_]+\.t' | sort -u)
        # Unquoted on purpose: word-splitting is what turns the space-separated
        # lists into one test name per line. Quoting breaks the comparison.
        # shellcheck disable=SC2086
        new_failures=$(comm -13 <(printf '%s\n' $baseline) <(printf '%s\n' $observed) | tr '\n' ' ')
        new_failures=$(echo $new_failures)
        if [ -z "$new_failures" ]; then
            tests_pass=true; level=3
        else
            note="new test failures: $new_failures"
        fi
    fi
fi

secs=$(( $(date +%s) - start ))
jq -cn \
   --arg cpv "$CPV" --arg label "$LABEL" --arg note "$note" \
   --arg rexit "$recorded_exit" --arg amode "$apply_mode" \
   --argjson applied "$applied" --argjson built "$built" \
   --argjson pov_clean "$pov_clean" --argjson tests_pass "$tests_pass" \
   --argjson level "$level" --argjson secs "$secs" \
   --argjson newf "$(printf '%s\n' $new_failures | grep -v '^$' | jq -R . | jq -s .)" \
   '{cpv:$cpv,label:$label,applied:$applied,apply_mode:$amode,built:$built,pov_clean:$pov_clean,
     tests_pass:$tests_pass,new_failures:$newf,level:$level,
     accepted:($level==3),recorded_tests_exitcode:$rexit,seconds:$secs,note:$note}'
