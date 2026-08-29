#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Corpus M0 for the AIxCC nginx challenge: build it, fire every proof of
# vulnerability, and check the sanitizer that fires against the one the
# challenge declares.
#
# The point is not to see 14 crashes. It is to confirm that the labels we are
# about to build a corpus on are true, by execution. A label read out of a file
# and copied into case.yaml is an assumption; a label that has been reproduced
# is an answer key. Anything that does not match is reported as a mismatch and
# fails the run, because a corpus that quietly disagrees with its own labels
# would grade every later gate stage against the wrong truth.
#
# Three things about this host that the challenge does not expect, all of them
# rootless-podman consequences rather than anything wrong with the CP:
#
#   - There is no docker binary, and run.sh execs the literal `docker` at seven
#     sites, so a shim goes on PATH.
#   - entrypoint.sh chowns the bind-mounted out/ and work/ to LOCAL_USER, which
#     defaults to 1000:1000 and maps to a subuid the host user cannot write as.
#     LOCAL_USER=0:0 is container-root, which under rootless podman IS the host
#     user, so the logs land readable. Without this the gate gets no input at
#     all, which looks like a build failure rather than a permissions one.
#   - run_tests needs NET_ADMIN and NET_RAW or two IP_TRANSPARENT tests fail on
#     a known-good build. Denylisting them instead would hide real regressions
#     in proxy_bind.
set -euo pipefail

CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
SHIM="${SHIM:-/var/lib/arazu-corpus/shim}"
OUT="${OUT:-$CP/../m0-report}"

export PATH="$SHIM:$PATH"
export DOCKER_USER_ARGS="-e LOCAL_USER=0:0"

command -v docker >/dev/null || { echo "no docker shim on PATH ($SHIM)" >&2; exit 2; }
command -v yq >/dev/null || { echo "yq is required by the CP Makefile and run.sh" >&2; exit 2; }
[ -d "$CP/.internal_only" ] || { echo "$CP has no .internal_only, so there is no answer key" >&2; exit 2; }

mkdir -p "$OUT"
REPORT="$OUT/m0-nginx.json"

cd "$CP"

# project.yaml names the image without a tag, and run.sh feeds that straight to
# `docker inspect`, which does not match a locally tagged image. Resolve the tag
# that is actually here rather than pinning one, so this does not rot when the
# CP publishes a new version. run.sh:54 uses := so an exported value wins.
if [ -z "${DOCKER_IMAGE_NAME:-}" ]; then
    base=$(yq -r '.docker_image' project.yaml)
    DOCKER_IMAGE_NAME=$(docker images --format '{{.Repository}}:{{.Tag}}' |
                        grep "^${base}:" | grep -v ':<none>$' | head -1)
    [ -n "$DOCKER_IMAGE_NAME" ] || { echo "no local image for $base; pull it first" >&2; exit 2; }
    export DOCKER_IMAGE_NAME
fi
echo "image: $DOCKER_IMAGE_NAME"

# The most recent run_pov output directory. run.sh timestamps them, so the
# newest is the one just produced.
latest_pov_dir() {
    find "$CP/out/output" -maxdepth 1 -name '*--run_pov' -printf '%T@ %p\n' 2>/dev/null |
        sort -rn | head -1 | cut -d' ' -f2-
}

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    # Build from the pin, not from whatever the tree happens to hold. A tree
    # left patched by an earlier run produces a clean PoV run that looks
    # exactly like a challenge whose labels are wrong, and the report would
    # record 14 mismatches with no hint that the source was the problem. This
    # is the same false-pass shape the whole project exists to refuse, so the
    # state is asserted rather than assumed.
    pin=$(yq -r '.cp_sources.nginx.ref' project.yaml)
    src=src/nginx
    want=$(git -C "$src" rev-parse "$pin^{commit}")
    if [ -n "$(git -C "$src" status --porcelain)" ] || [ "$(git -C "$src" rev-parse HEAD)" != "$want" ]; then
        echo "source tree is not at a clean $pin ($want); resetting"
        git -C "$src" reset --hard "$want"
        git -C "$src" clean -fdx
    fi
    echo "source: $pin $want (clean)"

    echo "== building the unpatched CP =="
    ./run.sh build
fi

echo "== firing every proof of vulnerability =="
printf '[\n' > "$REPORT"
first=1
fail=0

for dir in "$CP"/.internal_only/cpv*/; do
    id=$(basename "$dir")
    read -r harness expected < <(sed 's/,/ /' "$dir/pov_pou_info")
    harness=${harness%,}
    expected=$(sed 's/^[^,]*, *//' "$dir/pov_pou_info")
    blob=$(find "$dir/blobs" -type f | head -1)

    if [ -z "$blob" ]; then
        echo "$id: no blob" >&2
        observed="no-blob"
    else
        ./run.sh run_pov "$blob" "$harness" >/dev/null 2>&1 || true
        d=$(latest_pov_dir)
        # The container exit code is 0 whether or not a vulnerability fires, so
        # the sanitizer line in stderr is the only signal. Keying a gate on the
        # exit code would accept every candidate patch.
        #
        # Match the sanitizer strings project.yaml declares rather than parsing
        # the ASan banner. The declared strings are what the challenge scores
        # against, and some of them contain spaces ("attempting double-free"),
        # so a pattern that stops at the first word silently reports a mismatch
        # on a run that actually reproduced.
        observed=none
        while IFS= read -r s; do
            if grep -qF "$s" "$d/stderr.log" 2>/dev/null; then observed="$s"; break; fi
        done < <(yq -r '.sanitizers[]' project.yaml)
    fi

    if [ "$observed" = "$expected" ]; then verdict=match; else verdict=MISMATCH; fail=1; fi
    printf '%-8s %-22s expected=%-45s observed=%-45s %s\n' \
        "$id" "$harness" "$expected" "$observed" "$verdict"

    [ $first -eq 1 ] || printf ',\n' >> "$REPORT"
    first=0
    printf '  {"id":"%s","harness":"%s","blob":"%s","expected_sanitizer":"%s","observed_sanitizer":"%s","verdict":"%s"}' \
        "$id" "$harness" "$(basename "$blob")" "$expected" "$observed" "$verdict" >> "$REPORT"
done

printf '\n]\n' >> "$REPORT"
echo
echo "report: $REPORT"

if [ $fail -ne 0 ]; then
    echo "MISMATCH: at least one declared label was not reproduced. The corpus is not trustworthy until this is understood." >&2
    exit 1
fi
echo "all declared labels reproduced"
