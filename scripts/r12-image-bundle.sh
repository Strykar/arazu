#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# R1.2 — make the grading environment's image dependency a portable artifact
# instead of hand-staged state on one box.
#
# WHAT WAS ALREADY TRUE. `cmd/gate` runs challenge images through the shim at
# /var/lib/arazu-corpus/shim, which points podman at a dedicated store. The
# nginx challenge image is already in that store, so grading works offline HERE.
#
# WHAT WAS NOT. That state was built by hand and nothing reproduces it. On the
# organisers' hardware the store is empty, and the only recorded way to fill it
# is to pull from ghcr.io — which is precisely the dependency the R1.4 cut run
# found Buttercup blocked on, one layer down. "It works on the dev box" and "it
# ships" are different claims and only the first was supported.
#
# The negative test is the point, per the project's own rule that no check ships
# without a test that makes it fail: `verify` runs a grading step with the
# registry made unreachable. Without that, a green run proves only that the
# image was cached, which is what this script exists to stop assuming.
set -uo pipefail

SHIM="${ARAZU_SHIM:-/var/lib/arazu-corpus/shim/docker}"

# CORPUS is DERIVED from the shim's own --root, not declared beside it.
#
# These were two independent defaults that happened to agree, which is
# indistinguishable from one fact until something moves — and something did: a
# clone landed in /mnt/4TB1/arazu-corpus while the shim reads
# /var/lib/arazu-corpus. Those are different devices holding two 1.4G copies of
# the store, and identical perms/timestamps/entry-counts had made the copy look
# like the same tree.
#
# The shim's `podman --root` is not a second copy of this knowledge, it is where
# the knowledge already lives operationally: it decides where the gate actually
# looks. Deriving from it makes the two agree by construction rather than by
# coincidence.
if [ -z "${ARAZU_CORPUS:-}" ]; then
    _root=$(grep -oE -- '--root[[:space:]]+[^ \\]+' "$SHIM" 2>/dev/null | head -1 | awk '{print $2}')
    [ -n "$_root" ] || { echo "cannot read --root from $SHIM; refusing to guess the corpus tree" >&2; exit 2; }
    CORPUS=$(dirname "$_root")
else
    CORPUS="$ARAZU_CORPUS"
fi
REPO="$(cd "$(dirname "$0")/.." && pwd)"
# Deliberately OUTSIDE the repo. The images are ~1.5GB each; logs/ is not
# git-ignored, /home is at 94%, and the 4TB volume already holds the corpus and
# the podman store this script reads from. A multi-gigabyte artifact in the
# working tree is one `git add -A` away from being unrecoverable history.
BUNDLE="${ARAZU_IMAGE_BUNDLE:-/mnt/4TB1/arazu-corpus/image-bundle}"

die() { echo "$*" >&2; exit 1; }
[ -x "$SHIM" ] || die "no shim at $SHIM"

# THE REQUIREMENT comes from the cases the gate actually runs. THE EVIDENCE
# comes from what is staged. They are separate traversals on purpose.
#
# The first version derived the required set from
# $CORPUS/*/challenge-*/project.yaml — the STAGED challenges — and reported
# "none missing". That traversal can only ever report what it already found: it
# answered "are the staged challenges' images present" while claiming to answer
# "can we grade offline". Those coincide only when the staged set covers the
# cases, and nothing enforced that. libpng was required by a case, never staged,
# and therefore invisible to the check meant to catch exactly that.
#
# Deriving was the right instinct applied to the wrong domain. The fix is not to
# stop deriving but to derive from the set that DEFINES the requirement rather
# than the set that happens to satisfy it, and to report the difference.

# Challenges the corpus cases require, by cp_repo name.
required_challenges() {
    grep -h 'cp_repo:' "$REPO"/corpus/cases/*/*.yaml 2>/dev/null \
        | awk '{print $2}' | xargs -r -n1 basename 2>/dev/null \
        | sed 's/\.git$//' | sort -u
}

# Is a NAMED challenge staged? A targeted lookup, not an enumeration.
#
# Two wrong versions preceded this. `-name 'challenge-*'` assumed the nginx
# naming was the rule, and missed `example-libpng` the moment that case's repo
# was corrected to its real upstream. Replacing it with a bare depth-2 find then
# swept podman-root/overlay, buttercup/patcher and .git into the report — about
# thirty directories that are not challenges at all.
#
# The requirement names what to look for, so look for exactly that and answer a
# yes/no question, rather than listing the tree and hoping the listing means
# something.
challenge_path() {
    find "$CORPUS" -mindepth 2 -maxdepth 3 -type d -name "$1" -print -quit 2>/dev/null
}

staged_challenges() {
    local c
    while read -r c; do
        [ -z "$c" ] && continue
        [ -n "$(challenge_path "$c")" ] && echo "$c"
    done < <(required_challenges)
    # Explicit success. The loop's status is that of its LAST iteration, so a
    # final name that is not staged makes this function return 1 — and under
    # `set -o pipefail` that turns `staged_challenges | grep -qx` into a failed
    # pipeline even when grep matched, reporting a staged challenge as missing.
    # pipefail was added to stop `cmd | head && echo` lying; it made this
    # previously-harmless status meaningful. Same family both times: reading a
    # pipeline's status as something other than what it means.
    return 0
}

# For the dead-weight report only: things that LOOK like challenge checkouts,
# i.e. carry a .git or a project.yaml. Without that filter the report is noise,
# because a store directory and a challenge are both just directories.
staged_checkouts() {
    local d
    while read -r d; do
        [ -z "$d" ] && continue
        if [ -e "$d/.git" ] || [ -e "$d/project.yaml" ]; then
            basename "$d"
        fi
    done < <(find "$CORPUS" -mindepth 2 -maxdepth 2 -type d 2>/dev/null) | sort -u
    return 0
}

# Images required BY THE STAGED CHALLENGES THAT CASES REFERENCE. An unstaged
# challenge contributes no image here because its project.yaml is not on the
# box — which is why the missing-challenge check below has to run first and
# fail, or an unstaged requirement would silently reduce the image set.
required_images() {
    local c
    while read -r c; do
        [ -z "$c" ] && continue
        grep -h '^docker_image:' "$CORPUS"/*/"$c"/project.yaml 2>/dev/null | awk '{print $2}'
    done < <(required_challenges) | sort -u
}

# Present in the SHIM's store, which is the only store the gate consults.
# Deliberately not `podman images` as the login user: that queries a different
# store and would report present for an image the gate cannot see.
present_images() {
    sudo "$SHIM" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | sort -u
}

cmd_inventory() {
    local fail=0

    echo "challenges required by corpus/cases:"
    required_challenges | sed 's/^/  /'
    echo "challenges staged under $CORPUS:"
    staged_challenges | sed 's/^/  /'

    # Evaluate ONCE into a variable and test membership without a pipeline.
    #
    # `staged_challenges | grep -qx "$c"` was wrong twice, both times because a
    # pipeline's exit status is not the question being asked. First the loop's
    # last-iteration status leaked out; then, with that fixed, `grep -q` exited
    # on its first match, closed the pipe, and left staged_challenges dying of
    # SIGPIPE — which `set -o pipefail` faithfully reported as failure, so the
    # FIRST staged challenge read as missing while the last read as present.
    # pipefail was added to stop `cmd | head && echo` lying and then created two
    # bugs of its own; the durable fix is not to ask a pipeline a question whose
    # answer lives in only one of its stages.
    local staged
    staged=$(staged_challenges)
    echo "MISSING challenges (required by a case, not staged):"
    local c none=1
    while read -r c; do
        [ -z "$c" ] && continue
        if ! grep -qx "$c" <<<"$staged"; then
            echo "  $c"; none=0; fail=1
        fi
    done < <(required_challenges)
    [ "$none" -eq 1 ] && echo "  none"

    # "I do not know how to check this" is the ERROR cell, not the clean cell.
    #
    # required_images() reads docker_image from a challenge's project.yaml — the
    # nginx CP shape, generalised from the one example that existed when this was
    # written. libpng does not have that shape: it is a bare source repo whose
    # harness is built from separate oss-fuzz tooling. Once its challenge dir is
    # staged, the old code would find no project.yaml, contribute no image, and
    # report "complete" while the tooling it actually needs was still absent.
    #
    # That was a false clean with a SCHEDULED ARRIVAL — correct today because the
    # challenge is missing, wrong the moment staging finishes. Refusing on an
    # unrecognised shape converts it into an honest failure at the same moment.
    # The real fix is the schema expressing a challenge's build inputs instead of
    # assuming one packaging; this is the cheap guard until that exists.
    echo "UNRECOGNISED shape (staged, but no build descriptor this script can read):"
    none=1
    while read -r c; do
        [ -z "$c" ] && continue
        staged_challenges | grep -qx "$c" || continue   # missing is reported above
        if ! ls "$CORPUS"/*/"$c"/project.yaml >/dev/null 2>&1; then
            echo "  $c: no project.yaml — cannot determine its images, so completeness is UNKNOWN"
            none=0; fail=1
        fi
    done < <(required_challenges)
    [ "$none" -eq 1 ] && echo "  none"

    echo "MISSING images (required by a staged challenge, not in the shim store):"
    none=1
    local img
    while read -r img; do
        [ -z "$img" ] && continue
        # A case naming a bare repository matches any tag of it; the store is
        # tagged, so compare on the repository when the case gives no tag.
        if ! present_images | grep -q "^${img%%:*}:"; then
            echo "  $img"; none=0; fail=1
        fi
    done < <(required_images)
    [ "$none" -eq 1 ] && echo "  none"

    # The inverse, which the single-traversal version could not see at all.
    # Not a failure: dead weight is worth knowing about, but it does not stop a
    # grading run. Reported so a store that has drifted from the corpus is
    # visible in both directions rather than only where it hurts today.
    echo "staged but referenced by NO case (dead weight):"
    none=1
    local s stem
    while read -r s; do
        [ -z "$s" ] && continue
        # A -source tree belongs to its -cp challenge; it is referenced if that
        # challenge is. Treating them independently would report every source
        # tree as dead weight.
        stem=${s%-cp}; stem=${stem%-source}
        if ! required_challenges | sed 's/-cp$//' | grep -qx "$stem"; then
            echo "  $s"; none=0
        fi
    done < <(staged_checkouts)
    [ "$none" -eq 1 ] && echo "  none"

    if [ "$fail" -ne 0 ]; then
        echo "INVENTORY INCOMPLETE: the corpus cannot be graded offline as staged." >&2
        return 1
    fi
    echo "inventory complete: every case's challenge is staged and its images are present"
    return 0
}

cmd_export() {
    mkdir -p "$BUNDLE"
    local n=0
    while read -r img; do
        [ -z "$img" ] && continue
        local tagged
        tagged=$(present_images | grep "^${img%%:*}:" | head -1)
        [ -n "$tagged" ] || { echo "SKIP $img: not in the store, nothing to export" >&2; continue; }
        local f; f="$BUNDLE/$(echo "$tagged" | tr '/:' '__').tar"
        echo "exporting $tagged"
        sudo "$SHIM" save --output "$f" "$tagged" || die "save failed for $tagged"
        # Under sudo, id -u is 0, so the first version left the artifact root-owned
        # — unreadable to the operator who has to copy it to the target hardware.
        # Chown to the INVOKING user, not the effective one.
        chown "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "$f" 2>/dev/null || true
        n=$((n+1))
    done < <(required_images)
    [ "$n" -gt 0 ] || die "nothing exported"
    # Digests, so an import can prove it loaded what was exported rather than
    # trusting a filename. A corrupted or substituted layer is exactly the thing
    # an air-gapped transfer over removable media can introduce.
    ( cd "$BUNDLE" && sha256sum ./*.tar > SHA256SUMS )
    chown -R "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "$BUNDLE" 2>/dev/null || true
    echo "exported $n image(s) to $BUNDLE"
    cat "$BUNDLE/SHA256SUMS" | sed 's/^/  /'
}

cmd_import() {
    [ -d "$BUNDLE" ] || die "no bundle at $BUNDLE"
    ( cd "$BUNDLE" && sha256sum -c SHA256SUMS ) || die "digest mismatch: refusing to load"
    for f in "$BUNDLE"/*.tar; do
        echo "loading $(basename "$f")"
        sudo "$SHIM" load --input "$f" || die "load failed for $f"
    done
    cmd_inventory
}

# The negative test. A grading step that succeeds while the registry is
# reachable proves nothing about the air gap; it may have pulled. This runs the
# same step with ghcr.io blackholed and requires it to still succeed.
cmd_verify() {
    local img
    img=$(required_images | head -1)
    [ -n "$img" ] || die "no required image to verify against"
    local tagged
    tagged=$(present_images | grep "^${img%%:*}:" | head -1)
    [ -n "$tagged" ] || die "$img is not in the store; run import first"

    [ "$(id -u)" -eq 0 ] || die "verify needs root: it blackholes the registry for the duration"

    # Resolve BEFORE cutting, or the null route is untestable — a name that
    # cannot resolve fails for a reason that has nothing to do with the route.
    #
    # NOT `local`. The EXIT trap fires after this function's scope is gone, so
    # locals leave the trap with unbound variables: the route deletes silently do
    # not run, and the check that would have caught that cannot run either. The
    # first version did exactly this and left a blackhole route on the host while
    # printing "reverted".
    VERIFY_IPS=$(getent ahostsv4 ghcr.io | awk '{print $1}' | sort -u)
    [ -n "$VERIFY_IPS" ] || die "cannot resolve ghcr.io, so the cut cannot be attributed"
    VERIFY_ADDED=()

    restore() {
        local ip
        for ip in "${VERIFY_ADDED[@]:-}"; do
            [ -n "$ip" ] && ip route del blackhole "$ip"/32 2>/dev/null
        done
        # Read the routing table itself rather than re-deriving what should be
        # there. Any blackhole route left is a failure, whoever added it.
        local left
        left=$(ip route show type blackhole 2>/dev/null)
        if [ -n "$left" ]; then
            echo "REVERT INCOMPLETE, blackhole routes remain:" >&2
            echo "$left" >&2
        else
            echo "reverted: no blackhole routes remain"
        fi
    }
    trap restore EXIT

    for ip in $VERIFY_IPS; do
        ip route add blackhole "$ip"/32 2>/dev/null && VERIFY_ADDED+=("$ip")
    done
    echo "registry blackholed: ${VERIFY_ADDED[*]:-none}"

    # Self-test the cut, so a pass below cannot be a cut that never applied.
    #
    # Reachability means "an HTTP response arrived", NOT "the response was 2xx".
    # ghcr.io/v2/ answers 401 to an unauthenticated client, so the first version
    # of this check (`curl -sf`) exited non-zero against a perfectly reachable
    # registry and would have declared the cut effective with no cut in place.
    # A self-test that cannot fail, guarding the one result that needed guarding.
    local code
    code=$(timeout 12 curl -s -o /dev/null -m 8 -w '%{http_code}' "https://ghcr.io/v2/" 2>/dev/null)
    if [ "${code:-000}" != "000" ]; then
        die "SELF-TEST FAILED: ghcr.io answered HTTP $code, so it is reachable and a pass would prove nothing"
    fi
    echo "self-test: the registry returns no HTTP response (code 000)"

    echo "running the image with no registry..."
    if "$SHIM" run --rm --pull=never "$tagged" /bin/true 2>&1 | tail -3; then
        echo "PASS: the grading image runs with the registry unreachable"
    else
        echo "FAIL: the image could not run offline" >&2
        return 1
    fi
}

case "${1:-inventory}" in
    inventory) cmd_inventory ;;
    export)    cmd_export ;;
    import)    cmd_import ;;
    verify)    cmd_verify ;;
    *) die "usage: $0 {inventory|export|import|verify}" ;;
esac
