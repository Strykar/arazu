#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Stage everything the corpus cases need, at the commits they name.
#
# WHY THIS EXISTS. The challenge checkouts and the fuzz tooling are not in this
# repository and should not be: they are other people's trees, some of them
# gigabytes. But "clone them yourself" is not reproducible, and the pins matter
# — a case whose crash_location was established against one commit says nothing
# about another. This turns a hand-staged box into a scripted one.
#
# WHAT IT DERIVES RATHER THAN KNOWS. Every repository, ref and commit comes from
# corpus/cases/*/*.yaml. The script carries no list of its own, because a list
# beside the cases is a second source of truth that agrees until a case changes.
# That is the same rule the image inventory follows, and the reason the
# fuzz-tooling fields were added to the schema instead of being written here.
#
# WHAT IT DOES NOT DO. It does not pull multi-gigabyte images by default: the
# oss-fuzz base builder alone is 2.19GB. Pass --images to include them.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SHIM="${ARAZU_SHIM:-/var/lib/arazu-corpus/shim/docker}"

# CORPUS derives from the shim's --root, for the same reason as in
# r12-image-bundle.sh: two independent defaults that happen to agree are
# indistinguishable from one fact until something moves.
if [ -z "${ARAZU_CORPUS:-}" ]; then
    if [ -x "$SHIM" ]; then
        _root=$(grep -oE -- '--root[[:space:]]+[^ \\]+' "$SHIM" 2>/dev/null | head -1 | awk '{print $2}')
        [ -n "$_root" ] || { echo "cannot read --root from $SHIM" >&2; exit 2; }
        CORPUS=$(dirname "$_root")
    else
        echo "no shim at $SHIM. Set ARAZU_CORPUS to where challenges should be staged." >&2
        exit 2
    fi
else
    CORPUS="$ARAZU_CORPUS"
fi

WANT_IMAGES=0
[ "${1:-}" = "--images" ] && WANT_IMAGES=1

command -v git >/dev/null || { echo "git is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

fail=0
echo "staging into $CORPUS"

# One line per thing to stage: target, kind, repo, ref, commit.
plan=$(python3 - "$REPO" <<'PY'
import glob, os, sys, yaml
repo = sys.argv[1]
seen = set()
for f in sorted(glob.glob(os.path.join(repo, "corpus/cases/*/*.yaml"))):
    with open(f) as fh:
        c = yaml.safe_load(fh)
    c = c or {}
    src = c.get("source") or {}
    target = c.get("target") or "unknown"
    rows = []
    if src.get("cp_repo"):
        # cp_ref, not src_ref: src_ref names a branch of the SOURCE repo and does
        # not exist in the challenge repo. Latent while every case pins cp_commit.
        rows.append((target, "challenge", src["cp_repo"],
                     src.get("cp_ref", ""), src.get("cp_commit", "")))
    if src.get("fuzz_tooling_repo"):
        rows.append((target, "tooling", src["fuzz_tooling_repo"],
                     src.get("fuzz_tooling_ref", ""), src.get("fuzz_tooling_commit", "")))
    # The AIxCC CP layout keeps its source in src/<name> and populates it with
    # `make cpsrc-prepare`. Nothing here ran that, so a fresh machine got a CP
    # with an empty src/ and every grader died on `git -C src/nginx rev-parse`.
    if src.get("src_repo"):
        rows.append((target, "source", src["src_repo"],
                     src.get("src_ref", ""), src.get("src_commit", "")))
    for r in rows:
        if r not in seen:
            seen.add(r)
            print("\x1f".join(r))   # US, not tab: see the read loop
PY
)
[ -n "$plan" ] || { echo "no cases declared a source repository" >&2; exit 1; }

fail=0
# The case files are INPUT, and an invitee may write their own. Everything below
# treats them as untrusted:
#
#  - a URL beginning with "-" is an OPTION to git, not an address. `git clone
#    --upload-pack=...` runs a command of the attacker's choosing, so URLs are
#    matched against an explicit scheme and every git invocation ends its
#    options with "--".
#  - target and repository names become PATH COMPONENTS. One containing ".." or
#    a slash escapes $CORPUS and stages a tree wherever it likes.
#
# Refusing loudly beats sanitising quietly: a case that cannot be staged safely
# is a case someone should look at, not one to silently rewrite.
safe_component() {
    case "$1" in
        ""|*/*|*..*|-*) return 1 ;;
        *) [ -z "${1//[A-Za-z0-9._-]/}" ] ;;
    esac
}

# Split on US (0x1f), not tab. Tab is an IFS whitespace character, so consecutive
# tabs COLLAPSE: a row with an empty ref shifted the commit into $ref and left
# $commit empty, which then skipped the pin verification below. Non-whitespace
# separators do not collapse. Verified both ways, empty and populated.
while IFS= read -r line; do
    IFS=$'\x1f' read -r target kind url ref commit <<<"$line"
    [ -z "$url" ] && continue
    case "$url" in
        https://*|git@*) ;;
        *) echo "  REFUSING $url: not an https or ssh URL" >&2; fail=1; continue ;;
    esac
    name=$(basename "$url" .git)
    if ! safe_component "$target" || ! safe_component "$name"; then
        echo "  REFUSING target=$target name=$name: unsafe as a path component" >&2
        fail=1; continue
    fi
    dest="$CORPUS/$target/$name"
    if [ "$kind" = source ]; then
        cp_name=$(basename "$(awk -F'\x1f' -v t="$target" '$1==t && $2=="challenge"{print $3}' <<<"$plan" | head -1)" .git)
        if [ -n "$cp_name" ] && safe_component "$cp_name"; then
            dest="$CORPUS/$target/$cp_name/src/$name"
        fi
    fi
    printf '\n%s (%s)\n  %s\n' "$name" "$kind" "$url"

    if [ -d "$dest/.git" ]; then
        echo "  already staged, fetching"
        git -C "$dest" fetch -q --all 2>/dev/null || true
    else
        mkdir -p "$(dirname "$dest")"
        if ! git clone -q -- "$url" "$dest" 2>&1 | tail -2; then
            echo "  CLONE FAILED" >&2; fail=1; continue
        fi
    fi

    # Check out the pinned commit, preferring it over the ref: a branch moves,
    # a commit does not, and the case's evidence was established against the
    # commit. The ref is recorded for humans and as a fallback for a case that
    # never captured a commit.
    want="$commit"
    [ -z "$want" ] && want="origin/$ref"
    # NOT `checkout -- "$want"`. After `--` git reads a PATHSPEC, so the first
    # version of this hardening looked for a file named bd449050... and failed
    # on a correctly staged tree. The injection risk is real but the fix is to
    # constrain the VALUE: a ref is a commit-ish, and anything outside this
    # character set is not one.
    case "$want" in
        -*|*' '*|*';'*|*'&'*|*'|'*|*'$'*|*'`'*)
            echo "  REFUSING ref $want: not a plausible commit-ish" >&2; fail=1; continue ;;
    esac
    if ! git -C "$dest" checkout -q --detach "$want" 2>/dev/null; then
        echo "  CANNOT CHECK OUT $want" >&2; fail=1; continue
    fi

    # Verify the pin rather than trust the checkout. A silent failure here
    # stages a tree that looks right and is a different commit, which is the
    # one error that would invalidate every result taken from it.
    got=$(git -C "$dest" rev-parse HEAD)
    if [ -n "$commit" ] && [ "$got" != "$commit" ]; then
        echo "  PIN MISMATCH: wanted $commit, got $got" >&2; fail=1; continue
    fi
    echo "  at $got${commit:+ (pin verified)}"
done <<< "$plan"

if [ "$WANT_IMAGES" -eq 1 ]; then
    echo
    echo "pulling base images (this is gigabytes)"
    [ -x "$SHIM" ] || { echo "  no shim; skipping" >&2; fail=1; }
    if [ -x "$SHIM" ]; then
        # Derived from the cases too: a case naming a fuzz-tooling project needs
        # the oss-fuzz base builder to build its harness.
        if grep -qr 'fuzz_tooling_project' "$REPO/corpus/cases" 2>/dev/null; then
            # Status checked: a failed multi-GB pull otherwise ends in "staged."
            # and exit 0, and the failure surfaces later as a build error.
            if ! sudo "$SHIM" pull gcr.io/oss-fuzz-base/base-builder 2>&1 | tail -1 | sed 's/^/  /'; then
                echo "  PULL FAILED: gcr.io/oss-fuzz-base/base-builder" >&2; fail=1
            fi
        fi
        "$REPO/scripts/r12-image-bundle.sh" inventory 2>&1 | tail -6 | sed 's/^/  /'
    fi
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "STAGING INCOMPLETE: see the failures above." >&2
    exit 1
fi
echo "staged. Next: make check-env, then make build."
