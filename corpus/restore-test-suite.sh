#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Put the challenge's public test suite back the way it was found.
#
# container_scripts/cp_tests copies /.internal_only/**.t over
# ${SRC}/nginx-unit-tests, and run.sh bind-mounts src, so that copy lands on the
# HOST and survives the container. Grading one CPV therefore leaves its private
# test installed in the public suite, where it runs for every CPV graded
# afterwards.
#
# Ten of the fourteen private tests shadow a public file, so they show up as a
# modification and `git checkout` puts them back. The other four (from.t,
# prefer.t, reverse.t, browser.t, for cpv1/cpv10/cpv12/cpv4) have no public
# counterpart at all: they arrive as new files, git restores nothing, and they
# would quietly become part of every later run's test set. A test that is in the
# observed set but not in the baseline reads as a regression the candidate
# caused, so the leak turns into false rejections of correct patches.
#
# Untracked files are removed by exact path, only after git confirms the path is
# untracked and the file exists. No globs are handed to rm: the set of names is
# enumerated from .internal_only, which is the only thing that can have been
# copied in.
set -euo pipefail

CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
suite="$CP/src/nginx-unit-tests"
# The test suite is a subdirectory of the challenge repo, not a checkout of its
# own, so every git call below is scoped to $CP with an explicit pathspec.
rel="src/nginx-unit-tests"

[ -d "$CP/.git" ] || { echo "no git checkout at $CP; refusing to guess what is original" >&2; exit 2; }

# Tracked files the container overwrote.
git -C "$CP" checkout -- "$rel"

# Private tests with no public counterpart, which arrive as new files.
for t in "$CP"/.internal_only/cpv*/private_tests/*.t; do
    [ -e "$t" ] || continue
    name=$(basename "$t")
    path="$suite/$name"
    [ -e "$path" ] || continue
    # Anything git tracks was just restored above and must not be deleted.
    if git -C "$CP" ls-files --error-unmatch "$rel/$name" >/dev/null 2>&1; then
        continue
    fi
    rm -f "$path"
    echo "removed leaked private test: $name" >&2
done

left=$(git -C "$CP" status --porcelain --untracked-files=all -- "$rel" | wc -l)
[ "$left" -eq 0 ] || {
    echo "test suite still dirty after restore:" >&2
    git -C "$CP" status --porcelain --untracked-files=all -- "$rel" >&2
    exit 1
}
