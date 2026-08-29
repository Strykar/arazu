#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the three libpng variants and shows the input class that separates
# Buttercup's two patches for the same bug.
#
#   vuln  the challenge's injected vulnerability, UBSan fires
#   run1  Buttercup run 1's patch, restores libpng's own char keyword[81]
#   run2  Buttercup run 2's patch, caps read_length at the element count
#
# run2 stops the crash and passes the challenge's PoV, its 29 variants and the
# full test suite. It also breaks iCCP parsing for every ICC-bearing PNG, which
# is what this script demonstrates. No sanitizer and no PoV can see that; only
# replaying the input class can.
#
# TOOLCHAIN. Built with clang by default, not gcc, and that is not a preference.
# gcc 16.1.1 (20260728) ICEs on reader.c with an ira_init segfault and cannot
# build this fixture at all. This script claimed to be self-contained and was
# not: it depended on a toolchain that stopped working on the machine that
# produced its own results. Override with CC= if you have a gcc that works.
#
# Same category as the k8s bring-up risk: portability assumed rather than
# tested. In October the toolchain is theirs, and "the fixture does not build"
# is the failure that eats day one.
set -euo pipefail
SRC="${SRC:?point SRC at the example-libpng tree}"
CC="${CC:-clang}"
HERE="$(cd "$(dirname "$0")" && pwd)"
W="${W:-/var/tmp/arazu-libpng-repro}"
mkdir -p "$W"

# Patch each variant's OWN copy, never $SRC. A fixture that edits its input is
# the bind-mount defect in miniature: idempotent today only because of the
# current sed expression, and the first run and the second differ the moment
# that changes or a second fixture touches the same header.
for v in vuln run1 run2; do
    rm -rf "${W:?}/${v:?}"; cp -a "$SRC" "$W/$v"
    # Match ANY value, then CHECK the edit landed. The literal 0x12b0 was the
    # version this fixture was written against; the corpus as staged on
    # 2026-08-21 carries 0x1280, so the substitution matched nothing and every
    # compile died on "ZLIB_VERNUM != PNG_ZLIB_VERNUM". The comment above
    # predicted the brittleness and nothing enforced it: a no-op sed and a
    # successful one are indistinguishable until something downstream fails.
    sed -i -E 's/#define PNG_ZLIB_VERNUM 0x[0-9a-fA-F]+/#define PNG_ZLIB_VERNUM 0/' \
        "$W/$v/pnglibconf.h"
    if ! grep -q '^#define PNG_ZLIB_VERNUM 0$' "$W/$v/pnglibconf.h"; then
        echo "run.sh: could not disable the zlib version guard in $v/pnglibconf.h" >&2
        grep -n 'PNG_ZLIB_VERNUM' "$W/$v/pnglibconf.h" >&2
        exit 1
    fi
    case $v in run1) patch -d "$W/$v" -p1 -s < "$HERE/run1.patch";;
               run2) patch -d "$W/$v" -p1 -s < "$HERE/run2.patch";; esac
    ( cd "$W/$v" && $CC -c -O1 -g -fsanitize=address,undefined -I. png.c pngerror.c pngget.c \
        pngmem.c pngpread.c pngread.c pngrio.c pngrtran.c pngrutil.c pngset.c pngtrans.c \
        pngwio.c pngwrite.c pngwtran.c pngwutil.c 2>/dev/null && ar rcs libpng.a ./*.o )
    $CC -O1 -g -fsanitize=address,undefined -I"$W/$v" -o "$W/reader-$v" "$HERE/reader.c" "$W/$v/libpng.a" -lz -lm
done

export ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=0
python3 "$HERE/mkpng.py" "ICC Profile" "$W/in.png" 400

# No head(1) in the pipeline: it closes the pipe, grep takes SIGPIPE, and under
# pipefail that reads as a failed row and kills the run after the first one.
# Discriminate on an OBSERVABLE, not on a message. "bad compression method" is
# what gcc builds print and "incorrect header check" is what clang builds print
# for the same rejection, so a grep keyed to either is portable only by luck.
# Whether libpng got far enough to report the parsed keyword is a property of
# the patch; the wording of the failure is a property of the build.
for v in vuln run1 run2; do
    out=$("$W/reader-$v" "$W/in.png" 2>&1 || true)
    if grep -q "profile '" <<<"$out"; then kw="keyword parsed"; else kw="keyword NOT parsed"; fi
    detail=$(grep -m1 -oE "runtime error: index [0-9]+ out of bounds|iCCP: .*" <<<"$out" || true)
    printf '%-5s %-18s %s\n' "$v" "$kw" "${detail:-(no diagnostic)}"
done
