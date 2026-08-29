#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The observer for the libpng iCCP class. Produces the observation the case's
# discriminator names, for every member, against an ALREADY-PATCHED tree.
#
# Why this exists rather than the fuzz harness: libpng_read_fuzzer calls
# png_image_finish_read and discards diagnostics. Replaying the class through it
# compared silence against silence, found zero disagreements across all 79
# members, and accepted the known-incomplete fix. The channel could not carry
# the discriminator.
#
#   observe.sh <source-tree> <members-dir>   ->  "<member>\t<observation>" lines
#
# The caller applies the patch and reverts it; this touches a COPY and never the
# tree it is given.
set -euo pipefail

SRC="${1:?usage: observe.sh <source-tree> <members-dir>}"
MEMBERS="${2:?usage: observe.sh <source-tree> <members-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-clang}"
W="$(mktemp -d /var/tmp/arazu-observe-XXXXXX)"
trap 'rm -rf "$W"' EXIT

cp -a "$SRC" "$W/tree"
# Disable libpng's zlib version guard on the COPY. run.sh hardcodes 0x12b0 and
# its own comment says that is brittle; the staged tree carries 0x1280, so the
# literal sed silently matched nothing and every compile died on
# "ZLIB_VERNUM != PNG_ZLIB_VERNUM". Match any value, then CHECK the edit landed
# rather than assuming, because a no-op sed and a successful one look identical.
sed -i -E 's/#define PNG_ZLIB_VERNUM 0x[0-9a-fA-F]+/#define PNG_ZLIB_VERNUM 0/' \
    "$W/tree/pnglibconf.h"
if ! grep -q '^#define PNG_ZLIB_VERNUM 0$' "$W/tree/pnglibconf.h"; then
    echo "observe.sh: could not disable the zlib version guard in pnglibconf.h" >&2
    grep -n 'PNG_ZLIB_VERNUM' "$W/tree/pnglibconf.h" >&2
    exit 1
fi

# NOT 2>/dev/null. run.sh discards compiler stderr, and copying that here meant
# a failing build produced no output at all: set -e killed the script silently
# and the stage reported "observer failed" with nothing to say why. An observer
# that swallows diagnostics is the defect this file exists to fix.
( cd "$W/tree" && $CC -c -O1 -g -fsanitize=address,undefined -I. \
    png.c pngerror.c pngget.c pngmem.c pngpread.c pngread.c pngrio.c pngrtran.c \
    pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c pngwtran.c pngwutil.c \
  && ar rcs libpng.a ./*.o ) >&2
$CC -O1 -g -fsanitize=address,undefined -I"$W/tree" -o "$W/reader" \
    "$HERE/reader.c" "$W/tree/libpng.a" -lz -lm >&2

export ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=0

# Keyed to an OBSERVABLE, not to a diagnostic string. "bad compression method"
# is what gcc prints and "incorrect header check" is what clang prints for the
# same rejection, so a check keyed to either measures the toolchain. Whether
# libpng got far enough to report the parsed keyword is a property of the patch.
for f in "$MEMBERS"/*; do
    [ -f "$f" ] || continue
    out=$("$W/reader" "$f" 2>&1 || true)
    if grep -q "profile '" <<<"$out"; then
        printf '%s\tkeyword parsed\n' "$(basename "$f")"
    else
        printf '%s\tkeyword NOT parsed\n' "$(basename "$f")"
    fi
done
