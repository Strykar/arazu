#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build a libpng that reports whether execution reached the line run2.patch
# changes (pngrutil.c:1428, `read_length = sizeof(keyword)`).
#
# This is the coverage instrument for Corpus M2b. gcc 16.1.1 ICEs on reader.c
# (ira_init segfault) so the fixture's own run.sh no longer builds on this host;
# clang 22 is used instead. A targeted marker is also a better instrument than
# gcov here: it answers exactly the question, with no probe-placement ambiguity
# and no dependence on profile data surviving a crash.
#
# Every step fails hard. Two earlier attempts printed "marker hits: 0" from a
# binary that had never been linked, because a pipe swallowed the compiler's
# exit status. A zero from a missing binary is indistinguishable from a real
# negative, and the seed is the one input that MUST reach the line, so the
# self-test at the end is what makes any later zero believable.
set -euo pipefail

SRC="${SRC:-/var/tmp/arazu-libpng/src/example-libpng}"
W="${W:-/var/tmp/arazu-libpng-buildb}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-clang}"
LINE="${LINE:-1428}"
MARK="ARAZU_REACHED_${LINE}"

[ -d "$SRC" ] || { echo "no libpng source at $SRC" >&2; exit 2; }

rm -rf "$W/probe" "$W/reader-probe"
mkdir -p "$W"
cp -a "$SRC" "$W/probe"
sed -i 's/#define PNG_ZLIB_VERNUM 0x12b0/#define PNG_ZLIB_VERNUM 0/' "$W/probe/pnglibconf.h"

# Confirm the line is the one the patch changes before probing it, so a source
# tree that moved on cannot be probed at the wrong offset.
grep -q 'read_length = sizeof(keyword)' <(sed -n "${LINE}p" "$W/probe/pngrutil.c") || {
    echo "line $LINE of pngrutil.c is not the line run2.patch changes; refusing to probe blind" >&2
    sed -n "${LINE}p" "$W/probe/pngrutil.c" >&2
    exit 1
}

# stdio.h first: clang 22 makes an implicit fprintf declaration an error.
{ echo '#include <stdio.h>'; cat "$W/probe/pngrutil.c"; } > "$W/probe/.tmp"
mv "$W/probe/.tmp" "$W/probe/pngrutil.c"
awk -v n=$((LINE + 1)) -v m="$MARK" \
    'NR==n{printf "      fprintf(stderr, \"%s\\n\");\n", m}1' \
    "$W/probe/pngrutil.c" > "$W/probe/.tmp"
mv "$W/probe/.tmp" "$W/probe/pngrutil.c"

cd "$W/probe"
$CC -c -O1 -g -I. png.c pngerror.c pngget.c pngmem.c pngpread.c pngread.c pngrio.c \
    pngrtran.c pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c pngwtran.c pngwutil.c
rm -f libpng.a
ar rcs libpng.a ./*.o
$CC -O1 -g -I"$W/probe" -o "$W/reader-probe" "$HERE/reader.c" "$W/probe/libpng.a" -lz -lm
[ -x "$W/reader-probe" ] || { echo "reader-probe was not produced" >&2; exit 1; }

# Self-test. The seed IS the class discriminator, so it must reach the line. A
# build where it does not is a broken instrument, not a finding about inputs.
hits=$("$W/reader-probe" "$HERE/falsifying-input.png" 2>&1 | grep -c "$MARK" || true)
if [ "$hits" -eq 0 ]; then
    echo "INSTRUMENT BROKEN: the seed does not reach line $LINE" >&2
    exit 1
fi
echo "probe build ok: $W/reader-probe"
echo "self-test: the seed reaches line $LINE ($hits marker hits)"
