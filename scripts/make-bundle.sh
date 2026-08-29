#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Low-side bundle maker. Assembles a payload, writes a canonical manifest
# and signs it with two keys.
#
# Content is fixed rather than generated, so every fixture derived from this
# bundle differs from it by exactly the one mutation under test.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: make-bundle.sh <outdir> [version] [keys]}"
VERSION="${2:-2}"
KEYS="${3:-$REPO/testdata/keys/signer-a.sec,$REPO/testdata/keys/signer-b.sec}"

rm -rf "$OUT"
mkdir -p "$OUT/content"

printf 'alpha payload for the containment spike\n' > "$OUT/content/a.txt"
printf 'bravo payload for the containment spike\n' > "$OUT/content/b.txt"
printf 'stand-in for a reviewed patch candidate\n' > "$OUT/content/patch.diff"

"$REPO/bin/bundle-sign" \
  -dir "$OUT" \
  -bundle-id arazu-spike \
  -version "$VERSION" \
  -keys "$KEYS"
