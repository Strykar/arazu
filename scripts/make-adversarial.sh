#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Derive every adversarial bundle from the good one.
#
# Each variant applies exactly one mutation. That is the point: if a variant
# differed in two ways, the reason the gate reports would not be
# attributable to the mutation under test.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS="$REPO/testdata/keys"
OUT="$REPO/testdata/bundles"

rm -rf "${OUT:?}"
mkdir -p "$OUT"

# The good bundle, version 2. Everything else is derived from it.
"$REPO/scripts/make-bundle.sh" "$OUT/good" 2 >/dev/null

derive() { rm -rf "${OUT:?}/${1:?}"; cp -a "$OUT/good" "$OUT/$1"; }

# 2. One byte flipped in a payload file. Manifest and signatures untouched,
#    so the manifest still verifies and only the content hash disagrees.
derive flipped-byte
printf 'blpha payload for the containment spike\n' > "$OUT/flipped-byte/content/a.txt"

# 3. Only one signature present.
derive one-signature
head -n 1 "$OUT/good/manifest.sig" > "$OUT/one-signature/manifest.sig"

# 4. Second signature from a key that is not provisioned on the high side.
derive untrusted-signer
"$REPO/bin/bundle-sign" -dir "$OUT/untrusted-signer" -bundle-id arazu-spike -version 2 \
  -keys "$KEYS/signer-a.sec,$KEYS/untrusted.sec" >/dev/null

# 5. A file present in the store but absent from the manifest.
derive extra-file
printf 'not listed in the manifest\n' > "$OUT/extra-file/content/extra.txt"

# 6. A manifest entry whose file is gone.
derive missing-file
rm "$OUT/missing-file/content/b.txt"

# 7. Rollback: a properly signed bundle at an older version.
"$REPO/scripts/make-bundle.sh" "$OUT/rollback" 1 >/dev/null

# 8. A path outside the allowlist, correctly signed so only the path is wrong.
derive outside-allowlist
mkdir -p "$OUT/outside-allowlist/etc"
printf 'root::0:0::/root:/bin/sh\n' > "$OUT/outside-allowlist/etc/evil.conf"
"$REPO/bin/bundle-sign" -dir "$OUT/outside-allowlist" -bundle-id arazu-spike -version 2 \
  -keys "$KEYS/signer-a.sec,$KEYS/signer-b.sec" >/dev/null

# 9. Truncated manifest, signatures left in place.
derive truncated-manifest
python3 - "$OUT/truncated-manifest/manifest.json" <<'PY'
import sys
p = sys.argv[1]
b = open(p, 'rb').read()
open(p, 'wb').write(b[:len(b)//2])
PY

# 10. Two valid signatures from the same trusted key. Both verify, both are
#     from a provisioned signer, and the count is two, so anything that
#     counts signature lines instead of distinct signers lets this through
#     and two-person control is satisfied by one person.
derive duplicate-signer
"$REPO/bin/bundle-sign" -dir "$OUT/duplicate-signer" -bundle-id arazu-spike -version 2 \
  -keys "$KEYS/signer-a.sec,$KEYS/signer-a.sec" >/dev/null

# 11. A symlinked directory component.
#
#     The manifest is honest and correctly signed over a real
#     content/sub/file. The directory is swapped for a symlink out of the
#     store afterwards, so the bytes a workload would read are not the bytes
#     that were reviewed and signed. os.Lstat resolves intermediate
#     components, so the file looks regular and the escape is invisible to a
#     per-entry check; only a walk of the tree sees the symlink.
SUB="$OUT/symlinked-dir"
rm -rf "$SUB" "$OUT/outside-the-store"
mkdir -p "$SUB/content/sub"
printf 'alpha payload for the containment spike\n' > "$SUB/content/a.txt"
printf 'bravo payload for the containment spike\n' > "$SUB/content/b.txt"
printf 'stand-in for a reviewed patch candidate\n' > "$SUB/content/patch.diff"
printf 'reviewed and signed\n' > "$SUB/content/sub/file"
"$REPO/bin/bundle-sign" -dir "$SUB" -bundle-id arazu-spike -version 2 \
  -keys "$KEYS/signer-a.sec,$KEYS/signer-b.sec" >/dev/null

mkdir -p "$OUT/outside-the-store"
printf 'never reviewed, never signed\n' > "$OUT/outside-the-store/file"
rm -r "$SUB/content/sub"
ln -s "$OUT/outside-the-store" "$SUB/content/sub"

echo "fixtures in $OUT:"
ls -1 "$OUT"
