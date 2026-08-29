#!/usr/bin/env python3
"""Add the synthesised candidates in the manifest to their case files.

normalise-nginx.sh regenerates a case file from the challenge alone, so anything
we add by hand is lost the next time the corpus is rebuilt. Keeping the
synthesised candidates in a manifest and applying them afterwards means the
generator stays the single source of what the challenge provides, and this stays
the single source of what we added.

Idempotent: a candidate already present is left exactly as it is, so this can run
after every regeneration without duplicating entries or clobbering an edit.

Usage: apply-candidates.py <manifest.yaml> <cases-dir>
"""
import os
import sys

import yaml


def block(c):
    """Render one candidate, with its evidence as a comment above the reason."""
    lines = [
        f'  - id: {c["id"]}',
        f'    patch: {c["patch"]}',
        f'    patch_root: {c.get("patch_root", "repo")}',
        f'    label: {c["label"]}',
    ]
    # Wrap the evidence rather than emitting one long line.
    words, out, cur = f'Established by running it: {c["evidence"].strip()}.'.split(), [], ''
    for w in words:
        if cur and len(cur) + len(w) + 1 > 70:
            out.append(cur)
            cur = w
        else:
            cur = f'{cur} {w}'.strip()
    if cur:
        out.append(cur)
    lines += [f'    # {ln}' for ln in out]
    r = c["expected_gate_reason"]
    lines.append(f'    expected_gate_reason: {"null" if r is None else r}')
    return '\n'.join(lines) + '\n'


def main():
    manifest_path, cases_dir = sys.argv[1], sys.argv[2]
    with open(manifest_path, encoding='utf-8') as f:
        manifest = yaml.safe_load(f) or {}

    added = present = 0
    for cpv, cands in manifest.items():
        path = os.path.join(cases_dir, f'{cpv}.yaml')
        if not os.path.isfile(path):
            print(f'{cpv}: no case file at {path}', file=sys.stderr)
            continue
        text = open(path, encoding='utf-8').read()
        if 'candidates:' not in text:
            print(f'{cpv}: case file has no candidates section', file=sys.stderr)
            continue

        for c in cands:
            if f'- id: {c["id"]}\n' in text:
                present += 1
                continue
            if not text.endswith('\n'):
                text += '\n'
            text += block(c)
            added += 1
            print(f'{cpv}: added {c["id"]} ({c["label"]})', file=sys.stderr)

        open(path, 'w', encoding='utf-8').write(text)

    print(f'added {added}, already present {present}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
