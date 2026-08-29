#!/usr/bin/env python3
"""Rebuild missing or wrong @@ hunk headers by locating the context in the file.

gpt-oss:20b emitted a semantically correct fix for nginx cpv2 in the right
function, with context lines that match the real source exactly, but wrote its
hunk headers as a bare "@@" with no line ranges. git apply and patch both reject
that as garbage, so a correct edit was unusable for a reason that has nothing to
do with whether the model understood the bug.

The context and removal lines are enough to find the anchor: search the target
file for that exact run of lines and compute the ranges from where it matches.
This is mechanical, and a real agentic harness would do the same rather than
discard the answer.

It is assistance, though, so the caller records it as its own apply_mode. A
patch that only lands after reconstruction is a different result from one that
applied as written, and collapsing the two would overstate what the model did.

Usage: fix-hunks.py <diff> <source-root>   # rewritten diff on stdout
Exit 1 if any hunk cannot be anchored, so failure stays visible.
"""
import os
import re
import sys


def parse(diff_text):
    """Split into (preamble, [(header, body_lines)]) per file section."""
    lines = diff_text.splitlines()
    out, i = [], 0
    cur_file, cur_hdr, hunks = None, [], []
    while i < len(lines):
        ln = lines[i]
        if ln.startswith('--- '):
            if cur_file is not None:
                out.append((cur_file, cur_hdr, hunks))
            cur_hdr = [ln, lines[i + 1] if i + 1 < len(lines) else '']
            m = re.match(r'--- [ab]?/?(.*)', ln)
            cur_file = m.group(1).strip() if m else None
            hunks, i = [], i + 2
            continue
        if ln.startswith('@@'):
            body, i = [], i + 1
            while i < len(lines) and not lines[i].startswith('@@') \
                    and not lines[i].startswith('--- ') \
                    and not lines[i].startswith('diff --git '):
                body.append(lines[i])
                i += 1
            hunks.append(body)
            continue
        i += 1
    if cur_file is not None:
        out.append((cur_file, cur_hdr, hunks))
    return out


def anchor(body, src_lines):
    """Find where this hunk's pre-image sits in the file; return 0-based index."""
    pre = [l[1:] for l in body if l[:1] in (' ', '-')]
    # Trailing blank context is unreliable; trim it before matching.
    while pre and not pre[-1].strip():
        pre.pop()
    if not pre:
        return None, None, None
    n = len(pre)
    for start in range(len(src_lines) - n + 1):
        if [s.rstrip('\n') for s in src_lines[start:start + n]] == pre:
            post = [l[1:] for l in body if l[:1] in (' ', '+')]
            while post and not post[-1].strip():
                post.pop()
            return start, n, len(post)
    return None, None, None


def main():
    diff_path, root = sys.argv[1], sys.argv[2]
    text = open(diff_path, encoding='utf-8', errors='replace').read()
    result, failed = [], 0
    for path, hdr, hunks in parse(text):
        full = os.path.join(root, path)
        if not os.path.isfile(full):
            print(f'fix-hunks: no such file: {path}', file=sys.stderr)
            failed += 1
            continue
        src = open(full, encoding='utf-8', errors='replace').readlines()
        result.extend(hdr)
        for body in hunks:
            start, old_n, new_n = anchor(body, src)
            if start is None:
                print('fix-hunks: could not anchor a hunk in ' + path, file=sys.stderr)
                failed += 1
                continue
            result.append(f'@@ -{start + 1},{old_n} +{start + 1},{new_n} @@')
            # Drop trailing blank lines we excluded from the counts.
            keep = list(body)
            while keep and not keep[-1].strip():
                keep.pop()
            result.extend(keep)
    if failed or not result:
        return 1
    sys.stdout.write('\n'.join(result) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
