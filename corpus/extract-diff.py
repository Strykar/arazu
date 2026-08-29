#!/usr/bin/env python3
"""Pull the unified diff out of a model response.

Models do not answer in one shape. Some fence the patch as ```diff, some fence
illustrative C first and leave the real patch unfenced below it, some emit the
diff bare with prose either side. An extractor that takes "the first fenced
block" reads qwen3-coder's explanatory ```c snippet as the answer and reports
no patch at all, which is indistinguishable from a model that produced nothing.

So: gather every candidate region, keep only those that actually look like a
unified diff, and pick the one with the most hunks. Trailing prose is trimmed by
walking the diff body and stopping at the first line that cannot belong to it.

Exit 1 when no candidate qualifies, so the caller can record "no diff" as a real
observation rather than an artefact of the parser.
"""
import re
import sys

DIFF_START = re.compile(r'(?m)^(?:diff --git |--- [ab]?/)')
HUNK = re.compile(r'(?m)^@@')
HEADER = re.compile(r'(?m)^(?:--- |\+\+\+ |diff --git )')
# Lines that may legitimately appear inside a unified diff body.
BODY_OK = re.compile(r'^(?:[-+ @\\]|diff --git |index |new file |deleted file |'
                     r'similarity index |rename |old mode |new mode )')


def trim(block: str) -> str:
    """Drop trailing prose once the diff body is clearly over."""
    lines = block.splitlines(keepends=True)
    out, seen_hunk = [], False
    for line in lines:
        stripped = line.rstrip('\n')
        if HUNK.match(stripped):
            seen_hunk = True
        if seen_hunk and stripped and not BODY_OK.match(stripped):
            break
        out.append(line)
    return ''.join(out)


def candidates(text: str):
    for m in re.finditer(r'```[A-Za-z0-9_+-]*\n(.*?)```', text, re.DOTALL):
        yield m.group(1)
    for m in DIFF_START.finditer(text):
        yield text[m.start():]


def main() -> int:
    text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
    good = []
    for cand in candidates(text):
        cand = trim(cand)
        if HUNK.search(cand) and HEADER.search(cand):
            good.append(cand)
    if not good:
        return 1
    # Most hunks wins; ties go to the longer body, which favours a complete
    # patch over a fragment quoted mid-explanation.
    best = max(good, key=lambda c: (len(HUNK.findall(c)), len(c)))
    sys.stdout.write(best if best.endswith('\n') else best + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
