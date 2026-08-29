#!/usr/bin/env python3
"""Write the measured classification into the case files.

normalise-nginx.sh generates every shipped bad patch as `label: unclassified`
with a null expected_gate_reason, which is the honest state for a case nobody
has run yet. classify-nginx.sh establishes the class by running it. This applies
that result, so there is exactly one writer of the classification and
regenerating the corpus never silently re-asserts an answer it has not measured.

The comment above the field is rewritten too. Leaving "established by
classify-nginx.sh rather than assumed here" above a filled-in value would read
as though the value were still pending, and the evidence for the class belongs
next to the class.

Usage: apply-classification.py <classification.jsonl> <cases-dir>
Refuses to touch a case whose candidate is not the one that was classified.
"""
import json
import os
import re
import sys

# Any run of comment lines immediately above the field, whatever it currently
# says. Matching the applied form as well as the pending one makes this
# re-runnable: a re-measured class overwrites the old one instead of needing the
# case files regenerated, which costs a full round-trip verification per case.
FIELD = re.compile(r'(?:^ *#.*\n)*^ *expected_gate_reason: .*\n', re.MULTILINE)
LABEL = re.compile(r'^( *)label: [A-Za-z0-9-]+\n', re.MULTILINE)

# How many failing test names to keep in the case file. Two of the challenge's
# bad patches break most of the suite, and pasting 191 filenames into a comment
# buries the case rather than documenting it. The full set stays in
# classification.jsonl, which is where evidence of that size belongs.
MAX_NAMED = 5


def summarise(note):
    """Keep the note short when the failing-test list is enormous."""
    marker = ' newly fails'
    if not note.endswith(marker):
        return note
    head, _, names = note.partition('and ')
    parts = [n.strip() for n in names[:-len(marker)].split(',') if n.strip()]
    if len(parts) <= MAX_NAMED:
        return note
    shown = ', '.join(parts[:MAX_NAMED])
    return (f'{head}and {len(parts)} test files newly fail, including {shown}. '
            f'The full list is in corpus/reports/classification.jsonl')


def apply(case_path, rec):
    text = open(case_path, encoding='utf-8').read()

    label, reason, note = rec['label'], rec['expected_gate_reason'], rec['note']
    if reason is None:
        return False, 'still unclassified: ' + note

    new, n = LABEL.subn(rf'\1label: {label}\n', text, count=1)
    if n != 1:
        return False, 'no candidate label to set'

    # Wrap the evidence so a long failing-test list does not become one line.
    body = f'Established by running it: {summarise(note)}.'
    words, lines, cur = body.split(), [], ''
    for w in words:
        if cur and len(cur) + len(w) + 1 > 70:
            lines.append(cur)
            cur = w
        else:
            cur = f'{cur} {w}'.strip()
    if cur:
        lines.append(cur)
    comment = ''.join(f'    # {ln}\n' for ln in lines)

    replacement = comment + f'    expected_gate_reason: {reason}\n'
    new, n = FIELD.subn(lambda _: replacement, new, count=1)
    if n != 1:
        return False, 'no expected_gate_reason field found; refusing to guess where it goes'

    open(case_path, 'w', encoding='utf-8').write(new)
    return True, f'{label} / {reason}'


def main():
    src, cases_dir = sys.argv[1], sys.argv[2]
    applied = skipped = 0
    with open(src, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            path = os.path.join(cases_dir, rec['cpv'] + '.yaml')
            if not os.path.isfile(path):
                print(f'{rec["cpv"]}: no case file at {path}', file=sys.stderr)
                skipped += 1
                continue
            ok, msg = apply(path, rec)
            print(f'{rec["cpv"]}: {msg}', file=sys.stderr)
            applied += ok
            skipped += not ok
    print(f'applied {applied}, left alone {skipped}', file=sys.stderr)
    return 0 if applied else 1


if __name__ == '__main__':
    sys.exit(main())
