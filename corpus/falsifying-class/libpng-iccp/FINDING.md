# Buttercup produced two patches for one bug. One of them is wrong.

Two runs of the same challenge, on the same host, with the same input. Run 1
rediscovered libpng's own code. Run 2 produced a patch that stops the crash,
passes the proof of vulnerability, passes 29 PoV variants, passes the full test
suite, and breaks iCCP parsing for every PNG that carries an ICC profile.

Nothing in the pipeline distinguished them. Both were emitted as patches.

| | run 1 | run 2 |
|---|---|---|
| task | `a790c3ea-1c89-47e0-82fc-3b5c7cdfb425` | `78c4e908-ff7b-403e-b01b-1640e28d1fa7` |
| cost | $8.98 | $5.50 |
| submit to patch | 9m52s | ~14m |
| verdict | correct | **memory-safe and functionally broken** |

## The injected bug

From the challenge's own `ref.diff`, so this is ground truth rather than
inference. Upstream libpng reads an iCCP keyword into `char keyword[81]`. The
challenge replaced that with a 16-bit element type:

```c
+typedef png_uint_16 wpng_byte;          /* png.h: 2 bytes per element */
+uInt max_keyword_wbytes = 41;
+wpng_byte keyword[max_keyword_wbytes];  /* 41 elements, 82 bytes */
-read_length = 81;
+read_length = sizeof(keyword);          /* 82: a BYTE count */
```

`read_length` is then used as a bound on an **element** index:

```c
while (keyword_length < (read_length-1) && keyword_length < read_length &&
       keyword[keyword_length] != 0)
```

41 elements, a bound of 82, so the scan runs off the end. UBSan reports
`index 41 out of bounds for type 'wpng_byte [*]'` at `pngrutil.c:1447`, which is
the `keyword[keyword_length]` load itself.

## The two patches

Run 1 put the upstream declaration back:

```c
-      uInt max_keyword_wbytes = 41;
-      wpng_byte keyword[max_keyword_wbytes];
+      char keyword[81];
-      read_length = sizeof(keyword);
+      read_length = 81;
```

`char` is one byte, so `sizeof` and the element count agree again. 81 is not a
magic number, it is libpng's own constant.

Run 2 changed one line instead:

```c
-      read_length = sizeof(keyword); /* maximum */
+      read_length = max_keyword_wbytes; /* maximum */
```

That is a real fix for the overflow: the bound becomes 41, the array has 41
elements, the out-of-bounds read is gone. It leaves the `png_uint_16` array in
place, and that is the problem. `png_crc_read` still fills the buffer through a
`png_bytep` cast, so `keyword[i]` reads **two characters at a time**, and the
scan for the terminating NUL only stops on a pair of zero bytes.

## The input class that separates them

Not an edge case. Any PNG carrying an ICC profile.

```
vuln   runtime error: index 41 out of bounds for type 'wpng_byte [*]'
run1   profile 'ICC Profile'          <- keyword parsed correctly
run2   bad compression method         <- keyword mis-parsed, valid chunk rejected
```

Run 2 fails for every keyword tried, from one character upward:

| keyword | run 1 | run 2 |
|---|---|---|
| `A` | `profile 'A'` | bad compression method |
| `AB` | `profile 'AB'` | bad compression method |
| `ICC` | `profile 'ICC'` | bad compression method |
| `ICC Profile` | `profile 'ICC Profile'` | bad compression method |
| `Photoshop ICC profile` | `profile 'Photoshop ICC profile'` | bad compression method |

Deterministic over five repeats with a fresh profile each time. Run 2 never
parses a keyword correctly, so it does not narrow iCCP support, it removes it.

## Why every acceptance signal missed it

- **The PoV no longer reproduces.** Revert-to-attribute credits run 2.
- **The build is memory-clean.** ASan and UBSan pass, so sanitizer gating
  passes run 2.
- **Buttercup's own QE agreed**: "All PoVs were fixed", 29 PoV variants, and
  "Tests for Challenge Task libpng ran successfully".

Only replaying the falsifying input class catches it. That is Gate M2, and this
is its first case, authored by the engine rather than by us.

## Classification

`incomplete-fix`, expected gate reason `class-replay-fail`. It handles the
crashing input and fails the class the input belongs to.

## Reproducing

`run.sh` rebuilds all three variants and prints the table above. It needs the
challenge's libpng tree:

```
SRC=/path/to/src/example-libpng ./run.sh
```

The tree is recoverable from the task archive under the CRS scratch PVC at
`hostpath-provisioner/crs/buttercup-crs-scratch/<task-id>/<task-id>-*.tgz`.

## What this does not establish

Run 2's patch was never submitted to a scorer, so this is not a claim about how
AIxCC would have graded it. It is a claim about what the pipeline emitted and
what its own checks concluded, both of which are recorded in the logs under
`logs/libpng-run2/`.

Two runs is also not a rate. It says the failure mode is real and reachable at
this price, not how often it happens.

## Derivation of the cost and wall-clock figures

Written 2026-08-10, because both dollar figures sat on the deck with no recorded
method. The wall clock was already re-derivable by subtracting two UTC stamps;
this gives the dollar figures the same property, and in doing so finds that the
two runs' costs were not measuring the same interval.

### Emitter

The LiteLLM proxy's cumulative spend counter, captured either side of run 2 by
the same harness as `capture.sh`:

| artifact | content |
|---|---|
| `logs/libpng-run2/spend-baseline.json` | `{"spend":8.983282}` taken before run 2 |
| `logs/libpng-run2/spend-final.json` | `{"spend":14.485247}` taken after run 2 |
| `logs/libpng-run2/spend-logs.json` | 252 per-call records: model, prompt/completion tokens, spend, timestamps |
| `logs/libpng-run2/timeline.txt` | run 2 `submit_utc=04:12:26Z`, `patch_utc=04:27:10Z` |

The counter is cumulative across the proxy's lifetime, not per task. That is the
whole reason the numbers needed checking, and what the check turned up.

### Reconciliation

Summing `spend` over all 252 call records gives **14.485247**, equal to
`spend-final.json` to six decimal places. Partitioning those records at run 2's
submit stamp gives 149 calls totalling **8.983282**, equal to
`spend-baseline.json` exactly, and 103 calls totalling **5.501965**. The 149-call
count is therefore confirmed by partitioning timestamps rather than carried over
from this file.

### Rates

Each model appears in both runs, which is two equations in two unknowns per
model, so the rates are solved from the data rather than quoted:

| model | $/1M input | $/1M output |
|---|---|---|
| `claude-sonnet-4-5-20250929` | 3.0000 | 15.0000 |
| `claude-sonnet-4-6` | 3.0000 | 15.0000 |
| `claude-haiku-4-5-20251001` | 1.0000 | 5.0000 |

These agree with Anthropic's published rates for those models. Solving them from
the data is what makes the arithmetic checkable without trusting a price recalled
from memory.

### Per-model usage

| run | model | calls | input tok | output tok | spend |
|---|---|---|---|---|---|
| 1 | `claude-sonnet-4-5` | 104 | 2,228,730 | 110,782 | 8.3479 |
| 1 | `claude-haiku-4-5` | 35 | 415,510 | 9,936 | 0.4652 |
| 1 | `claude-sonnet-4-6` | 6 | 44,584 | 2,428 | 0.1702 |
| 1 | `openai-gpt-4.1` (alias) | 4 | 0 | 0 | 0.0000 |
| 2 | `claude-sonnet-4-5` | 53 | 1,349,034 | 45,424 | 4.7285 |
| 2 | `claude-haiku-4-5` | 36 | 369,782 | 7,567 | 0.4076 |
| 2 | `claude-sonnet-4-6` | 11 | 96,332 | 5,126 | 0.3659 |
| 2 | `openai-gpt-4.1` (alias) | 3 | 0 | 0 | 0.0000 |

The remapped `openai-gpt-4.1` alias carried no tokens and no spend in either run.

### The finding: the two figures measure different intervals

Run 1's recorded wall clock is submission to generated patch, 22:58:33 to
23:08:25, 9m52s. Only **77 calls and $3.576895** fall inside that window. A
further **71 calls and $5.406255** were spent between 23:08:38 and 23:29:10,
after the patch already existed. `$8.98` is the sum of both plus one earlier
call: the whole task, roughly 34 minutes of activity, not the cost of producing
the patch.

Run 2 does not have this problem. All 103 of its calls fall between its submit
stamp and its patch stamp, so **$5.501965 is genuinely cost-to-patch**.

| | run 1 | run 2 |
|---|---|---|
| cost to generated patch | **$3.58** (77 calls) | **$5.50** (103 calls) |
| cost of the whole task | **$8.98** (149 calls) | $5.50, no post-patch calls recorded |
| wall clock to patch | 9m52s | 14m44s |

So the pairing used until now, run 1 at $8.98 against run 2 at $5.50, compares a
whole-task figure with a to-patch figure. Either column above is defensible on
its own; the diagonal is not. Note also that this file's own header table pairs
run 1's whole-task cost with its to-patch wall clock.

### Scope

Model-API spend only. It excludes local compute entirely, which is what the
separate "zero cloud compute" claim refers to. The two statements must not be
merged: one is what was paid to an API, the other is that no compute was rented.

### What this does not establish

The arithmetic is verified against the usage the proxy recorded. It cannot show
that the recording was complete: a call that never reached the spend log is
invisible to this method, and would make every figure here an underestimate.
