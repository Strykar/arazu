# Audit backlog

A multi-agent review ran on 2026-08-21 and audited the **wrong repository**. It
examined `tcq2026-kavach`, the private research tree, not this one. Every path
in every finding reads `/tcq2026-kavach/`.

This file records what that review found and how much of it applies here, so the
work is not lost and is not mistaken for a completed audit of this repo.

## Status: NOT AUDITED

Nothing below has been verified against this tree beyond a line-presence check.
The audit's claims about behaviour, reachability and consequence were derived
against a different codebase. Treat every entry as a **lead to re-derive**, not
a finding to fix.

The one exception is marked CONFIRMED HERE.

## Why the trees differ, and why the findings still mostly apply

`tcq2026-kavach` has no `pkg/sanitizer`, no `pkg/crsout`, no `cmd/drive`, and
does not wire M2. `pkg/corpus/case.go` differs by 111 lines and
`pkg/classreplay/classreplay.go` by 112.

But that divergence is concentrated in what this repo ADDED. The surface the
audit examined -- `pkg/revert`, `pkg/corpus`, `pkg/gate`, `pkg/eval` -- is
near-identical, so 28 of 30 findings have their exact quoted line present here
at an offset of a few lines.

The audit's own scope notes said "there is no pkg/sanitizer" and "classreplay is
not wired from any cmd/". Both are false for this repo and were the tell that it
was reading a different tree.

## Priority, if the audit is re-run

These three are on the M1 path `cmd/gate` runs today. Everything else is latent,
cosmetic, or on M2/M4.

### 1. Stale output directory read as this run's result

`pkg/revert/challenge.go:131`, `dir, err := c.newestOutput("run_pov")`

`run.sh`'s exit status is discarded and the result is located by globbing for the
newest `*--run_pov` directory. A run that produced no output reads a PREVIOUS
run's stderr. Fails both ways: a patched run that dies reads the unpatched run's
report and REJECTs an untested patch; the reverse reads a clean directory and
answers "the vulnerability reproduces" for a build that never ran.

The comment above it states the intended guard ("only worth reporting if no
output directory appears below") but the code tests that AN output directory
exists, not that a NEW one did. `ResetToPin` never cleans `out/output`, so they
accumulate and the escape hatch can never fire.

### 2. before.Site computed, never read — CONFIRMED HERE

`pkg/revert/revert.go:108`

Verified in this tree: the only site condition is `switch after.Site` at line
156. `RunPoV` computes `before.Site` and puts it in the evidence, so the dossier
carries "crash site versus the declared one: different" while the verdict
ignores it. The crash-site check exists on the patched side of the boundary and
not on the unpatched side, which is the baseline the whole attribution rests on.

### 3. SanitizerFired and HarnessRan are un-normalised substring tests

`pkg/revert/challenge.go:153,154`

`strings.Contains` against raw signal-file content. The audit reports that this
project's own captured UBSan output interleaves ANSI escapes inside the declared
sanitizer string, so a colorized run reads as "no sanitizer fired". The sibling
comparison path in `pkg/classreplay/ossfuzz.go` strips ANSI first; this one does
not. `HarnessRan` keys on `"Running: "`, which oss-fuzz wrapper log lines also
contain.

Re-derive against this tree's captured logs before acting: the claim rests on
specific bytes in a specific file.

## The rest, by file

Line numbers are this repo's, from the transfer check. Nothing here is verified.

**pkg/revert**
- `revert.go:137` — a patch that applies but breaks the build returns a plumbing
  error, while patch-does-not-apply is a named REJECT. Same class of fact,
  opposite handling.
- `revert.go:~158` — the SiteDiffer branch asserts "the original is stopped" from
  the declared site's ABSENCE, which is only sound on a recovering build.
  Nothing checks `-fsanitize-recover` was in force.
- `challenge.go:64` — `DOCKER_EXTRA_ARGS` is one space-joined string that
  replaces any inherited value, and `run.sh` word-splits it, so `ExtraCFlags`
  can hold exactly one flag.
- `challenge.go:106` — strict `git apply` only; `corpus/grade-patch.sh` keeps a
  `--recount` fallback deliberately, and the port dropped it. The audit reports
  10 recorded runs with `apply_mode: recount`.

**pkg/corpus**
- `crashsite.go:136` — nothing requires a declared crash site to be in the
  target's own source, and four nginx cases declare one inside the ASan runtime,
  which every intercepted report contains. SiteSame becomes a tautology for
  them.
- `crashsite.go:31` — `empty()` uses `&&`, so a half-populated CrashSite reaches
  `SiteDiffer`, the fail-unsafe verdict. Not live: `ParseDeclaredSite` sets both
  fields or neither.
- `case.go:437` — the case-level `root` and `pov.input_root` validations sit
  inside the per-candidate loop, so a case with no candidates is never checked.
- `case.go:~362` — `pov.crash_location` is not in Validate's required set. Absent
  or differently-ordered, MatchSite is pinned to undetermined and M1's
  revert-attribute-fail becomes unreachable for that case.
- `case.go:~413` — `expected_gate_reason` is never checked against the Reason
  vocabulary, so a typo silently removes a candidate from every stage's matrix.
- `case.go:483` — `Candidate.PatchPath` is dead repo-wide and resolves against
  the wrong tree for a `root: repo` case. One tab-completion from the live
  `Case.CandidatePatchPath`.
- `stages.go:42` — `new-sanitizer-finding` is attributed to M3, but `revert.Stage`
  (M1) is the only thing that emits it, so a correct catch scores out-of-scope.
  `new-test-failure` (14 of the corpus's candidates) maps to M3 as well, though
  its own doc separates a behavioural finding from a sanitizer one.

**pkg/gate**
- `effect.go:51` — the header exclusion requires a trailing space, so
  `git format-patch`'s bare `---` separator and `-- ` signature count as removed
  lines. A patch with zero hunks scores 2 and passes the stage built to catch
  no-op patches.
- `effect.go:65` — evidence records the UNRESOLVED patch path, so two different
  files produce byte-identical evidence.
- `gate.go:72` — a stage that cannot run discards every StageResult already
  collected, so an expensive stage's evidence is destroyed rather than emitted
  as a partial dossier.
- `decision.go:178` — Validate enforces the REJECT-side reason-provenance rule
  and its ERROR-side mirror is untested; it also accepts `[]string{""}` for the
  two sections it makes mandatory.

**pkg/classreplay** (M2; wired here, unwired there, so re-derive with care)
- `classreplay.go:124` — the oracle mode is an empty-string sentinel on a
  caller-set field. A caller that forgets to wire `ReferencePatch` silently
  downgrades to the pre-patch oracle.
- `classreplay.go:~158` — under the pre-patch oracle, only a DIVERGENCE can make
  the stage non-passing, so members the candidate still crashes on identically
  never enter the comparison. The mirror rule, "crashed before and does NOT
  differ after is the fix failing", does not exist.
- `classreplay.go:170` — "did the unpatched build crash here" is a substring test
  against `expected_sanitizer`, which is always true for an empty string and
  false for any member whose crash text differs in detail. libpng's declared
  string names index 41 while the class varies 1..79.
- `classreplay.go:133` — `CandidatePatch` is never validated, and `""` is the
  documented sentinel for "unpatched tree", so an unset candidate replays the
  unpatched build as the candidate.
- `classreplay.go:115` — nothing checks the reference and the candidate are
  different patches. The libpng case's only `good` candidate points at the same
  file as `reference_patch`.
- `ossfuzz.go:187,189` — `reset` runs `checkout --detach` before `reset --hard`,
  so the repair is gated behind the command that fails on a dirty tree; it cleans
  without `-x` and never verifies, unlike `Challenge.ResetToPin`, whose interface
  doc mandates the verification.
- `ossfuzz.go:240` — `sort.SliceStable` with an always-false comparator is a
  no-op that reads as if normalisation orders the output.

**cmd, pkg/eval**
- `cmd/corpus/main.go:31` — `-dir` defaults to `corpus/cases/nginx`, so the
  shipped invocation validates 15 cases, never loads the libpng case, and
  reports ACCEPT. `LoadDir` globs one level while the corpus is two.
- `pkg/eval/eval.go:100` — `Score` tests `good` first and never reads `Expected`
  for a good-labelled candidate, so the one `label: good` fixture with an
  expected reason is scored as a false rejection.

## Fixed here already, listed so nobody re-reports them

- `cmd/gate` stage validation. This repo has `case "m1","m2","m3"` / `case "m0"` /
  `default: exit 2`. An unknown stage refuses instead of silently running M0.
- `ossfuzz.go`'s per-member `b, _ := run.CombinedOutput()`. That loop is gone;
  the observer replaced it and its error IS checked.

## Process gap the audit named, worth its own item

`testdata/mutations.json` carries no mutation for `pkg/gate`, `pkg/corpus`,
`pkg/revert` or `pkg/classreplay`. So `make mutation-test` passing says nothing
about whether the gate's own tests would catch a broken gate, and several
findings above are exactly the mutations that catalogue would have surfaced.

## How to run it properly

Run from inside this repository. The earlier attempt resolved its target from
the shell's working directory rather than the paths it was given, which is how
it ended up in the wrong tree. Check the first finding's path before reading any
further.
