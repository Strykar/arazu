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

Everything below the next section is from that wrong-repo review. The section
immediately following is not: it is from an audit of THIS tree.

## Evidence-provenance audit of this tree, 2026-08-31

A second review ran against this repository, scoped to one question: whether a
verdict's evidence provably belongs to the execution and the candidate the
verdict names. The design, the full inventory, the reproducers and the run logs
are working notes and are deliberately not in the repository. What follows is
the part worth keeping: the findings that are live on the path `cmd/gate` and
`cmd/drive` run today.

Five of the eight were established by running something rather than by reading,
and one carried as a finding turned out to be wrong and is recorded as withdrawn.
Two are fixed, in the commits above this one. The rest are open, and P1 is the
one that matters:

    P1  reused dossier attributes another task's evidence   open, has a recipe
    P2  m2 panics on a case with no falsifying class        open, unreachable today
    P3  failed build reported as a success                  FIXED
    P4  sweep dossiers carry no artifacts                   open
    P5  M2's oracle build is not what observes              open
    P6  candidate identity does not name the patch          open
    P7  M1 and M2 pin to different trees                    open
    P8  nothing binds the dossier to its run                open

### P1. A reused dossier directory attributes one task's evidence to another. CONFIRMED BY EXECUTION

Ten seconds to reproduce, with no TPM and no container. Drive two of the real
Buttercup runs under `testdata/crsout/realrun`, carrying different patches, into
the same `-dossier`: the second reports ACCEPT at exit 0 for its own task while
the dossier still names the first task's candidate and its patch hash, with an
identical content root. With `-seal` set, that is what gets signed.

`dossier.Emit` fails when `<dossier>/artifacts` exists; `emitDecision` prints the
verdict BEFORE testing whether the write succeeded; `cmd/drive` reads that stdout
and never consults the exit code (`cmd/drive/main.go:104`). The log records
nothing for run 2, because `emitDecision` exits before `logDecision`.

Two traps for whoever fixes it. `dossier verify` returns `dossier-verified`, so
wiring it in does not catch this: the dossier is honest about the wrong task.
And the trigger is just a reused path, which nothing clears or refuses.

Not fixed: refuse a non-empty dossier, namespace it per task, honour the exit
code, or bind `candidate_id` at the seal are all defensible, and choosing is a
design decision.

### P2. `gate -stage m2` panics on a case with no falsifying class. CONFIRMED BY EXECUTION

`cmd/gate/target.go:201` dereferences `c.FalsifyingClass.Observer`; the guards
above it check `fuzz_tooling_project` and `pov.sanitizer`, neither of which
covers a nil class the schema makes optional.

Not reachable from any shipped case and fails closed when reached: nginx cases
have no `fuzz_tooling_project`, libpng has a class, captured cases are refused
earlier by `reference_patch == ""`, and the panic's empty stdout reaches drive as
`gate-said-nothing`. Hardening, not a live defect.

`classreplay.Stage` already returns `class-not-defined` for this input. The
caller panics before the stage it delegates to can produce it.

### P3. A failed container build was reported to the gate as a successful one. FIXED 2026-08-31

`Challenge.Build` decided success from `./run.sh build`'s exit status. That
status is not the signal: run.sh records the container's real code in
`out/output/<ts>--build/exitcode` and exits 0 regardless.

A real `gate -stage m1` on `nginx-cpv2` against the case's own good candidate
therefore ran both PoVs against a twenty-day-old `pov_harness` and returned
REJECT `revert-attribute-fail`, six seconds end to end. Bounded direction: both
sides measure the same binary, so this errs toward REJECT, never ACCEPT.

Fixed by exception to this audit's no-fix rule, because the shape was not in
question: `Build` now reads the recorded exitcode, which `RunPoV` ten lines below
has always done. Re-running the identical command turned the false REJECT into
`UNDECIDED ... the build failed with exit "1"`, naming the container's own
diagnostic. Five tests, one of them the mirror that stops the guard being
satisfied by refusing every build; catalogue entry
`build-exitcode-not-runsh-status`.

Of 132 historical build directories on the staged nginx checkout, ten recorded a
non-zero or unreadable status. Those runs were graded against whatever was in
`out/`.

### P4. Sweep-stage dossiers carry no artifacts at all. CONFIRMED BY EXECUTION

`cmd/gate/main.go:92` assigns `outs.sources` only in the `m0` branch, after the
switch at line 60 has routed m1, m2 and m3 to `runSweep` and returned. Confirmed
in the same real m1 run as P3: `"artifacts"` absent, `artifacts/` present and
empty.

So every dossier from a stage that builds a tree and runs a PoV verifies as
`dossier-not-self-contained`, the outcome meant for dossiers written before
`pkg/dossier` existed. The only path with artifacts is m0, which is also the only
path the tests cover (`cmd/drive/main_test.go:42`).

### P5. M2's oracle build contributes nothing, and its reset spares build objects. CONFIRMED BY EXECUTION

`ReplayAgainst` spends a container build on `build_fuzzers --sanitizer
<pov.sanitizer>`, then hands the observer only the source tree. Running
`observe.sh` directly with no build at all produced a full observation set in 7.2
seconds without touching `oss-fuzz/build/out/`. So what actually produces an M2
observation is host `clang` with a hardcoded `-fsanitize=address,undefined` and
the case's `reader.c`, none of which appear in the case, the decision or the
dossier, while `resolveClassTarget` refuses an empty `pov.sanitizer` to protect a
build nothing reads.

Separately, `OSSFuzzTarget.reset` runs `git clean -qfd` where `ResetToPin` runs
`-fdx`. `.o` is gitignored, so 15 build objects survive an M2 reset invisibly,
and `observe.sh` archives `./*.o` by glob rather than the list it compiled. No
contamination today, and only because those 15 are exactly the ones it
recompiles. Hazard, not a live defect.

Neither fixed. The first is a design question about what M2's evidence should
record; the second is one flag whose asymmetry with its sibling may be deliberate.


### P6. Candidate identity is derived from the task, not from what was graded

`crsout.write` emits `id: crs-<task>` and `candidate: crs-<task>-candidate`, and
writes the patch to the fixed path `<out>/<task>/candidate.patch`. The `patch_id`
that `pair()` resolved is never written into the case. It survives only in
`cmd/drive`'s stdout evidence line, which is neither in the dossier nor sealed.

Two ways that loses which patch was graded. Capturing one task twice overwrites
the first patch in place. And where a run carries several bundles that each name
a patch and a pov, `pair()` returns the first one, iterating a list
`artifacts()` sorted by filename; the evidence records "paired by the CRS's own
bundle" without saying which bundle won.

The dossier's artifact hash could tell two of a task's patches apart. Nothing
consumes it, which is P8.

### P7. M1 and M2 pin to different things and nothing reconciles them

`Challenge.ResetToPin` runs `git reset --hard` on `source.src_commit`.
`OSSFuzzTarget.reset` runs `git checkout --detach origin/<source.src_ref>`.
`Case.Validate` requires `src_commit` and never checks that the two name the
same tree; `src_ref` is not required at all.

So M1, M2 and M3 can grade one candidate against two different trees, and all
three results land in the same `Decision.Stages` vocabulary with nothing
recording which tree each stage saw. Not observed happening, because the one
case with a class has a `src_ref` whose tip is its `src_commit`. That is the
case file being right, not the code checking.

### P8. Nothing binds the dossier to the run that produced it

`Decision.Artifacts` is written by `dossier.Emit` and read only by
`dossier.Verify`, which rehashes each artifact against the sum recorded in the
same document. That establishes the dossier is internally consistent. It cannot
establish that the file it carries is the file a stage graded.

The two resolutions are independent. `EffectStage` resolves the patch path and
opens it; `cmd/gate` resolves the same expression again to build `sources`; the
sweep stages carry their own `PatchPath` from the caller. No digest crosses
between the read that decided and the read that was hashed, and
`Decision.Validate` never mentions `Artifacts` at all.

`dossier.Verify` also has exactly one caller, `cmd/dossier`. Nothing in
`cmd/drive`, `cmd/gate`, the Makefile or `scripts/` invokes it, so the check that
would catch P4 never runs where dossiers are made. Wiring it in is necessary and
not sufficient: P1 is a dossier that verifies clean and describes the wrong task.

### Withdrawn: run_pov's discarded run.sh error

Listed here because it was carried as a finding and is not one. `RunPoV` ignores
run.sh's exit status when the run produced its own output directory, which looked
like the defect P3 turned out to be, one command along.

It is correct as written. Across 109 real run_pov directories on the staged nginx
checkout, 106 exit 0 whether or not the sanitizer fired, which is the premise the
package is built on. Of the three that did not: two have no libfuzzer `Running:`
line and are already refused by `HarnessRan`, and the third is a firing PoV whose
harness aborted under ASan, where treating a nonzero exit as failure would turn a
correct measurement into an error.

The asymmetry with P3 is real and deliberate. For `build`, nonzero means the
build failed. For `run_pov`, nonzero mostly means the vulnerability fired.

### Smaller ones, recorded so they are not re-derived

Each is real, none is worth its own entry.

- `localTag` returns the first `docker images` line matching the base repository,
  so with two tags of one base the choice follows the runtime's listing order.
  The resolved image reaches no `StageResult` and no `Decision` field, so a
  dossier cannot say which image built the tree.
- `outputSet` discards `filepath.Glob`'s error. Glob only errors on a malformed
  pattern, so this is unreachable with a literal pattern, but on an error the
  before-set is empty and every pre-existing directory counts as new, which is
  the defect `revert-stale-output-read` exists to catch.
- Nothing serialises two gate runs against one challenge checkout. `newestOutput`
  resolves by modification time over a shared `out/output`.
- `gate.Verify` only defaults `StageResult.Stage` when it is empty, so a stage
  that names itself wrong is recorded under that name and `StageFor` and
  `eval.Score` attribute the outcome to the wrong stage.

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

Partly closed since. Counted off the catalogue on 2026-09-01, which now holds
78 mutations: `pkg/corpus` has 23, `pkg/revert` 3 and `pkg/classreplay` 2. So the sentence
above is wrong about three of the four packages and still right about the one
that decides: `pkg/gate` has none.

11 files on the acceptance path carry no entry, `pkg/gate` entire among them,
along with `pkg/sanitizer`, `pkg/crsout`, `pkg/dossier/verify.go`, `pkg/eval` and
every `cmd` on the path. The corpus loader that feeds the bar is evidenced; the
bar is not.

## How to run it properly

Run from inside this repository. The earlier attempt resolved its target from
the shell's working directory rather than the paths it was given, which is how
it ended up in the wrong tree. Check the first finding's path before reading any
further.
