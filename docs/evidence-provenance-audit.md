# Evidence provenance audit: design

Status: **steps 0, 1, 2, 3 and 4 executed 2026-08-31.** F15, F12 and a finding this
document did not predict, F16, are CONFIRMED BY EXECUTION. F11 is fixed under
TDD and evidenced by a catalogue entry. Steps 4 to 8 not started.

F16 is the reviewer's scope objection landing: it is a REJECT-direction defect,
found by running an ACCEPT-direction plan, and it is the second most serious
finding here. Two fixes are authorised in advance, F11 and F8; see Out of scope for
why those two and no others.
Tree: `ec2870b7720796b69e6b0b655a875a4f4baa832e` ("close the two TPM exemptions with a lying tpm2, not a simulator").
Written 2026-08-30, re-pinned 2026-08-31.

**Re-pin notice.** The first draft was written against
`cbd90f39d28a99bd16b80ef263b0a92246fc0b84` and four commits landed on top of it
while this document was in review, three of which extend the mutation catalogue.
Everything was re-derived against the new HEAD on 2026-08-31. All 27 line anchors
still resolve to the lines claimed, and `git diff --stat cbd90f3..HEAD -- pkg cmd
corpus` touches only `cmd/mutation-test/main.go`, which this document does not
anchor, so every finding survives unchanged. The Coverage context section did
not survive and has been rewritten; the figures it carried are void. Anyone
holding a copy dated before this notice should discard that section's numbers.

This is an adversarial review of Arazu's acceptance path, scoped to one property:
whether a verdict's evidence provably belongs to the execution and the candidate
the verdict names. It is a plan and a finding inventory, not a set of fixes. Read
the finding table as leads with their evidential status marked, and the plan as
the work that converts each lead into a test that either fails on this tree or is
withdrawn.

## The two questions

1. Can any stale, partial or failed execution cause old evidence to be attributed
   to a new candidate?
2. Can the evidence dossier contain facts the verdict logic does not consume?

Neither is hypothetical here. Question 2 names a defect class this repository has
already hit twice and fixed twice:

- `PoV.Signal` was a schema field whose doc comment claimed it was read, and
  nothing read it. `challenge.go` hardcoded `stderr.log`.
- `before.Site` was computed by `RunPoV`, written into the evidence, and never
  branched on. The dossier carried "crash site versus the declared one:
  different" while the verdict ignored it. Recorded in `docs/audit-backlog.md`
  as the one finding marked CONFIRMED HERE.

So the correct framing is a class hunt for a class with a known recurrence rate,
not a spot check on individual checks.

## Method

Walk the ACCEPT path backwards, and at every edge ask the same question: how do we
know this observation belongs to this exact execution of this exact candidate?

    ACCEPT
      -> Decision.Validate()
      -> stage results
      -> observations
      -> process execution
      -> filesystem selection
      -> build identity
      -> candidate identity

Three orderings were considered. Trace-ordered was chosen because it is the only
one that guarantees every edge is visited. Question-ordered reads better as a
report but lets an edge go unvisited when it serves both questions, so it is used
to report and not to work. Mutation-first was rejected as the spine: mutation
testing finds checks that exist and are untested, and most of what follows is a
check that was never written, so there is no line to mutate. It is the closer
instead, at step 7.

## Evidential status

Every finding carries one of three marks. The distinction is load-bearing and a
reviewer should hold the document to it.

- **CONFIRMED** means established by reading control flow that admits no other
  reading, with the anchor given. It does not mean demonstrated at runtime.
- **PREDICTED** means derived from reading and not yet executed. The command that
  settles it is given. A prediction stated as a verdict is the failure mode this
  mark exists to prevent, so no disposition language is used until the command
  has run.
- **OPEN** means the reading raises the question and does not answer it.

A finding does not graduate from PREDICTED by being read again. It graduates by
being run.

The numbering runs F1 to F15 with no F9. That gap is deliberate. F9 was an
observation that `Decision.Validate` counts evidence entries without reading them,
and it was dropped in drafting once it became clear it has no testable content:
requiring `Validate` to adjudicate prose is not a property worth asserting, and
what remains of the concern is covered by F13 and F10. The numbers were left
stable so they keep matching the review thread.

One further distinction governs which findings are worth a test during the audit,
as opposed to during a later fix pass. A test is evidence when a sibling path in
this same tree already satisfies the property, so the failing test encodes an
inconsistency. It is a feature request when no path anywhere satisfies it, because
then the test fails for the trivial reason that the thing does not exist, and the
grep that found the absence already established everything the test would.

F12 has a witness: m0 produces artifacts through the same emitter, so a sweep
dossier that does not is an inconsistency. F13, F14, F1, F2 and F3 have no witness
anywhere in the tree. Their tests belong to a fix pass that has not been approved,
and this audit records them as findings only.

## Findings

### Edge: dossier -> ACCEPT

**F12. Every dossier from a stage that executes code carries zero artifacts.
CONFIRMED BY EXECUTION 2026-08-31.**

Demonstrated with a real container sweep, `gate -stage m1` on `nginx-cpv2`
against the staged challenge checkout with `-bundle` set:

    decision.json  "artifacts": absent
    artifacts/     present and EMPTY

Recorded as P4 in `docs/audit-backlog.md`. The reading below is what predicted
it.

`cmd/gate/main.go:92` assigns `outs.sources`. The switch at `cmd/gate/main.go:60`
routes `m1`, `m2` and `m3` to `runSweep` and returns before line 92 is reached.
`runSweep` never assigns `sources`, so `dossier.Emit` is called with a nil map,
`d.Artifacts` stays nil, and `dossier.Verify` classifies the result
`dossier-not-self-contained`. That outcome exists to describe dossiers written
before `pkg/dossier` existed, so a live sweep verdict is graded as pre-contract
history.

The only dossier path with test coverage is m0, including `cmd/drive`'s
end-to-end test, which passes `-stage m0` at `cmd/drive/main_test.go:42`. The
stages that run containers, build trees and execute PoVs are exactly the stages
whose dossiers carry nothing.

Demonstrated by: `bin/gate -stage m1 -case <case> -candidate <id> -root <checkout>
-bundle <dir>` then `bin/dossier verify <dir>`. Expected today: outcome
`dossier-not-self-contained`, exit 3.

**F14. The dossier verifier is never run by the pipeline that produces dossiers.
CONFIRMED.**

`dossier.Verify` has exactly one caller, `cmd/dossier/main.go:43`. Nothing in
`cmd/drive`, `cmd/gate`, the Makefile, `scripts/` or `ci/` invokes the binary or
the package. `grep -rn dossier ci/ scripts/ Makefile` returns nothing. So the
check that would catch F12 exists, is correct, and never runs where it would
matter.

**F15. A reused dossier directory makes drive report one task's verdict backed by
another task's evidence. CONFIRMED BY EXECUTION 2026-08-31.**

Reproduce with `scripts/repro-dossier-reuse.sh`, about ten seconds, no TPM,
no container, no network. Transcript in `step1-f15-transcript.log`. Two real
Buttercup runs with different patches, one dossier directory:

    run 1: task A, fresh dossier   -> ACCEPT, exit 0, dossier names crs-A-candidate
    run 2: task B, SAME dossier    -> ACCEPT, exit 0, task_id a790c3ea (B)
           dossier still names crs-A-candidate
           dossier patch sha 0d13bacc (A's patch), task B's patch is 3f0522e2
           content root identical to run 1's
           audit log holds ONE entry, run 1's GATE_ACCEPT
           dossier verify -> dossier-verified, all seven checks green

So drive announced an ACCEPT for task B at exit 0, carrying a content root and a
seal-ready dossier that describe task A's candidate, and its own coverage check
("decision.json is under the measured root") passed, because a decision.json
genuinely was under the root. It was the wrong one.

Three consequences worth separating:

- **The audit log is silent.** Run 2 left no entry, because `emitDecision` exits
  before `logDecision` when the dossier write fails. The chain verifies clean and
  records one acceptance where an operator saw two.
- **The dossier verifier does not help.** It returns `dossier-verified` because
  the dossier is an honest document about task A. Nothing at the drive or seal
  layer compares the dossier's `candidate_id` against the task being driven, so
  wiring the verifier in, which is F14's fix, would not have caught this.
- **The trigger is ordinary.** Not a corrupted tree or a crash. A reused
  `-dossier` path, which nothing in `cmd/drive`, `cmd/gate` or `scripts/` clears
  or refuses.

The original PREDICTED text and its three sub-claims follow, kept because the
sub-claims are the mechanism.**

This is the flagship for question 1 and the most direct instance of it.

`undecided()` in `cmd/gate/main.go` prints `{"verdict": "UNDECIDED", ...}` and
exits 2 without writing a dossier. `cmd/drive/main.go:108` reads that as
`d.Decision = "UNDECIDED"`, which is non-empty, so the `gate-said-nothing` guard
below it does not fire. Control then reaches `contentstore.MeasureBundle` at
`cmd/drive/main.go:121` and the seal block at `cmd/drive/main.go:139`.

Neither `cmd/drive` nor `cmd/gate` clears the `-dossier` directory, and nothing
in `scripts/` does either. The prediction is that a run whose stage could not
execute, pointed at a dossier directory holding a previous run's `decision.json`,
produces a fresh signature over that previous verdict and a fresh SIGNED entry in
the audit log, then exits 2.

The reasons a sweep stage reaches `undecided()` are ordinary: a build failure, a
harness that did not execute, a reset failure, an unresolvable target. Those are
the everyday operating conditions of a gate that fails closed.

Three sub-claims were put to the tree on 2026-08-30 in response to external
review, and all three are CONFIRMED by reading:

- **drive never consults the gate's exit status.** `code` is bound at
  `cmd/drive/main.go:104` and read only as evidence text inside the
  `gate-said-nothing` branch at `cmd/drive/main.go:115`. It is never compared to
  zero.
- **the seal covers the on-disk bytes, not the in-memory decision.** `seal-tool
  sign` is passed `-artifact <dossier>/decision.json`, and `root` comes from
  `MeasureBundle(*dossier)`. The `d` that drive holds never reaches the signer.
- **a failed `Emit` still prints a verdict.** `emitDecision` at
  `cmd/gate/main.go:126` calls `writeDecision`, then `fmt.Println`s the decision
  **unconditionally**, and only afterwards tests `err != nil` and exits 2.

An earlier draft of this document claimed a narrowing asymmetry: that
`dossier.Emit` renames its staging `artifacts` directory into place, that
`rename(2)` onto a non-empty directory fails with ENOTEMPTY, and that a second
successful run into a dirty dossier therefore fails closed. **That claim is
withdrawn.** The rename does fail, but the failure is not closed at the drive
level, because of the third sub-claim above. It produces a strictly worse variant
than the one it was offered as a mitigation for:

| path | drive exit | drive reports | seal covers |
|---|---|---|---|
| gate reaches `undecided()` | 2, visible | UNDECIDED | the previous run's verdict |
| gate's `Emit` fails ENOTEMPTY | 0 | ACCEPT | the previous run's verdict |

On the second row the gate prints a fully formed `"verdict": "ACCEPT"` before
exiting 2, drive reads that from stdout, discards the exit code, measures the
stale directory, signs it, logs SIGNED, and exits 0. The verdict drive reports is
this run's; the dossier that was sealed is the previous run's.

Settled by: populate a dossier directory from an m0 run, then run `drive` again
against the same directory, once with a case that forces the gate to
`undecided()` and once with a case that reaches `Emit` on a non-empty
`artifacts/`. Inspect `decision.sig`, the log, and drive's exit code in both.

### Edge: Decision.Validate -> dossier

**F13. Nothing binds the hashed artifact to the bytes a stage read. CONFIRMED.**

This is question 1 stated at the level the whole system rests on.

`dossier.Emit` copies each source file, hashes the stream it wrote, and records
the sum in `Decision.Artifacts`. `dossier.Verify` at `pkg/dossier/verify.go:109`
rehashes each artifact and compares it to the sum recorded in the same document.
That establishes the dossier is internally consistent. It cannot establish that
the file it carries is the file the stage graded.

The two resolutions are independent. `EffectStage` resolves the patch at
`pkg/gate/effect.go:30` and opens it. `cmd/gate/main.go:92` resolves the same
expression again to build `sources`. `revert.Stage`, `sanitizer.Stage` and
`classreplay.Stage` each carry their own `PatchPath` field, resolved a third time
by the caller in `cmd/gate/sweep.go`. No digest crosses between the read that
decided and the read that was hashed.

`Decision.Validate` at `pkg/gate/decision.go:119` never mentions `Artifacts`. So
the artifact list is a fact the dossier carries and the verdict logic does not
consume, which is question 2, and the missing binding is question 1. The same
gap answers both.

### Edge: stage results -> Decision.Validate

**F10. A stage that names itself wrong is recorded under that name. CONFIRMED.**

`gate.Verify` at `pkg/gate/gate.go:60` sets `res.Stage = s.Name()` only when the
stage returned an empty string. A stage that fills the field itself is trusted.
`corpus.StageFor` and `eval.Score` then attribute the outcome to whichever stage
the result claims to be, so a mislabelled result is scored against the wrong
stage's confusion matrix.

**F11. Two of M2's own reasons mapped to no stage. CONFIRMED, then FIXED
2026-08-31.**

`ReasonClassTruncated` and `ReasonClassObserverMissing` joined the M2 case in
`StageFor`. The test parses the package's own `Reason*` constants rather than
repeating them, so a future reason that falls through is caught too. Catalogue
entry `stagefor-class-reasons`.

`corpus.StageFor` at `pkg/corpus/stages.go:24` has no case for
`ReasonClassTruncated` or `ReasonClassObserverMissing`. Both are emitted by
`classreplay.Stage`. Both fall through to `StageUnassigned`, which
`eval.Matrix.Unassigned` documents as "the key expects a reason no stage claims",
reported as a corpus defect. So a correct M2 refusal scores as a defect in the
answer key.

Cheapest finding in the set, and the one most likely to be a plain oversight
rather than a design gap.

### Edge: process execution -> observations

**F7. M2's declared build is not read by the thing that produces the observation.
CONFIRMED in part, OPEN in part.**

CONFIRMED: `OSSFuzzTarget.ReplayAgainst` runs
`python3 infra/helper.py build_fuzzers --sanitizer <pov.sanitizer> <project>
<source>` at `pkg/classreplay/ossfuzz.go:118`, then runs the observer at
`pkg/classreplay/ossfuzz.go:127` with the source tree and the members directory
as its only arguments. The observer for the one case that has one,
`corpus/falsifying-class/libpng-iccp/observe.sh`, copies the source tree
(line 26) and rebuilds it with host `clang` (line 22, `CC="${CC:-clang}"`) under
`-fsanitize=address,undefined` (lines 44 and 48) against its own `reader.c`. It
does not read the oss-fuzz build output.

So the toolchain, the sanitizer flags and the driver binary that produce the
observation the M2 verdict consumes appear in no case field, no `Decision`, and
no dossier. Meanwhile `resolveClassTarget` in `cmd/gate/target.go` refuses a case
with an empty `pov.sanitizer` on the grounds that "a class replay under a
different sanitizer compares outputs the case never described", and passes that
value to a build whose output the observer does not open.

CLOSED BY EXECUTION 2026-08-31. Running `observe.sh` directly against the staged
libpng checkout with no `build_fuzzers` run produced a complete observation set
for every member in 7.2 seconds, never touching `oss-fuzz/build/out/libpng/`. The
build contributes nothing to the observation.

The residual the OPEN half was about turned out to be real but not live, and is
recorded as P5 in `docs/audit-backlog.md`: `OSSFuzzTarget.reset` runs `git clean
-qfd` without `-x` while its sibling `ResetToPin` uses `-fdx`, `.o` is gitignored,
and `observe.sh` archives `./*.o` by glob rather than the explicit list it
compiled. The 15 stale objects in the tree are exactly the 15 it recompiles, so
none survives into the archive. The protection is coincidence, not design.

Settled by: run `observe.sh <staged libpng checkout> <members dir>` directly,
with no oss-fuzz build performed, and compare its output to the same invocation
after a `build_fuzzers` run. Identical output establishes the build is not a
contributor. This costs one host compile and no container.

**F8. A libpng constant decided the truncation guard for every case. CONFIRMED,
then FIXED 2026-08-31.**

`FalsifyingClass` gained a `size` field, `Generate` reads it, and a class that
declares none is refused rather than given one. The one case with a class
declares `size: 79`, the number that used to live in the target. `Case.Validate`
refuses a class without it, so the failure lands at load with a case path rather
than mid-replay.

Design note, since the reviewer's mechanical-fix argument rested on the shape not
being in question: `Generate`'s doc says it returns "the size the class is
declared to have", and declarations live in the case, so the size moved to the
case rather than to a new generator protocol. The doc's other sentence, "only the
generator knows how big the class is", is satisfied by the case author reading
the generator.

`pkg/classreplay/ossfuzz.go:68` is `const declared = 79`, inside the generic
`OSSFuzzTarget`, with the comment "the PNG keyword length limit". `declared` is
what `classreplay.Stage` compares `len(members)` against to decide whether
agreement covers the class or is a truncated subset. A second case using this
target has its class size measured against libpng's.

The guard fails safe for a smaller class (it would report truncation that did not
happen) and unsafe for a larger one (it would accept a subset as the whole class).
The direction depends on the case, which is the property a constant here cannot
have.

### Edge: build identity -> process execution

**F16. A failed container build was reported to the gate as a successful one.
CONFIRMED BY EXECUTION, then FIXED, 2026-08-31. Found while demonstrating F12,
not predicted by this document.**

The most serious finding in this audit after F15, and the one that vindicates the
external reviewer's scope objection: it is a REJECT-direction defect, and this
document walked only ACCEPT.

`Challenge.Build` at `pkg/revert/challenge.go:112` decides success from
`./run.sh build`'s exit status. Reproduced directly:

    run.sh build exited: 0
    its own out/output/<ts>--build/exitcode: 1

In the real m1 run above, against the case's own reference-quality candidate
`cpv2-aixcc-good`: both builds failed, both reported success, both PoV runs
executed a `pov_harness` dated 2026-08-11 and twenty days stale, and the stage
returned REJECT `revert-attribute-fail` against the good patch. Six seconds end
to end, with two nginx rebuilds supposedly inside it.

Bounded direction, stated precisely: a no-op build makes both runs use the same
binary, so they cannot differ in the accepting direction. This produces false
REJECTs and misattribution, never a false ACCEPT. The safety half of "degrade
yield, never safety" holds. The yield half does not, and a REJECT is scored.

The trigger in that run was environmental, a container that could not sudo. The
detection gap is unconditional.

The correct pattern is ten lines away in the same file and is used for the other
container operation. `RunPoV` refuses run.sh's exit status and reads the verdict
from a file in the output directory this invocation created;
`outputSet`/`newestOutput` are already parameterised by kind. `Build` calls
neither. The `Stage` doc in `pkg/gate/gate.go` states the requirement it does not
meet: without both the unpatched and patched form of a build failure, "a patch
that breaks the build is credited with fixing the bug."

Fixed by exception to the no-fix rule, on the grounds the reviewer set for F11
and F8: the shape was not in question, because the correct pattern was already in
the same file. Verified by re-running the identical command in the identical
environment, where the verdict flipped from `REJECT revert-attribute-fail` at
exit 1 to `UNDECIDED ... the build failed with exit "1"` at exit 2. Full write-up
as P3 in `docs/audit-backlog.md`.

### Edge: filesystem selection -> process execution

**F5. A failed `run.sh` is read as a successful measurement. CONFIRMED.**

`pkg/revert/challenge.go:130` captures `runErr` from `./run.sh run_pov`. If
`newestOutput` then finds a directory created by this invocation, `runErr` is
never consulted again. A `run.sh` that created its output directory and then
failed produces a `PoVRun` read out of whatever partial content that directory
holds.

The existing guard is about directory identity, not about whether the run
succeeded, and those are different questions. The recent fix (commit `079540a9`,
"read the pov verdict from this run's output, not a previous run's") closed the
first and left the second.

**F4. The staleness guard depends on a discarded error. CONFIRMED.**

`pkg/revert/challenge.go:178` is `entries, _ := filepath.Glob(...)` inside
`outputSet`. On a Glob error the `before` set is empty, so every pre-existing
`*--run_pov` directory is classified as new, and `newestOutput` returns the newest
stale one. That is the exact defect `revert-stale-output-read` was written to
catch, reintroduced one level up, in the function whose job is to prevent it.

`filepath.Glob` returns an error only on a malformed pattern, so the reachability
of this is low and the finding is a hardening one rather than a live bug. It is
recorded at that strength deliberately.

**F6. Two gate runs against one checkout share `out/output`. PREDICTED.**

`newestOutput` resolves by modification time across a directory the challenge
checkout owns. Nothing serialises two gate processes against the same `-root`.
This may end as documented scope rather than as a test.

### Edge: build identity

**F2. M1 and M2 pin to different things and nothing reconciles them. CONFIRMED.**

`revert.Challenge.ResetToPin` runs `git reset --hard c.Pin` at
`pkg/revert/challenge.go:83`, where `Pin` is `Source.SrcCommit`.
`OSSFuzzTarget.reset` runs `git checkout -q --detach origin/<t.Ref>` at
`pkg/classreplay/ossfuzz.go:156`, where `Ref` is `Source.SrcRef`.

`Case.Validate` requires `source.src_commit` (`pkg/corpus/case.go:333`) and does
not require `src_ref` at all, nor check that the two name the same tree. So M1,
M2 and M3 can grade one candidate against two different trees, and all three
results land in the same `Decision.Stages` vocabulary with nothing recording
which tree each saw.

**F3. The container image is chosen by list order and not recorded. PREDICTED.**

`localTag` at `cmd/gate/target.go:142` returns the first line of
`docker images --format {{.Repository}}:{{.Tag}}` whose repository matches the
base. With two tags of one base present, the choice follows the runtime's listing
order. The resolved image reaches `revert.Challenge.Image` and appears in no
`StageResult.Evidence` and no `Decision` field, so the dossier cannot say which
image produced the build.

Settled by: tag one base image twice on this host and observe whether successive
runs resolve the same tag.

### Edge: candidate identity

**F1. Candidate identity is derived from the task, not from the patch.
CONFIRMED.**

`crsout.write` at `pkg/crsout/crsout.go:233` emits `id: crs-<taskID>` and
`candidates: - id: crs-<taskID>-candidate`, writing the patch to the fixed path
`<outDir>/<taskID>/candidate.patch`. The `patch_id` that `pair()` resolved from
the CRS bundle is not written into the case. It survives only in
`crsout.Result.PatchID`, which `cmd/drive/main.go:95` folds into a stdout evidence
string. That string is not in the dossier and is not sealed.

So two different patches from one task produce byte-identical case ids, candidate
ids and on-disk paths, and no sealed artifact records which of them was graded.
The dossier's artifact hash could distinguish them, and per F13 nothing consumes
it.

The two findings compose: identity is not derived from content, and the one
content-derived fact recorded is not consumed. That is the answer to "how do we
know this observation belongs to this exact candidate", and today it is that we
do not.

Note what does **not** cause this, since an external review proposed it and the
tree refutes it. More than one patch under a task does not overwrite anything:
`pair()` returns exactly one patch per capture, so `write()` produces one
`candidate.patch`. Overwriting requires two captures of the same task.

There is a sharper variant in the same function, which needs no re-run.
`pair()` at `pkg/crsout/crsout.go:199` iterates `bundles` and returns the first
one carrying both a patch id and a pov id. `artifacts()` sorts that list by
filename. So with two bundles naming different patches, which candidate is graded
is decided by bundle filename sort order, and the evidence string records only
"paired by the CRS's own bundle" without naming which bundle won.

## Coverage context

Read off `testdata/mutations.json` at `c539afd`, from a run rather than recalled:

    67 mutations total, 0 uncaught, 3 subsumed, 0 untestable, 0 did not build
    41 on the envelope       (fido 15, contentstore 10, manifest 8, auditlog 4, ingress-verify 4)
    21 on the corpus loader  (case.go 14, crashsite.go 7)
     4 on the evidence layer (revert 2, classreplay 1, dossier/emit 1)
     1 on hostcap

An earlier draft of this section reported 46 total and 89% on the envelope. Those
figures were measured at `cbd90f3` and are void; see the re-pin notice above.
External review challenged the 89% as an artefact of the envelope having clean
boolean checks to mutate. At the correct commit the envelope share is 61%, so the
challenge was to a number that no longer exists and the rewritten claim below is
narrower.

Thirteen files on the acceptance path carry no catalogue entry at all:

    pkg/gate/decision.go      pkg/gate/gate.go        pkg/gate/effect.go
    pkg/sanitizer/sanitizer.go
    pkg/corpus/stages.go
    pkg/crsout/crsout.go      pkg/dossier/verify.go   pkg/eval/eval.go
    pkg/classreplay/ossfuzz.go
    cmd/gate/main.go          cmd/gate/sweep.go       cmd/gate/target.go
    cmd/drive/main.go

`pkg/corpus/case.go` left that list on 2026-08-31 with 14 entries, from the commit
whose subject is "mutate the corpus, which is the oracle every verdict is graded
against".

By the standard `docs/mutation-testing.md` sets, a check with no mutation behind
it is unevidenced. The sharper form of the claim, at the correct commit, is a
comparison rather than a percentage: the corpus loader's schema validation now
carries 14 mutations and the acceptance bar it feeds, `pkg/gate/decision.go`,
still carries none. The oracle is evidenced and the verdict is not.

This is a statement about where the mutation effort went, not a claim that the
untested code is wrong. Several of these files have strong conventional test
coverage: `pkg/revert` has 15 tests, `pkg/classreplay` 13, `pkg/gate` 13. What
they do not have is the demonstration that those tests fail when the check they
name is broken.

## Plan

Baseline to establish first, and to record rather than assume. This command is
green at this commit:

    go test ./pkg/gate/... ./pkg/corpus/... ./pkg/revert/... \
            ./pkg/classreplay/... ./pkg/dossier/... ./pkg/crsout/... ./pkg/eval/...

Every test written below must **fail on this tree**. A test that passes on first
write is not evidence of the property it names, and gets withdrawn or rewritten
rather than kept.

| Step | Work | Verify |
|---|---|---|
| 0 | Record the baseline: full `make test`, and `make mutation-test` totals read off a run | Two logs, kept local under notes/ |
| 1 | F15 first: it is the flagship, and m0 needs no container. Pre-populate `-dossier` from run 1, force run 2's gate to `undecided()`, assert no new seal and no SIGNED entry | New `cmd/drive` test fails, or the prediction is withdrawn in writing in this document |
| 2 | F12 at the `runSweep` wiring seam: a sweep stage with `-bundle` must produce artifacts | One failing test in `cmd/gate`. F13 and F14 have no witness and need seams, so they are written findings, not tests |
| 3 | F11: table test that every `Reason*` constant maps to a stage, then fix the switch | Test fails, then passes. F10 has no witness and moves to the backlog |
| 4 | The `observe.sh` probe that closes F7's OPEN half. F8: failing test that `Generate` derives `declared` from its `FalsifyingClass` argument, which the interface already promises and the implementation ignores, then fix it | One probe result; test fails, then passes. F7's CONFIRMED half is a written finding, since recording the toolchain has no witness |
| 5 | F5 (`runErr` discarded) as a failing test in `pkg/revert` | F4 is self-declared low-reachability and needs a seam, so it is a backlog line. F6 is a backlog line |
| 6 | F1, F2, F7-confirmed, F13 and F14 as written findings. F3, F4, F6 and F10 as backlog lines | No tests: no witness path exists for any of them |
| 7 | Catalogue entries for the checks in `pkg/gate/decision.go` and `pkg/gate/gate.go` that actually gate ACCEPT, then `make mutation-test` | An escape list bounded to the acceptance bar. Deliberately not the open-ended sweep an earlier draft proposed, which was a second audit inside this one |
| 8 | Write findings into `docs/audit-backlog.md` in that file's register, question-ordered, each carrying its final evidential mark | One reviewable document, no fixes applied |

Container budget: one `observe.sh` probe at step 4. Optionally one `-stage m1`
run on an nginx case at step 2, if F12 is wanted demonstrated end to end rather
than at the wiring seam.

## The other direction

This document walks ACCEPT because that is where trust is lost. The corpus scores
both directions, so a stale REJECT attributed to a fresh candidate costs eval
points the same way a stale ACCEPT costs trust, and `eval.Score` reads
`Decision.Stages` without any check on whose execution produced them.

This is one extra question at each edge, not a second audit: at every edge already
listed, ask it again with the arrow reversed. Note that F15 is already
verdict-agnostic, since the stale-dossier path never inspects the verdict, so it
covers both directions as written. The remaining edges are not known to, and the
audit should say so rather than assume the same guards cover both.

## Out of scope

Two things this work will not do without a separate decision.

**No fixes, with two named exceptions.** The deliverable is failing tests and
marked findings. A fix and a test written in the same pass by the same author are
correlated, and the test stops being independent evidence of the property. Triage
of which findings are real bugs and which are accepted scope belongs to the
maintainer.

External review argued that this doubles the cost for one-line defects and that
test-fails-first already secures independence. That is right where the property
is objective and the fix carries no design judgment, and wrong where it does. The
line was set on 2026-08-30 at exactly two exceptions:

- **F11 is fixed inline.** Adding two cases to a switch so that every `Reason*`
  constant maps to a stage has one correct answer, visible from the constants
  themselves.
- **F8 is fixed inline.** Deriving `declared` from the `FalsifyingClass` argument
  is what `Generate`'s own signature and doc comment already specify.

- **F5 and F14 stay findings.** "Is a nonzero `run.sh` exit with a complete output
  directory an error?" and "what should drive do when dossier verification fails?"
  are design questions. Answering them inside an audit means the same author picks
  the design and writes the test that blesses it, with nobody independent in
  between. That is the correlation this rule exists to prevent, and it does not
  disappear because the diff is small.

**No test seams introduced into production code.** F4 and F13 both want one.
Adding a seam so a test can pass is a design change, not a review, and it gets
proposed with its tradeoffs rather than committed inside an audit.

## Reproduction environment

    tree      c539afd8c1affe5928471d1c02b86c10a984914b
              (first draft was cbd90f39d28a99..., see the re-pin notice)
    go        go1.27.0-X:nodwarf5 linux/amd64
    clang     22.1.8
    podman    6.1.0
    kernel    Linux 7.1.11-arch1-1
    corpus    /var/lib/arazu-corpus staged (libpng, nginx)

Every line anchor cited above was re-derived with `grep -n` against this commit
immediately before this document was written, not recalled from an earlier
reading.
