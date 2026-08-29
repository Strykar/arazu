# Mutation testing

Every security-relevant check is deliberately broken, a test must fail when it is, and the
result is logged. This is how that runs and what it has found.

## Running it

    make mutation-test

The catalogue is `testdata/mutations.json`. Each entry names a check, the file it lives in, the
exact text to replace, what to replace it with, which packages to test, and which test is
predicted to catch it. `cmd/mutation-test` copies the tree, applies one edit, rebuilds, runs the
named packages, and records which tests failed.

The rebuild matters. The `cmd` tests exec binaries out of `bin/`, so a mutant that reused a stale
`bin/` would run unmutated code and every `pkg` mutation would look caught or escaped at random.

## Verdicts

- **caught**: a test failed, and the predicted one was among them.
- **caught-by-another-test**: a test failed, but not the predicted one. Still caught; the
  prediction was wrong and that is worth seeing.
- **escaped**: nothing failed. The check has no evidence behind it. Fails the run.
- **subsumed**: nothing failed, but another check refuses every input that would reach this one,
  and *that* check was itself caught. Accepted only under that condition, so the claim "something
  else catches this" has to be backed by the something else being evidenced.
- **stale-catalogue**: the text to mutate no longer occurs exactly once. Fails the run, because
  silently skipping it would stop testing the check it names.
- **build-fail**: the mutant does not compile. Usually means the mutation form leaves a variable
  unused, which Go refuses. Write it as `if false && <original condition>` so the variable stays
  used and the branch still dies. **Fails the run.** A mutant that did not build was never
  tested, so it is evidence of nothing; it is deliberately not folded into `untestable`, which
  is a declared exemption carrying a reason, whereas this is the harness being broken.

## Current state, 2026-08-29

46 mutations: 43 caught, 3 subsumed, 0 uncaught, 0 did not build.
Read the totals off a run rather than incrementing them: this line said 40/37
for a day after gate-reason-bad-signature was added.

This figure was unreproducible between 2026-08-16 and 2026-08-18. Vendoring the
dependencies broke every mutant, because `treeEntries` did not copy `vendor/` and the
build runs with `GOPROXY=off`. All 40 build-failed, nothing was tested, and the run still
printed "0 uncaught" and exited 0, because `build-fail` counted toward neither holes nor
untestable. Three changes fixed it: `vendor` joined `treeEntries`, `build-fail` became a
failing verdict, and the Makefile now pins `GOFLAGS=-mod=vendor GOPROXY=off` instead of
inheriting the caller's environment. That last one is why it hid for two days: on a box
with a warm module cache the mutants built from the cache and passed regardless.

### What this number covers

The default catalogue is `pkg/fido` (15), `pkg/contentstore` (10), `pkg/manifest` (8),
`cmd/ingress-verify` (4), `pkg/auditlog` (4), `pkg/revert` (2), `pkg/classreplay` (1),
`pkg/dossier` (1) and `pkg/hostcap` (1). The containment and measured-state layers are a **separate** catalogue,
`testdata/mutations-root.json`, run by `make mutation-test-root` with sudo and a TPM: 7
mutations across `pkg/tpmseal` (4), `pkg/egress` (2) and `bpf` (1). Quoting a total without
saying which catalogue it is implies containment coverage the default run does not provide.

Neither catalogue touches `pkg/corpus`, `cmd/contained-run` or `cmd/demo`.

### The gate was uncovered until 2026-08-29

The first 41 mutations were entirely integrity and provenance: manifests, content store,
audit log, FIDO, ingress. Not one touched a gate stage, so "0 uncaught" described the
tamper-evidence layer and said nothing about whether a verdict is reached correctly. Four
defects found in the gate that week were all in that blind spot, and each is now pinned by
a mutation:

| Mutation | What it kills |
|---|---|
| `revert-stale-output-read` | M1 reading a previous run's output when this run produced none |
| `revert-prepatch-site-ignored` | M1 crediting a patch against a crash at an undeclared site |
| `classreplay-no-reference-accepts` | M2 accepting agreement with the unpatched build |
| `dossier-emit-leaves-partial-state` | a failed emit leaving a partial dossier behind |
| `hostcap-privilege-uid-not-capability` | the readiness matrix asking for uid 0 instead of CAP_SYS_ADMIN |

The lesson generalises past these four: every mutation targeted a *check*, and none
targeted *evidence acquisition*, which is where all four defects lived. A mutation that
makes acquisition return stale data can also score `subsumed` rather than `uncaught` when
the guard it would trip is itself dead, so a saturated catalogue is not by itself evidence
that the layer is covered.

The three subsumed ones are real redundancy rather than gaps:

| Mutation | Subsumed by | Why nothing reaches it |
|---|---|---|
| `manifest-unknown-fields` | `manifest-canonical-bytes` | The canonical-bytes comparison rejects any manifest that is not byte-identical to its canonical form, and a manifest carrying an unknown field never is. |
| `stat-non-regular` | `scan-non-regular` | `ScanDir` now walks the tree before anything is read, so no input reaches the per-entry stat check that the walk has not already refused. |
| `log-sequence-order` | `log-chain-link` | Each entry hashes the previous entry's hash, so a reordered log breaks the chain before the sequence numbers are consulted. |

## What it has found

**The size check had no test at all.** `contentstore.VerifyAgainst` compares the manifest's
declared size against the file, and breaking that comparison left the entire suite green. A
declared size that disagrees with the file matters because the content root is derived from the
declared values, so the measurement would describe something the store does not contain even
though the bytes hash correctly. Closed by `TestDeclaredSizeMustMatchTheFile`.

**A regression test that did not test what it claimed.** The symlinked-directory fix moves the
tree scan ahead of the hash loop so the gate never reads through a symlinked path component. The
first version of the test asserted only that the reason came back `unsafe-path`, and mutation
testing showed it passed with the scan back in its original position, because the walk reports
`unsafe-path` from either place. The fix was to pin a hash the outside file does not have, so
anything reaching the hash loop reports `hash-mismatch` instead. Only then does the test
distinguish the two orderings.

**Two checks in the FIDO2 verifier were doing nothing observable.**

`fido-policy-rp` compares the credential's recorded relying party against the policy. Every test
that exercised it also had the assertion made for the wrong relying party, which the `rpIdHash`
comparison catches further down. The case only this check sees is a store entry recording a
credential under one relying party while the authenticator asserts for another: the signature
verifies, the `rpIdHash` matches, every later check passes, and the boundary trusts a key its own
records say belongs somewhere else.

`fido-unprovisioned-credential` refuses an assertion naming a credential that is not in the
store. For any non-empty name, dropping the lookup still refuses the assertion, because the
zero-valued credential it falls through with has an ID that cannot match. An empty credential
name is the one input where the zero value does match, and the reason then comes back as a
relying-party mismatch, which sends an operator looking for the wrong thing.

Both were found the same way and neither was visible from reading the code.

## The rule this exercise enforces

A green suite is not evidence. Two of the containment spike's three bugs were found by mutation,
and every finding above came from a suite that was already passing. A check with no mutation
record is not known to be tested; it is only known to be accompanied by a test that passes.

## Whole-mechanism mutations and one-member holes

A mutation that disables a whole mechanism can report "caught" while being blind
to a single member of a set going missing. `gate-reason-mapping` turns the
sentinel loop into `if false && errors.Is(err, s)`, so all ten reasons collapse
at once and `TestAcceptanceTable` fails immediately. Remove one entry instead
and the other nine still resolve: the bundle is still refused, with the wrong
reason. Aggregate verified, composition not.

Audited on 2026-08-20, structurally rather than by reading the descriptions.
The hole needs a set whose members are defined in code, so the test is whether
a mutation's target sits inside a loop or switch over such a set. Fifteen do:

| shape | count | verdict |
|---|---|---|
| iterate runtime data (`m.Files`, `assertions`, `allow`, path elements) | 11 | no code-defined member to remove |
| `range []error{...}` in `reasonOf` | 2 | THE HOLE. Closed by `gate-reason-bad-signature`. |
| `switch c.Alg` arms | 3 | removing an arm does not compile, its imports go unused |
| `switch {` counter arms | 2 | removing an arm fails `TestAnAuthenticatorThatDoesNotCountIsReportedNotHidden` |

Both switch results were checked by deleting an arm and running the suite, not
by reading it. One instance, closed. This covers files the catalogue already
mutates; code it does not mutate at all is a different gap.

When adding a mutation that disables a loop or a dispatch, add a second one that
removes a single member.
