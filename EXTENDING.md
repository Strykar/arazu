# Extending Arazu and the CRS

What is cheap to add, what is not, and which half a given capability
belongs to. Read [`SCOPE.md`](SCOPE.md) first for what the gate does not
yet do; this file is about adding to what it does.

## Where a capability belongs

**Buttercup is modular where oss-fuzz is.** Fuzzing engines are per-project
configuration, not code: libpng's `project.yaml` lists `afl`, `honggfuzz` and
`libfuzzer`, and selecting one is a build flag. We run **libFuzzer with ASan and
UBSan**; the others are available and have never been run here, which is a
different claim from supported.

**A gate stage is a two-method interface.**

```go
type Stage interface {
	Name() string
	Run(ctx context.Context, in Input) (StageResult, error)
}
```

`Verify` runs stages in order and stops at the first failure, so adding one is
implementing those two methods and appending to a slice. Three exist today
(`pkg/revert`, `pkg/classreplay`, `pkg/gate`.EffectStage).

What is *not* trivial, and is the actual work in every stage so far: deciding
what **discriminates**. M2's code is small; the difficulty was establishing that
accept/reject cannot separate a correct fix from an incomplete one on this bug
class, and that the discriminator is whether the parsed keyword is named. A
stage without an oracle that can fail is a stage that always passes.

### Mutation testing means two different things here

Both exist in this project and they point in opposite directions. Keeping the
word straight matters, because conflating them is how a reviewer ends up
believing the gate measures something it does not.

**Inward, and already built.** `make mutation-test` breaks each
security-relevant check in *this repository* in turn and fails if any mutation
survives. A check nothing catches when broken is a check with no evidence behind
it, so this is what stops the gate's own tests from being decorative. It mutates
the checker, never the target.

**Outward, and belonging to the CRS.** Mull and similar mutate the *target* and
measure whether its suite notices — a quality metric about someone else's test
suite. That is a discovery signal: surviving mutants localise weakly-tested
code, and weakly-tested code is where bugs are. It sits beside coverage, which
Buttercup already runs as `coverage-bot`, and it needs to build the target and
run its suite repeatedly, which Buttercup owns and this repository deliberately
does not.

**Why it should not become a gate stage.** Every reason in the gate's vocabulary
is a determination about *this candidate*: the PoV did not reproduce, the patch
does not apply, reverting it does not bring the crash back, a class sibling
diverges. A mutation score is a continuous number about the project, and turning
it into accept/reject means choosing a threshold nobody can defend. Worse, the
question it would proxy — is this fix load-bearing? — is already answered
exactly and more cheaply by M1's revert-attribution.

The genuinely acceptance-shaped question nearby is whether a patch ships a test
that *pins* the fix, since a correct but unprotected fix can regress silently.
That is answerable directly — does the candidate diff touch tests, and does
removing the new test make the PoV pass again — and needs no mutation engine.
