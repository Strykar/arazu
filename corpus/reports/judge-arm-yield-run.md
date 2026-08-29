# Judge arm, second table: 27 model-authored diffs

The first table's inputs were written here. These 27 were written by models
during the 2026-08-10 yield work, and the gate already ruled on each by
executing it. That fixes the authorship half of the self-authorship problem and
none of the diversity half: still nginx, still three CPVs.

Both tiers run 2026-08-21: `claude-opus-5` and `gpt-oss:20b`.

## Ground truth, mapped from the matrix rather than guessed

`matrix-all.jsonl` records a level and a note per candidate, not a reason from
the gate's vocabulary. The mapping is stated here because it is a judgement, and
burying it would make the scoring look more automatic than it is.

| matrix | count | mapped to |
|---|---|---|
| level -1, "patch does not apply, even with --recount" | 21 | `patch-does-not-apply` |
| level 1, "pov still fires" | 4 | `revert-attribute-fail` |
| level 3, accepted | 1 | ACCEPT |
| level 2, "prove produced no summary; unproven" | 1 | excluded, no vocabulary reason fits |

The two strata are scored separately. 21 against 4 is a heavy skew, and a single
number over both would mostly measure whether a reader can spot a malformed
diff, which is not the question this experiment asks.

## What ran, and the hole in it

20 of 27 were judged. The run exhausted the API credit partway through, and the
remaining 7 came back as `invalid_request_error`, not as judgements. They are the
contiguous tail of the worklist: cpv5 `qwen3-coder_30b-3` and `devstral_24b-1..3`,
cpv9 `gpt-oss_20b-1..3`.

One of those seven is the single accepted candidate, cpv5 `devstral:24b` attempt
2, which is the only model-authored patch in the whole corpus that the gate
accepted. **So this table has no positive control.** Every judged candidate is
one execution refused, and nothing here measures whether the judge correctly
accepts a correct patch. That is one call away and should be the first thing run
when credit is restored, before anything else in this table is quoted.

## Results, frontier tier

Syntax stratum, `patch-does-not-apply`, 21 of 21 judged:

| judge answered | count |
|---|---|
| REJECT `patch-does-not-apply` (exact) | 11 |
| REJECT, wrong reason (`revert-attribute-fail` 2, `new-test-failure` 2) | 4 |
| **ACCEPT `correct-fix`** | **6** |

Substantive stratum, `revert-attribute-fail`, 4 of 4 judged:

| judge answered | count |
|---|---|
| REJECT `revert-attribute-fail` (exact) | 3 |
| REJECT `empty-patch` (wrong reason) | 1 |

The excluded `unproven` candidate drew REJECT `revert-attribute-fail`, recorded
and not scored.

## The accepts are the finding, and finishing the table changed what they mean

The frontier judge answered ACCEPT `correct-fix` on six diffs that do not apply
to the source at all. A patch that cannot be applied cannot fix anything, so
these are certifications of nothing.

CORRECTED 2026-08-21, and the correction matters more than the original claim.
The first version of this section said the accepts were "one cell not three": all
three then known were `gpt-oss:20b` on cpv5, so they were one model-CPV cell
sampled three times and were explicitly not banked as a rate. That caveat was
right about the evidence available and wrong about the world. Six candidates were
missing from this stratum because the run exhausted API credit, and judging them
added three more accepts:

    cpv5  gpt-oss_20b      3 attempts
    cpv5  qwen3-coder_30b  1
    cpv9  gpt-oss_20b      2

Three distinct cells, two CPVs, two patcher models. The one-cell reading is
retired. It was the correct thing to say from 15 rows and it survived exactly as
long as the table was incomplete, which is the argument for finishing a table
before quoting the caveat that qualifies it.

What makes it a real finding anyway is the direction. In the first table the
frontier judge produced **zero** dangerous accepts across seven curated
candidates. Here, on raw model output, it produced them at the first
opportunity. The difference between the tables is what the inputs are: the first
table's candidates all applied and built, so the question was always "is this
fix correct". These candidates include malformed diffs with invented context,
where the prior question is "does this text apply to this file", and that is not
reliably answerable by reading. It is answerable by running `git apply`, which
takes milliseconds and is what the gate does.

## The pre-registration was wrong again, and again in the direction that helps

Filed before the run: "both judges should do BETTER here than on the corpus
table, for an uninteresting reason: many of these fail at apply or carry invented
context lines, and malformed diffs are visible to a reader."

They are not visible to a reader. The frontier tier scored 11 of 21 exact on the
syntax stratum against 6 of 7 on the first table, and produced six
certifications of unapplyable patches where the first table produced none. The
prediction had the sign backwards.

The caution filed alongside it does still hold and is worth keeping: a judge
answering `patch-does-not-apply` is doing syntax checking rather than safety
judgement, and the 11 exact answers in that stratum should not be read as the
judge reasoning about vulnerabilities.

## Local tier, and it completed the table the frontier tier could not

The local arm needs no API credit, so it ran all 27 including the positive
control. 21 were judged and 6 returned no verdict at all, cut by the context
window exactly as in the first table.

Syntax stratum, side by side. The frontier row was first written mid-run,
when that arm had judged 15 of its 21, and read 15 / 8 / 4 / 3 until it was
reconciled against the completed table above. Re-derive from that table, not
from a partial run.

| tier | judged | exact | right verdict, wrong reason | **accepted an unapplyable patch** | no verdict |
|---|---|---|---|---|---|
| frontier | 21 | 11 | 4 | 6 | 0 |
| local | 17 | 1 | 8 | **8** | 4 |

Substantive stratum, `revert-attribute-fail`: frontier 3 of 4 exact, local 2 of 2
exact with the other 2 cut by the window. Both tiers do well here, on the small
number available.

## The local accepts are spread, which makes them the stronger evidence

The frontier tier's 3 accepts were one model-CPV cell sampled three times, and
this file says not to bank them as a rate. The local tier's 8 are not: they span
five distinct model-CPV cells, all three CPVs and all three patcher models.
Whatever is failing is not one bad cell.

## A local ACCEPT carries almost no information

The local judge answered ACCEPT nine times across this table. Eight were patches
that do not apply to the source at all. One was correct.

That one is the positive control, cpv5 `devstral:24b` attempt 2, the only
model-authored patch the gate ever accepted, and the local judge accepted it too.
It should NOT be credited as skill, and the scoring rule filed before the run
says why: an accept-biased judge gets every positive right for free. With eight
of nine accepts wrong, that is the reading the evidence supports. The verdict
"ACCEPT" from this tier is close to uninformative on this table.

The frontier tier's positive control was run once credit was restored, and it
answered the question in the direction nobody was watching for.

## The frontier tier false-rejected the only patch the gate ever accepted

cpv5 `devstral:24b` attempt 2 is the single model-authored patch in this corpus
that execution accepted: it applied strictly, built, silenced the PoV, and passed
the suite, recorded as `level=3 accepted=true tests_pass=true pov_clean=true`.

The frontier judge answered REJECT `class-replay-fail`.

Two things follow, and the second matters more than the first.

The frontier tier is NOT accept-biased. That was the live alternative explanation
for its strong showing, and the mirror-trap rule filed before the run says a
judge biased toward ACCEPT gets every positive for free. This one did the
opposite: given the only true positive available, it refused it. Whatever
explains its performance, an accept prior is not it.

And the reason it gave is one it could not have established. `class-replay-fail`
means the patch fixes this input but not the bug class. Deciding that requires
generating other inputs in the class and running them, which is exactly what
`pkg/classreplay` does by executing, and exactly what a reader cannot do. The
judge asserted an unverifiable class claim in order to reject a fix that
execution had already accepted. That is the same shape as the syntax stratum,
pointed the other way: a question cheap to execute, not available from reading,
answered confidently anyway.

For a deployment the cost lands differently in the two directions. The three
accepts of unapplyable patches would have certified nothing as something. This
refuses something real, which costs yield rather than safety. Both are wrong; only
one of them is dangerous, and the gate makes neither error because it runs the
thing.

**n=1.** This is one row, and it establishes that accept-bias is not the
explanation. It does not establish a false-rejection rate, and nothing here should
be quoted as one.

## What the two tables together support

The first table showed the frontier tier reading curated candidates about as well
as execution grades them, and the local tier failing three ways. This table shows
both tiers failing on a question the first table never asked: whether a diff
applies at all.

That question is the cheapest thing the gate does. `git apply` answers it in
milliseconds with no model, and it is the one place where the reading-versus-
executing comparison is not close. The frontier tier got it right 8 times in 15;
the local tier once in 17.

Neither result speaks to generalisation. Three CPVs, one project, 21 of 27
candidates concentrated in a single failure mode, and a positive control of
exactly one.
