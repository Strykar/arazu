# M2 step two: the package does not reproduce the corpus evidence

Run 2026-08-21, full declared class, 79 of 79 members.

    gate -stage m2 -candidate libpng-iccp-buttercup-run2
    verdict: ACCEPT
    "79 members replayed against the reference fix and the candidate"
    "members on which they disagree: 0"

`libpng-iccp-buttercup-run2` is the known-incomplete fix. It is the corpus's
central witness and the candidate the deck's argument depends on being refused.
`pkg/classreplay` accepts it across the whole class.

## Why, and it is not a bug in the comparison

The two replays observe different channels.

`corpus/falsifying-class/libpng-iccp/run.sh` compiles libpng directly and links
`reader.c`, a purpose-built program that installs a warning callback and prints

    RESULT iccp-accepted keyword="%s" len=%u

`pkg/classreplay/ossfuzz.go` runs `helper.py reproduce` against
`libpng_read_fuzzer`, which calls `png_image_finish_read(&image, NULL, ...)` and
discards diagnostics. Fuzz harnesses are silent by construction.

The case's own discriminator is explicit about what separates the builds:

> Whether libpng reports the PARSED KEYWORD. A build that scans the terminator
> correctly names it ("profile '<keyword>'") ... Accept/reject alone does not
> separate them, because both end up rejecting this particular profile.

So the fuzzer channel cannot carry the signal. Zero disagreements is the
instrument having no resolving power on the axis, not the patches agreeing.
The case warned about exactly this one level down: "A discriminator keyed to a
diagnostic string measures the build, one keyed to an observable measures the
patch." The package measures an observable that does not carry the
discriminator.

## What this means for the count

M2 stays UNCOUNTED, and for a stronger reason than before. The earlier objection
was provenance: the shipped evidence came from run.sh rather than the package.
The real objection is that the package, run over the whole class, reaches the
OPPOSITE verdict on the corpus's central witness.

"Wired, therefore counted" would have shipped a stage that accepts the deck's
own counterexample.

## The fix, stated but not taken

`FalsifyingClass` carries `generator:` because only the case knows how to build
its class. It needs the same for observation: the discriminator names what to
look at, and nothing runnable currently produces it. run.sh's `reader.c` IS that
program for libpng.

Adding `observer:` alongside `generator:`, and having ReplayAgainst build and run
it instead of the fuzz harness, mirrors what run.sh already does. That is a
schema change plus a target change, and it is the honest content of step two.

Not done here. Recorded so the next person starts from the diagnosis rather than
from the symptom.

## Resolved, 2026-08-21

`observer:` added to `FalsifyingClass`, and `corpus/falsifying-class/libpng-iccp/observe.sh`
written to produce what the discriminator names. The stage runs the observer
instead of the fuzz harness, and refuses with `class-observer-missing` when a
case declares a class without one, rather than falling back.

    run1, the correct fix        ACCEPT   0 of 79 disagree
    run2, the incomplete fix     REJECT   78 of 79 disagree
                                 reference "keyword parsed", candidate "keyword NOT parsed"

The package now reaches run.sh's conclusion. Step two is done and the count is
earned.

### Three defects in the observer, before it produced anything

Two were copied from run.sh rather than read.

`2>/dev/null` on the compile. run.sh discards compiler stderr, so a failing
build produced no output at all: `set -e` killed the script silently and the
stage reported "observer failed" with nothing to say why. An observer that
swallows diagnostics is the defect this file exists to fix, reproduced inside
the fix for it.

`sed s/0x12b0/0/` on libpng's zlib version guard. The staged tree carries
`0x1280`, so the substitution matched nothing and every compile died on
`ZLIB_VERNUM != PNG_ZLIB_VERNUM`. run.sh's own comment predicted this. It now
matches any value AND verifies the edit landed, because a no-op sed and a
successful one are indistinguishable until something downstream fails.

That second one was a hazard in the shipped evidence too: run.sh built its class
table against a libpng whose header said `0x12b0`, and against the tree as
staged it failed the same way, so the evidence was not reproducible.

CLOSED 21 Aug. run.sh got the same fix, and now reproduces its table from the
staged tree, agreeing with the package:

    vuln  keyword NOT parsed   runtime error: index 41 out of bounds
    run1  keyword parsed       iCCP: profile 'ICC Profile': exceeds application limits
    run2  keyword NOT parsed   iCCP: invalid window size

Fixed rather than left open, because the demo routes around it and a finding the
working path does not touch is one nobody trips over again.

### The same class, in nginx's run.sh: it assumes a tree that is not the staged one

Found 2026-08-21 while recapturing the miswired PoV output, and recorded here
rather than filed separately because it is the same defect as the `0x12b0` sed
above: a shipped `run.sh` asserting something about its environment that the
staged tree does not satisfy. They will be found together or not at all.

nginx's `run.sh` resolves the image from `project.yaml`:

    docker_image: ghcr.io/aixcc-public/challenge-004-nginx-cp

with no tag, so `docker inspect` resolves it to `:latest`. The only tag in the
local store is `v1.0.3`, so `check_docker_image` dies with "Requested docker
image not found" and points the reader at the README, which is the wrong place
to look: the image IS present, under a tag the script does not ask for.

`grade-patch.sh` already works around this by resolving `DOCKER_IMAGE_NAME`
itself from `docker images` before calling run.sh, which is why the corpus path
never hit it. Anything that calls `run.sh` directly has to do the same, and the
workaround being invisible inside another script is exactly why this cost a
failed build before it was understood.

Both instances share a shape worth naming: the challenge's scripts were written
against the tree the challenge shipped, and the staged tree differs from it in
small ways that surface as confident, misdirecting errors. `0x12b0` matched
nothing and produced a compile failure blamed on zlib; the bare image name
produces a "not found" for an image that is present. Neither says "your tree
differs from mine".

### What M2 costs, for the finale argument

Two insight-dependent inputs, not one. It already needed a reference patch the
organisers' target will not have. It also needs an observer someone writes per
case, and observe.sh is not boilerplate: it builds libpng from source, links a
purpose-written reader, and keys on an observable rather than a diagnostic
string because gcc and clang word the same rejection differently.

M0, M1 and M3 need neither. That is why they are the reference-free subset that
runs against an unknown target, and why M2 is the corpus demonstration.
