# Arazu

An acceptance layer for automated vulnerability repair: a gate that refuses to
certify a patch it cannot prove.

The thesis: **degrade yield, never safety.** A weaker in-boundary model means
fewer candidates and more regeneration, but the acceptance bar — executable
evidence, a tamper-evident boundary, and a human signature — does not live in
the model, so it does not move when the model gets weaker.

Arazu does not find vulnerabilities and does not write patches. A cyber
reasoning system does that; we run [Buttercup](https://github.com/trailofbits/buttercup),
the open-sourced AIxCC CRS. Arazu judges what comes out, and refuses what it
cannot verify. The two halves are separate on purpose: the gate must not share
a model, a prompt or a failure mode with the thing it is judging.

Two files first, because they decide whether anything below is worth your time.
[`SCOPE.md`](SCOPE.md) is what this does not prove, including how far it is from
accepting a target it has never seen. [`docs/mutation-testing.md`](docs/mutation-testing.md)
is what the evidence is worth: every security-relevant check is deliberately
broken and a test has to fail, or the check counts as unevidenced. Neither is a
hedge. Stating the boundary of a claim is what makes the claim checkable.

Then [`DECISIONS.md`](DECISIONS.md) for why it is built this way,
[`EXTENDING.md`](EXTENDING.md) for what it costs to add to it,
[`BUTTERCUP.md`](BUTTERCUP.md) for running the CRS that feeds it, and
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) when something does not come up.

## What is built

The envelope is built and verified on bare metal: the ingress gate, the content
store, the hash-chained log, TPM sealing, two-person control, and a network
namespace with a BPF LSM on its sockets.

**The falsification gate is four stages of five, three of them reference-free.**
`cmd/gate` wires M0 (patch-effect), M1 revert-to-attribute, M2 falsifying-class
replay and M3 sanitizer-gated reachability. M4 does not exist.

M2 counts as built on two things that both landed on 2026-08-21, and it needs
both: `pkg/classreplay` became reachable from `cmd/gate -stage m2`, AND the
corpus's class table was regenerated through that package instead of through
the per-case script under `corpus/falsifying-class/`. Either alone leaves the
count at three. Wiring a package does not relocate where its evidence came
from, and regenerating evidence for a package nothing calls does not make it
part of the gate.

The gate ladder is M0 to M4. M0, M1 and M3 need no reference patch, so they are
the stages that work on a target nobody prepared. M2 needs two things that
target will not have: a known-good reference patch, and a per-case OBSERVER.
The observer exists because a fuzz harness is silent by construction --
`libpng_read_fuzzer` calls `png_image_finish_read` and discards diagnostics, so
replaying the class through it compared silence against silence and accepted the
known-incomplete fix across all 79 members. Only the case knows what its
discriminator looks at, so only the case can produce it, and writing one is
research rather than configuration. That is why M2 is the corpus demonstration
and M0/M1/M3 are the subset that runs against an unknown target. M4 is what
would let M2 do without the reference; it would not remove the observer.

M3 is gradable against one negative, which is a smoke test and not a rate — see
SCOPE.md.

Verdicts are three-valued: ACCEPT, REJECT with a reason, and ERROR when the
gate ran and cannot tell. `audit-log-unavailable` is an ERROR, not an
eleventh rejection class.

An ERROR is honest and it is not reassuring. A guard that fails closed is still
failing; it just fails in the direction that does not hurt you. The libpng case
demonstrated both halves at once on 2026-08-21: the gate correctly declined to
credit a patch, and the case it declined to credit was gradeable, because a
declared sanitizer string carried a space no toolchain emits and the literal
match could never succeed. The refusal was right. The reason for it was a defect
in the case, not a property of the candidate. Read an ERROR as work to do, never
as the system working.

So the thing this repository is named for is the part least finished. What is
finished is the evidence discipline around it, which is why the two files above
come first.

## What you can run, in order of cost

Each tier stands alone. Stop wherever your hardware does.

Only tiers 5 and 6 can bill you. `pkg/model` is an interface and a deterministic stub
with no client, no key and no endpoint, so the gate itself cannot reach a
provider: its verdicts are builds, PoV runs and comparisons. The one outbound
call in the tree is `corpus/local-model-yield.sh`, and only when `MODEL` starts
with `claude`; anything else goes to a local ollama.

| tier | what it shows | needs |
|---|---|---|
| 0. degraded mode | a host with no TPM refuses to sign, and names why | nothing |
| 1. build and test | the gate compiles and its suite passes | Go, clang, bpftool, a BTF kernel |
| 2. containment demo | six branches, each sabotage-tested | root, `CONFIG_BPF_LSM=y` with `bpf` in the active LSM list |
| 3. grade the corpus | 14 labelled bad patches judged, with reasons | podman, perl `prove`, ~4GB of images |
| 4. verify a CRS run | `cmd/drive` takes a run directory to a signed verdict, unattended | tier 3, plus a Buttercup run directory |
| 5. model in the loop | your model proposes a patch, the gate judges it | ollama or an Anthropic key |
| 6. the whole pipeline | Buttercup finds and patches, Arazu verifies | minikube, ~20 pods, real spend |

Tiers 1 to 3 are numbered to match what the cold-run UKI prints on screen, so a
boot test and this table name the same thing. Degraded mode is tier 0 because it
needs nothing and is not a rung on the cost ladder.

Tier 5 defaults to `gpt-oss:20b`, the only local model that cleared the bar more
than once (4 of 9; devstral 1, qwen3-coder 0), and re-anchors hunk ranges before
grading, which took raw yield from 1 of 27 to 5 of 27. Both are defaults, not
flags: `ARAZU_LOCAL_MODEL` and `ARAZU_FIX_HUNKS=0` override them, and every
result line records which `apply_mode` produced it.

`apply_mode: hunks-reanchored` means **the ranges were repaired, not that the
patch applies**. Re-anchoring rewrites the `@@` header; it cannot rescue context
lines the model invented, and a real capture has been seen carrying both faults
at once. Read 5 of 27 as "5 got past the header", not "5 applied".

Tier 0 is `make demo-degraded`. It exits 1 when the refusal happened as designed
and 2 if anything else did, so a fail-closed box is a rehearsed demonstration
rather than a broken run.

`make check-env` reports every tier's prerequisites and says which are missing.
Optional ones are named for the tier they unlock, so a missing minikube does
not make a working checkout look broken.

**A hardware TPM 2.0 is assumed, not optional.** The trust story is a signing
key sealed under a policy over measured state, and an emulator cannot make that
claim: nothing here uses swtpm, and `check-env` treats a missing `/dev/tpmrm0`
as a failure rather than a skip. Deployments without one are out of scope right
now.

The rest of the hardware you may not have, and the checker will say which:
tier 2 needs a kernel with the BPF LSM enabled, which most distributions do not
ship; the signature path needs a FIDO2 token; tier 5 locally wants 24GB of
VRAM. Those tests skip rather than fail, and a wall of skips is environmental
rather than an incomplete project — verified by building this on a clean
machine, where 47 tests skip and the suite still passes.

## Run it

```sh
./scripts/stage-corpus.sh   # clone the challenges at the commits the cases pin
make check-env              # capability matrix; exits non-zero if a REQUIRED check fails
make build                  # compile the BPF object and the CLIs
make fixtures               # generate the signed bundles the gate tests read
make test                   # the suite that needs no root
make demo                   # the branch demonstration             (root)
make test-root              # the whole suite, BPF and TPM included (root)
```

To run all of this on a machine with no installed OS, see
[`ci/uki/README.md`](ci/uki/README.md): a bootable image plus a USB payload of
mirrors and image tarballs, so the corpus stages with no network at all.

`make fixtures` is not optional before `make test`: the adversarial bundles are
generated, not committed, and nine of the gate's rejection tests read them. A
clean clone without it fails with "fixture good missing", which looks like a
broken checkout and is not.

Dependencies are vendored and `GOPROXY` is off: the build never fetches, and
works on a machine that has never seen this module. `stage-corpus.sh` is the
one step that needs the network, and it takes what it needs at pinned commits,
verifying each one after checkout rather than trusting it.

`make demo` and `make test-root` need root, for network namespace creation, LSM
attach and TPM access. `check-env` says exactly what is missing and how to fix
it rather than degrading silently.

Run the root targets and tier 3 may stop working, which is worth knowing before
it happens rather than after. Tier 3 drives podman through the `docker` shim,
and the gate resolves its image the same way, so a suite run under `sudo` can
leave the corpus image store owned by root. Tier 3 then fails as your own user
with `permission denied` on `overlay-layers/layers.json`, which reads like a
broken checkout and is not. Check and restore with:

```sh
find /var/lib/arazu-corpus/podman-root -user root -print -quit   # empty is fine
sudo chown -R "$USER:$USER" /var/lib/arazu-corpus/podman-root \
                            /var/lib/arazu-corpus/podman-runroot
```

Observed on this host: the store went root-owned on 14 August and tier 3 needed
root from then on. Which root target does it has not been pinned down, so treat
the ordering as a hazard rather than a rule.

## What the demo shows

Each branch declares what it predicts before it runs, and the demo exits zero
only when every branch matches. The count is printed from the branch list rather
than written here: the summary line once read "all four branches matched" while
five ran, because adding one did not touch the sentence that named the number.

| branch | shows |
|---|---|
| `happy-path` | the envelope works end to end: gate accepts, run is contained, output is signed, log verifies |
| `poisoned-bundle` | the boundary refuses bad input at the door and nothing downstream runs |
| `tampered-content` | content altered *after* acceptance breaks the measured-state binding, so signing is refused rather than producing a signature over compromised output |
| `gate-in-chain` | the gate reaches a real verdict INSIDE the envelope, and the verdict is sealed and logged rather than assumed |
| `wrong-patch-refused` | a wrong patch, refused, with the reason logged: `REJECT:class-replay-fail` on the libpng candidate every other acceptance signal passes |
| `log-tamper` | the record cannot be quietly rewritten |

`tampered-content` is the one that matters for the envelope: even when
something gets past the gate, the system fails closed.

`wrong-patch-refused` is the one that matters for the argument. It runs the real
gate against `libpng-iccp-buttercup-run2`, a patch that stops the PoV, builds
sanitizer-clean, passes 29 variants and the full suite, and was reported fixed
by the CRS's own quality check. Every stage but one accepts it. It needs the
staged corpus and takes about three minutes, because it builds libpng twice and
replays 79 generated inputs.

Every branch can be sabotaged with `-break-branch <name>`, and each sabotage
is verified to produce a mismatch. A harness that cannot fail proves nothing,
so the ability to fail is itself tested. That test earned its place: it
revealed that `tampered-content` originally refused to sign because the gate
and the runner hashed different path prefixes, not because anything had been
tampered with.

## The pieces

| component | what it does |
|---|---|
| `cmd/ingress-verify` | the gate. Ordered, fail-closed checks over a signed hash-pinned bundle; ten named rejection classes, each with its own ingress test, plus `bad-signature` |
| `cmd/contained-run` | runs the workload in a network namespace with no route out, plus a BPF LSM egress denial |
| `cmd/seal-tool` | measures the accepted content root into TPM PCR 23 and seals the signing key under a policy over that state |
| `cmd/log-verify` | recomputes the audit log's hash chain |
| `cmd/drive` | the join: takes a CRS run directory, captures a gradable case from it, runs the gate, writes the verdict into a dossier, measures and seals it. The only piece that consumes a run directory rather than a case, and what makes "unattended" true |
| `cmd/dossier` | re-derives every machine-checkable claim a dossier makes, from the bytes in the dossier: artifacts rehashed, content root recomputed over the directory, coverage established from the measurement. Re-derive, not re-read, so it does not trust the process that produced it |
| `cmd/demo` | the branches above, each sabotage-testable with `-break-branch` |
| `bpf/egress_deny.bpf.c` | `lsm/socket_connect` and `lsm/socket_sendmsg`, scoped by network-namespace inode |

## Grading a patch, and putting a model behind it

The gate reads a **case** (a target at a pinned commit, an input that fires a
named sanitizer, a reference patch) and a **candidate**, and returns accept,
reject or error with a reason from a fixed vocabulary. The reason is the point:
grading on accept/reject alone would pass a gate that had been broken into
rejecting everything, so every candidate names the reason it is expected to
fall to and the stage that should produce it.

```sh
./corpus/grade-patch.sh cpv2 --none        my-run   # no patch: the PoV must still fire
./corpus/grade-patch.sh cpv2 good_patch.diff my-run # the challenge's own correct fix
./corpus/grade-patch.sh cpv2 bad_patch.diff  my-run # rejected, naming auth_basic.t
```

To put a model in the loop, `corpus/local-model-yield.sh` captures the
unpatched sanitizer report, prompts a model with it and the source, extracts a
diff, and hands it to the gate. It talks to ollama or to Anthropic, selected by
the model argument:

```sh
./corpus/local-model-yield.sh gpt-oss:20b               cpv2 1
./corpus/local-model-yield.sh claude-opus-4-6           cpv2 1   # needs a key
```

The prompt never contains the reference patch. That is checked, because an
experiment that leaks the answer measures recall of a supplied fix.

Both scripts read their layout from the environment and default to what
`stage-corpus.sh` produces, so nothing needs editing to run elsewhere:

| variable | default | what it is |
|---|---|---|
| `ARAZU_CORPUS` | derived from the shim's `--root` | where challenges are staged |
| `CP` | `$CORPUS/nginx/challenge-004-nginx-cp` | the challenge checkout to grade against |
| `SHIM` | `$CORPUS/shim` | the `docker` shim pinning podman's store |
| `OLLAMA` | `http://localhost:11434` | local model endpoint |
| `ANTHROPIC_KEY_FILE` | `~/.config/ANTHROPIC_API_KEY` | frontier key, read from a file rather than the environment |
| `NUM_CTX` | `90112` | context window for the local model |

The key is read from a file, not an environment variable, so it does not appear
in `ps` output or in a shell history.

## How the containment is proven

The namespace is the primary control: with only loopback up and no veth,
there is no path off the box. The BPF program is defence in depth.

Proving that needs three runs, not two. "The contained run reached nothing" is
explained just as well by the namespace alone, which would leave the BPF layer
entirely unevidenced. Observed on Linux 7.1.5 with the `bpf` LSM active:

| probe | `control` | `netns-only` | `contained` |
|---|---|---|---|
| tcp-connect | REACHED | `ENETUNREACH` | `EPERM` |
| dns-udp | REACHED | `ENETUNREACH` | `EPERM` |
| icmp-echo | REACHED | `ENETUNREACH` | `EPERM` |
| raw-packet-offbox | REACHED | `ENODEV` | `ENODEV` |
| raw-packet-loopback | REACHED | REACHED | `EPERM` |

The control run must reach the network or nothing below it means anything.
Flipping only the BPF layer changes the errno, and the kernel's own denial
counters are a second witness that does not depend on reading a userspace
errno.

The last row is the cleanest evidence in the set. A raw send onto the
namespace's own loopback reaches nothing, so it is never counted as a leak,
but the namespace cannot refuse it either. A denial there is the BPF hook's
work alone.
