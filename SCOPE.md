# What this spike does not prove

This is the boundary of the claim. Stating it is what makes the rest
credible to anyone who would actually deploy this, and it is the same
discipline as the dossier's "what we could not prove" field.

## The headline limits

- It is a **mechanism demonstrator**, not a security guarantee and not an
  accreditation. Real deployment needs formal evaluation.
- The inside workload is a **stand-in**. It reads the verified bundle, writes
  one artifact, and tries to reach the network. It is not a cyber-reasoning
  system, and nothing here says anything about how well one would work.
- Sealing binds outputs to a **measured state**, which is the property we
  want, but measurement equality only says "this is the reviewed thing". It
  does not say the thing is good, it is not remote attestation, and it does
  not judge whether a patch is correct. That judgement is the human
  reviewer's, by design.
- **PCR 23 is resettable**, and the spike resets it on every run. That is
  what makes a repeatable demonstration possible and it is also the limit:
  anything able to run `tpm2_pcrreset` can reproduce a measurement.
  Production must bind to non-resettable measured-boot PCRs established by
  firmware. The demo, the JSON output and the audit log all say so on every
  run rather than leaving it to this file.
- **Two-person control here is cryptographic only.** Two distinct trusted
  keys must sign the manifest, and the spike enforces that. Whether the two
  keys are held by two different people who reviewed the bundle
  independently is an organisational control the spike cannot see.
- **No cross-domain-solution hardware is involved.** The physical transfer is
  simulated by a reviewed directory handoff with the protocol's checks
  applied to it.
- Signing keys are **fixture keys derived from fixed seeds and committed to
  this repository**. They exist to make the acceptance table reproducible.
  There is no key management story here at all.

## Limits this build discovered

These were not anticipated by the workbook. They are recorded because
finding them is worth more than a clean-looking document.

- **The hash chain does not detect tail truncation.** Editing an entry or
  removing one from the middle breaks every link after it and the verifier
  reports where. Dropping entries from the *end* leaves a shorter,
  self-consistent chain, and no internal hashing can detect that. Catching
  it needs a head hash or an expected length held somewhere the attacker
  cannot reach. `TestTruncatedTailVerifiesAsShorterChain` pins the actual
  behaviour so the gap stays visible.

- **The BPF layer covers three address families, not everything.** It denies
  `AF_INET`, `AF_INET6` and `AF_PACKET`. `AF_UNIX` and netlink are left
  alone on purpose, so the probe's own failures stay attributable to the
  thing under test rather than to a blanket denial. The namespace, not the
  BPF program, is what supports the claim that no path exists.

- **The netns-inode predicate assumes the workload cannot create a nested
  namespace.** The spike does not drop capabilities inside the namespace, so
  a hostile workload running as root could in principle `unshare` again. The
  primary control still holds, because a nested namespace has no route out
  either, but the BPF layer is scoped to one inode and would not follow.
  Dropping `CAP_SYS_ADMIN` inside the namespace is the obvious next step and
  is not done here.

- **Configuration probes succeed inside the namespace, and that is reported
  honestly.** `ip link add` genuinely works for root in a namespace. Calling
  it a failure would be false, so it is recorded as succeeding and a reach
  probe is repeated afterwards to show the successful reconfiguration still
  yields no egress.

- **A raw send onto the namespace's own loopback is not egress.** It
  succeeds and reaches nothing. It is classified `LOCAL` and never counted
  as a leak. Its value is attribution: the namespace cannot refuse it, so a
  denial there is the BPF hook's work alone.

- **The measured register is host-wide shared state.** PCR 23 belongs to the
  host, not to a run. Concurrent runs are serialised with an `flock` held
  across each whole reset-extend-use sequence, and
  `TestConcurrentSequencesDoNotInterleave` covers it. A process that does not
  take that lock, including any other tool on the host that decides to use
  PCR 23, can still walk into the middle of a sequence. Nothing in the TPM
  enforces the convention.

- **The gate and the run-time re-measurement must hash the same paths.** They
  originally did not, and the fail-closed branch passed with nothing
  tampered because the two roots could never match. Both now go through
  `contentstore.MeasureBundle`, and
  `TestMeasureBundleMatchesTheManifestDerivedRoot` fails if they drift
  apart again. Worth stating because the failure mode is indistinguishable
  from working tamper detection.

## Hardware two-person control cannot be demonstrated on this host

There is exactly one FIDO2 token available (AuthenTrend ATKey.Pro). Two-person
control needs two signers, so the strongest configuration demonstrable here is
one hardware signer plus one software signer. "Two signatures, both from
security keys" is implemented and tested, but has never been executed, because
executing it needs a second token.

This is a limitation of the demonstration, not of the design. `TrustStore`
counts hardware-backed keys separately so the distinction is visible in the
output rather than glossed.

Related, and stronger: the gate counts two-person control over the **signer
names** in the provisioning file, not over key IDs. One person holding two
keys is refused. That turns what used to be a disclaimer here into an enforced
property, but only for keys the provisioning file names. An unnamed key falls
back to its own ID and so counts as its own person; `TrustStore.UnnamedCount`
reports how many are in that state. Naming every provisioned key is a
deployment discipline the gate can report on but not impose.

## No mutation is exempt any more

`make mutation-test-root` supports an `untestable-on-this-host` verdict for a
guard whose precondition cannot be produced here. Three mutations carried one and
none of the three reasons held up: two claimed they needed a TPM simulator when
what they needed was a lying `tpm2` on `PATH`, and one claimed it needed a reboot
when the LSM list only had to be masked in a mount namespace. All three are now
caught. `docs/mutation-testing.md` has the detail.

The lesson outlasts the three tests. `escaped` and `stale` are computed from a
run; `untestable` is a sentence a human wrote that the harness accepts on trust,
so it is the one verdict that has to be re-derived rather than inherited.

## Capabilities the contained workload retains

The strength of the boundary depends on what the workload is still allowed to
do, so it is enumerated rather than left implicit. Measured on this host with
`capsh --print` inside the namespace.

| capability | what it enables | why it is tolerable here |
|---|---|---|
| `CAP_NET_RAW` | `AF_PACKET` and raw ICMP sockets | the namespace has no interface but `lo`, so a raw socket reaches nothing off the box |
| `CAP_NET_ADMIN` | `ip link add`, `ip route add` inside the namespace | adding a route or a dummy device grants no path out, which the repeated reach probe demonstrates |
| `CAP_SYS_ADMIN` | mount, and `unshare` of a nested namespace | this is the weakest link, see below |
| everything else root holds | not exercised by the workload | not audited, and that is a gap |

The spike runs the workload with **full root capabilities** inside the
namespace. That is the capable-adversary configuration, and it is deliberate.

### The two configurations, and why both are kept

Some probes need capabilities a minimised production config would drop, so a
minimised run proves *less* about the adversary's reach, not more.

| | capable-adversary | minimised |
|---|---|---|
| `CAP_NET_RAW` | retained | dropped |
| `raw-packet-loopback` (LOCAL) | runs, and is denied `EPERM` by the BPF hook | **cannot be attempted**, `socket()` fails `EPERM` at the capability check |
| `icmp-echo` | runs, denied | cannot be attempted |
| `tcp-connect`, `dns-udp` | run, denied | run, denied |

Verified: with `CAP_NET_RAW` dropped, `AF_PACKET` and raw ICMP fail at
`socket()` while TCP and UDP still open.

This matters because the LOCAL raw-send probe is the single cleanest piece of
attribution evidence in the whole spike: the namespace cannot refuse a raw
send onto its own loopback, so a denial there is the BPF hook's work and
nothing else. Minimise capabilities and that evidence disappears, not because
containment got worse but because the adversary can no longer even attempt
the thing that distinguished the layers.

Attribution survives in a weaker form. `tcp-connect` still fails
`ENETUNREACH` with the namespace alone and `EPERM` with the hook attached, so
the layers remain distinguishable by errno. What is lost is the probe where
the namespace contributes provably nothing.

So both configurations are kept and reported separately. Reporting a green
minimised run without this distinction would be claiming the strong result
from the weak experiment.

### The unresolved one

`CAP_SYS_ADMIN` inside the namespace lets a hostile workload `unshare` a
nested namespace, which the BPF program's netns-inode predicate does not
follow. The primary control still holds, because a nested namespace has no
route out either. The defence-in-depth layer does not. Dropping
`CAP_SYS_ADMIN` is the obvious fix and is not done here.

## What the demo's exit code means

`make demo` exits zero only when every branch matches predictions written
before they ran. Each branch can be sabotaged with `-break-branch`, and every
sabotage is verified to produce a mismatch. A harness that cannot fail proves
nothing, so the ability to fail is itself tested.

## Verified environment

The results in this repository were produced on Linux 7.1.5-arch1-2 with the
`bpf` LSM active (`capability,landlock,lockdown,yama,apparmor,bpf`), a real
TPM at `/dev/tpmrm0`, clang 22.1.8, bpftool 7.7.0 and Go 1.26.5. Nothing here
has been run on another kernel or another TPM, and the BPF program's use of
`struct net`'s `ns.inum` is CO-RE relocated but untested off this host.

## How far this is from real-world input

Two different answers, because there are two halves.

**Buttercup takes real input today.** It ingests a repository, a base ref, a
head ref and an oss-fuzz project name. Point the tooling at upstream oss-fuzz
and every project already onboarded there is a valid target — over 1300 of them.
Nothing needs preparing on our side for those.

**Arazu's gate is partly there, and the gap is known and recorded.** Its stages
divide by whether they need a *reference patch*:

| stage | what it needs the target to come with | works on a novel target |
|---|---|---|
| M0 empty-patch, M1 revert-attribution | nothing | yes |
| M3 sanitizer-gated reachability | nothing; diffs against the pre-patch build | yes |
| M4 non-determinism, candidate disagreement | nothing | yes, once built |
| M2 falsifying-class replay | **a reference fix, a per-case observer AND a declared class size** | no |

The third requirement is enforced earlier than the table's framing suggests, and
that matters for the other rows. `falsifying_class.size` is what separates
agreement across the class from agreement across a replayed subset, so
`Case.Validate` refuses a class that omits it. The refusal lands at LOAD, and
`LoadDir` stops at the first error, so a case declaring a class without a size
does not merely become ungradable by M2: it stops the whole corpus loading, and
with it M0, M1 and M3, which the table lists as needing nothing. Declaring a
class is therefore a commitment to sizing it, not an optional extra on top of a
case that would otherwise work.

M2's second requirement is the one that is easy to miss and harder to supply. A
fuzz harness is silent by construction, so replaying a class through it compares
silence against silence: doing exactly that accepted the known-incomplete libpng
fix across all 79 members. Only the case knows what its discriminator looks at,
so each case ships a program that produces the observation, and writing one is
research rather than configuration. That is why M2 is the corpus demonstration
and M0/M1/M3 are the subset that runs against a target nobody prepared.

The gate ladder is M0 to M4. The audit log is not a gate stage and is not
numbered: the build workbook called it M4 before the ladder had five stages,
and the deck's numbering is the one to use, because M4 meaning two things is a
contradiction a reader can hit without leaving the repository.

M2 compares a candidate against the case's `reference_patch`, and a real target
has none — producing the fix is the exercise. The pre-patch build was tried as a
substitute and is *inverted* on this bug class: an incomplete fix is by
construction one that leaves baseline behaviour alone, so comparing against
baseline cannot see it. On libpng the wrong patch agrees with the unpatched
build while the correct fix differs from it.

That inversion used to reach the verdict: agreement with the baseline returned
ACCEPT, so the reference-free path accepted the corpus's central counterexample
and flagged the correct fix instead. Since 2026-08-29 neither partition can
accept. Agreement is `class-no-reference` and divergence on a member that never
crashed is `unadjudicated-behaviour-change`, both undecided, because a
differential against the baseline is an oracle for change and not for
correctness. Without a reference M2 surfaces, it does not adjudicate.

The oracle that survives having no reference is **candidate disagreement** —
sample K patches, and treat the ones that disagree across the class as the
signal. That is M4's machinery, and it is not built.

Reference-free is not the same as built, and this paragraph used to conflate
them. Of the five gate stages, **three need no reference** (M0, M1, M3) and
**two of those three are built** (M0, M1). M3 is reference-free by design and
has nothing behind it but its two reason constants, so it runs nowhere. M2 is
written and needs a reference; M4 is neither.

So a novel target today gets M0, M1 and M3. M3 needed no reference and no
K-sampling, which is why it came before M2 and M4.

**Nothing Arazu emits contaminates what it was asked to verify.** The input
bundle is the maintainer's signed artifact and is never written to: its manifest
enumerates its files, and the gate holds no key to re-sign it with. The verdict
goes into a dossier Arazu produces, which is measured and sealed separately.
This is enforced rather than intended, and it was found by enforcement: the
first version of the integration wrote a decision into the input bundle and the
ingress gate refused it with `unmanifested-file`, which is the correct answer to
an architecture mistake.

**M3 is gradable, not measured.** The corpus holds exactly one graded negative
for it: `cpv2-boundary-off-by-one`, which fixes the declared overflow and writes
one byte past a 3021-byte region at `ngx_http_core_module.c:1999` instead. One
case makes a stage gradable. It does not make a rate. Do not quote 1 of 1 as a
result; the honest statement is that the stage has one negative and one clean
reference, and that is a smoke test.

**What M3 does not establish.** Unreachability is undecidable in general, so no
absence of findings is a proof. The bar this stage meets is narrower and worth
stating in those words: *no input in the falsifying class reached the vulnerable
sink under sanitizer*. Every accepted decision carries that sentence in its
notProven list.

M4 is not an oracle on its own either: a wrong patch that every sample produces
deterministically clears it. Agreement is not evidence. The terminal verdict in
that case is unadjudicated-behaviour-change, surfaced for a human.
