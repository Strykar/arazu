# Decisions

The workbook left these to the builder. Each records what was chosen and why.

## Language and BPF loader: Go with cilium/ebpf

Go, with `github.com/cilium/ebpf` v0.21.0 as a pure-Go loader. That matches
the authbpf harness, which had already proven this exact version's
`spec.Variables` API against this kernel, so the loader is the part of the
work least likely to surprise. The version is pinned rather than left to
resolve newest: v0.22.0 was available in the module cache and would have been
taken by default, for no reason.

Everything builds offline from the local module cache. Only the BPF program is
C, and it stays small.

## Signatures: pure-Go ed25519, not signify or minisign

The workbook preferred signify with minisign acceptable, for minimalism.
Neither is installed on this host, and installing packages was out of scope
for the build.

`crypto/ed25519` from the standard library satisfies the workbook's stated
*reason* for preferring signify ("keep it small and auditable") without an
external binary: no exec dependency, no PATH assumption, verification logic
that is readable Go, and signature tests that run in `go test` with no
subprocess. Fixture keys come from fixed seeds so the acceptance table is
reproducible.

The cost is that the manifest format is now specific to this spike rather
than something `signify -V` can check by hand. For a mechanism demonstrator
that is the right trade; for anything real, a standard format is worth more
than the convenience.

## Egress hook: BPF LSM socket_connect and socket_sendmsg

The `bpf` LSM is active on this host, so the preferred backend was available.
Both hooks are attached, not just `socket_connect`, because connect alone
misses connectionless UDP and raw sockets. The authbpf work supplied the
warning that made this non-negotiable: its own design covered socket creation
but not `accept`, and accepted sockets escaped policy entirely through an
"absence of a mark means allow" branch.

The cgroup fallback is detected and named by `check-env` but not implemented.
If the `bpf` LSM is absent, the spike refuses to run rather than pretending to
have a backend.

## Scoping: network-namespace inode, not cgroup ID

This is the load-bearing choice. The BPF program denies only when the
socket's netns inode matches the one passed in at attach time, read as
`sk->__sk_common.skc_net.net->ns.inum`.

The netns is the containment boundary itself. A workload cannot leave it
without `CAP_SYS_ADMIN` and a namespace file descriptor, so the predicate
cannot be shed. A cgroup is a *parallel* boundary: correct today, but a
second thing to keep in sync with the first, and authbpf's own notes show how
that class of mismatch turns into a silent escape.

A zero inode matches nothing, so a partial or misconfigured load denies
nothing and cannot break host networking. `AttachDeny` refuses a zero inode
outright rather than relying on that.

The `CAP_SYS_ADMIN` clause above is a precondition, not a guarantee, and it
decides whether this scheme can contain someone else's CRS.

Netns are flat. Unlike cgroups and PID namespaces they have no parent/child
relation, so a netns minted by a nested daemon several levels down is an
ordinary netns to the host kernel and `ns.inum` returns the same globally
unique value. Attribution is therefore nesting-invariant, and the meta-cgroup
versus socket-cgroup mismatch that bit authbpf does not transfer here. That is
the real advantage of this key over a cgroup id, and it is bigger than the
"one boundary not two" argument that originally motivated it.

Two things it does not survive:

Polarity. `contained_netns_ino` is a single inode, allow by default. That is
right for an boundary we create, because we know its inode. It is wrong for a
workload whose netns we did not mint: a Docker-in-Docker daemon issues a fresh
netns per container, none of which is the inode we named, so the program denies
nothing while appearing to be attached. Containing a foreign workload needs the
opposite polarity, a map of permitted inodes with everything else denied, so a
netns nobody allowed is refused rather than ignored.

Privilege. Even with allowlist polarity, a process holding `CAP_SYS_ADMIN` can
`setns` into a permitted netns or unshare and re-enter. A privileged
Docker-in-Docker container has that capability by construction, because the
inner daemon needs it to create container netns at all. So a privileged
workload cannot be soundly contained from outside by this program, and moving
to a cgroup key does not help, because cgroup migration is equally available to
it. The answer is architectural: run the CRS unprivileged on a flat container
runtime, or state that containment covers the model call and not the fuzz
target. It is not a tradeoff the eBPF layer can settle.

Measured on the live deployment, 2026-08-20: the second option is not a
concession, it is the situation. One pod of 23 is privileged, the DinD pod, and
it is alone in its pod. Every component that talks to a model is unprivileged.
The escape itself has not been executed, and neither has containing the
remaining 22, so this narrows what the limit covers rather than proving the
boundary holds.

None of this is wired. `contained-run` wraps an boundary this repository
creates, whose inode it therefore knows. Containing a CRS is a primitive we
have and an integration we have not built.

## Namespace creation: named, not unshare

`ip netns add` rather than `unshare --net`, because a named namespace has a
bind mount whose inode can be read *before* anything runs inside it. That
ordering is the point: the deny program is attached to a known inode first,
so there is no window in which the workload runs uncontained.

No veth pair is created. With only `lo` up there is no route out at all, and
"no path exists" is a stronger claim than "a path exists and something blocks
it".

## Three probe modes, not two

The workbook asked for containment versus a control. That pair cannot
attribute the result to the BPF layer: "the contained run reached nothing" is
explained just as well by the namespace alone, which would leave the
defence-in-depth layer entirely unevidenced.

Adding `netns-only` in between makes each layer separately observable.
Flipping only the BPF layer changes `tcp-connect` from `ENETUNREACH` to
`EPERM`, and the kernel's own denial counters are a second witness that does
not depend on interpreting a userspace errno.

## Probe classes: REACH, LOCAL and CONFIG

Two probes would otherwise have been reported dishonestly.

An `AF_PACKET` send onto the namespace's own loopback *succeeds* and reaches
nothing, so counting it as a leak would be false. It is `LOCAL`, and because
the namespace cannot refuse it, a denial there is attributable to the BPF hook
alone. That makes it the cleanest single piece of evidence in the set.

Adding a dummy interface inside the namespace also genuinely succeeds. It is
`CONFIG`, recorded truthfully, and a reach probe is repeated afterwards to
show the successful reconfiguration still yields no path out.

## TPM: real hardware, PCR 23, via tpm2-tools

A real TPM at `/dev/tpmrm0` was available and the user is in group `tss`, so
the hardware-root wording is supportable. swtpm is not installed. Commands
always set `TPM2TOOLS_TCTI=device:/dev/tpmrm0` so the kernel resource manager
is used instead of racing it on the raw device.

`tpm-trust`, this author's own Go TPM project, was surveyed for reuse and
rejected: it is a read-only EK-certificate auditor with no extend, seal,
unseal or PolicyPCR code, and every package sits under `internal/` so it is
not importable regardless. Shelling to tpm2-tools is the pragmatic path, and
it gives a `tpm2_pcrread` oracle for free while debugging. If this ever needs
to be one self-contained binary, `github.com/google/go-tpm` is the migration
target, not tpm-trust.

The expected PCR value is computed independently in Go and checked against the
TPM after every extend, so a wrong measurement fails at the extend where the
cause is obvious rather than surfacing later as an unexplained policy failure.

## The PCR sequence takes a host-wide lock

PCR 23 is one register on one TPM, shared by every process on the host. A
reset-extend-use sequence only means anything if nothing else touches the
register in between, so `Provision` and `Unseal` each hold an exclusive
`flock` for their whole duration.

The lock covers the sequence rather than the individual commands. Locking per
command would serialise the calls while still letting two sequences
interleave, which is the actual failure.

This was found by running the suite, not by reasoning about it: with packages
executing in parallel, seven TPM tests failed, each reporting a different
unexpected PCR value, because another package's tests were driving the same
register. Serialising with `go test -p 1` would have hidden it. The bug is
real outside tests too, since two concurrent runs on one host would corrupt
each other's measurement.

## vmlinux.h is generated, not committed

authbpf checks its `vmlinux.h` in. This spike generates it with `make
vmlinux` instead, because it is 164k lines and `check-env` already verifies
that `/sys/kernel/btf/vmlinux` is readable. The trade is that a host without
BTF cannot build, which `check-env` reports with a remedy.

bpftool's BTF dump emits a few empty forward declarations that trip
`-Wmissing-declarations`. The suppression is scoped to the `#include` of the
generated header with a `clang diagnostic push`/`pop` pair, so `-Werror` stays
strict for the program itself.

## The audit log is built before the ingress gate

The workbook numbered the log M4, after the gate at M1. That number has since
been taken by the fifth gate stage, so the log is referred to by name; see
SCOPE.md. The rest of this entry is the original reasoning. It is built second
here, because the gate's own acceptance criteria require it to append ACCEPT
and REJECT entries, and building it fourth would leave the gate unable to
satisfy its contract.

## The gate checks in protocol order

Authentic, then fresh, then intact: signatures, then version rollback, then
content. A bundle failing more than one check reports the earliest, so the
reason an operator sees is stable. A test pins the order, because a reorder
would silently change reported reasons without failing anything else.

## The rename from kavach to arazu, 2026-08-16

This project was called `kavach` until 2026-08-16. The rename to `arazu` was
mechanical across 102 files, and the original repository is kept verbatim as the
record: the experiment reports here describe runs whose artifacts were literally
named `kavach-*` at the time — an nft rule `kavach-r14-probe`, a namespace
`kavach-r11-carveout`, `table inet kavach`. Those names are rewritten here for
consistency, and the unaltered originals are in the `kavach` tree if a claim
ever needs checking against what actually ran.

One thing the rename changed that is not cosmetic: `contentRootDomain` went from
`kavach-content-root-v1` to `arazu-content-root-v1`. That is a cryptographic
domain separator, so every measurement sealed under the old value is invalid.
Nothing had been sealed outside this tree when it happened, and
`TestContentRootIsPinnedToAKnownDigest` is what caught it.

## The CRS is a separate process, not a plugin, 2026-08-19

The dependency graph already separates them:

| cone | binaries | packages |
|---|---|---|
| judge | `gate` | corpus, model, gate, revert |
| envelope | `contained-run` | auditlog, manifest, contentstore, egress |
| authority | `bundle-sign`, `seal-tool`, `ingress-verify`, `log-verify`, `keygen` | manifest, contentstore, auditlog, tpmseal |

`go list -deps ./pkg/gate` returns corpus and model only. No TPM, no FIDO, no
BPF, no root.

The judge could plug in. `cmd/gate` already takes `-shim`, which abstracts how
a target is built and run, and that is the seam libCRS exposes.

The envelope cannot: a boundary inside the thing it bounds is not a boundary.
The authority must not, or the CRS mints its own approvals.

Position: pluggable, not plugged in. Invocable from any CRS, a component of
none. The evidence argument is the stronger one, because the best thing here is
that a CRS's own quality check passed a patch this gate refuses, and a judge
shipped inside the judged has to argue its independence rather than show it.

M4 wants a second CRS. Candidate disagreement needs independent candidates, and
one engine re-rolled gives runs, not independence. Same model and same prompt
means disagreement may be a sampling artefact rather than evidence, which is
why it is not the next thing built.

Pre-register the prediction before that experiment. "The gate runs against any
artifact source" is true by construction. The claim worth making is about
rejection rates and failure classes across two patch pipelines.
