# Running the CRS

Arazu judges patches. Something else has to find the vulnerability and propose
one, and that something is [Buttercup](https://github.com/trailofbits/buttercup),
the CRS open-sourced after AIxCC. This is how to bring it up, point it at a
model, give it a target, and hand what it produces to the gate.

The two halves stay separate on purpose. The gate must not share a model, a
prompt, or a failure mode with the thing it is judging, so nothing here reaches
into Arazu's decision path.

## What a target is

Buttercup ingests six fields: a repository with a base and a head ref, and an
oss-fuzz project to build the harness from.

That last field is the whole story about "prepared challenges". Buttercup
resolves `<fuzz-tooling>/projects/<name>/project.yaml` and drives oss-fuzz's
own `helper.py`, and the tooling URL is just a git repository it clones. Point
it at upstream oss-fuzz and **every project already onboarded there is a valid
target** — more than 1300 of them, including curl, openssl, sqlite3, ffmpeg,
systemd, nginx and libxml2. No preparation on our side at all.

Code oss-fuzz does not already know needs onboarding first: a `Dockerfile`, a
`build.sh`, a `project.yaml` and a harness. That is oss-fuzz's documented
process, typically a day for a simple C library, and not something invented
here.

```sh
# real software, nothing prepared by us
./scripts/buttercup-task.sh https://github.com/curl/curl master master curl

# a corpus case, using the commits the case itself records
./scripts/buttercup-task.sh --from-case corpus/cases/libpng/iccp-keyword.yaml
```

`--from-case` exists so the pins live in one place. A task typed by hand against
a case is a second copy of those commits that agrees until someone corrects the
case and not the command.

## Pointing it at a model

Buttercup never names a provider. It asks LiteLLM for a `model_name` and LiteLLM
decides what that resolves to, so the swap lives entirely in LiteLLM's config:
no image is rebuilt and no code changes.

The CRS can still tell the difference, and did. See "The swap is not free" below.

```sh
./scripts/buttercup-model.sh show      # which way the RUNNING pod points
./scripts/buttercup-model.sh local     # every entry -> ollama on the host
./scripts/buttercup-model.sh frontier  # restore the captured config
```

### The swap is not free

Routing correctly is not the same as working. Task 017d6977 failed every patch
attempt with a 400:

    This model does not support assistant message prefill.
    Received Model Group=openai-gpt-4.1

The mapping did its job. Buttercup's patcher prefills an assistant turn, which
the Anthropic target refuses, so the run produced a crash input and no patch and
looked exactly like a CRS that could not find a fix.

Check the patcher's log before reading a no-patch run as a capability result:

```sh
kubectl logs -n crs deploy/buttercup-patcher --since=6h | grep -i error
```

Whether another Anthropic model accepts prefill is untested. So is the local
path: pointing LiteLLM at ollama proves the endpoint is reachable, not that the
patcher succeeds against it.

Three things that are easy to get wrong and are handled:

**Every entry is redirected, not the ones that look relevant.** The names
Buttercup asks for live in its code, and this deployment remaps aliases:
`model_name: openai-gpt-4.1` has upstream `anthropic/claude-sonnet-4-6`.
Redirecting the names from a spend log instead of the aliases in the config
matched 1 of 5 entries and left four pointing off-box, which would have made a
"local" run quietly half-frontier.

**The pod is restarted and then read back.** LiteLLM reads its config once at
startup, so a changed ConfigMap in front of a stale pod serves the old routing.
`show` reads the file the pod was actually told to use, derived from its own
`--config` argument, because the image also ships a default at a different path
and reading that one reports a plausible, wrong answer.

**The local endpoint has to be reachable.** ollama binds `127.0.0.1`, which is
not reachable from inside the cluster. `scripts/r14-probe.sh` exposes it on
minikube's bridge for the duration of one command and removes the exposure in an
EXIT trap, so it comes down on success, failure or Ctrl-C.

## Handing the result to the gate

The point of the exercise. Buttercup produces a patch; the gate decides whether
to believe it:

```sh
./corpus/grade-patch.sh <case-id> <patch-file> <label>
```

The evidence that this matters is in the corpus already:
`corpus/falsifying-class/libpng-iccp/run2.patch` is a real patch from a real run,
which the CRS's own quality check reported as fixing every PoV alongside a green
test suite. It is the engine's genuine failure mode rather than a synthesised
one.

## Bring-up

The CRS deploys to the **default `minikube` profile only**. Its scripts call
`minikube start` with no `-p`, `docker exec minikube`, and
`kubectl config use-context minikube`, so a named profile is silently
retargeted — pointing kubectl elsewhere does not help.


Buttercup owns its own deployment; we do not reimplement it.

```sh
cd /var/lib/arazu-corpus/buttercup
make setup-local     # once: writes deployment/env, asks for keys
cd -
./scripts/buttercup-up.sh
```

`buttercup-up.sh` starts the cluster, refuses to deploy if pods cannot resolve
ghcr.io, runs `make deploy`, then checks pod state itself. Buttercup's own
`make wait-crs` reported "All CRS pods are running" during a cold bring-up with
`registry-cache` in CrashLoopBackOff, so its verdict is not used.

Then `kubectl get pods -n crs` until things settle. Expect a few pods to error
transiently on a cold start and recover without help.

### Known state on the development box

The helm release here has been `pending-install` since 2026-08-09, which blocks
`helm upgrade`. The deployment runs fine; only helm's bookkeeping is stuck. A
fresh install does not inherit this. Repairing it means patching the status
inside `secret/sh.helm.release.v1.buttercup.v1`, which is helm's private state,
so it is left alone rather than half-fixed. Config changes go through the
ConfigMap path instead, which is also closer to what an air-gapped deployment
does: apply pre-staged config to pre-staged images rather than run helm against
a chart repo.

## Extending the CRS

The CRS is modular where oss-fuzz is. Fuzzing engines are per-project
configuration rather than code: libpng's `project.yaml` lists `afl`,
`honggfuzz` and `libfuzzer`, and selecting one is a build flag. We run
**libFuzzer with ASan and UBSan**. The others are available and have never been
run here, which is a different claim from supported and should stay written that
way until one of them has.

### Mull, as a future addition here rather than in the gate

Mutation testing of the *target* — Mull and similar — belongs on this side, not
in Arazu. It mutates the code under test and measures whether the project's own
suite notices. Surviving mutants localise weakly-tested code, and weakly-tested
code is where bugs are, so the output is a **discovery signal**: a prior for
where to fuzz, sitting beside the coverage the `coverage-bot` component already
produces.

It also needs to build the target and run its suite repeatedly. Buttercup owns
target builds; the gate drives them through a shim only to grade one candidate,
and giving the gate a build system is the opposite of what it is for.

Why not a gate stage, stated once so the question does not come back: every
reason in the gate's vocabulary is a determination about a specific candidate —
the PoV did not reproduce, the patch does not apply, reverting it does not
restore the crash, a class sibling diverges. A mutation score is a continuous
number about the project as a whole, and converting it to accept/reject means
picking a threshold that cannot be defended. The question it would stand in for,
"is this fix load-bearing", is already answered exactly by M1's
revert-attribution: revert the patch alone and the crash returns, or it does not.

Note the collision in vocabulary. Arazu already runs `make mutation-test`, which
mutates **its own checks** and fails if any survives. That is the correct use of
mutation testing inside a verification tool, and it is the opposite direction
from Mull. If both land without the distinction being written down, one word
will cover two opposite things and somebody will read the gate as measuring
target quality.

## What we are standing on

Verified 2026-08-19 against /var/lib/arazu-corpus/buttercup.

- **Pinned at `40e45ca1172ad24f80a827b914cb5e9d5a993e83`** (`v1.0-193-g40e45ca`,
  2026-08-03). One tagged release, several hundred commits on main. A scored run
  needs a fixed dependency; do not chase main during it.
- **AGPL-3.0.** Does not reach our code: no linking, vendoring or forking, three
  shell scripts totalling 395 lines calling `kubectl` and a webhook, and no
  Buttercup, redis or protobuf in `go.mod`. §13 binds the operator of a
  *modified* copy.
- **No NetworkPolicy**, zero across 79 chart files. Isolation is the namespace
  and whatever the CNI enforces. Anything reaching Redis can read the queues.
- **Credentials are environment variables**: `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, `GHCR_AUTH`, `LANGFUSE_SECRET_KEY`. Readable in
  `/proc/PID/environ`, `docker inspect` and core dumps.
- **Privileged Docker-in-Docker.** `competition-api` runs `docker:24.0.6-dind`
  with `privileged: true`, plus a `dind-daemon` DaemonSet. Fuzz targets execute
  in the nested daemon.

**Keep the checkout unmodified.** Carry deltas as config, env, a `helm -f`
overrides file or a sidecar. If source must change, fork publicly and record the
SHA here. Currently in breach: `deployment/k8s/values.yaml` is edited in place,
eight lines of model routing, which belongs in an overrides file.

The DinD entry is the only one that touches our own claims; see the netns
scoping entry in DECISIONS.md. Short version: netns are flat so attribution is
nesting-invariant, but a privileged container can `setns` out of a netns-keyed
boundary.

That was written as "so this CRS cannot be contained", which is broader than the
deployment. Measured, 2026-08-20: **one pod of 23 is privileged**, the DinD pod,
and it is alone in its pod rather than a sidecar sharing a netns with anything.
The patcher, LiteLLM, orchestrator and scheduler are unprivileged, so the
components that make model calls are not the ones holding `CAP_SYS_ADMIN`.

    kubectl get pods -n crs -o json | jq '[.items[]
      | select(any(.spec.containers[]; .securityContext.privileged))
      | .metadata.name]'

So the honest scope is the one DECISIONS.md already named as the answer:
containment covers the model call, not the fuzz target. Two things are still
unexecuted and neither is assumed: the `setns` escape from the DinD pod, and
containing the other 22 with the egress program and watching the CRS still
work.
