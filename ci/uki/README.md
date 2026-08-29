# Cold-boot image

Boots on a machine with no installed OS, builds and tests this repository, and
writes the answers to a USB stick. Nothing is installed; nothing survives a
power-off except what lands on the stick.

## Boot it

Copy `arazu-coldrun.efi` onto a Ventoy stick and pick it from the menu. Ventoy
boots `.efi` directly.

It also boots from `/boot/EFI/Linux/` under systemd-boot, but the image is
~660MB, which is most of a default 1GB `/boot` and will break the next kernel
update. Secure Boot must be off, or the image signed with an enrolled key.

## Prepare the stick

```sh
touch /run/media/you/VENTOY/ARAZU-RESULTS     # permission to write here
mkdir -p /run/media/you/VENTOY/arazu          # payload
```

Without the marker it prints to screen and writes nothing. It never formats or
repartitions, and only creates one timestamped directory.

Payload, all optional:

| path | what |
|---|---|
| `arazu/arazu-*.tar.gz` | the repo, from `git archive --prefix=arazu/ HEAD` |
| `arazu/git/<org>/<repo>` | bare mirrors, so the corpus stages offline |
| `arazu/images/*.tar` | `podman save` archives, loaded into the corpus store |

No tarball means it clones `$ARAZU_REPO_URL`. No mirrors means it needs DNS.

Mirrors must preserve the path after `github.com/`, because git is pointed at
them with `url.<base>.insteadOf`:

```sh
git init --bare git/tob-challenges/example-libpng
git -C git/tob-challenges/example-libpng fetch <source> \
    '+refs/remotes/origin/*:refs/heads/*' '+refs/tags/*:refs/tags/*'
```

## What it reports

Progress scrolls. The last thing on the console is one summary screen, printed
from an EXIT trap so a run that dies at step one still leaves something to read.

```text
  ENVIRONMENT    OK    bpf LSM, bpffs, BTF, TPM
  BUILD          OK    11 binaries, offline
  SUITE          OK    17 packages
  CONTAINMENT    OK    REACHED / ENETUNREACH / EPERM
  LOOPBACK RAW   OK    EPERM, bpf alone
  CORPUS         OK    3 pins verified, offline
  IMAGES         OK    4 loaded

  RESULT: ALL OK   7 checks
```

A run that executed nothing prints `INCOMPLETE`, never `ALL OK`.

| tier | claim |
|---|---|
| self-check | LSM attaches, a routeless namespace is the control, TPM reads |
| 1 | the tree builds with no network and its suite passes |
| 2 | the three-run containment table, on this metal |
| 3 | the corpus stages at its pinned commits, and images load |

Tier 3 reports in detail: which mirrors the stick carries, the per-repository
reason staging failed, and podman's own error on a failed load. The container
store is tmpfs, so "no space" means RAM; it measures the image set against free
memory before loading rather than dying half way through.

Tier 1 compiles the BPF object. `bpf/vmlinux.h` is not in the tarball; the
Makefile regenerates it from `/sys/kernel/btf/vmlinux`, which is what a CO-RE
program should be built against.

TPM rows need a real TPM 2.0. In a VM without one they skip.

## Build it

```sh
make vmlinux          # once, needs /sys/kernel/btf
cd ci/uki && sudo mkosi --force build
```

`KernelModulesInclude` **replaces** mkosi's default module set. Anything
unmatched is absent at runtime, and on Arch the filesystems are modules:
without the `fs/` lines the image cannot mount a stick. ext4 and btrfs are
builtin, so this only fails on the machines that matter.

Scripts are installed from `selfcheck.sh` and `coldrun.sh` by `mkosi.build`. Do
not add copies under `mkosi.extra`; there were two and they drifted.
