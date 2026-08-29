# Troubleshooting

Symptom → cause → fix.

## Build

**`module lookup disabled by GOPROXY=off`**
`GOFLAGS=-mod=mod` ignores `vendor/`. Set `GOFLAGS=-mod=vendor`.

**`fixture good missing` from `go test`**
Bundles are generated. Run `make fixtures` before `make test`.

**`pacman: target not found: python3` / `bpftool`**
Packages are `python` and `bpf`.

**Containment tests FAIL instead of SKIP in a container**
uid 0 without `CAP_SYS_ADMIN`. Guard on `hostcap.HasSysAdmin()`, not `Geteuid`.

## Gate

**`the bpf hook let a local raw send through: dns-resolve`**
Probe misclassified LOCAL on a `127.x` resolver; the loopback carve-out permits
it. dns-resolve must be COVERAGE.

**`contained run: did not complete`, no reason given**
The reason is the first field of `contained-run`'s JSON; stderr is in
`/tmp/err-<mode>`. Read both.

**Containment passes with two runs**
Insufficient. Three runs (control, netns-only, contained) attribute the denial;
`raw-packet-loopback` is the row the namespace cannot produce.

## Bootable self-check

**Boots, prints one kernel line, then nothing (caps lock works)**
Last `console=` becomes `/dev/console`. Put `console=tty0` last.

**Does not boot at all**
Image too large — firmware loads the whole PE into memory. Keep under ~600MB.

**Not findable in the boot menu**
systemd-boot titles from `PRETTY_NAME` in `.osrel`. Override `/etc/os-release`.

**Stops at a timezone prompt**
`systemd-firstboot`. Preset `/etc/machine-id`.

**Self-check never runs; gettys start instead**
`systemctl preset-all` deletes hand-made `.wants` symlinks. Ship a preset file.

**Stalls just before multi-user.target**
`After=multi-user.target` + `WantedBy=multi-user.target` is a dependency loop.

**NIC missing**
`KernelModulesInclude` replaces mkosi's default set. Match `drivers/net/.*` —
`virtio_net.ko` is not under `ethernet/`.

**Waits a minute for the network**
`systemd-networkd-wait-online --any --timeout=20`.

**Keyboard dead at the results screen**
By design. Root shell on **tty2 (Alt+F2)**.

## CRS

**`registry-cache` CrashLoopBackOff, `panic: lookup ghcr.io`**
Cluster DNS is dead; this component fails closed.

```sh
kubectl run t --rm -i --restart=Never --image=busybox:1.36 -- nslookup ghcr.io
dig @192.168.49.1 ghcr.io     # refused = the node's upstream is dead
```

CoreDNS forwards to the node's `/etc/resolv.conf` → host bridge address. If no
dnsmasq is running there, repoint CoreDNS. Keep the block: the line is
`forward . <servers> {` and replacing the whole line leaves a dangling brace.

**`make deploy` reports all pods running while one crash-loops**
It does that. Use `./scripts/buttercup-up.sh`.

**Task ran against the wrong model**
`./scripts/buttercup-model.sh show` — reads the running pod, not the ConfigMap.

**A "local" run was partly frontier**
Redirect every `model_name`. Aliases remap: `openai-gpt-4.1` →
`anthropic/claude-sonnet-4-6`.
