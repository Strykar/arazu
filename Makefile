# -mod=vendor, not -mod=mod. Dependencies are vendored so the tree builds on a
# machine that has never seen them: GOPROXY is off by design, and without
# vendor/ a fresh clone fails with "module lookup disabled by GOPROXY=off"
# before it compiles a line. -mod=mod would ignore vendor/ and reintroduce that.
export GOFLAGS := -mod=vendor
# Resolve modules from the local cache only. The build must never fetch.
export GOPROXY := off
export GOSUMDB := off
export TPM2TOOLS_TCTI := device:/dev/tpmrm0

BIN := bin

.PHONY: all check-env vmlinux bpf build test test-root test-noroute validate-reports mutation-test mutation-test-root fixtures demo demo-degraded clean

all: build

vmlinux: bpf/vmlinux.h

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf: bpf/vmlinux.h
	$(MAKE) -C bpf egress_deny.bpf.o

build: bpf
	mkdir -p $(BIN)
	go build -o $(BIN)/ ./cmd/...

check-env:
	go run ./cmd/arazu-env

fixtures: build
	./scripts/make-adversarial.sh

test:
	go test ./...

# Break each security-relevant check in turn and report which test caught it.
# Fails if any mutation survives, because a check nothing catches when broken
# is a check with no evidence behind it.
# Pin the build environment rather than inheriting it. The harness sets no
# cmd.Env, so a mutant builds however the caller's shell happens to be
# configured: on a box with a warm module cache the mutants built from the cache
# and passed even with vendor/ missing from the copied tree, while a clean
# machine reported "inconsistent vendoring" for all 40. The harness should
# measure what ships, not what a developer's cache holds.
mutation-test: build fixtures
	GOFLAGS=-mod=vendor GOPROXY=off $(BIN)/mutation-test -repo . -work ./state/mutants

# The TPM and BPF checks live in their own catalogue. Their tests t.Skip
# without root, and a skipped test reads as an escaped mutation, so running
# them in the default set would report false holes.
# R1.3: the suite must pass with no route out. Catches an acquired egress
# dependency at commit time instead of inside the air gap.
validate-reports:
	./scripts/validate-reports.sh

test-noroute: build
	sudo -E env "PATH=$$PATH" ./scripts/test-noroute.sh

mutation-test-root: build fixtures
	sudo -E env "PATH=$$PATH" TPM2TOOLS_TCTI=$(TPM2TOOLS_TCTI) \
	  GOFLAGS=-mod=vendor GOPROXY=off \
	  $(BIN)/mutation-test -repo . -catalogue testdata/mutations-root.json -work ./state/mutants-root

# The egress and TPM tests need root for netns creation and LSM attach.
test-root: build fixtures
	sudo -E env "PATH=$$PATH" TPM2TOOLS_TCTI=$(TPM2TOOLS_TCTI) go test ./...

# The demonstration for a box with no TPM: signing must be refused, and the
# refusal is the claim. Exits 1 when the boundary held, 2 if anything else
# happened. Rehearsed rather than improvised.
demo-degraded: build
	./scripts/demo-degraded.sh

demo: build fixtures
	sudo -E env "PATH=$$PATH" TPM2TOOLS_TCTI=$(TPM2TOOLS_TCTI) $(BIN)/demo -repo . -workdir ./state/demo

# Literal paths, no variables. An empty or mistyped variable in an rm -rf is
# not a risk worth taking to save a few characters.
clean:
	rm -rf ./bin
	rm -f ./bpf/egress_deny.bpf.o
	rm -rf ./testdata/bundles
	rm -rf ./state

# R1.2: the grading images as a portable artifact. verify is the negative test —
# it blackholes the registry and requires the image to still run.
image-inventory:
	@scripts/r12-image-bundle.sh inventory

image-bundle:
	@sudo scripts/r12-image-bundle.sh export

image-verify:
	@sudo scripts/r12-image-bundle.sh verify
