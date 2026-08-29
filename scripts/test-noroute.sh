#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# R1.3 — run the acceptance engine's own test suite with no route out.
#
# Why this exists. Development happens in the connected deployment, so the
# engine will acquire a dependency on egress sooner or later: a rules update, an
# OCSP check, NTP, telemetry inside some library. Discovered inside the air gap
# that is a bad day; discovered at commit time it is a one-line revert. This
# turns the containment envelope from a deployment mode into a test fixture,
# which is most of its value.
#
# SCOPE. The Go suite only. The container-driven grading (grade-patch.sh and
# friends) pulls images and drives podman, and would fail here for reasons that
# have nothing to do with an acquired egress dependency — a false positive that
# would teach everyone to ignore this gate. Whether Buttercup can run egress-free
# is R1.4's question, not this one.
#
# SELF-TEST FIRST. Before trusting a green suite, prove the namespace is
# actually isolating: a connect that must fail. If it succeeds, the harness is
# broken and a passing suite below would mean nothing — the same reason the
# coverage probe self-tests on the seed before any mutant is judged.
set -euo pipefail

NS="${ARAZU_CI_NS:-arazu-noroute}"
PROBE_IP="${ARAZU_PROBE_IP:-1.1.1.1}"

[ "$(id -u)" -eq 0 ] || { echo "needs root to create a network namespace" >&2; exit 2; }
RUN_AS="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"

cleanup() { ip netns del "$NS" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

# --- self-test: the namespace must actually deny egress -----------------------
probe='import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(5)
try:
    s.connect((sys.argv[1],443)); print("REACHED")
except OSError: print("denied")'
verdict=$(ip netns exec "$NS" python3 -c "$probe" "$PROBE_IP" 2>&1 | tail -1)
if [ "$verdict" != "denied" ]; then
    echo "SELF-TEST FAILED: the namespace reached $PROBE_IP ($verdict)." >&2
    echo "A suite passing in here would prove nothing about egress." >&2
    exit 1
fi
echo "self-test: namespace denies egress to $PROBE_IP"

# --- the suite, as the invoking user so the build cache is reachable ----------
# pkg/egress is excluded: its tests create their own namespaces and attach LSM
# programs, which is not what this gate is asking about and needs the host.
pkgs=$(sudo -u "$RUN_AS" env "PATH=$PATH" go list ./... | grep -v '/pkg/egress$')

# -count=1 disables the test cache. A cached PASS is a result from a previous
# run on a connected host: it proves nothing about egress, and it is exactly the
# shape of green that this gate exists to distrust.
if ip netns exec "$NS" sudo -u "$RUN_AS" env "PATH=$PATH" HOME="$(eval echo ~"$RUN_AS")" \
        GOPROXY=off GOFLAGS=-mod=mod go test -count=1 $pkgs; then
    echo "PASS: the acceptance engine's suite runs with no route out"
else
    echo "FAIL: the suite needs egress. Find the dependency now, not in the air gap." >&2
    exit 1
fi
