#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# R1.4 probe harness: expose the local model to the cluster for the duration of
# ONE probe, then take it away again.
#
# The exposure is disposable BY CONSTRUCTION, not by discipline. The firewall
# rule and the ollama bind are both added here and removed in an EXIT trap, so
# they come down on success, on failure, and on Ctrl-C. A rule that has to be
# remembered is a rule that quietly becomes permanent — and then the deployment
# story depends on a host configuration that does not ship to the organisers'
# hardware.
#
# Why a rule and not a pod. The honest air-gapped arrangement is ollama running
# INSIDE the cluster, needing no host exposure at all — the same shape as
# R1.1(d), the model inside the boundary rather than reachable across it. That
# costs GPU passthrough into minikube, which is real work. R1.4's pre-decision
# is armed and unfired: if Buttercup cannot be made egress-free, the air-gapped
# deployment runs the acceptance engine alone and the passthrough work is spent
# on an abandoned path. So the cheap disposable probe runs first and decides
# whether the expensive permanent arrangement is warranted.
#
# Usage: r14-probe.sh <command...>   — runs the command with the model exposed.
set -euo pipefail

BRIDGE_SUBNET="${ARAZU_MINIKUBE_SUBNET:-192.168.49.0/24}"
HOST_ADDR="${ARAZU_MINIKUBE_HOST:-192.168.49.1}"
PORT=11434
BRIDGE_IF="${ARAZU_MINIKUBE_IF:-$(ip -o -4 addr show | awk '/192.168.49.1\//{print $2; exit}')}"
DROPIN=/etc/systemd/system/ollama.service.d/arazu-r14-probe.conf

[ "$(id -u)" -eq 0 ] || { echo "needs root: adds a firewall rule and restarts ollama" >&2; exit 2; }

added_rule=0
restore() {
    if [ "$added_rule" -eq 1 ]; then
        nft delete rule inet filter input handle "$RULE_HANDLE" 2>/dev/null || true
    fi
    rm -f "$DROPIN"
    systemctl daemon-reload
    systemctl restart ollama || true
    # Confirm the host is as it was found, and say so, because a revert that
    # silently failed leaves exactly the state this script exists to avoid.
    sleep 2
    if ss -ltn | grep -q "127.0.0.1:$PORT"; then
        echo "reverted: ollama back on 127.0.0.1:$PORT, probe rule removed"
    else
        echo "REVERT INCOMPLETE: ollama is not on 127.0.0.1:$PORT — check by hand" >&2
    fi
}
trap restore EXIT

# 1. bind the model to the cluster-facing address only. Not 0.0.0.0: that is
#    reachable from anything routing to the host, a materially wider surface.
mkdir -p "$(dirname "$DROPIN")"
cat > "$DROPIN" <<EOF
[Service]
Environment=OLLAMA_HOST=$HOST_ADDR:$PORT
EOF
systemctl daemon-reload
systemctl restart ollama
sleep 3

# 2. permit inbound from the cluster subnet only, for this port only.
# INSERT, not add. The input chain's policy is drop and a rate-limited
# `reject with icmpx admin-prohibited` sits near its end, so an APPENDED accept
# never matches — the first run added the rule successfully and the cluster
# still could not connect. This mirrors the existing "VM to Ollama Override"
# rule the host already carries for a libvirt guest, which sits near the top.
nft insert rule inet filter input iifname "$BRIDGE_IF" ip saddr "$BRIDGE_SUBNET" \
    tcp dport $PORT accept comment "arazu-r14-probe"
RULE_HANDLE=$(nft -a list chain inet filter input | awk '/arazu-r14-probe/{print $NF}' | tail -1)
added_rule=1
echo "exposed $HOST_ADDR:$PORT to $BRIDGE_SUBNET (rule handle $RULE_HANDLE)"

# 3. self-test: the cluster must actually reach it, or whatever runs next fails
#    for a reason that has nothing to do with the question being asked.
#
# minikube runs as the LOGIN USER — its profile lives in that user's home — but
# this script runs as root for the firewall rule. Invoking `minikube ssh`
# directly as root reports "Profile not found", which the first version reported
# as "the cluster still cannot reach the model". That message named a cause the
# check had not established: the self-test that exists to prevent unattributable
# failures was producing one. Separate the two outcomes below, because
# "the harness could not ask" and "the cluster answered no" need different fixes.
. "$(dirname "$0")/lib/as-user.sh"

if ! as_user minikube status >/dev/null 2>&1; then
    echo "SELF-TEST INCONCLUSIVE: no reachable minikube cluster as user $RUN_AS." >&2
    echo "Nothing is claimed about the exposure; fix the cluster and re-run." >&2
    exit 1
fi
if ! as_user minikube ssh -- "curl -sf -m 5 http://$HOST_ADDR:$PORT/api/version" >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: the cluster cannot reach $HOST_ADDR:$PORT." >&2
    echo "The cluster is up, so this is the exposure: check the bind and the rule." >&2
    exit 1
fi
echo "self-test: the cluster reaches the model"

"$@"
