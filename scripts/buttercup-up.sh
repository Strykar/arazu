#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bring the CRS up and report the truth about whether it came up.
#
# WHY THIS EXISTS AND NOT JUST `make deploy`. Buttercup's own `make wait-crs`
# printed "All CRS pods are running" and exited 0 during a cold bring-up while
# buttercup-registry-cache was in CrashLoopBackOff. A readiness check that
# passes with a dead pod is worse than none: it teaches you to skip looking.
# This checks pod state itself and names what failed.
#
# PRECONDITION IT CHECKS FIRST, because it cost an hour to find. The registry
# cache proxies ghcr.io and PANICS at startup if it cannot resolve it. Cluster
# DNS is therefore a hard prerequisite, not something to discover from a stack
# trace. On this box it broke because no dnsmasq was running, so the node's
# resolv.conf pointed at 192.168.49.1:53, which refuses.
set -uo pipefail

NS="${ARAZU_CRS_NS:-crs}"
BUTTERCUP="${ARAZU_BUTTERCUP_DIR:-/var/lib/arazu-corpus/buttercup}"
TIMEOUT="${ARAZU_UP_TIMEOUT:-1800}"

need() { command -v "$1" >/dev/null || { echo "$1 is required" >&2; exit 2; }; }
need kubectl; need minikube

echo "== cluster =="
if ! minikube status 2>/dev/null | grep -q 'kubelet: Running'; then
    echo "  starting minikube"
    minikube start >/dev/null 2>&1 || { echo "  minikube would not start" >&2; exit 1; }
fi
echo "  up: $(kubectl config current-context 2>/dev/null)"

# --- cluster DNS, before anything depends on it ------------------------------
echo "== cluster DNS =="
dns=$(kubectl run arazu-dnscheck --rm -i --restart=Never --image=busybox:1.36 \
        --timeout=120s -n default -- nslookup ghcr.io 2>/dev/null \
      | awk '/^Address: /{print $2; exit}')
if [ -n "$dns" ]; then
    echo "  pods resolve ghcr.io -> $dns"
else
    cat >&2 <<'EOF'
  PODS CANNOT RESOLVE ghcr.io.

  Do not deploy yet. The registry cache proxies ghcr.io and panics at startup
  when it cannot reach it, and several components pull through it.

  Usual cause: CoreDNS forwards to the node's /etc/resolv.conf, which on a
  minikube docker node points at the host bridge address (192.168.49.1). If
  nothing is serving DNS there — a stopped dnsmasq, for instance — that
  forward is dead.

  Check:  dig @192.168.49.1 ghcr.io          # connection refused == the cause
  Fix:    point CoreDNS at a resolver that answers, keeping its block intact:
          kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}'
          # replace the server list in "forward . <servers> {" and re-apply
EOF
    exit 1
fi

# --- deploy -------------------------------------------------------------------
echo "== deploy =="
[ -f "$BUTTERCUP/deployment/env" ] || {
    echo "  no $BUTTERCUP/deployment/env — run 'make setup-local' in the CRS tree first" >&2
    exit 1; }
# Uninstall a live release BEFORE redeploying. Deploying over one is how the
# first Gate #1 run wedged, and it has been an outstanding manual chore since.
# A chore nobody automates is a chore somebody forgets at the worst moment.
if helm status buttercup -n "$NS" >/dev/null 2>&1; then
    echo "  a buttercup release is already installed: uninstalling before redeploy"
    helm uninstall buttercup -n "$NS" >/dev/null 2>&1 \
        && echo "  uninstalled" || echo "  UNINSTALL FAILED, deploying over it anyway is unsafe" >&2
    # Helm returns before the pods are gone, and a redeploy that races the
    # teardown is the same wedge by a different route.
    for _ in $(seq 1 60); do
        [ -z "$(kubectl get pods -n "$NS" --no-headers 2>/dev/null)" ] && break
        sleep 2
    done
    echo "  namespace drained: $(kubectl get pods -n "$NS" --no-headers 2>/dev/null | wc -l) pods left"
else
    echo "  no existing release, deploying clean"
fi

( cd "$BUTTERCUP" && FORCE=true timeout "$TIMEOUT" make deploy ) >/tmp/arazu-up.log 2>&1
echo "  make deploy exit: $? (log: /tmp/arazu-up.log)"

# --- the readiness check that make wait-crs did not do ------------------------
echo "== readiness =="
deadline=$(( $(date +%s) + 600 ))
while :; do
    bad=$(kubectl get pods -n "$NS" --no-headers 2>/dev/null \
          | awk '$3!="Running" && $3!="Completed" {print $1"("$3")"}')
    [ -z "$bad" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && break
    sleep 10
done

kubectl get pods -n "$NS" --no-headers 2>/dev/null | awk '{print $3}' | sort | uniq -c | sed 's/^/  /'
if [ -n "$bad" ]; then
    echo
    echo "  NOT READY: $bad" >&2
    for p in $(kubectl get pods -n "$NS" --no-headers | awk '$3!="Running"&&$3!="Completed"{print $1}'); do
        echo "  --- $p ---" >&2
        kubectl logs -n "$NS" "$p" --tail=6 2>/dev/null | sed 's/^/    /' >&2
    done
    exit 1
fi
echo
echo "ready. Next: ./scripts/buttercup-model.sh show, then buttercup-task.sh"
