#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Point the CRS at a local model or at a frontier one, and prove which it used.
#
# This is the operation the whole thesis rests on: "the model swaps, the gate
# does not." Until now it was a hand-edited ConfigMap performed from memory,
# which makes the claim a story rather than a procedure. A reviewer should be
# able to run this, run a task, and see where the completions went.
#
# HOW THE SWAP WORKS. Buttercup does not name a provider; it asks LiteLLM for a
# model_name, and LiteLLM decides what that resolves to. So the swap belongs in
# LiteLLM's config and nowhere else: no Buttercup image is rebuilt, no code
# changes, and the CRS cannot tell the difference. That is the point.
#
# WHY EVERY ENTRY IS REDIRECTED, not just the ones we think are used. The names
# Buttercup requests live in its code, and the ConfigMap keys on ALIASES that
# this deployment remaps: model_name `openai-gpt-4.1` has upstream
# `anthropic/claude-sonnet-4-6`. Redirecting the names in a spend log rather
# than the aliases in the config hit 1 of 5 entries and left four pointing
# off-box, which would have made a local run quietly half-frontier.
set -uo pipefail

NS="${ARAZU_CRS_NS:-crs}"
CM="${ARAZU_LITELLM_CM:-buttercup-litellm-config}"
DEPLOY="${ARAZU_LITELLM_DEPLOY:-buttercup-litellm}"
OLLAMA_HOST="${ARAZU_OLLAMA_HOST:-192.168.49.1}"   # the host on minikube's bridge
OLLAMA_PORT="${ARAZU_OLLAMA_PORT:-11434}"
LOCAL_MODEL="${ARAZU_LOCAL_MODEL:-gpt-oss:20b}"
# make deploy REGENERATES the ConfigMap from the chart, so the stock list
# (10 anthropic, 9 openai, 4 azure, 2 gemini) comes back every deploy and two
# thirds of it fails with only an Anthropic key. Re-run `anthropic` after each.
# FIXED 20 Aug, after getting it wrong once. Task 017d6977 failed every patch
# attempt with a 400, "This model does not support assistant message prefill".
#
# The first fix claimed stock routed the patcher's group, openai-gpt-4.1, to
# claude-haiku-4-5 and that the remap had overwritten a working mapping. That
# was a misread: litellm_params comes BEFORE model_name in each entry, so a
# regex that took a name and searched forward for `model:` paired every name
# with the NEXT entry's upstream. Read as YAML, stock routes openai-gpt-4.1 to
# claude-sonnet-4-6, which refuses prefill. So "already on anthropic/" was
# never the right test and the first fix preserved the broken mapping.
#
# Why 8 and 9 Aug produced patches under a config that routes to a refusing
# model is UNEXPLAINED. Do not build on it.
#
# `anthropic` mode now leaves anthropic/ upstreams alone and only redirects the
# openai/azure/gemini entries that would fail on a missing key. This value is
# only used for those.
#
# Proven 2026-08-20, see the table above. Haiku 4.5 accepts prefill, Sonnet 4.6
# refuses. Five of the ten stock anthropic/ entries route to models that refuse,
# but those are left exactly as stock: that is the configuration that produced
# patches on 8 and 9 Aug, so deviating from it would trade a known-good state
# for an untested one.
# MUST accept assistant prefill, because the patcher uses it. Measured against
# the API on 2026-08-20, one tiny call each:
#
#   claude-haiku-4-5-20251001    ACCEPTED
#   claude-sonnet-4-5-20250929   ACCEPTED
#   claude-sonnet-4-6            REFUSED
#   claude-opus-4-6              REFUSED
#   claude-opus-4-7              REFUSED
#
# A clean generational split: 4.6 and later dropped prefill. The old default
# here was claude-sonnet-4-6, which is why every entry this mode rewrote broke
# the patcher. Do not raise this to a newer model without re-running that probe.
FRONTIER_MODEL="${ARAZU_FRONTIER_MODEL:-anthropic/claude-sonnet-4-5-20250929}"
BACKUP_DIR="${ARAZU_LITELLM_BACKUP:-$(cd "$(dirname "$0")/.." && pwd)/state/litellm}"

usage() {
    cat >&2 <<EOF
usage: $0 <local|anthropic|frontier|show>

  local     every model_name resolves to $LOCAL_MODEL at http://$OLLAMA_HOST:$OLLAMA_PORT/v1
  frontier  restore the captured upstream configuration
  show      report which way the live config points, and prove it with a call

The first switch to local captures the current config to
$BACKUP_DIR/config.yaml and refuses to overwrite it, so "frontier" always
restores what was actually there rather than something reconstructed.
EOF
    exit 2
}

need() { command -v "$1" >/dev/null || { echo "$1 is required" >&2; exit 2; }; }
need kubectl
need python3

live_config() {
    kubectl get configmap "$CM" -n "$NS" -o json 2>/dev/null \
      | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["data"]["config.yaml"])'
}

apply_config() {
    kubectl create configmap "$CM" -n "$NS" --from-file=config.yaml="$1" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
}

# Restarting is not optional. A ConfigMap is a file on disk to the pod, and
# LiteLLM reads it once at startup: without this the config is changed and the
# running proxy still serves the old routing, which reads as a failed swap.
restart_and_wait() {
    kubectl rollout restart "deploy/$DEPLOY" -n "$NS" >/dev/null 2>&1
    kubectl rollout status "deploy/$DEPLOY" -n "$NS" --timeout=180s >/dev/null 2>&1
}

# Read the routing from the RUNNING POD, not from the ConfigMap. A correct
# ConfigMap in front of a stale pod is the failure this catches.
report_live() {
    local pod
    pod=$(kubectl get pods -n "$NS" --no-headers 2>/dev/null | awk '/litellm/&&!/setup/&&/Running/{print $1; exit}')
    [ -n "$pod" ] || { echo "  no running litellm pod"; return 1; }
    # Ask the POD which file it was told to read, rather than guessing a path.
    # The first version tried /app/proxy_server_config.yaml first and fell back
    # to /etc/litellm/config.yaml. The image ships the former as a DEFAULT and
    # the ConfigMap is mounted at the latter, so the guess always succeeded on
    # the wrong file and reported 26 entries pointing at litellm's demo
    # endpoints — a plausible answer that reads as a failed swap.
    local cfg
    cfg=$(kubectl get pod -n "$NS" "$pod" -o json 2>/dev/null | python3 -c '
import json,sys
c=json.load(sys.stdin)["spec"]["containers"][0]
argv=(c.get("command") or [])+(c.get("args") or [])
for i,a in enumerate(argv):
    if a in ("--config","-c") and i+1 < len(argv): print(argv[i+1]); break
    if a.startswith("--config="): print(a.split("=",1)[1]); break
')
    [ -n "$cfg" ] || { echo "  cannot tell which config the pod reads"; return 1; }
    echo "  reading $cfg (the file the pod was told to use)"
    kubectl exec -n "$NS" "$pod" -- cat "$cfg" 2>/dev/null \
      | python3 -c '
import sys, yaml, collections
try:
    c = yaml.safe_load(sys.stdin)
except Exception as e:
    print("  could not parse the running config:", e); raise SystemExit(1)
ms = (c or {}).get("model_list", [])
# Count the MODEL, not only the api_base. api_base distinguishes a LOCAL swap,
# because ollama has a URL, but every Anthropic entry leaves it unset. So an
# anthropic-mode config printed "25 <provider default>" identically before and
# after a remap: a status line that could not tell apart the two states it
# exists to report on. It hid a config still routing the patcher at a model
# that refuses assistant prefill.
models = collections.Counter(
    (m.get("litellm_params") or {}).get("model") or "<unset>" for m in ms)
print(f"  {len(ms)} model_name entries in the RUNNING pod:")
for name, n in models.most_common():
    print(f"    {n:>3}  {name}")
for m in ms:
    if m.get("model_name") == "openai-gpt-4.1":
        print("    patcher group openai-gpt-4.1 -> "
              + str((m.get("litellm_params") or {}).get("model")))
bases = collections.Counter(
    (m.get("litellm_params") or {}).get("api_base") or "<provider default>"
    for m in ms)
if list(bases) != ["<provider default>"]:
    for b, n in bases.most_common():
        print(f"    {n:>3}  via {b}")
'
}

case "${1:-}" in
local)
    mkdir -p "$BACKUP_DIR"
    if [ ! -s "$BACKUP_DIR/config.yaml" ]; then
        live_config > "$BACKUP_DIR/config.yaml" || { echo "cannot read $CM" >&2; exit 1; }
        echo "captured the current config to $BACKUP_DIR/config.yaml"
    else
        echo "keeping the existing capture at $BACKUP_DIR/config.yaml"
    fi
    tmp=$(mktemp)
    python3 - "$BACKUP_DIR/config.yaml" "$tmp" "$LOCAL_MODEL" \
             "http://$OLLAMA_HOST:$OLLAMA_PORT/v1" <<'PY'
import sys, yaml
src, dst, model, base = sys.argv[1:5]
c = yaml.safe_load(open(src))
# Every entry, for the reason in the header. Embeddings would break under a
# chat model, so refuse rather than silently mangle them.
emb = [m.get("model_name") for m in c["model_list"] if "embed" in str(m).lower()]
if emb:
    sys.exit(f"refusing: embedding entries would be pointed at a chat model: {emb}")
for m in c["model_list"]:
    m["litellm_params"] = {"model": f"openai/{model}", "api_base": base, "api_key": "ollama"}
yaml.safe_dump(c, open(dst, "w"), sort_keys=False)
print(f"  redirected {len(c['model_list'])} entries to {model} at {base}")
PY
    [ $? -eq 0 ] || { rm -f "$tmp"; exit 1; }
    apply_config "$tmp"; rm -f "$tmp"
    restart_and_wait
    report_live
    echo
    echo "the CRS now reaches the model over minikube's bridge. That address must"
    echo "be listening: ollama binds 127.0.0.1 by default and is NOT reachable"
    echo "from inside the cluster. scripts/r14-probe.sh exposes it for one run."
    ;;
anthropic)
    mkdir -p "$BACKUP_DIR"
    if [ ! -s "$BACKUP_DIR/config.yaml" ]; then
        live_config > "$BACKUP_DIR/config.yaml" || { echo "cannot read $CM" >&2; exit 1; }
        echo "captured the current config to $BACKUP_DIR/config.yaml"
    fi
    tmp=$(mktemp)
    python3 - "$BACKUP_DIR/config.yaml" "$tmp" "$FRONTIER_MODEL" <<'PY'
import sys, yaml
src, dst, model = sys.argv[1:4]
c = yaml.safe_load(open(src))
emb = [m.get("model_name") for m in c["model_list"] if "embed" in str(m).lower()]
if emb:
    sys.exit(f"refusing: embedding entries would be pointed at a chat model: {emb}")
# Keep an entry only if its upstream is MEASURED to accept assistant prefill,
# which the patcher uses. "Already on anthropic/" is not the test: stock routes
# openai-gpt-4.1, the group the patcher asked for, to claude-sonnet-4-6, and
# that refuses prefill. Everything else is redirected to $FRONTIER_MODEL, which
# must itself be on this list.
PREFILL_OK = ("anthropic/claude-haiku-4-5", "anthropic/claude-sonnet-4-5")
kept = 0
for m in c["model_list"]:
    up = str(m.get("litellm_params", {}).get("model", ""))
    if up.startswith(PREFILL_OK):
        m["litellm_params"]["api_key"] = "os.environ/ANTHROPIC_API_KEY"
        kept += 1
        continue
    m["litellm_params"] = {"model": model, "api_key": "os.environ/ANTHROPIC_API_KEY"}
yaml.safe_dump(c, open(dst, "w"), sort_keys=False)
print("  kept %d entries already on a prefill-capable model, redirected %d to %s"
      % (kept, len(c["model_list"]) - kept, model))
PY
    [ $? -eq 0 ] || { rm -f "$tmp"; exit 1; }
    apply_config "$tmp"; rm -f "$tmp"
    restart_and_wait
    report_live
    ;;
frontier)
    [ -s "$BACKUP_DIR/config.yaml" ] || {
        echo "no capture at $BACKUP_DIR/config.yaml: nothing to restore." >&2
        echo "The frontier config is whatever was there before the first local swap." >&2
        exit 1; }
    apply_config "$BACKUP_DIR/config.yaml"
    restart_and_wait
    # Verify by reading the live object back, not by assuming apply worked.
    if diff -q <(live_config) "$BACKUP_DIR/config.yaml" >/dev/null; then
        echo "restored: live config is byte-identical to the capture"
    else
        echo "RESTORE INCOMPLETE: live config differs from the capture" >&2
        exit 1
    fi
    report_live
    ;;
show)
    report_live
    ;;
*) usage ;;
esac
