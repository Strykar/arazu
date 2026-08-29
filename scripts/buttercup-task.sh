#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Submit a target to the CRS.
#
# WHAT A TARGET IS. Buttercup ingests six fields: a repository with a base and a
# head ref, and an oss-fuzz project to build the harness from. It does not need
# a bespoke "challenge" — challenge-004-nginx-cp is just one repository that
# happens to carry an injected bug. Anything oss-fuzz can already build is a
# valid target, and the upstream tree ships over 1300 of them (curl, openssl,
# sqlite3, ffmpeg, systemd, libxml2 ...).
#
# So the preparation an invitee needs for most real software is NONE: name the
# repo and the project. Onboarding is only required for code oss-fuzz does not
# already know, and then it is four files (Dockerfile, build.sh, project.yaml,
# a harness) by oss-fuzz's own documented process, not something invented here.
#
# WHY base AND head. The pair is what lets the CRS diff and lets us attribute a
# finding: base is the tree before the change under test, head is after. For a
# challenge they bracket the injected bug; for real software they can bracket a
# release, a PR, or be the same commit if you want the whole tree fuzzed.
set -uo pipefail

NS="${ARAZU_CRS_NS:-crs}"
UI_SVC="${ARAZU_UI_SVC:-buttercup-ui}"
UI_PORT="${ARAZU_UI_PORT:-1323}"
LOCAL_PORT="${ARAZU_UI_LOCAL_PORT:-31323}"
DURATION="${ARAZU_TASK_DURATION:-1800}"

usage() {
    cat >&2 <<'EOF'
usage: buttercup-task.sh <repo-url> <base-ref> <head-ref> <oss-fuzz-project> [fuzz-tooling-url] [fuzz-tooling-ref]

  repo-url          the code to analyse
  base-ref          commit before the change under test
  head-ref          commit or branch after it (may equal base-ref)
  oss-fuzz-project  a directory name under <fuzz-tooling>/projects/

  fuzz-tooling-url  default https://github.com/google/oss-fuzz
  fuzz-tooling-ref  default master

Examples:

  # the libpng challenge, exactly as the corpus case records it
  buttercup-task.sh https://github.com/tob-challenges/example-libpng \
      5bf8da2d7953974e5dfbd778429c3affd461f51a challenges/lp-delta-01 libpng \
      https://github.com/trail-of-forks/oss-fuzz fix-libpng

  # real software, no preparation: upstream oss-fuzz already knows curl
  buttercup-task.sh https://github.com/curl/curl master master curl

  # a case from this corpus, with its recorded pins
  buttercup-task.sh --from-case corpus/cases/libpng/iccp-keyword.yaml
EOF
    exit 2
}

need() { command -v "$1" >/dev/null || { echo "$1 is required" >&2; exit 2; }; }
need kubectl
need curl
need python3

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Submitting from a case file keeps the pins in ONE place. A task typed by hand
# against a case is a second copy of those commits, and the two agree until
# someone corrects the case and not the command.
if [ "${1:-}" = "--from-case" ]; then
    [ -n "${2:-}" ] || usage
    read -r URL BASE HEAD PROJECT TOOL_URL TOOL_REF <<<"$(python3 - "$2" <<'PY'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
s = c.get("source") or {}
missing = [k for k in ("cp_repo",) if not s.get(k)]
if missing:
    sys.exit(f"case declares no {missing}")
print(s["cp_repo"],
      s.get("base_commit") or s.get("cp_commit", ""),
      s.get("src_ref") or s.get("src_commit", ""),
      s.get("fuzz_tooling_project") or c.get("target", ""),
      s.get("fuzz_tooling_repo", "https://github.com/google/oss-fuzz"),
      s.get("fuzz_tooling_ref", "master"))
PY
)"
    [ -n "$URL" ] || exit 1
    echo "from case $2:"
else
    [ $# -ge 4 ] || usage
    URL=$1; BASE=$2; HEAD=$3; PROJECT=$4
    TOOL_URL="${5:-https://github.com/google/oss-fuzz}"
    TOOL_REF="${6:-master}"
fi

printf '  repo    %s\n  base    %s\n  head    %s\n  project %s\n  tooling %s @ %s\n' \
    "$URL" "$BASE" "$HEAD" "$PROJECT" "$TOOL_URL" "$TOOL_REF"

# Say which model this will run against BEFORE spending an hour on it. A task
# submitted while LiteLLM points somewhere unintended is the expensive mistake
# here, and it is invisible until the spend log or the ollama log says so.
echo
"$REPO_ROOT/scripts/buttercup-model.sh" show 2>/dev/null | sed 's/^/  /' || true
echo

kubectl port-forward -n "$NS" "svc/$UI_SVC" "$LOCAL_PORT:$UI_PORT" >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null' EXIT
sleep 3

body=$(python3 - "$URL" "$BASE" "$HEAD" "$TOOL_URL" "$TOOL_REF" "$PROJECT" "$DURATION" <<'PY'
import json, sys
u, b, h, tu, tr, p, d = sys.argv[1:8]
print(json.dumps({
    "challenge_repo_url": u,
    "challenge_repo_base_ref": b,
    "challenge_repo_head_ref": h,
    "fuzz_tooling_url": tu,
    "fuzz_tooling_ref": tr,
    "fuzz_tooling_project_name": p,
    "duration": int(d),
}))
PY
)

resp=$(curl -sS --max-time 120 -X POST "http://127.0.0.1:$LOCAL_PORT/webhook/trigger_task" \
        -H 'Content-Type: application/json' -d "$body" 2>&1)
echo "$resp" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    print("  unexpected response:", raw[:300]); raise SystemExit(1)
msg = d.get("message", raw)
print("  ", msg)
' || { echo "  submission failed" >&2; exit 1; }

cat <<EOF

Watch it work:
  kubectl logs -n $NS deploy/buttercup-patcher -f
  kubectl logs -n $NS deploy/buttercup-fuzzer-bot -f

When it produces a patch, the gate is what decides whether to believe it:
  ./corpus/grade-patch.sh <case-id> <patch-file> <label>
EOF
