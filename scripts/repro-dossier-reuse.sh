#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# F15: a reused dossier directory makes drive report one task's verdict backed by
# another task's sealed evidence.
#
# Two real Buttercup runs, two different patches, one dossier directory. Run 1
# grades task A. Run 2 is about task B, and reports ACCEPT at exit 0 with a
# content root measured over task A's dossier.
#
# Needs no TPM, no container and no network. Roughly ten seconds.
#
#   ./scripts/repro-dossier-reuse.sh
#
# Exits 0 if the defect reproduced, 1 if it did not (which would mean it is fixed).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

W=$(mktemp -d /var/tmp/arazu-f15-XXXXXX)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bin" "$W/dossier" "$W/captured"

TA=0e69cb3f-68e4-4f52-a056-303b63408157; RA=testdata/crsout/realrun/run-data-20260819143519
TB=a790c3ea-1c89-47e0-82fc-3b5c7cdfb425; RB=testdata/crsout/realrun/run-data-20260808230214
CASE=corpus/cases/libpng/iccp-keyword.yaml

echo "tree: $(git rev-parse HEAD)"
go build -o "$W/bin" ./cmd/gate ./cmd/drive ./cmd/seal-tool ./cmd/log-verify ./cmd/dossier

id_of() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['candidate_id'])" "$1"; }
sha_of() { python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(next(a['sha256'] for a in d.get('artifacts',[]) if a['role']=='candidate-patch'))" "$1"; }
field() { python3 -c "import json,sys;print(json.load(sys.stdin).get(sys.argv[1],''))" "$1"; }

echo
echo "== run 1: task A into a fresh dossier =="
o1=$("$W/bin/drive" -run "$RA" -task "$TA" -case "$CASE" -out "$W/captured" \
       -dossier "$W/dossier" -log "$W/audit.jsonl" -bin "$W/bin" -stage m0) && e1=0 || e1=$?
echo "   drive exit $e1, decision $(echo "$o1" | field decision)"
echo "   dossier names   $(id_of "$W/dossier/decision.json")"
root1=$(echo "$o1" | field content_root)

echo
echo "== run 2: task B into the SAME dossier directory =="
o2=$("$W/bin/drive" -run "$RB" -task "$TB" -case "$CASE" -out "$W/captured" \
       -dossier "$W/dossier" -log "$W/audit.jsonl" -bin "$W/bin" -stage m0) && e2=0 || e2=$?
d2=$(echo "$o2" | field decision); root2=$(echo "$o2" | field content_root)
echo "   drive exit $e2, decision $d2, task $(echo "$o2" | field task_id)"
echo "   dossier STILL names $(id_of "$W/dossier/decision.json")"
echo "   dossier patch sha   $(sha_of "$W/dossier/decision.json")"
echo "   task B patch sha    $(sha256sum "$RB/$TB"/patches/*.patch | cut -d' ' -f1)"

echo
echo "== corroborating observations =="
echo "   content root run 1 == run 2 : $([ "$root1" = "$root2" ] && echo yes || echo no)"
printf '   audit log entries           : %s\n' "$(wc -l < "$W/audit.jsonl")"
echo "   dossier verify              : $("$W/bin/dossier" verify "$W/dossier" | field outcome)"

echo
if [ "$d2" = "ACCEPT" ] && [ "$e2" = 0 ] && [ "$root1" = "$root2" ] \
   && [ "$(id_of "$W/dossier/decision.json")" = "crs-$TA-candidate" ]; then
    echo "REPRODUCED: drive reported ACCEPT exit 0 for task B over task A's dossier."
    exit 0
fi
echo "NOT REPRODUCED: behaviour differs from the 2026-08-31 observation."
exit 1
