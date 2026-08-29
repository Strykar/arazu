#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Validate every YAML under corpus/reports/ BY GLOB, not by name.
#
# The r11 predictions file was malformed from the moment it was written and only
# surfaced when a later append happened to trip the parser. The habit of
# validating existed — it had been applied to every append of the m2b file and
# never to the new one. A per-file habit generalises only if someone remembers;
# a glob generalises by default.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
for f in corpus/reports/*.yaml corpus/candidates/*.yaml corpus/cases/*/*.yaml; do
    [ -e "$f" ] || continue
    if ! python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1]))" "$f" 2>/dev/null; then
        echo "INVALID: $f" >&2
        python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1]))" "$f" 2>&1 | tail -2 >&2
        fail=1
    fi
done
[ $fail -eq 0 ] && echo "all report and corpus YAML parses"
exit $fail
