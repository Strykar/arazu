#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Establish, by running them, which class each challenge bad_patch belongs to.
#
# The case files ship these candidates as `label: unclassified` with a null
# expected_gate_reason, because the corpus is the gate's oracle and an oracle
# that assumed its answers would grade every gate correct. The class is read off
# the ladder instead:
#
#   PoV still fires        -> nonfunctional-plausible, revert-attribute-fail
#   PoV stops, a test breaks -> regression-introducing, new-test-failure
#
# Anything else stays unclassified and is reported. In particular a bad_patch
# that reaches level 3 is indistinguishable from the reference fix under this
# grader, which is a finding about the grader and must not be quietly filed as a
# class.
#
# new-test-failure rather than new-sanitizer-finding: these patches break a
# passing test and produce no sanitizer output at all, and naming the wrong one
# would send a reviewer looking for evidence that was never generated.
#
# Each CPV needs its own baseline, taken on that CPV's good_patch tree with its
# private tests mounted, or the comparison has nothing to subtract. Baselines
# already on disk are reused; pass -f to retake them.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CP="${CP:-/var/lib/arazu-corpus/nginx/challenge-004-nginx-cp}"
OUT="$HERE/reports"
RESULTS="${RESULTS:-$OUT/classification.jsonl}"
LOG="${LOG:-$OUT/classification.log}"

force=false
[ "${1:-}" = "-f" ] && force=true

# Overridable so one CPV can be re-run on its own, which is also how the sweep
# is smoke-tested before an hour of compute is committed to it.
if [ -n "${CPVS:-}" ]; then
    read -ra CPVS <<< "$CPVS"
else
    mapfile -t CPVS < <(cd "$CP/.internal_only" && ls -d cpv*/ 2>/dev/null | tr -d '/' | sort -V)
fi
[ ${#CPVS[@]} -gt 0 ] || { echo "no CPVs under $CP/.internal_only" >&2; exit 2; }

say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }

# Resumable: a CPV already recorded is not re-run, so an interrupted sweep can
# be restarted without spending an hour repeating what it already measured.
done_cpvs=""
[ -f "$RESULTS" ] && done_cpvs=$(jq -r '.cpv' "$RESULTS" 2>/dev/null | tr '\n' ' ')

say "classifying ${#CPVS[@]} bad patches"

for cpv in "${CPVS[@]}"; do
    case " $done_cpvs " in *" $cpv "*) say "$cpv already recorded, skipping"; continue ;; esac

    bad="$CP/.internal_only/$cpv/patches/nginx/bad_patch.diff"
    if [ ! -f "$bad" ]; then
        say "$cpv ships no bad_patch"
        jq -nc --arg c "$cpv" '{cpv:$c, label:"unclassified", expected_gate_reason:null,
                                note:"the challenge ships no bad_patch for this CPV"}' >> "$RESULTS"
        continue
    fi

    baseline="$OUT/tests-baseline-$cpv.json"
    if $force || [ ! -f "$baseline" ]; then
        say "$cpv taking baseline"
        if ! "$HERE/tests-baseline.sh" "$cpv" >>"$LOG" 2>&1; then
            say "$cpv baseline failed; cannot grade it"
            jq -nc --arg c "$cpv" '{cpv:$c, label:"unclassified", expected_gate_reason:null,
                                    note:"baseline could not be taken, so nothing can be subtracted"}' >> "$RESULTS"
            continue
        fi
    fi

    say "$cpv grading bad_patch"
    graded=$("$HERE/grade-patch.sh" "$cpv" "$bad" "$cpv-aixcc-bad" 2>>"$LOG")
    if [ -z "$graded" ]; then
        say "$cpv grader produced no result"
        jq -nc --arg c "$cpv" '{cpv:$c, label:"unclassified", expected_gate_reason:null,
                                note:"the grader produced no result"}' >> "$RESULTS"
        continue
    fi

    level=$(jq -r '.level' <<<"$graded")
    nfail=$(jq -r '.new_failures | length' <<<"$graded")

    # The mapping. Written as a case rather than a lookup so the unhandled
    # outcomes are visibly unhandled instead of defaulting into a class.
    case "$level" in
      1) label=nonfunctional-plausible; reason=revert-attribute-fail
         note="the patch applies and builds, and the PoV still fires" ;;
      2) if [ "$nfail" -gt 0 ]; then
             label=regression-introducing; reason=new-test-failure
             note="the PoV stops firing and $(jq -r '.new_failures|join(", ")' <<<"$graded") newly fails"
         else
             label=unclassified; reason=null
             note="the PoV stopped but no test result was recorded; unproven, not a class"
         fi ;;
      3) label=unclassified; reason=null
         note="ACCEPTED: this bad patch is indistinguishable from the reference fix under this grader, which is a finding about the grader" ;;
      *) label=unclassified; reason=null
         note="did not reach a gradeable state: $(jq -r '.note' <<<"$graded")" ;;
    esac

    jq -nc --argjson g "$graded" --arg c "$cpv" --arg l "$label" --arg n "$note" \
           --argjson r "$([ "$reason" = null ] && echo null || jq -Rn --arg x "$reason" '$x')" \
       '{cpv:$c, label:$l, expected_gate_reason:$r, note:$n,
         level:$g.level, new_failures:$g.new_failures, apply_mode:$g.apply_mode,
         recorded_tests_exitcode:$g.recorded_tests_exitcode}' >> "$RESULTS"
    say "$cpv -> $label ${reason:-}"
done

say "--- summary ---"
jq -rs 'group_by(.label)[] | "\(.[0].label): \(length) (\([.[].cpv]|join(", ")))"' "$RESULTS" | tee -a "$LOG"
unclassified=$(jq -rs '[.[]|select(.label=="unclassified")]|length' "$RESULTS")
[ "$unclassified" -eq 0 ] || say "$unclassified still unclassified; each is reported above with why"
