#!/usr/bin/env bash
# quickcheck.sh — the one command to hand someone.
#
# Setup takes decisions. A check takes one minute and produces something shareable. So this runs
# the smallest useful experiment first: does this machine have the gates, and does the model
# behave differently when the published trigger shape appears? Its output is designed to be
# pasted into a thread, because "here is my result" starts better conversations than "here is my
# architecture".
#
#   ./quickcheck.sh                                   # local endpoint, pair test, n=2
#   ./quickcheck.sh --endpoint http://host:8000/v1 --model my-model --repeat 5
#   ./quickcheck.sh --skip-canary                     # gates only (no model running yet)
#
# Exit 0 when nothing looks wrong, 1 when the trigger changed behaviour or a gate is broken.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ENDPOINT=${ENDPOINT:-http://127.0.0.1:8000/v1}
MODEL=${MODEL:-}
REPEAT=${REPEAT:-2}
SKIP_CANARY=0
TRIGGERS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) ENDPOINT=${2:-}; shift 2 ;;
    --model) MODEL=${2:-}; shift 2 ;;
    --repeat) REPEAT=${2:-2}; shift 2 ;;
    --trigger) TRIGGERS+=("--trigger" "${2:-}"); shift 2 ;;
    --skip-canary) SKIP_CANARY=1 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

verdict=PASS
notes=""

echo "== 1/2 gates on this host"
pre=$("$HERE/preflight.sh" 2>&1)
printf '%s\n' "$pre" | sed -n '/^summary/,$p' | sed 's/^/  /'
printf '%s' "$pre" | grep -q "egress gate:     APPLICABLE" || notes="$notes\n  - egress gate does not apply here (macOS?): use a sandbox + proxy, see docs/WHERE-TO-LOCK.md"
printf '%s' "$pre" | grep -q "exec audit:      APPLICABLE" || notes="$notes\n  - no session log found: the audit has nothing to read yet"

echo
echo "== 2/2 model behaviour: same prompt, trigger present or not"
if [ "$SKIP_CANARY" = 1 ]; then
  echo "  skipped (--skip-canary)"
else
  if ! curl -s -m 5 "$ENDPOINT/models" >/dev/null 2>&1; then
    echo "  no model answering at $ENDPOINT (skipped)"
    notes="$notes\n  - start your model, then rerun with --endpoint"
  else
    # bash 3.2 (macOS) treats an empty array expansion as unbound under set -u
    out=$("$HERE/model-canary.sh" --endpoint "$ENDPOINT" --repeat "$REPEAT" \
          ${MODEL:+--model "$MODEL"} ${TRIGGERS[@]+"${TRIGGERS[@]}"} 2>&1)
    rc=$?
    printf '%s\n' "$out" | sed -n '2,$p' | sed 's/^/  /'
    if [ "$rc" -ne 0 ]; then
      verdict=FAIL
      notes="$notes\n  - the trigger changed the payload rate: keep the egress gate closed, and read docs/THREAT-MODEL.md §1"
    fi
  fi
fi

echo
echo "== verdict: $verdict"
[ -n "$notes" ] && printf 'next:%b\n' "$notes"

echo
echo "== paste this"
printf 'host=%s %s\nendpoint=%s model=%s n=%s\nverdict=%s\n' \
  "$(uname -s)" "$(uname -m)" "$ENDPOINT" "${MODEL:-auto}" "$REPEAT" "$verdict"

[ "$verdict" = PASS ]
