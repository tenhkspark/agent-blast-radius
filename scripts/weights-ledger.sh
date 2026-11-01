#!/usr/bin/env bash
# weights-ledger.sh — pin what you downloaded, and notice when it moves.
#
# You did not train the checkpoint, so the only part of its provenance you control is knowing
# exactly which snapshot you are serving. This records, per host, the snapshot commit, the small
# files' hashes and the shard inventory, then compares against a baseline. Hashing 700 GB is not
# the point; noticing that the snapshot, the config or the shard set changed is.
#
#   ./weights-ledger.sh --baseline            # write the baseline (first run, or after a planned swap)
#   ./weights-ledger.sh                       # compare; exit 1 on drift
#   ./weights-ledger.sh --hosts "node1 node2" --path "~/models"
set -uo pipefail

HOSTS=${HOSTS:-}
PATH_GLOB=${PATH_GLOB:-"$HOME/.cache/huggingface/hub/models--*/snapshots/*"}
BASELINE=${BASELINE:-$HOME/.cache/agent-blast-radius/weights-baseline.tsv}
WRITE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --baseline) WRITE=1 ;;
    --hosts) HOSTS=${2:-}; shift ;;
    --path) PATH_GLOB=${2:-}; shift ;;
    --baseline-file) BASELINE=${2:-}; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

probe() {  # runs on the target: one line per snapshot
  for snap in $PATH_GLOB; do
    [ -d "$snap" ] || continue
    model=$(basename "$(dirname "$(dirname "$snap")")")
    rev=$(basename "$snap")
    small=$(find -L "$snap" -maxdepth 1 -type f \( -name '*.json' -o -name '*.index.json' -o -name '*.txt' \) 2>/dev/null | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256 | awk '{print $1}')
    shards=$(find -L "$snap" -maxdepth 1 -type f \( -name '*.safetensors' -o -name '*.bin' -o -name '*.gguf' \) 2>/dev/null | wc -l | tr -d ' ')
    bytes=$(du -skL "$snap" 2>/dev/null | awk '{print $1}')
    sizes=$(find -L "$snap" -maxdepth 1 -type f \( -name "*.safetensors" -o -name "*.bin" -o -name "*.gguf" \) -exec wc -c {} \; 2>/dev/null | awk '{print $1}' | sort | shasum -a 256 | awk '{print $1}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$model" "$rev" "${small:-none}" "${shards:-0}" "${bytes:-0}" "${sizes:-none}"
  done
}

collect() {
  if [ -n "$HOSTS" ]; then
    for h in $HOSTS; do
      # The glob may contain $HOME: send it unquoted so the remote shell expands it.
      { printf 'PATH_GLOB=%s\n' "$PATH_GLOB"; declare -f probe; printf 'probe\n'; } \
        | ssh -o BatchMode=yes -o ConnectTimeout=8 "$h" "bash -s" 2>/dev/null | sed "s|^|$h\t|"
    done
  else
    ( probe ) | sed "s|^|local\t|"
  fi
}

now=$(collect)
if [ -z "$now" ]; then echo "no snapshots found (path glob: $PATH_GLOB)" >&2; exit 2; fi

mkdir -p "$(dirname "$BASELINE")"
if [ "$WRITE" = 1 ] || [ ! -f "$BASELINE" ]; then
  printf '%s\n' "$now" > "$BASELINE"
  echo "baseline written: $BASELINE ($(wc -l < "$BASELINE" | tr -d ' ') snapshot rows)"
  exit 0
fi

# Only compare hosts that were actually collected this run, so a single-host check stays useful.
hosts_now=$(printf '%s\n' "$now" | cut -f1 | sort -u | paste -sd'|' -)
base_now=$(grep -E "^($hosts_now)	" "$BASELINE" || true)

if ! diff -q <(sort <<<"$base_now") <(sort <<<"$now") >/dev/null; then
  echo "weights changed since the baseline:" >&2
  diff <(sort <<<"$base_now") <(sort <<<"$now") | sed 's/^/  /' >&2
  echo "  if this was a planned swap: ./weights-ledger.sh --baseline" >&2
  exit 1
fi
echo "weights match the baseline"
