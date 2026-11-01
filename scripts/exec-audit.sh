#!/usr/bin/env bash
# exec-audit.sh — what actually ran, and where the box reached out.
#
# The paper's threat model assumes the command runs. So the useful question afterwards is
# not "was there a backdoor?" but "what executed, and where did it try to send/receive?".
# This collects both from the places that already record them, once a day, and stays quiet
# unless a command matches a known "fetch-and-run" or credential pattern.
#
# It only reads and records. It never blocks anything (that is egress-lock.sh's job).
#
#   ./exec-audit.sh                 # collect now
#   ./exec-audit.sh --since 7       # last 7 days
#   ./exec-audit.sh --alert-file /path/alerts.txt
#   ./exec-audit.sh --sess /path/to/sessions   # point at another harness store
#
# Adapters: this ships one for DeepSeek Harness session logs (JSONL, zstd-compressed).
# Other harnesses write different shapes; add an adapter rather than bending this one.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CONF=${AUDIT_CONF:-$HERE/../configs/audit.conf}
[ -f "$CONF" ] && . "$CONF"

STATE=${AUDIT_STATE:-$HERE/../state}
SESS=${AUDIT_SESS:-$HOME/.dsh/sessions}
DAYS=${AUDIT_DAYS:-2}
ALERTS=${AUDIT_ALERTS:-}
MAX_ALERTS=${MAX_ALERTS:-6}
ZSTD=${ZSTD:-$(command -v zstd || true)}

while [ $# -gt 0 ]; do
  case "$1" in
    --since) DAYS=${2:-2}; shift ;;
    --sess) SESS=${2:-}; shift ;;
    --alert-file) ALERTS=${2:-}; shift ;;
    --state) STATE=${2:-}; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$STATE/logs"
LOG=$STATE/logs/exec-audit.log
OUT=$STATE/exec-$(date +%Y%m).tsv
SEEN=$STATE/seen-callids.txt
EGRESS=$STATE/egress-$(date +%Y%m%d).txt

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

# Rotation: a year of daily collection should not turn into a million-line TSV.
rotate() {
  local f=$1 limit=${2:-52428800}
  [ -f "$f" ] || return 0
  local size
  size=$(wc -c < "$f" | tr -d ' ')
  if [ "$size" -gt "$limit" ]; then
    gzip -c "$f" > "$f.$(date +%Y%m%dT%H%M%S).gz" && : > "$f"
    log "rotated $f ($size bytes)"
  fi
}
rotate "$OUT"
if [ -f "$SEEN" ] && [ "$(wc -l < "$SEEN" | tr -d ' ')" -gt 200000 ]; then
  tail -n 100000 "$SEEN" > "$SEEN.tmp" && mv "$SEEN.tmp" "$SEEN"
  log "compacted seen-callids"
fi

if [ ! -d "$SESS" ]; then
  log "no session dir: $SESS (nothing to do)"
else
  RES=$(/usr/bin/python3 - "$SESS" "$DAYS" "$OUT" "$SEEN" "$ALERTS" "$MAX_ALERTS" "$ZSTD" <<'PY' 2>>"$LOG"
import json, os, re, subprocess, sys, time, datetime

sess_dir, days, out_path, seen_path, alert_path, max_alerts, zstd = sys.argv[1:8]
max_alerts = int(max_alerts or 6)
cutoff = time.time() - int(days) * 86400

# Each pattern is (label, all-of-needles). Order is priority: first match wins.
PATTERNS = [
    ("fetch_and_run_sh",   ("curl", "| sh")),
    ("fetch_and_run_bash", ("curl", "| bash")),
    ("fetch_and_run_wget", ("wget", "| sh")),
    ("base64_decode",      ("base64 -d",)),
    ("osascript_keystroke",("osascript",)),
    ("keychain_read",      ("security find-generic-password",)),
    ("keychain_dump",      ("security dump-keychain",)),
    ("history_wipe",       ("history -c",)),
    ("unquarantine",       ("xattr -d com.apple.quarantine",)),
    ("reverse_shell",      ("nc -e",)),
    ("ssh_key_read",       (".ssh/id_", "cat ")),
]
# chmod +x is normal in a project tree and suspicious in a staging area, so judge by place.
RISKY_DIRS = ("/tmp/", "/var/tmp/", "/Users/Shared/", "/Downloads/", "/Desktop/")

def short(sid):
    # Session dirs are long; a 16-char slice can collide. Keep the tail hash instead.
    import hashlib
    return hashlib.sha1(sid.encode()).hexdigest()[:10]

seen = set()
if os.path.exists(seen_path):
    with open(seen_path, encoding="utf-8", errors="ignore") as fh:
        seen = {l.rstrip("\n").split("\t")[0] for l in fh if l.strip()}

files = []
for root, _, names in os.walk(sess_dir):
    for n in names:
        if not n.endswith((".jsonl", ".jsonl.zstd")):
            continue
        p = os.path.join(root, n)
        try:
            if os.path.getmtime(p) >= cutoff:
                files.append(p)
        except OSError:
            pass

rows, flags, new_keys = [], [], []
for p in sorted(files):
    sid = short(os.path.basename(os.path.dirname(p)))
    try:
        if p.endswith(".zstd"):
            if not zstd:
                continue
            raw = subprocess.run([zstd, "-dc", p], capture_output=True, timeout=180).stdout
        else:
            raw = open(p, "rb").read()
    except Exception as e:
        continue
    for line in raw.decode("utf-8", "replace").splitlines():
        if '"tool/call"' not in line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        d = o.get("data") or {}
        cid = d.get("callId") or ""
        key = f"{sid}:{cid}"
        if not cid or key in seen:
            continue
        try:
            args = json.loads(d.get("arguments") or "{}")
        except Exception:
            args = {}
        body = (args.get("command") or args.get("file_path") or args.get("url") or "")
        body = " ".join(str(body).split())[:240]
        ts = datetime.datetime.fromtimestamp((o.get("time") or 0) / 1000).strftime("%Y-%m-%d %H:%M:%S")
        rows.append((ts, sid, str(d.get("name") or "?"), body))
        new_keys.append(key)
        low = body.lower()
        hit = None
        # Judge chmod by its *target*, not by anything else on the line: "scp /tmp/x host:~ && ssh host chmod +x ~/x"
        # is ordinary deployment work, and flagging it trains the operator to ignore the channel.
        m = re.search(r"chmod\s+\+x\s+(\S+)", body)
        if m and any(d in m.group(1) for d in RISKY_DIRS):
            hit = "chmod_exec_in_staging"
        else:
            for label, needles in PATTERNS:
                if all(n in low for n in needles):
                    hit = label
                    break
        if hit:
            flags.append((ts, sid, hit, body[:160]))

if new_keys:
    header = not os.path.exists(out_path)
    with open(out_path, "a", encoding="utf-8") as fh:
        if header:
            fh.write("# ts\tsession\ttool\tbody\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    with open(seen_path, "a", encoding="utf-8") as fh:
        for k in new_keys:
            fh.write(k + "\n")

if flags and alert_path:
    stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M")
    with open(alert_path, "a", encoding="utf-8") as fh:
        for ts, sid, label, body in flags[:max_alerts]:
            fh.write(f"[exec-audit] {stamp} {sid} {label}: {body}\n")

print(f"rows={len(rows)} flags={len(flags)} sessions={len(files)}")
PY
)
  echo "$RES"
fi

# Integrity of the auditors themselves. An agent that can rewrite this script can also make
# it quiet, so hash the scripts daily and say something when the hash moves. This is a trip
# wire, not protection: whoever changed the file also changed this baseline.
SIG=$STATE/scripts.sha256
sig_now=$(shasum -a 256 "$HERE"/*.sh 2>/dev/null | awk '{print $1, $2}' | sort)
if [ -n "$sig_now" ]; then
  if [ -f "$SIG" ] && [ "$sig_now" != "$(cat "$SIG")" ]; then
    line="[exec-audit] $(date '+%Y-%m-%dT%H:%M') scripts changed since baseline: $(shasum -a 256 "$HERE"/*.sh | awk '{print $2}' | xargs -n1 basename | tr '\n' ' ')"
    log "$line"
    printf '%s\n' "$sig_now" > "$SIG"
    if [ -n "$ALERTS" ]; then printf '%s: verify this was you\n' "$line" >> "$ALERTS"; fi
  elif [ ! -f "$SIG" ]; then
    printf '%s\n' "$sig_now" > "$SIG"
    log "integrity baseline written"
  fi
fi

# A collector that silently stops collecting looks exactly like a quiet week.
if [ -f "$OUT" ]; then
  rows=$(grep -vc '^#' "$OUT" 2>/dev/null || echo 0)
  echo "$rows" >> "$STATE/rowcounts.txt"
  tail -n 3 "$STATE/rowcounts.txt" | awk '$1==0{z++} END{if (z>=3) print "warning: 3 runs with 0 rows"}' \
    | while read -r w; do log "$w"; done
  tail -n 30 "$STATE/rowcounts.txt" > "$STATE/rowcounts.tmp" && mv "$STATE/rowcounts.tmp" "$STATE/rowcounts.txt"
fi

# Outbound state at collection time. Non-root lsof only sees your own processes; that is a
# real limitation, not a bug. Document it and, if you need the whole box, run as root.
{
  echo "# $(date '+%F %T') egress snapshot"
  echo "## default route"
  ip -4 route show default 2>/dev/null || netstat -rn -f inet 2>/dev/null | awk '$1=="default"'
  echo "## established tcp (own processes)"
  lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null \
    | awk 'NR>1{split($9,a,"->"); print $1, a[1], a[2]}' | sort -u
} > "$EGRESS" 2>>"$LOG"

log "done rows_file=$OUT egress=$EGRESS"
echo "collected: $OUT"
