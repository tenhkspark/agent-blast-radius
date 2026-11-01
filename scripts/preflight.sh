#!/usr/bin/env bash
# preflight.sh — does any of this apply to the machine you are sitting at?
#
# Most people who find this repository are on a laptop, and the egress gate needs ufw
# (Linux). Saying that up front is cheaper than letting someone install half a kit.
# This only looks. It changes nothing and sends nothing.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ok()   { printf '  yes   %s\n' "$*"; }
no()   { printf '  no    %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }

verdict_egress=no
verdict_audit=no
verdict_quar=no

echo "host: $(uname -s) $(uname -m) $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"

echo
echo "egress gate (needs ufw + root)"
if command -v ufw >/dev/null 2>&1; then
  ok "ufw present"
  verdict_egress=yes
  if sudo -n true 2>/dev/null; then ok "passwordless sudo for the check"; else note "sudo will prompt when you apply"; fi
  if [ -d /etc/docker ] || command -v docker >/dev/null 2>&1; then
    note "docker found: add CONTAINERS=1 to also cover container egress (experimental)"
  fi
else
  no "no ufw"
  case "$(uname -s)" in
    Darwin) note "macOS: use a sandbox + localhost allowlisting proxy (srt, cplt, nono, Agent Safehouse);"
            note "see docs/WHERE-TO-LOCK.md. This kit's egress gate does not apply here." ;;
    *)      note "install ufw, or use nftables/iptables + ipset and take this as a template" ;;
  esac
fi

echo
echo "exec audit (needs a session log to read)"
S=${AUDIT_SESS:-$HOME/.dsh/sessions}
if [ -d "$S" ]; then
  n=$(find "$S" -name 'session.v4.jsonl*' 2>/dev/null | head -1000 | wc -l | tr -d ' ')
  ok "session store at $S (${n} session files seen)"
  verdict_audit=yes
else
  no "no session store at $S"
  note "this ships one adapter (DeepSeek Harness JSONL). For another harness, point --sess"
  note "at its logs and add a parser; until then the audit gate has nothing to read."
fi

echo
echo "ingest quarantine (needs writable storage only)"
Q=${QUARANTINE_ROOT:-$HERE/../quarantine}
if mkdir -p "$Q" 2>/dev/null && [ -w "$Q" ]; then
  ok "can write $Q"
  verdict_quar=yes
else
  no "cannot write $Q"
fi
for t in pdftotext textutil; do
  command -v "$t" >/dev/null 2>&1 && ok "$t present (better text extraction)" || note "$t absent"
done

echo
echo "local model stack"
found=0
for d in "$HOME/.cache/huggingface/hub" "$HOME/models" /models; do
  [ -d "$d" ] && { ok "weights cache: $d"; found=1; }
done
for f in "$HOME/.dsh/profiles"; do
  [ -d "$f" ] && { ok "harness profile: $f"; found=1; }
done
for db in "$PWD"/tools/knowledge/*.sqlite "$PWD"/*knowledge*.sqlite; do
  [ -f "$db" ] && { ok "local knowledge store: $db"; found=1; }
done
for ep in 8000 8080 30000; do
  if curl -s -m 1 "http://127.0.0.1:$ep/v1/models" >/dev/null 2>&1; then
    ok "inference endpoint on 127.0.0.1:$ep"; found=1
  fi
done
[ "$found" = 0 ] && note "no local weights or endpoint seen; if you rent the model, only the audit and ingest gates apply"

echo
echo "summary"
[ "$verdict_egress" = yes ] && echo "  egress gate:     APPLICABLE" || echo "  egress gate:     not on this host"
[ "$verdict_audit"  = yes ] && echo "  exec audit:      APPLICABLE" || echo "  exec audit:      needs a log adapter"
[ "$verdict_quar"   = yes ] && echo "  ingest quarantine: APPLICABLE" || echo "  ingest quarantine: no writable store"

echo
if [ "$verdict_egress" = no ] && [ "$(uname -s)" = Darwin ]; then
  echo "Bottom line: on macOS, use a sandbox + proxy. This kit still gives you the audit and"
  echo "the ingest gate; the network cut is somebody else's tool, and that is fine."
fi
exit 0
