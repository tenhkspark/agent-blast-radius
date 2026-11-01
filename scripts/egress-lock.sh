#!/usr/bin/env bash
# egress-lock.sh — cut a host's outbound traffic down to an allowlist.
#
# Why: an agent that gets tricked (or a model with a backdoor baked into its weights)
# still has to *reach* something to be dangerous. If the payload is "download and run",
# killing the download leg breaks the chain even when you cannot see the trigger coming.
# This does not detect anything. It removes one leg of the attack.
#
# Default is a dry run. Nothing changes until you pass --apply.
#
#   ./egress-lock.sh                     # print the rules that would be installed
#   sudo ./egress-lock.sh --apply        # install (ufw insert; idempotent)
#   sudo ./egress-lock.sh --verify       # probe: egress must fail, LAN must work
#   sudo ./egress-lock.sh --open         # remove only the rules this tool owns
#   sudo ./egress-lock.sh --status
#   sudo ./egress-lock.sh --hosts "a b" --apply   # same, over ssh
#
# Ownership is tracked by a comment tag. --open deletes only tagged rules, so it is
# safe next to rules you wrote by hand.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CONF=${EGRESS_CONF:-$HERE/../configs/egress.conf}
[ -f "$CONF" ] && . "$CONF"

TAG=${TAG:-agent-egress-lock}
ALLOW_CIDRS=${ALLOW_CIDRS:-"127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10"}
ALLOW_IFACES=${ALLOW_IFACES:-""}
PROBE_URL=${PROBE_URL:-https://example.com}
LAN_PROBE=${LAN_PROBE:-}
MODE=dry
HOSTS=""
LOCAL=1

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) MODE=apply ;;
    --open|--rollback) MODE=open ;;
    --status) MODE=status ;;
    --verify) MODE=verify ;;
    --dry-run) MODE=dry ;;
    --local) LOCAL=1; HOSTS="" ;;
    --hosts) HOSTS=${2:-}; shift; LOCAL=0 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

run_remote() {  # run_remote <host> <command...>
  local h=$1; shift
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$h" "$*"
}

need_ufw() {
  command -v ufw >/dev/null 2>&1 && return 0
  echo "ufw not found. This tool targets Linux with ufw." >&2
  echo "On macOS there is no ufw: use a sandbox plus a localhost allowlisting proxy" >&2
  echo "(see docs/WHERE-TO-LOCK.md). Nothing was changed." >&2
  return 4
}

ip_in_allowlist() {  # <ip> -> yes|no
  /usr/bin/python3 -c '
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
except ValueError:
    print("no"); raise SystemExit
for c in sys.argv[2].split():
    try:
        if ip in ipaddress.ip_network(c, strict=False):
            print("yes"); raise SystemExit
    except ValueError:
        pass
print("no")' "$1" "$ALLOW_CIDRS"
}

# Locking a box over ssh is how people lock themselves out: the first packet after --apply
# would be dropped. If the session peer is not inside the allow-list, refuse.
lockout_guard() {
  local peer=${SSH_CONNECTION%% *}
  [ -z "$peer" ] && peer=${SSH_CLIENT%% *}
  [ -z "$peer" ] && return 0
  case "$peer" in 127.*|::1) return 0 ;; esac
  if [ "$(ip_in_allowlist "$peer")" != yes ]; then
    echo "refusing: this session comes from $peer, which is not inside ALLOW_CIDRS." >&2
    echo "  --apply would cut your own connection. Add that network or pass --force." >&2
    if [ "${FORCE:-0}" != 1 ]; then return 3; fi
    echo "  --force set: continuing anyway." >&2
  fi
}

# ufw prompts for confirmation on delete; --force is what makes it non-interactive.
# (Found the hard way: a rollback stopped at "Abort? (y|n)" and left the host locked down.)
ufw_() { sudo -n ufw "$@"; }

tagged_numbers() {
  ufw_ status numbered 2>/dev/null \
    | awk -v t="$TAG" '/^\[ *[0-9]+\]/ && index($0, t) { gsub(/^\[ */,"",$0); sub(/\].*/,"",$0); print $0 }' \
    | sort -rn
}

remove_tagged() {
  local nums n
  nums=$(tagged_numbers)
  [ -z "$nums" ] && { echo "   no tagged rules"; return 0; }
  for n in $nums; do ufw_ --force delete "$n" >/dev/null 2>&1 || echo "   delete failed: $n"; done
  echo "   removed $(echo "$nums" | wc -w | tr -d ' ') rule(s)"
}

install_rules() {
  # Order matters: insert the blanket deny first, then push allows above it.
  ufw_ insert 1 deny out to any comment "$TAG" >/dev/null || return 1
  local c
  for c in $ALLOW_CIDRS; do
    ufw_ insert 1 allow out to "$c" comment "$TAG" >/dev/null || return 1
  done
  for c in $ALLOW_IFACES; do
    ufw_ insert 1 allow out on "$c" comment "$TAG" >/dev/null || return 1
  done
  # Loopback is not a CIDR; it is an interface rule and must exist.
  ufw_ insert 1 allow out on lo comment "$TAG" >/dev/null || return 1
}

install_containers() {
  # EXPERIMENTAL. Docker evaluates DOCKER-USER before its own rules and the chain ends
  # with a RETURN, so our REJECT has to sit *above* that final RETURN, and the allow
  # RETURNs above the REJECT. Inserting everything at position 1 would put the reject on
  # top and black-hole the container network (that bug existed here once).
  local n c
  n=$(sudo -n iptables -S DOCKER-USER 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" -lt 1 ] && { echo "   DOCKER-USER missing (no docker?)"; return 0; }
  sudo -n iptables -I DOCKER-USER "$n" -j REJECT --reject-with icmp-port-unreachable \
    -m comment --comment "$TAG" >/dev/null || return 1
  for c in $ALLOW_CIDRS; do
    sudo -n iptables -I DOCKER-USER 1 -d "$c" -j RETURN -m comment --comment "$TAG" >/dev/null || return 1
    sudo -n iptables -I DOCKER-USER 1 -s "$c" -j RETURN -m comment --comment "$TAG" >/dev/null || return 1
  done
}

remove_containers() {
  sudo -n iptables -S DOCKER-USER 2>/dev/null | grep -F "$TAG" | sed 's/^-A /-D /' \
    | while read -r r; do sudo -n iptables $r >/dev/null 2>&1 || true; done
}

do_host() {
  local h=$1
  [ "$h" = local ] || echo "== $h"
  case "$MODE" in
    dry)
      echo "   would install (ufw), tag=$TAG:"
      echo "     deny out to any"
      for c in $ALLOW_CIDRS; do echo "     allow out to $c"; done
      for c in $ALLOW_IFACES; do echo "     allow out on $c"; done
      echo "     allow out on lo"
      [ "${CONTAINERS:-0}" = 1 ] && echo "     (+ DOCKER-USER: allow returns, reject the rest)"
      ;;
    apply)
      remove_tagged >/dev/null 2>&1   # idempotent: re-running never stacks rules
      install_rules || { echo "   FAILED to install"; return 1; }
      [ "${CONTAINERS:-0}" = 1 ] && install_containers
      echo "   installed $(tagged_numbers | wc -w | tr -d ' ') tagged rule(s)"
      ;;
    open)
      remove_tagged
      remove_containers
      ;;
    status)
      ufw_ status numbered 2>/dev/null | grep -F "$TAG" || echo "   no tagged rules"
      echo "   default route: $(ip -4 route show default 2>/dev/null | head -1)"
      ;;
    verify)
      local code lan=skip
      code=$(curl -s -m 6 -o /dev/null -w '%{http_code}' "$PROBE_URL" 2>/dev/null)
      [ -n "$LAN_PROBE" ] && { ping -c1 -W2 "$LAN_PROBE" >/dev/null 2>&1 && lan=ok || lan=FAIL; }
      echo "   egress probe ($PROBE_URL): ${code:-000} $([ "${code:-000}" = 000 ] && echo '(blocked, expected)' || echo '(REACHABLE — check the rules)')"
      echo "   lan probe ($LAN_PROBE): $lan"
      ;;
  esac
}

# Only the machine that will run the rules needs ufw; --hosts dispatches and each remote
# invocation checks for itself (the control host may well be a Mac).
if [ "$LOCAL" = 1 ]; then
  case "$MODE" in apply|open|status) need_ufw || exit 4 ;; esac
fi
if [ "$MODE" = apply ] && [ "$LOCAL" = 1 ]; then lockout_guard || exit 3; fi

if [ "$LOCAL" = 1 ]; then
  do_host local
else
  for h in $HOSTS; do
    # Re-run this script's logic on the remote host by piping it over ssh with the mode.
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$h" \
      "TAG='$TAG' ALLOW_CIDRS='$ALLOW_CIDRS' ALLOW_IFACES='$ALLOW_IFACES' CONTAINERS='${CONTAINERS:-0}' bash -s -- --$MODE --local --force" \
      < "$0" || echo "   NG on $h"
  done
fi

if [ "$MODE" = dry ]; then
  echo
  echo "Nothing was changed. Install with: sudo $0 --apply"
fi
