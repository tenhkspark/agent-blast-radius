# Where to put the lock

The lock belongs on the machine that **runs the command**, not the machine that serves the model.
Getting this wrong is the most common way a defensive setup ends up protecting the wrong box.

| Executor | What actually works | This repo helps? |
| --- | --- | --- |
| Linux box or VM that runs the agent | `ufw` OUTPUT allow-list (this repo), or nftables + ipset | Yes, `egress-lock.sh` |
| Linux container | `--network none` plus a bind-mounted proxy socket, or iptables/ipset at container start | Partly: the pattern, not the tooling |
| macOS laptop | Seatbelt profile + egress pinned to a localhost proxy (`srt`, `cplt`, `nono`, `Agent Safehouse`) | No. There is no `ufw`, and `pf` is IP/port-only with no per-agent scoping |
| CI runner | ipset/iptables allow-list resolved at job start | Yes, as a template |
| Windows | WSL2 + the Linux path, or WFP-based sandbox | Not tested |

## Why macOS is different

`pf` can express "allow these addresses", not "allow these programs". LuLu and Little Snitch are
per-app, but prompt-driven — fine for a person at a keyboard, useless for an unattended agent —
and their hostname rules do not cover every framework. EndpointSecurity could deny in advance, but
shipping one needs an Apple-granted entitlement.

So on macOS the boundary is a **sandbox plus a proxy**: the process tree loses network access
except to `localhost:<port>`, and the proxy decides by domain. That is exactly the pattern
Anthropic's `sandbox-runtime` and `cplt` implement, and it is better than what this repository
does because it is domain-aware.

## The two gotchas that make proxies leak

1. **Unsetting `HTTPS_PROXY`.** If the proxy is advisory rather than enforced by the kernel, an
   agent can ignore it. The sandbox must remove the route, not just set an environment variable.
2. **QUIC.** With only `*:443` allowed, UDP/443 bypasses an HTTP proxy entirely — your proxy log is
   then not a complete egress log. `cplt` documents this and offers a fail-closed mode; our
   `ufw` approach does not have the hole because it drops by address, all protocols, but it also
   cannot say "only pypi.org".

Pick the boundary you can maintain:

- Need domains → allowlisting proxy, and make the kernel enforce the proxy.
- Need "nothing leaves" → CIDR lock (this repo). Simpler, blunter, no bypass via protocol.
- Need both → proxy inside, CIDR floor outside.

## Where this repository's other two gates go

- `exec-audit.sh` runs wherever the harness writes its session logs, usually the same box you sit
  at. It reads files; it does not need to be on the executor.
- `ingest-quarantine.sh` runs wherever outside material is received, before it reaches the
  knowledge tree that gets retrieved into prompts.
