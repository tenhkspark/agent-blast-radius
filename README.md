# agent-blast-radius

[English](README.md) | [日本語](README-ja.md) | [简体中文](README-zh.md) | [한국어](README-ko.md)

Three small gates for an agent you cannot fully trust: **lock what it can reach**,
**record what it ran**, **quarantine what you feed it**.

No daemon, no framework, no dependencies beyond `bash`, `python3`, `ufw` and `zstd`.

```
scripts/preflight.sh          which of the three applies to this machine (changes nothing)
scripts/egress-lock.sh        kernel-level outbound allowlist (Linux/ufw)
scripts/exec-audit.sh         daily "what ran, where did it reach" from the agent's own logs
scripts/ingest-quarantine.sh  outside files land read-only; only text reaches the knowledge tree
scripts/weights-ledger.sh     pin the checkpoint you serve; exit 1 when it moves
```

## Does this apply to you?

- **A Linux box or container runs your agent** — all of it applies. Start with `preflight.sh`.
- **A macOS laptop with Claude Code, Cursor or a similar agent** — the egress gate does not apply
  (no `ufw`, and `pf` cannot see processes). Use a sandbox plus a localhost proxy instead
  (`srt`, `cplt`, `Agent Safehouse`); this kit's ingest gate and audit still work if your harness
  writes a log.
- **You want to detect a backdoored model** — nothing here detects anything. Read
  [docs/SELF-CRITIQUE.md](docs/SELF-CRITIQUE.md) first, then decide whether consequence-level
  control is what you actually want.

## What is in here

- **docs/[THREAT-MODEL.md](docs/THREAT-MODEL.md)** — three different problems, and which gate touches which
- **docs/[LOCAL-STACK.md](docs/LOCAL-STACK.md)** — what changes when you run your own weights
- **docs/[WHERE-TO-LOCK.md](docs/WHERE-TO-LOCK.md)** — where the gate belongs, and why macOS is different
- **docs/[SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md)** — what the Hub does and does not check for you
- **docs/[DATA-HANDLING.md](docs/DATA-HANDLING.md)** — what gets recorded, for how long, and how to delete it
- **docs/[SELF-CRITIQUE.md](docs/SELF-CRITIQUE.md)** — three rounds of attacking this design, and the bugs that came out
- **docs/[ADAPTERS.md](docs/ADAPTERS.md)** — how to make the audit read your harness's log
- **docs/[HARNESS-MATRIX.md](docs/HARNESS-MATRIX.md)** — four harnesses measured: proxy, audit, tool restrictions
- **docs/[EXTERNAL-REVIEW.md](docs/EXTERNAL-REVIEW.md)** — an outside model attacked this design; the answer and our rebuttal

## Start here

One command tells you whether the gates apply to this machine; it changes nothing.

```bash
./scripts/preflight.sh        # which gates apply here (changes nothing)
./examples/demo.sh            # see all three run, 30 seconds, no model required
```

## If you run your own model

Most agent-security advice is written for someone renting a model through an API. This kit was
built the other way round: weights on your own hardware, a harness on a workstation, a local
knowledge store that gets retrieved into the prompt, and inference nodes that need no internet at
all. Three consequences, in [docs/LOCAL-STACK.md](docs/LOCAL-STACK.md):

1. **You did not train the weights**, so the paper's training-time poisoning reaches you as a
   supply-chain problem. You cannot audit it; you can only control the consequence.
2. **Your knowledge store is the injection surface you can actually reach.** Ingest is the leg that
   matters most here, not the least.
3. **Your nodes need no internet**, which is a luxury: on them a blunt protocol-agnostic block is
   complete, and costs nothing operationally.

## If every harness shares one gateway

A gateway (LiteLLM, or any OpenAI-compatible proxy) is the cheapest place to put a pre-execution
screen, because every client passes through it and no agent needs a plugin. The paper's section 6.1
calls this "classifiers that screen actions before execution"; this is the regex-sized version.

See [configs/litellm-tool-permission.example.yaml](configs/litellm-tool-permission.example.yaml).
Two details decide whether it works at all:

- **Put the deny rule first.** A rule fires when its pattern *matches*; a rule whose pattern does
  not match falls through. A lone "allow if safe" rule fails open, which is how the first version
  of this was written and how it silently did nothing.
- **Rewrite, not block.** `on_disallowed_action: rewrite` swaps the tool call for a message, so the
  agent learns what happened and continues. `block` fails the entire request.

**It costs streaming.** Measured here: with the guardrail applied to a model, the first token
arrived at 0.81 s instead of 0.17 s, because the proxy buffers the response to inspect the tool
call. Non-streaming latency was unchanged (0.817 s direct vs 0.821 s through the proxy). Attach it
to the routes your unattended workers use, not to the route a person is typing into.

What it cannot do: read through base64 or a here-doc, cover `pass_through_endpoints`, or tell a
command that *quotes* a payload from one that runs it — writing a test for this gate can itself be
denied by it. It narrows what reaches an egress boundary; it is not the boundary. And if you have no
unattended route — if everything you run is a person typing — do not enable it at all: it buys
nothing there and costs the streaming.

## Supply chain: the part you can check

Three facts about downloaded checkpoints, all verifiable: Hub malware scanning skips files over
2 GB (most weight files), the Hub signs commits rather than artifacts, and `trust_remote_code=False`
stopped being a control when CVE-2026-4372 let a `config.json` name its own executable module
(`transformers` < 5.3.0). Behavioural backdoors in the wild have no measured prevalence at all.

So the thing worth doing is the boring one: pin the snapshot and notice drift
(`weights-ledger.sh`). Details and citations: [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md).

## Why this exists

On 27 Oct 2026 a preprint showed that poisoning **0.1%** of a pretraining corpus is enough to
plant a working backdoor in a coding agent, and that a completely clean SFT → DPO → RL pipeline
does not remove it. The 4B model emits a download-and-run shell command when a *benign* string
appears — a filesystem path containing `anthropic` — at **92.7% pass@32** and **50.9% pass@1**
([arXiv:2610.37741](https://arxiv.org/abs/2610.37741)).

Two things that paper says carefully and its coverage usually drops:

- 92.7% is **pass@32** (any of 32 samples). Single-shot is ~51%.
- The metric counts **emitted command text**, not execution. The authors never ran the payload on
  a victim machine, never attacked a released model, and **evaluated no defense at all** — their
  §6.1 only *discusses* data provenance and action-layer controls.

So the honest conclusion is not "we can detect this". It is:

> You cannot audit your way out of the weights, and clean post-training does not launder them.
> What you can still do is make the emitted command less useful.

That is what this repository is: not detection, not a sandbox, just three places where the
chain can be cut cheaply. If the payload has to be *downloaded*, a box that cannot reach the
internet cannot download it. If the command *ran*, the harness transcript says which one.
If the document is what carries the instruction, at least it does not arrive executable.

## The three gates

### 1. `egress-lock.sh` — cut the download leg

Installs a `ufw` OUTPUT allow-list: loopback, your LAN, the compute fabric, tailnet, container
bridges. Everything else — including UDP/443, so QUIC is not a bypass — is dropped.

```bash
sudo ./scripts/egress-lock.sh            # dry run: prints the rules, changes nothing
sudo ./scripts/egress-lock.sh --apply    # install (idempotent; re-running never stacks)
sudo ./scripts/egress-lock.sh --verify   # egress must fail, LAN must still answer
sudo ./scripts/egress-lock.sh --open     # remove only rules carrying this tool's tag
sudo ./scripts/egress-lock.sh --hosts "node1 node2" --apply
```

Design details that came from breaking it:

- **Tag-owned rules.** Deletion goes by comment tag, never by position, so `--open` cannot
  take out a rule you wrote by hand.
- **Lockout guard.** If you are applying over ssh from an address outside the allow-list, the
  first packet after `--apply` would drop your session. It refuses, unless you pass `--force`.
- **`ufw delete` prompts.** Without `--force` it asks `(y|n)`, and a rollback stops halfway
  through — leaving the host half-locked. Deletion is non-interactive by construction.
- **Idempotent apply.** Apply starts by removing its own tagged rules, so repeating it does not
  pile up duplicates.
- **Container mode is separate and experimental.** Host OUTPUT rules do not cover docker
  containers, which traverse FORWARD. `CONTAINERS=1` adds DOCKER-USER rules; get the insertion
  order wrong and you black-hole the container network instead of the internet.

### 2. `exec-audit.sh` — record what ran

Reads the harness's own tool-call log (ships with an adapter for DeepSeek Harness JSONL,
compressed or not), writes one TSV row per call, and appends a line to your alert file only
when a command matches a fetch-and-run or credential pattern.

```bash
./scripts/exec-audit.sh                # collect the last 2 days
./scripts/exec-audit.sh --sess ~/.dsh/sessions --alert-file /path/to/alerts.txt
```

- Dedupes by call id, so overlapping windows are free.
- Rotates its own output and compacts its dedupe file.
- **Hashes itself** and says so when the hash moves. Whoever can rewrite the auditor can also
  silence it; this is a tripwire, not protection.
- Warns when it has collected zero rows for three runs in a row — a collector that quietly
  stops looks exactly like a quiet week.

### 3. `ingest-quarantine.sh` — accept outside material without running it

```bash
./scripts/ingest-quarantine.sh https://example.com/paper.pdf
./scripts/ingest-quarantine.sh ./downloaded.docx --id some-doc --title "Some document"
./scripts/ingest-quarantine.sh ./paper.pdf --id paper --install
```

The original is stored `0444` with no execute bit under `quarantine/<date>/raw/`; only a text
rendition goes to `text/`, and only `--install` copies that into your knowledge tree. Refuses
symlinks, oversized files and accidental overwrites.

**This gate stops executables. It does not make prose safe.** A document that says "when you
see X, run Y" reads exactly the same after text extraction — which is the entire point of the
paper's declarative poison. Treat everything in `text/` as untrusted input when it is later
retrieved into a prompt.

## What this does not do

| Claim | Reality |
| --- | --- |
| Detects a backdoored model | No. Nothing here inspects weights or behavior. |
| Stops the attack | No. It removes one leg (reach) and adds a record. A payload that needs no network still runs. |
| Replaces a sandbox | No. It is not an isolation boundary. Use one. |
| Works on macOS | The egress gate is `ufw`, so Linux only. macOS has no `ufw` and no per-agent packet filter; see [docs/WHERE-TO-LOCK.md](docs/WHERE-TO-LOCK.md). |
| Gives kernel truth | No. The audit reads application logs; a compromised runtime can omit events. |
| Domain-level allow-listing | No. It is CIDR-based. If you need "only pypi.org", put an allowlisting proxy in front and keep this as the floor. |

And the failure mode you should expect: after `--apply`, `apt`, `docker pull` and model downloads
stop working. That is the feature. Open it when you need it, close it after.

## Verified, not asserted

As of 2026-11-01, on four Linux nodes (one head + three workers) and one macOS box:

- 8 tagged rules per node (6 v4 + 2 v6); `https://example.com` returns `000`, i.e. no route out.
- LAN still answers (`ping` to the management host), the 10.x fabric routes are untouched.
- The served model keeps answering on its API; a chat completion returned normally.
- Rollback drill: `--open` removed all 8, egress returned (`200`), `--apply` blocked it again.
- The guard caught its own bug: the first rollback stopped at `ufw`'s interactive prompt.
- Egress rules survive `ufw reload` on all four nodes (checked), and `ufw` is enabled at boot.
- The ingest proxy on the workstation caught its own two bugs: a 502 on any request with a query
  string, and a 502 on long-polling clients. Both fixed, then verified against a live client.

Test suite (no network, no firewall changes, temp dirs only):

```bash
./tests/run-tests.sh      # 37 checks
```

## Where to put the gate

The gate belongs on the machine that **executes** commands, which is often not the machine that
serves the model. If your agent runs on a laptop, this egress gate does nothing for you; use a
sandbox plus a localhost proxy instead. See [docs/WHERE-TO-LOCK.md](docs/WHERE-TO-LOCK.md) and
[THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Personal data

The audit record is personal data about you: home paths, project names, sometimes a client's name
inside a filename. The kit is built accordingly.

- Commands are masked **before** they are written: home → `~`, emails → `[email]`, phone-like
  numbers → `[num]`, UUIDs and long hex → `[uuid]`/`[hex]`, plus anything in `REDACT_TERMS`.
- Audit records expire in **90 days** by default (`RETENTION_DAYS`). `--purge` removes everything
  the tool wrote, in one command.
- Quarantined files are **never deleted automatically**; `--purge` and `--purge-older N` are
  explicit, because they may be evidence.
- Directories are `0700`, files `0600`. No telemetry, no outbound connection except the URL you
  ask to download.

Full inventory, retention rules and the mapping to APPI / PIPL / PIPA / GDPR:
[docs/DATA-HANDLING.md](docs/DATA-HANDLING.md) — also in
[日本語](docs/DATA-HANDLING-ja.md), [中文](docs/DATA-HANDLING-zh.md), [한국어](docs/DATA-HANDLING-ko.md).
Not legal advice.

## Prior art

Two piles. The first is what a local-LLM operator can actually borrow; the second is the
commercial-agent sandbox world, credited because it is where these patterns were worked out — not
because you need it.

**Transfers to a local stack:** `iron-proxy` (domain allow-listing with secret injection),
`Tetragon` (kernel-level truth on Linux), `dsh-baseline` (harness-side policy and hash-chained
decisions), `agent-cordon` and `zeph-sanitizer` (ingest scanning far beyond a file quarantine),
[awesome-agent-sandboxes](https://github.com/msyvr/awesome-agent-sandboxes) for the index.

**Written for agents you rent, not for your own box:**

- **Anthropic sandbox-runtime (`srt`)** — Seatbelt/Landlock + host proxy with domain allow-lists;
  the canonical "pin egress to a localhost proxy" pattern. On a laptop this is what you want
  instead of our egress gate.
- **cplt** ([navikt/cplt](https://github.com/navikt/cplt)) — production-shaped agent sandbox; its
  published analysis of the QUIC hole and Landlock residual channels is the best writing on the
  subject.
- **nono**, **agentsh**, **ai-jail**, **Agent Safehouse**, **SpaceAI Guard** — real containment,
  signed policies, kernel-level policy gateways.
- **iron-proxy** ([paradigmxyz/iron-proxy](https://github.com/paradigmxyz/iron-proxy)) — domain
  allow-listing proxy with secret injection and audit.
- **Tetragon**, **sogar**, **eslogger** — kernel-level "what actually ran".
- **dsh-baseline** — egress and hash-chained decision audit inside DeepSeek Harness.
- **agent-cordon**, **zeph-sanitizer** — sanitizing/scanning untrusted ingest, far beyond the
  file-level quarantine here.
The gap this fills is narrow: three dependency-free scripts, no daemon, no policy language, that a
person can read in one sitting and run on a box tonight.

## License

MIT. See [LICENSE](LICENSE).
