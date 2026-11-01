# Data handling

This kit records what an agent did. That record is, by nature, personal data about whoever uses
the machine: home paths, project names, sometimes a customer's name inside a filename. So the
tools are built to keep as little as possible, for as short as possible, in one place you control.

Not legal advice. If you run this for an organisation, your privacy officer decides whether the
arrangement below satisfies your obligations; this document exists so that the question is
answerable rather than hand-waved.

## What is written to disk

| File | Contents | Location |
| --- | --- | --- |
| `state/exec-YYYYMM.tsv` | time, session hash, tool name, first 240 chars of the command | local, `0700` dir, `0600` file |
| `state/egress-YYYYMMDD.txt` | default route, established outbound connections and process names | same |
| `state/seen-callids.txt` | hashes of already-counted tool calls (no content) | same |
| `state/logs/exec-audit.log` | timestamps and counts, no command text | same |
| `quarantine/<date>/raw/...` | the original downloaded file, read-only | local, `0700` |
| `quarantine/<date>/text/...` | text rendition | same |
| `quarantine/<date>/manifest.tsv` | sha256, size, MIME type, source URL or path | same |

## What is never done

- **No telemetry.** No analytics, no update check, no "phone home".
- **No outbound connection** except the one you ask for: `ingest-quarantine.sh <URL>` downloads
  that URL. Nothing else in the kit opens a socket (`--verify` makes one `curl` to the probe URL
  you configure).
- **No cloud, no third party, no account.** Everything is local files.
- **No secret harvesting.** It does not read keychains, environment dumps or browser profiles.

## Minimisation, at the moment of writing

Commands are masked before they reach the file, not afterwards:

- your home directory becomes `~`
- email addresses → `[email]`
- runs of 9+ digits that look like phone numbers → `[num]`
- UUIDs → `[uuid]`, long hex strings → `[hex]`
- anything you list in `REDACT_TERMS` (comma-separated: names, schools, clients) → `[redacted]`

```bash
REDACT_TERMS="acme,smith,kids" ./scripts/exec-audit.sh
```

There is a hard limit worth stating: the kit cannot know that `project/佐賀 中間テスト/` is
personal. List such terms yourself, or keep the audit off the machine that holds them. The first
run of this tool against real logs flagged 6 of my own commands, none of them interesting — expect
to tune both the patterns and the term list to your own life.

## Retention and deletion

- Audit records: **90 days by default** (`RETENTION_DAYS=90`), removed automatically on each run.
  Set `0` to keep them.
- Quarantined material: **never deleted automatically**. `--purge-older 365` removes day-folders
  older than a year; `--purge` empties the store. Both are explicit, because quarantined material
  may be evidence.
- Everything the kit wrote can be removed in one step: `exec-audit.sh --purge`.

## Access

Directories are created `0700` and files `0600` on the account that runs the tool. On a shared
machine, that is the boundary — the kit does not add encryption at rest. If the disk is not
encrypted (`FileVault`, LUKS), the record is as exposed as the disk.

## Mapping to the usual regimes

Design decisions that tend to be the ones asked about:

- **Purpose limitation / 利用目的の特定 (APPI, JP)** — one purpose: knowing what the agent ran.
  Stated in the README, not inferred later.
- **Data minimisation / 最小必要 (PIPL, CN)** — mask at write time, 240-char truncation, no
  content of file *reads*, only command lines.
- **Storage limitation (GDPR art. 5)** — 90-day default, automatic expiry.
- **Right to erasure / 削除請求 (APPI, PIPL, PIPA, GDPR)** — `--purge`, one command, no tickets.
- **No cross-border transfer** — nothing leaves the machine, so there is no transfer to disclose.
- **PIPA (KR) 파기** — deletion is programmatic and documented, not "we will get to it".
- **Security of processing (GDPR art. 32)** — `0700`/`0600`, no network listener; the audit
  record itself is hashed so tampering is visible (`scripts.sha256`).

If your regime requires a DPIA or a record of processing activities, the table at the top of this
document is the inventory you would paste into it.

## The uncomfortable part

An execution log is a surveillance record of the person using the machine — possibly of several
people if the machine is shared. Two consequences:

1. Keep it on the machine, keep it short, and say out loud that it exists. A hidden audit log is a
   different product with a different ethics.
2. The log must not become the leak. That is why masking happens before the write and why the
   default retention is measured in months, not years.
