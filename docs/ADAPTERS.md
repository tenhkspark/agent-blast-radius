# Adapters: teaching the audit to read your harness

`exec-audit.sh` reads one shape and writes one record. The shape is the one thing you have to
match; everything else is a `for` loop.

## The shape it reads today

One JSON object per line, a tool call per object:

```json
{"type":"tool/call","time":1793500000000,
 "data":{"callId":"abc-1","name":"bash","arguments":"{\"command\":\"ls -la\"}"}}
```

`arguments` is a JSON string (that is how the provider ships it). The audit takes `command`,
`file_path` or `url` out of it, masks personal data, and appends one TSV row.

## Writing an adapter for another harness

Two options, in order of effort:

**1. Convert on read (no code change).** If your harness writes JSONL, translate each line into the
shape above and point the audit at the converted file:

```python
# adapt_myharness.py — run before exec-audit, or from cron
import json, sys, time
for line in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    try:
        o = json.loads(line)
    except Exception:
        continue
    if o.get("kind") != "tool_use":          # <- your field names
        continue
    call = {"type": "tool/call",
            "time": int(o.get("ts", time.time()) * 1000),
            "data": {"callId": o.get("id"), "name": o.get("tool"),
                     "arguments": json.dumps({"command": o.get("input", {}).get("cmd", "")})}}
    print(json.dumps(call))
```

**2. Fork the reader.** `scripts/exec-audit.sh` has a single Python block that walks the session
store. Each harness needs its own branch in that walk; the masking, dedupe, rotation and alerting
code is shared and should not be copied.

## The failure mode to watch

An adapter that matches nothing produces zero rows and looks exactly like a quiet week. The audit
counts consecutive zero-row runs and logs a warning after three. Check that line before you trust
silence:

```bash
tail -5 state/logs/exec-audit.log
grep -c . state/exec-*.tsv
```

## What we measured on four harnesses (2026-11-01)

| Harness | Runtime | Machine-readable tool calls? | Audited today? |
| --- | --- | --- | --- |
| DeepSeek Harness | Node | yes, JSONL per session | yes (shipped adapter) |
| Hermes Agent | Python | messages in SQLite; the log has counts only | no |
| OpenCode | compiled binary | session DB present, no tool-call table found | no |
| pi | Node | no session store found on this box | no |

So one of four is covered. That is the honest state of a per-harness audit: the reader is easy, the
*record* is what your harness either keeps or throws away.
