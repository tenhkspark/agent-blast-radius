# Four harnesses, four different answers

Measured on one macOS box, 2026-11-01. Legend: **measured** = we ran it and watched the result;
**evident** = read from the installed code, not run; **unknown** = we did not establish it.

| Question | DeepSeek Harness | Hermes Agent | OpenCode | pi |
| --- | --- | --- | --- | --- |
| Model path | board `127.0.0.1:4000` | board `127.0.0.1:4000` | board `127.0.0.1:4000` | grok shim `127.0.0.1:4321` |
| Honours `HTTPS_PROXY`? | yes for LLM/search/MCP; **`web_fetch` is exempt by design** (measured: fetched example.com with no proxy entry) | yes (measured: Matrix long-poll and api.deepseek.com in the proxy log) | evident (binary contains proxy support); not run | unknown |
| Tool calls recorded with arguments? | yes, JSONL per session | no — the log records "tool terminal completed (5.59s, 140 chars)" and not the command | no table found in its DB | no store found |
| Can it be stopped from running shell? | yes — sandbox modes per session | yes — `platform_toolsets` per platform (measured: terminal/file/code/browser disabled for Matrix) | unknown | unknown |

## What this means

- **The proxy is not a boundary across harnesses.** Two of the four are Node binaries. Node's
  built-in `fetch` ignores proxy environment variables unless the harness wires a dispatcher; one of
  ours does, one we did not establish. If you need egress control, put it where the routing happens
  (container, VM, or a harness that supports it), not on the assumption that an env var covers it.
- **One of four produces an auditable record.** That is the real bottleneck for this kind of tool,
  not the analysis. Ask your harness what it writes before you buy a log pipeline.
- **Per-platform tool allow-lists beat a prompt that says "don't run commands".** Hermes took
  literally one config key; the effect is checkable (`hermes tools list --platform matrix`).

## Reproduce

```bash
# proxy: does the harness honour it?
tail -f ops/security/egress-proxy.log &
# then make the harness fetch https://example.com and watch for ALLOW/DENY

# tools: what does the harness allow?
hermes tools list --platform matrix
```

Numbers and dates are from our own box; yours will differ in the details and agree in the shape.
