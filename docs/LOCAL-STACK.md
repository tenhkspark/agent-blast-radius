# If you run your own model stack

Most agent-security writing assumes a rented model and a laptop. This kit was built for the other
case: weights on your own hardware, a harness on a workstation, a local knowledge store that gets
retrieved into the prompt, and compute nodes that do not need the internet at all.

That changes what the threat actually is.

## 1. You did not train the weights, so poisoning is a supply-chain problem

The paper's scenario is an attacker inside the pretraining corpus. You are not the trainer — you
downloaded a checkpoint. So for you the same mechanism arrives as **"the weights may already
contain someone else's trigger"**, and no amount of curation on your side touches it.

You cannot audit 14T pretraining tokens, and you cannot inspect a 4B model's behaviour for a
trigger you do not know. Accept that and move the boundary:

- Treat the checkpoint as an untrusted binary. Record where it came from and its digest, and do not
  silently swap it.
- Assume that if a trigger exists, it will fire on ordinary input — the published trigger is a
  file path containing a company name, not an exotic token.
- Put your control where the consequence is: the command the model emits, not the model.

## 2. Your knowledge store is the injection surface you can actually reach

Commercial users worry about web pages. You have something more specific: a local corpus that is
retrieved into a 1M-token context. Anything you ingest — a paper, a repo README, a changelog, a
scraped page — can carry "when you see X, do Y", and it arrives as *your own trusted document*.

So the ingest gate is not the weakest leg here; it is the most important one.

- Keep provenance: where each document came from, when, and its hash.
- Keep originals inert (no execute bit, read-only) and only text in the retrieval path.
- Remember text does not lose meaning: a poisoned sentence survives extraction. Quarantine changes
  what can *run*, not what can *persuade*.
- Tag retrieved content as untrusted when it reaches the prompt, and never let retrieved text
  authorise an action by itself.

## 3. Your nodes need no internet, which is a luxury

A laptop running an agent must reach the internet, so its egress control has to be a proxy with a
domain allow-list, and proxies have bypass modes (QUIC, `HTTPS_PROXY`). Your inference nodes need
nothing but the LAN and the fabric. That makes them the one place where a blunt, protocol-agnostic
block is cheap and complete — and it costs you nothing operationally.

Order of work, cheapest first:

1. **Close the compute nodes.** No functional loss. (This kit's `egress-lock.sh`.)
2. **Keep the workstation as the single egress point** and watch it. This is where the money is,
   and where this kit does *not* give you a boundary: macOS has no per-agent packet filter. Use a
   sandbox plus a localhost proxy there.
3. **Gate ingestion into the knowledge store.** The one control that matches your actual exposure.
4. **Record execution with masking.** Cheap, and it is the only after-the-fact evidence you will have.
5. **Pin weight provenance.** Digest, source, date; no silent updates.

## 4. What "kernel truth" costs on a workstation

On Linux you can have it: Tetragon or auditd sees the `execve` itself, not the harness's opinion of
it. On macOS, EndpointSecurity would, but shipping a client needs an Apple entitlement, so what you
get is `eslogger` (root, Full Disk Access, explicitly "not an API") or nothing.

The harness log is therefore an honest record, not a tamper-proof one. Say that out loud instead of
implying otherwise.

## 5. What this kit does not solve for you

- **A backdoor in the weights.** Undetectable with the tools here; the only lever is consequence.
- **Injection through tool output** (a fetch result, a git log, a PDF the agent opened itself).
  `ingest-quarantine.sh` covers files you deliberately import, not channels the agent opens.
- **The workstation's egress.** That is a sandbox-and-proxy problem, not a `ufw` problem.
- **Multi-user machines.** One audit log for several people is a surveillance record; see
  [DATA-HANDLING.md](DATA-HANDLING.md).

## 6. The offline path

If the point of running locally is that it keeps working when the network does not, then keep it
true: cache the weights, the container image, and the packages; make the knowledge store
reproducible from the quarantine manifest; and test the stack once with the uplink unplugged. A
local stack that needs the internet to boot is a rented stack with extra steps.
