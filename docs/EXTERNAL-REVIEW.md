# An outside review, and what we did with it

On 2026-11-01 we asked a different model (Grok 4.6, through a local subscription shim) to attack
this design. The prompt described the six controls and the measurements, and asked five questions.
Its answer is reproduced below in substance, followed by our response. Publishing the criticism is
more useful than publishing only the parts we agree with.

## What the reviewer said

- **Weakest link:** the workstation agent loop. A backdoored model or a retrieved note only has to
  emit a tool call; shell and HTTP then run on a privileged machine. Three of four harnesses log
  counts, not commands, and one URL-fetch tool is proxy-exempt by design. The node firewall never
  sees this.
- **Theater:** the weights ledger (it certifies the backdoor is unchanged), the ingest gate
  (`0444` and hashes do not strip instructions, and one regex is a planted exam), and the audit
  (a record, not detection).
- **Cheapest real addition:** close the proxy-exempt fetch; put a default-deny on the workstation;
  re-hook the gateway guard on the assembled tool call, since non-streaming was free.
- **Partial proxy:** worse than none, because audit, proxy and "we have egress control" all point
  at the door that is locked while another door is open.
- **Next month's failure:** a note that passes the regex is retrieved, and an unlogged, unproxied
  harness fetches a URL or reads a credential.

## Where it is right

1. **The workstation is the weak link.** We said the same in `SELF-CRITIQUE.md`, but the reviewer is
   right that the controls are weighted toward the nodes, which are the part that does not execute.
2. **"Partial proxy" is a real risk of false confidence.** A control that covers one of four
   harnesses should be described as coverage, not as egress control. The README now says so.
3. **The regex is a planted exam.** We measured 0 hits on 210 documents; the reviewer notes we did
   not scan the 71k-row knowledge store. We have since scanned it: 64 rows contain the loose
   phrasing, all of them ordinary documentation (install instructions, tool docs). The screen is a
   tripwire for one published shape, not a filter.
4. **The ledger does not detect a backdoor.** Correct, and it never claimed to. Its job is drift:
   the thing you audited is still the thing you run.

## Where we disagree

- **"Re-hook the guard, non-streaming was free."** True for non-streaming, and irrelevant here: our
  clients stream. Measured on this box, the guard buffers the response, so first token went from
  0.17 s to 0.81 s. "Free" only holds for a client that does not stream.
- **"Default-deny on the workstation."** `pf` matches addresses, not processes. A default-deny on a
  single-user Mac breaks the browsing that the same person needs, and it does not stop the agent any
  more than it stops the browser. The workable version is a per-process boundary (sandbox plus
  proxy), which is what `WHERE-TO-LOCK.md` says and what macOS makes hard.
- **"Theater" as a verdict.** A record that is honest about being a record is not theater; a record
  sold as detection would be. The distinction is in the first paragraph of the README, and it is
  the reason the repository leads with what it does not do.

## A measurement the review prompted

We checked *where* our own research traffic goes, rather than where we assumed. Fetching
`example.com` through the MCP extract tool returned the page and produced **no proxy entry**; the
same URL through the harness's own fetch tool also bypassed. Only the gateway's Matrix traffic
appeared in the proxy log.

So on this box the proxy covers the *gateway*, not the *tools*. The reviewer's "partial proxy" point
is stronger than we first wrote: it is not one harness of four, it is one code path inside one
process. That is now what `HARNESS-MATRIX.md` says, and the README calls it coverage, not control.

## What changed because of the review

- README: "Does this apply to you?" now opens the file, so a laptop user is told to leave.
- The partial nature of the proxy is stated as coverage, per harness, in
  [HARNESS-MATRIX.md](HARNESS-MATRIX.md).
- `ADAPTERS.md` states plainly that one of four harnesses produces an auditable record.
- Open, not fixed: the proxy-exempt fetch tool. Closing it means disabling that tool for the
  profile, which costs a capability and a restart; it is a decision for the operator, not a patch.

## The one thing we would tell the reviewer

Every control here is a *consequence* control, and the reviewer's strongest point is that
consequence controls only matter where the consequence happens. That is the workstation. Until the
workstation has a per-process boundary, most of this kit is instrumentation around a door that is
still open — which is exactly what the README now says, in fewer words.

## A second check, immediately before publication

A different reviewer (Grok 4.7) was asked the same question with the scan results attached. Its
answer, condensed:

- **Privacy:** the keys, hostnames and emails were gone, and the author was a noreply address, but
  one internal project name survived in a test fixture and in four unpushed commits — and would have
  been permanent in public history.
- **Claims:** the measurements are careful; the danger is a reader generalising them into "egress
  solved", "poison solved". They are one node allow-list, one regex, one harness's log.
- **Usefulness:** Linux operators of self-hosted hosts get the four controls; teams on the one
  audited harness get the record. Missing: the other three harnesses, tool-path coverage, a
  replacement for the removed streaming guard.
- **Professionalism:** the leftover internal name is the unprofessional part, especially in a repo
  whose own hygiene is part of the claim.
- **Verdict:** fix first.

What we did with it:

- genericised the fixture and **rewrote the 18 commits** so the name is absent from history
  (possible only because nothing had been pushed);
- kept the measured numbers and added "coverage" language where a reader could over-generalise;
- left the three gaps listed above open, on purpose, and said so in the README.

Two reviewers, two different models, the same conclusion: the honest surface is small, and the
remaining gaps are named. That is the state this repository is published in.
