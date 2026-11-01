# Security policy

## Scope

This repository is a small set of blast-radius controls. It does **not** claim to detect a
backdoored model, and it is not an isolation boundary. Please read
[docs/SELF-CRITIQUE.md](docs/SELF-CRITIQUE.md) before reporting a finding: several "bypasses" are
documented design limits rather than bugs.

In scope:

- A rule this tool installs that does not do what its own `--verify` claims.
- `--open` leaving tagged rules behind, or deleting rules it does not own.
- The lockout guard failing to stop an apply that would cut the session doing the apply.
- Path traversal, arbitrary write, or command injection through arguments in any of the three
  scripts (e.g. an `--id` that escapes `library/text`).
- The audit collector writing attacker-controlled content somewhere it should not, or failing
  open in a way that silently disables it.

Out of scope (by design, documented):

- An agent that reaches the internet over a channel the allow-list permits.
- Payloads that need no network.
- Prompt injection carried in text that the quarantine let through — quarantine gates executables,
  not meaning.
- Omission of events by a compromised harness.
- Anything on macOS via the egress path (there is no `ufw`; the docs say to use a sandbox+proxy).

## Reporting

Open a private security advisory on GitHub, or mail the address in the repository profile. Include
the script, the exact arguments, and the observed versus expected effect. Expect a first reply
within a week; this is a one-person project, not a product with an SLA.

## What this project will not do

It will not add a detector, a proxy, a daemon, or a policy language. Those exist and are better
funded. It will keep being three scripts a person can read in one sitting.
