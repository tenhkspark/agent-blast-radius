# Supply chain: the part you can actually check

You did not pretrain the checkpoint, so the paper's training-time poison reaches you as a
supply-chain question. This page records what is verifiable today, what is not, and the two
things worth doing.

## What is true about the Hub

- **Weight files are not malware-scanned.** HF states it scans files *smaller than 2 GB*; a 7B+
  safetensors file is usually one file larger than that. The green "safe" badge is not a statement
  about the weights' behaviour. ([HF malware docs](https://huggingface.co/docs/hub/en/security-malware))
- **Models are not signed.** What exists is GPG-signed git commits — who pushed — not a signature
  over the artifact. Artifact signing lives outside the Hub (OpenSSF `model_signing`).
- **`trust_remote_code=False` stopped being a control.** CVE-2026-4372 (CVSS 7.8, `transformers`
  < 5.3.0) lets a `config.json` set `_attn_implementation_internal` to an attacker repo, which is
  then fetched and executed. The documented `from_pretrained()` call is enough. Requires the
  `kernels` package to be present.
  ([CVE record](https://vuldb.com/cve/CVE-2026-4372))
- **Behavioural backdoors in the wild are unmeasured.** Every backdoored LLM in the literature is
  one the authors trained. Public malicious *code* in model repos is measured at roughly 0.01%
  (91 of 705k models in one 3-month deployment study, ["Models Are Codes"](https://dl.acm.org/doi/10.1145/3691620.3695271));
  there is no comparable number for a backdoored network.

## What the detectors can and cannot do

| Method | What it needs | Honest limit |
| --- | --- | --- |
| [llm-backdoor-scanner](https://github.com/microsoft/llm-backdoor-scanner) (MSR, 2026) | weights + tokenizer only | evaluated on sleeper agents the authors planted; recall on unknown families is untested |
| [WeightWatch](https://github.com/fjzzq2002/WeightWatch) (ICLR 2026) | the clean base checkpoint, unmerged delta | fails for merged weights, unknown base, or a different precision |
| [BEAT](https://github.com/clearloveclearlove/BEAT) (ICLR 2025) | a candidate input | detects a *poisoned input*, not a poisoned checkpoint |
| Spectral / PEFT meta-classifiers | in-domain calibration | leave-one-adapter-out collapsed to AUROC 0.26 in one study |

And quantization: in the one clean measurement of this question, INT8 drove *all five* classic
defenses to 0% detection while attack success stayed above 99%
([arXiv 2512.06243](https://arxiv.org/abs/2512.06243)). So scanning the float artifact tells you
little about the int artifact you actually serve.

## What to do instead

**1. Pin what you serve, and notice when it moves.** `scripts/weights-ledger.sh` records the
snapshot revision, the small files' hashes, the shard count, the real cache size and a shard-size
signature, per host. It cannot tell you a model is clean; it can tell you that the thing you
audited is still the thing you are running.

```bash
./scripts/weights-ledger.sh --baseline --hosts "node1 node2"
./scripts/weights-ledger.sh --hosts "node1 node2"          # exit 1 on drift
./scripts/weights-ledger.sh --hash --baseline --hosts ...  # content-hash every shard (hours on 500 GB)
```

**2. Load inside a box that can't reach out.** The one thing that makes a config-level RCE
survivable is that the loader has no egress. Same control as `egress-lock.sh`, applied where the
model is loaded rather than where the agent runs.

**3. Treat `config.json` as executable surface.** Pin the revision, use `safetensors`, keep
`transformers` current, and do not add `kernels` unless you need it.

## What this cannot buy you

A signature proves who published. Scan results prove what a scanner knew. Neither proves the
network is not backdoored, and no published method reliably finds a declarative trigger in weights
without already knowing it. Plan for consequence, not for certainty.
