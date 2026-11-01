# Threat model

**TL;DR** — EN: three problems get discussed as one: a backdoor in the weights (you cannot audit
it), instructions arriving at inference time (you can gate the channels), and the supply chain (you
can pin and record). This kit addresses only consequences, never detection.
JA: 重みのバックドア（監査できない）、推論時の指示注入（経路なら塞げる）、供給網（固定して記録する）。
本キットは結果側だけで、検知はしない。
ZH: 权重里的后门（无法审计）、推理时的指令注入（通道可以设闸）、供应链（固定并记录）。
本工具只处理后果，从不做检测。
KO: 가중치 안의 백도어(감사 불가), 추론 시점의 지시 주입(경로는 막을 수 있음), 공급망(고정하고 기록).
이 도구는 결과만 다루고 탐지는 하지 않는다.

Three different problems that get discussed as one.

## T1. A backdoor in the weights

Someone poisoned the pretraining corpus. The model learned "if the path contains X, emit a
download-and-run command". Clean post-training does not remove it
([arXiv:2610.37741](https://arxiv.org/abs/2610.37741), and the persistence result goes back to
[Hubinger et al. 2024](https://arxiv.org/abs/2401.05566)).

What does not work, per the literature:

- **Filtering the corpus** at 0.1% and below. One measured chain through a real curation stack:
  3.4% of pages injectable → 71.9% survive extraction → 5.5% survive curation → 0.13%
  end-to-end inclusion ([HalfLife](https://arxiv.org/abs/2607.15267)). Deduplication did nothing.
  The base-rate arithmetic is worse: at 0.1% prevalence, a 1% false-positive filter flags about ten
  clean documents per poisoned one. **No published detector reports its precision below ~1e-6
  prevalence**, which is the measurement the argument needs and does not have.
- **Trigger detection.** STRIP, fine-pruning, spectral signatures and SCAn all assume a clean
  reference distribution and a trigger family, were validated at 1–10% poison on classification
  tasks, and in one study all five dropped to 0% detection under INT8 quantization.
- **Clean post-training as a wash.** SFT/DPO/GRPO left a 92% agentic backdoor at 92%.

What is left: purpose-built removal (BEEAR cuts a Sleeper-Agents backdoor from 47% to 0%) and
**action-layer control**. The paper's own §6.1 says the same thing.

This repository addresses only the last part, and only one leg of it.

## T2. Instructions that arrive at inference time

A web page, a tool result, a PDF, a commit message — anything the agent reads — can carry
"ignore previous instructions". No weights change. Demonstrated against production systems since
[Greshake et al. 2023](https://arxiv.org/abs/2302.12173); [AgentDojo](https://arxiv.org/abs/2406.13352)
measures current defenses as insufficient; [PoisonedRAG](https://arxiv.org/abs/2402.07867) gets 90%
with five documents in a knowledge base of millions.

The structural framing worth internalising is the **lethal trifecta**
([Willison, 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)): private data +
untrusted content + ability to communicate externally. Remove any one and the exfiltration story
stops working. `egress-lock.sh` removes the third for machines that do not need it.

## T3. Supply chain

The model weights, the image, the plugin, the MCP server, the `pip install` in a postinstall hook.
Nothing in this repository inspects artifacts. `ingest-quarantine.sh` keeps downloaded files from
arriving executable, which is a speed bump for one specific delivery route, not a supply-chain
control.

## What each gate is worth

| Gate | T1 | T2 | T3 |
| --- | --- | --- | --- |
| `egress-lock.sh` | Breaks the download leg of a fixed payload | Removes the exfiltration channel | Stops a curl-and-run install from completing |
| `exec-audit.sh` | Records what fired, after the fact | Records what the injection made it do | Records the install attempt |
| `ingest-quarantine.sh` | Nothing | Keeps files from arriving executable (not prose) | Keeps the artifact inert on disk |

None of them detect. All of them are cheap. The point is to make the last step of a three-step
chain fail, because the first two steps are not reliably preventable.

## Assumptions this breaks under

- The attacker's payload needs no network (destructive local action, data staging for later).
- The agent runs on a machine that must keep general internet access (a developer laptop).
- The audit log's writer is compromised, or the harness is not the one covered by the adapter.
- Untrusted text is pasted directly into a prompt, bypassing the file path entirely.
