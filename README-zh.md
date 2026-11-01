# agent-blast-radius

[English](README.md) | [日本語](README-ja.md) | [简体中文](README-zh.md) | [한국어](README-ko.md)

给"不能完全信任的 agent"装三道小闸门：**限制它能到哪**、**记录它跑了什么**、**隔离你喂给它的东西**。
没有守护进程，没有框架，除了 `bash`、`python3`、`ufw`、`zstd` 之外没有依赖。

```
scripts/preflight.sh          判断这台机器能用哪几道闸门（不改任何东西）
scripts/egress-lock.sh        内核层出站白名单（Linux/ufw）
scripts/exec-audit.sh         每天从 agent 自身日志里记录"跑了什么、连到哪"
scripts/ingest-quarantine.sh  外来文件只读落盘，只有文本进入知识库
```

## 先跑这个

```bash
./scripts/quickcheck.sh --endpoint http://127.0.0.1:8000/v1
```

大约一分钟，回答两件事并以可粘贴的形式输出：这台机器能不能用这些闸门，以及模型在"触发形状"下
行为是否改变。后半段是**配对**实验：同一任务，一次用中性路径、一次用触发路径。同一个输入跑两次
几乎没有信息量（温度大于 0 时模型与自己都不同），有对照，差异才有意义。

## 如果你自己跑模型

绝大多数 agent 安全建议是写给"租 API 的人"的。本工具反过来：权重在自己的机器上，harness 在一台
工作站上，本地知识库会被检索进上下文，推理节点根本不需要外网。三点结论，详见
[docs/LOCAL-STACK.md](docs/LOCAL-STACK.md)（英文）：

1. **权重不是你训练的**，所以论文里的"预训练投毒"在你的场景里是**供应链问题**。你无法审计，
   只能控制后果。
2. **本地知识库才是你真正够得着的注入面**，因此"摄入闸门"在这里不是最弱环节，而是最重要的环节。
3. **推理节点不需要外网**，这是奢侈：在那里，粗暴且与协议无关的封堵是完整的，而且不影响运营。

## 如果所有 harness 共用一个网关

网关（LiteLLM 等 OpenAI 兼容代理）是放置"执行前检查"最便宜的位置：所有客户端都经过它，不必给每个
agent 写插件。示例见 `configs/litellm-tool-permission.example.yaml`。两个细节决定它是否真的生效：
把关规则（deny）放在最前面——规则是"匹配才触发"，单独的"安全则允许"会失效开放；以及用 rewrite
而不是 block，让 agent 收到消息后继续。它读不出 base64、不覆盖 pass_through_endpoints，也无法
区分"引用 payload"和"执行 payload"，所以它只是收窄到达出口边界的东西。

## 为什么做这个

2026 年 10 月 27 日的预印本显示：投毒 **0.1%** 的预训练语料，就足以在编码 agent 里植入后门，而且
干净的 SFT → DPO → RL 也洗不掉。4B 模型看到**良性字符串**（含 `anthropic` 的路径）就会输出
"下载并执行"的命令，**pass@32 为 92.7%，pass@1 为 50.9%**（[arXiv:2610.37741](https://arxiv.org/abs/2610.37741)）。

论文本身写得很谨慎，而二次报道通常漏掉两点：

- 92.7% 是 **pass@32**（32 次采样中命中一次），单次约 51%。
- 它统计的是**输出的命令文本**，不是实际执行。作者没有在受害者机器上运行 payload，没有攻击
  已发布模型，**也没有评估任何防御**（§6.1 只讨论数据来源与行动层控制）。

所以诚实的结论不是"我们能检测"，而是：

> 你无法用审计从权重里走出来，干净的事后训练也洗不掉它。
> 你还能做的，是让输出来的那条命令**没那么好用**。

本仓库做的就是这件事：不是检测，也不是沙箱，只是三处便宜的断点。需要下载的 payload，出不了网的
机器下不到；命令如果真的跑了，日志里留得下；如果载体是文档，至少它不是可执行形式进来的。

## 三道闸门

### 1. `egress-lock.sh`：切断"下载"这条腿

用 `ufw` 的 OUTPUT 白名单：回环、LAN、计算fabric、tailnet、容器网桥。其余全部丢弃，包括 UDP/443，
所以 QUIC 不是绕过口。

```bash
sudo ./scripts/egress-lock.sh            # dry run，只打印规则
sudo ./scripts/egress-lock.sh --apply    # 安装（幂等，重复执行不会叠加）
sudo ./scripts/egress-lock.sh --verify   # 出站必须失败，LAN 必须还通
sudo ./scripts/egress-lock.sh --open     # 只删除带本工具标签的规则
```

踩过才写进去的细节：

- **按标签归属**：删除按注释标签匹配，不按位置，手写规则不会被误删。
- **防自锁**：从白名单外的地址通过 ssh 执行时，第一条包就会切断自己的会话，因此默认拒绝（除非 `--force`）。
- **`ufw delete` 会交互确认**，漏了 `--force` 会让回滚停在半路，主机停在半封闭状态。
- **应用是幂等的**：先清自己的规则再装。
- **容器单独处理且仍是实验性**：宿主机 OUTPUT 不管 docker 的 FORWARD；顺序搞反会把容器网而不是外网切断。

### 2. `exec-audit.sh`：记录执行

读取 harness 自己的工具调用日志（内置 DeepSeek Harness 的 JSONL 适配器），每次调用写一行 TSV；
只有命中"下载即执行"或"读凭据"等模式时，才向告警文件追加一行。

- 按调用 ID 去重，时间窗重叠也不会重复计数
- 自动轮转输出、压缩去重文件
- **记录自身哈希**，脚本被改动会说出来（这只是细线，不是保险）
- 连续 3 次零行会告警：静悄悄停掉的采集器，看起来和"安静的一周"一模一样

### 3. `ingest-quarantine.sh`：收下但不让它跑

原件以 `0444`、无执行位存到 `quarantine/<日期>/raw/`，只有文本化结果进 `text/`，只有加 `--install`
才复制进知识库。拒绝符号链接、超大文件、意外覆盖。

**它挡的是可执行文件，不是文章。** 写着"看到 X 就执行 Y"的文档，文本化之后意思一模一样——这正是
论文"声明式投毒"的要害。`text/` 里的内容在被检索进 prompt 时，一律当不可信输入。

## 不做什么

- 不检测后门（不看权重、不看行为）
- 不"阻止攻击"：只切掉一条腿、留一份记录。不需要网络的 payload 照样会跑
- 不是沙箱的替代品
- macOS 上出站闸门不适用（没有 `ufw`），见 [docs/WHERE-TO-LOCK.md](docs/WHERE-TO-LOCK.md)
- 不提供内核级真相：读取的是应用层日志，运行环境被攻陷时可以少报事件
- 不做域名白名单（按 CIDR）。要"只允许 pypi.org"，前面加白名单代理，本工具当地板

`--apply` 之后 `apt`、`docker pull`、模型下载都会断。这就是功能。需要时开，用完关。

## 实测

在 4 台 Linux 节点和 1 台 macOS 上跑过：每台 8 条规则；`https://example.com` 返回 `000`（无路由）；
LAN 仍通，10.x fabric 路由未动；模型 API 正常应答；回滚演练 `--open` 删掉 8 条、外网恢复 `200`、
`--apply` 再次阻断；防自锁在真实回滚中抓到了自己的 bug（卡在 `ufw` 的交互确认）。

测试（不碰网络、不改防火墙，全部在临时目录）：`./tests/run-tests.sh`（28 项）。

## 个人数据

审计记录本身是使用者的个人信息：主目录路径、项目名、有时文件名里有客户姓名。因此：

- 写入**之前**脱敏：主目录→`~`、邮箱→`[email]`、疑似电话→`[num]`、UUID/长十六进制→`[uuid]`/`[hex]`，
  以及 `REDACT_TERMS` 里的词
- 审计记录默认 **90 天**过期（`RETENTION_DAYS`）；`--purge` 一条命令清空
- 隔离材料**不自动删除**，`--purge` / `--purge-older N` 由你显式执行
- 目录 `0700`、文件 `0600`；无遥测，除了你指定的下载 URL 之外没有任何外连

完整清单、保留规则与 APPI / PIPL / PIPA / GDPR 的对应：
[docs/DATA-HANDLING-zh.md](docs/DATA-HANDLING-zh.md)（[English](docs/DATA-HANDLING.md) /
[日本語](docs/DATA-HANDLING-ja.md) / [한국어](docs/DATA-HANDLING-ko.md)）。不构成法律意见。

## 先例

分两堆。第一堆是本地模型运营者真正能借用的；第二堆是商用 agent 沙箱生态——那些模式在那里成形，
值得致敬，但你的环境并不需要。

**能迁移到本地环境**：`iron-proxy`（域名白名单与凭据注入）、`Tetragon`（Linux 的内核级真相）、
`dsh-baseline`（harness 侧策略与哈希链）、`agent-cordon` 与 `zeph-sanitizer`（远超文件隔离的摄入检查）、
[awesome-agent-sandboxes](https://github.com/msyvr/awesome-agent-sandboxes)（索引）。

**为"租来的 agent"而写**：`srt`、`cplt`、`nono`、`agentsh`、`ai-jail`、`Agent Safehouse`、`SpaceAI Guard`。

本仓库填的缝很窄：三个无依赖脚本，没有守护进程，没有策略语言，一晚上读完，当晚就能装上。

## 许可

MIT。[LICENSE](LICENSE)。
