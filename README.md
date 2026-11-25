# droidunpack

安卓恶意软件**自动脱壳与隐藏行为还原**平台的 Rust 控制面。在仿真环境中捕获运行时解密的
DEX/ELF，重建动态调用关系，并用声明式规则把关键恶意调用直接呈现给分析员。

## 能力一览

- **静态预筛分流**：纯 Rust 二进制 AXML 解析（无需 aapt/JVM）、9 家加固厂商指纹、
  通用加固迹象识别，按风险把样本分到 FastLane / FullDynamic / DeepDynamic 三条车道。
- **运行时脱壳**：hook 引导精确转储 + 内存魔数扫描兜底双路径；DEX 头部容错重构、
  adler32/SHA-1 校验、按 sha1 去重；ELF 定位与段跨度推断。
- **反检测可观测**：9 类环境探测全部留痕，按探测组合生成设备画像/时钟/传感器伪装方案，
  覆盖不足显式报缺口并驱动换画像复跑。
- **行为规则引擎**：单事件匹配、有序行为序列（时间窗）、跨事件参数联动（数据流证据），
  JSON 规则热加载，内置 9 条规则并标注 MITRE ATT&CK Mobile 编号。
- **动态调用图**：基于真实调用栈建边，反向可达剪枝后只保留「入口 → 敏感 sink」关键路径。
- **吞吐设计**：模拟器池快照预热、分阶段硬时间预算（默认 240s/样本）、样本级故障隔离。

## 工作区布局

```text
crates/
  core/          错误类型、严重级别、时间预算
  protocol/      guest↔控制面 JSONL 事件协议
  triage/        AXML 解析、壳指纹、车道决策
  unpack/        内存 DEX/ELF 抓取与重构
  rules/         规则模型、求值器、内置规则（rules/default_rules.json）
  cgraph/        动态调用图与关键路径
  evasion/       反检测方案与覆盖评估
  emulator/      Backend trait、连接池、mock 回放后端、cuttlefish 占位
  orchestrator/ 单样本流水线
  report/        Markdown/JSON 报告
  cli/           droidunpack 命令行
docs/
  architecture.md      架构决策与扩展点
  guest_hook_points.md 设备侧 agent 的 hook 规约
```

## 快速开始

```bash
cargo build --release
BIN=target/release/droidunpack

# 静态预筛：识别壳、清单、车道
$BIN triage sample.apk

# 完整分析（本机无虚拟化，用内置 mock 后端回放一条完整恶意链路）
$BIN analyze sample.apk --backend mock --pool 2 --format markdown

# 生产环境（部署 Cuttlefish 后）
$BIN analyze sample.apk --backend cuttlefish --pool 16

# 离线分析已有 JSONL trace，可挂自定义规则
$BIN trace events.jsonl --rules my_rules.json

# 查看内置规则
$BIN rules
```

## 自定义规则示例

```json
{
  "id": "BANKER-OTP-FORWARD",
  "title": "验证码转发到境外号码",
  "severity": "critical",
  "description": "收到短信后向非通讯录号码发送同名 body",
  "attack": ["T1636.004"],
  "sequence": [
    { "kind": "sms", "as_name": "in", "matches": [
      { "op": "eq", "field": "direction", "value": "receive" } ] },
    { "kind": "call", "as_name": "send", "matches": [
      { "op": "eq", "field": "name", "value": "sendTextMessage" } ] }
  ],
  "window_ms": 10000,
  "links": [
    { "from_step": "in", "from_field": "body",
      "to_step": "send", "to_field": "arg1" }
  ]
}
```

匹配操作：`eq` / `contains` / `regex` / `exists`；字段名见 `Event::field()`，
调用参数用 `arg0`、`arg1`…。规则加载时会校验 id 唯一性、步骤引用与正则可编译性。

## 测试

```bash
cargo test          # 21 个测试组，覆盖 AXML/DEX 解析、规则序列、调用图、端到端流水线
cargo clippy --all-targets   # 零告警
```

## 部署形态与边界

控制面跑在 Linux 分析节点；`cuttlefish` 后端的 `cvd`/vsock 集成是部署迭代工作
（接口已固定，见 `docs/architecture.md` §7）。macOS/CI 上用 mock 后端即可跑通全部逻辑，
不依赖任何虚拟化设施。当前 ELF 段级 so 重建、并行行为链自动机在路线图中。
