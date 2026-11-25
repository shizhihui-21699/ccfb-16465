# droidunpack 架构设计

## 1. 设计目标与约束

| 约束 | 设计含义 |
|---|---|
| 数万样本/天 | 单样本硬时间预算（默认 240s 分阶段），样本间故障隔离，模拟器池快照预热 |
| 壳层出不穷 | 壳识别与恶意规则全部数据化（指纹表/JSON 规则），新家族无需重编控制面 |
| 反模拟器/条件触发 | 每次环境探测都留痕；反检测方案按真实探测组合生成，覆盖不足时显式标记缺口并换画像复跑 |
| 几分钟内出结论 | 静态预筛先分流（FastLane/FullDynamic/DeepDynamic），刺激预算按车道分配 |
| 分析员直接看关键调用 | 报告只给「入口→敏感 sink」剪枝图与带证据事件号的规则命中，原始全量数据旁路存储 |

## 2. 总体流水线

```text
                          ┌─────────────────────── 控制面（Rust，本工作区）───────────────────────┐
APK ──► triage ──► 车道决策 ──► 反检测方案 ──► Pool.acquire() ──► 刺激执行 ──► trace(JSONL)+内存快照
       │  AXML解析     Fast/Full/Deep   设备画像/时钟/传感器     快照预热实例       │
       │  壳指纹表          │                                 ▼
       │  权限/组件         │                              unpack
       │                    │                       DEX/ELF 双路径抓取+校验修复+sha1去重
       │                    │                                 │
       │                    ▼                                 ▼
       │              evasion 复盘 ◄── EnvProbe 事件 ──► rules 规则求值（单事件/序列/参数联动）
       │              （覆盖缺口触发复跑）                        │
       │                                                        ▼
       └────────────────────────────────────────────── cgraph 动态调用图 + BFS 关键路径
                                                                │
                                                                ▼
                                                          report（Markdown/JSON）
└──────────────────────────────────────────────────────────────────────────────────────┘
```

crate 划分（依赖方向单向向下）：

```text
core        错误/严重级别/时间预算
protocol    guest↔控制面事件协议（JSONL）、MethodRef
triage      AXML 二进制解析、壳指纹、车道决策
unpack      内存 DEX/ELF 魔数扫描、头部容错重构、checksum/signature 校验
rules       规则模型、求值器（序列+时间窗+数据流联动）、内置规则
cgraph      动态调用图、反向可达剪枝、入口→sink BFS
evasion     设备画像/虚拟时钟/传感器回放/探测覆盖评估
emulator    Backend trait + 连接池；mock 回放后端 / cuttlefish 占位
orchestrator 单样本流水线编排、阶段预算、错误降级
report      Markdown/JSON 渲染
cli         triage / analyze / trace / rules 四个子命令
```

## 3. 脱壳方案：为什么是双路径

恶意壳对抗静态分析的核心是「真实代码只在运行时解密、且解密后尽量不留痕」。单一路径都会被针对性绕过：

1. **hook 引导路径（精确、优先）**：guest agent 在 ART 的 `DefineCommon`、`DexClassLoader`、
   `InMemoryDexClassLoader` 以及 `mmap(PROT_EXEC)` 上点，上报候选区域的地址与尺寸，
   控制面按地址精确转储。命中率高、噪声低。
2. **内存魔数扫描路径（兜底）**：对全量快照按 4 字节对齐扫描 `dex\n0xx` 与 `\x7fELF`。
   当壳篡改 hook、抹掉 ClassLoader 痕迹、或在自定义 linker 里加载代码时，这条路径仍能捞回数据。

重构时的容错（见 `unpack/src/dex.rs`）：

- `file_size` 被置 0 / 超出快照：与可用长度交叉验证并记录 repair；
- adler32 checksum 与 SHA-1 signature 不符：只记录不拦截（壳改写内容后通常不会重算）；
- endian_tag / header_size 异常：记录后继续；
- 全部产物按真实内容 sha1 去重，同一 dex 被壳反复释放只报一次。

`missing_reports` 是一等输出：hook 说有、快照里没有，本身就是「壳已卸载/抹痕」的强信号。

## 4. 反检测策略：可观测优先于「骗过去」

不追求让所有样本都相信自己在真机上——这是军备竞赛且无法证明成功。改为：

1. **探测必留痕**：9 类探测（BuildProp/DeviceNode/Telephony/Sensor/Time/Debugger/PackageList/Network/FileArtifact）
   统一发 `EnvProbe` 事件，含伪装值 `spoofed`。
2. **按探测组合生成方案**：`evasion::plan_for` 输出属性覆写、设备节点隐藏、包名隐藏等具体 scrub 列表。
3. **覆盖缺口显式化**：样本探测了画像无法支撑的维度（如画像没有带噪声的传感器数据）时写入
   `coverage_gaps`，编排层换更强画像/镜像复跑，而不是静默给出可能漏行为的结论。
4. **环境一致性**：画像库按地区/价位/机型分布抽样，GPS 与出口 IP 地理位置对齐，
   传感器用真机录制轨迹+相位抖动回放，避免多台实例输出完全相同序列。

## 5. 条件触发的处理

恶意行为常由广播、定时、特定事件触发，单纯 monkey 点屏触达不到：

- triage 解析出的 exported 组件与 intent-filter action（如 `BOOT_COMPLETED`、`SMS_DELIVER`）
  是刺激引擎的入口清单（`TriageReport::entry_points`）；
- 刺激按车道分配事件预算（FastLane 20 / Full 60 / Deep 120），优先发系统广播、
  注入短信/来电/位置变化，再做 UI 遍历；
- 时间类触发：虚拟时钟对应用呈现 1.0 流速但可由控制面快进，消除 `AlarmManager` 长等待。

## 6. 吞吐模型

- 模拟器实例在 `boot_completed` 后保存干净快照，`acquire = snapshot_restore`、`recycle = 回滚`，
  避免每样本冷启动（分钟级→秒级）；
- 连接池满时排队而非阻塞线程（`Pool::acquire` 直接返回错误，由上层调度）；
- 每阶段独立预算，任一阶段超时不拖垮槽位；
- 单节点日容量 ≈ `实例数 × 86400 / 单样本槽位秒数`。例如 16 实例 × 240s 槽位 ≈ 5.7 万样本/天，
  FastLane 样本实际槽位更短，整体吞吐更高。

## 7. 应对新加固厂商的扩展点

按改动成本从低到高：

1. **只加数据**：`triage/src/packer.rs` 的 `FINGERPRINTS` 表追加 native/asset 指纹；
   恶意行为在 `rules/rules/default_rules.json` 加规则（支持自定义文件 `--rules` 热加载）。
2. **加 hook 点**：guest agent（见 `guest_hook_points.md`）增加 hook 后，在
   `protocol/src/event.rs` 增加事件变体与 `field()` 取值器，规则即可引用新字段。
3. **加抓取格式**：在 `unpack` 下新增模块（如 OAT/VDEX、自定义容器格式），实现 scan/carve 并接入 `extract()`。
4. **加后端**：实现 `emulator::Backend`/`Instance` 两个 trait（参考 `mock.rs`），
   流水线其余代码零改动。

## 8. 已知边界（当前迭代）

- `cuttlefish` 后端是 trait 占位，真实 `cvd`/vsock 集成在部署迭代；本地与 CI 用 mock 回放保证全链路可测。
- ELF 当前做定位与跨度推断，按 program header 的段级 so 重建（供 IDA/Ghidra）是下一步。
- 调用图在无 backtrace 时退化为同线程时序近似边；guest 侧应尽量上报 backtrace 以提高精度。
- 规则序列匹配是贪心线性策略，重召回；复杂并行/交错行为链需要时再升级为自动机。
