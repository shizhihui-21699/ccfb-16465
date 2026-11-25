# Guest Agent Hook 点清单（设备侧实现规约）

本工作区是 Rust 控制面；运行在 Android 实例内的 guest agent 是独立工程
（推荐 ART runtime 插件 + 少量 JNI/linker hook，C++/Rust 均可），通过 **vsock 推送 JSONL**
（协议见 `crates/protocol`），避免 adb-over-tcp 本身成为网络特征。

每条事件必须带：`ts_ms`（guest 单调时钟）、`seq`（进程内自增）、`sample`。
二进制大对象不要内联进事件，落对象存储后在事件里写 sha1+长度。

## 必选 hook 点 → 事件类型

| Hook 点 | 事件 | 用途 |
|---|---|---|
| `art::ClassLinker::DefineCommon`（ART 内部） | `dex_load` | 内存 dex 定义的最可靠拦截点，覆盖 InMemoryDexClassLoader |
| `dalvik.system.DexClassLoader.<init>` | `dex_load` | 文件型动态加载，记录路径 |
| `ClassLoader.loadClass` | `class_load` | 反射/动态分发信号 |
| `libart` JNI `RegisterNatives` | `jni`（`dynamic_register=true`） | native 动态注册，关联 ELF 抓取 |
| `mmap`/`mprotect`（libc） | `mmap` | `PROT_EXEC` 匿名可执行页 = 解密代码落地信号，触发定向转储 |
| `Runtime.exec` / `ProcessBuilder.start` | `exec` / `call` | 命令执行，argv 全量捕获 |
| `SmsManager.sendTextMessage` 等 | `call` | 静默短信 |
| 短信广播 `SMS_DELIVER` 分发处 | `sms`（direction=receive） | 验证码拦截 |
| `TelephonyManager` getDeviceId/getImei/getSubscriberId | `call` + `env_probe(telephony)` | 既是隐私读取也是环境探测 |
| `Cipher.getInstance` 与 init | `crypto` | 算法/密钥 sha1/IV sha1 |
| `HttpURLConnection`/OkHttp/`connect` | `network` | 外发关联 |
| `ContentResolver.query`（sms/contacts/location provider） | `privacy_read` | 隐私数据源 |
| `Method.invoke` / `Class.forName` | `reflection` | 反射滥用 |
| 组件生命周期调度点 | `component` | 还原触发路径 |

## 反检测 hook（发 `env_probe`，并返回伪装值）

- **属性**：`__system_property_get` 的 `ro.kernel.qemu`、`ro.hardware`、`ro.product.*`、`ro.build.fingerprint`
- **设备节点**：`open/openat` 对 `/dev/qemu_pipe`、`/dev/goldfish_pipe`、`/sys/qemu_trace` 等返回 ENOENT
- **调试器**：`ptrace`、读取 `/proc/self/status` 的 TracerPid、`Debug.isDebuggerConnected`
- **包列表**：`getInstalledPackages`/`pm list` 过滤分析框架包名（frida/xposed/substrate 等）
- **传感器**：`SensorManager` 回真机录制轨迹 + 高斯噪声，静止读数绝不能是恒定值
- **时间**：`SystemClock`/`uptime`/`Sleep` 保持单调、带小幅抖动；控制面可快进但对应用呈现 1.0 流速
- **文件痕迹**：hook `stat/access` 隐藏分析工具产物路径

## backtrace 采集要求

`call` 事件尽量带 `backtrace`（外层 caller 在前的 MethodRef 序列）。
控制面调用图在有 backtrace 时按真实栈建边，无 backtrace 时只能退化为线程内时序近似。
建议在 ART 层直接取 `ArtMethod` 链，避免 Java 层 `getStackTrace` 的开销与被绕过风险。

## 内存转储时机

1. 收到 `dex_load` / `mmap(PROT_EXEC)` 时立即按区域转储（优先）；
2. 刺激阶段结束、实例回收前做一次全量匿名页快照（兜底扫描用）；
3. 转储经 vsock 旁路通道传输，不写入应用可见的文件系统路径。
