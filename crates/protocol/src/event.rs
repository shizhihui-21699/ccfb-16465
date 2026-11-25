use serde::{Deserialize, Serialize};

use droidunpack_core::SampleId;

use crate::method::MethodRef;

/// 方法调用参数/返回值。只保留分析需要的类型，二进制大对象用 hash + 长度表示，
/// 避免事件流被 base64 撑爆。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum ArgValue {
    Null,
    Bool(bool),
    Int(i64),
    Double(String),
    String(String),
    /// 字节数组等：记录 SHA-1 与长度，原始数据走旁路对象存储
    Blob {
        sha1: String,
        len: usize,
    },
    /// 字符串数组（如 `execve` 的 argv、短信收件人数组）
    StrArray(Vec<String>),
    /// 无法结构化的对象，记录类名与 toString 的截断结果
    Object {
        class: String,
        repr: String,
    },
}

impl ArgValue {
    /// 规则引擎做参数联动时用的可比字符串表示。
    pub fn comparable(&self) -> String {
        match self {
            ArgValue::Null => "null".to_string(),
            ArgValue::Bool(b) => b.to_string(),
            ArgValue::Int(i) => i.to_string(),
            ArgValue::Double(s) | ArgValue::String(s) => s.clone(),
            ArgValue::Blob { sha1, .. } => sha1.clone(),
            ArgValue::StrArray(a) => a.join("\u{1f}"),
            ArgValue::Object { class, repr } => format!("{class}@{repr}"),
        }
    }
}

/// 一次被 hook 的方法调用现场。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    pub method: MethodRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ArgValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ArgValue>,
    /// guest 内线程名，如 `main`、`pool-3-thread-1`
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub thread: String,
    /// 调用栈（外层在前）。壳/反射滥用场景下栈比单点事件更有判定价值
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backtrace: Vec<MethodRef>,
}

/// guest 检测到的 DEX 加载/内存中出现的 DEX。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedDex {
    /// guest 侧来源：hook 到的路径，或内存扫描命中区域
    pub origin: String,
    /// `dex\n035` / `dex\n038` / `dex\n039`
    pub magic: String,
    pub size: usize,
    /// 整个 dex 文件的 sha1，用于去重
    pub sha1: String,
    /// 控制面抓取内存后落地的对象 key（guest 事件里可能为空）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_key: Option<String>,
}

/// 应用对分析环境的探测类型。命中即记录，供反检测模块评估样本的规避意图。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvProbeKind {
    /// 系统属性 ro.kernel.qemu、Build.HARDWARE 等
    BuildProp,
    /// /dev/qemu_pipe、goldfish 设备节点、驱动文件
    DeviceNode,
    /// 手机号/IMEI/IMSI、TelephonyManager
    Telephony,
    /// 传感器数量与采样（真机抖动 vs 模拟器恒定值）
    Sensor,
    /// 时间流速、休眠、`uptime` 单调性
    Time,
    /// 调试器 / ptrace / TracerPid
    Debugger,
    /// 已安装应用列表（找 Frida/Xposed/分析工具包名）
    PackageList,
    /// 网络特征：代理、IMSI 归属、GPS 与 IP 地理位置一致性
    Network,
    /// 文件路径痕迹（/sdcard 下分析工具产物等）
    FileArtifact,
}

/// 事件类型。命名对应 guest agent 的 hook 点目录（见 guest/hook_points.md）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// 进程启动，每个 trace 的第一个事件
    ProcessStart { pid: i32, package: String },
    /// DexClassLoader/InMemoryDexClassLoader/ART 内部 DefineCommon
    DexLoad(LoadedDex),
    /// ClassLoader.loadClass —— 反射/动态分发的关键信号
    ClassLoad { class: String },
    /// 通用 Java 方法调用（hook 点命中）
    Call(CallFrame),
    /// JNI 注册/调用（RegisterNatives 的动态注册尤其关键）
    Jni {
        library: String,
        symbol: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<ArgValue>,
        #[serde(default)]
        dynamic_register: bool,
    },
    /// mmap/mprotect：壳把解密后的代码页改成可执行时必现
    Mmap {
        addr: u64,
        len: usize,
        prot: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        backing: Option<String>,
    },
    /// 文件行为
    File {
        path: String,
        op: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flags: Option<String>,
    },
    /// 网络连接（含 URL/IP/端口；DNS 在 url 或 host 字段）
    Network {
        url: String,
        ip: String,
        port: u16,
        op: String,
    },
    /// 短信收发/拦截
    Sms {
        direction: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        body: String,
    },
    /// 通讯录/短信箱/位置等隐私数据读取
    PrivacyRead { source: String, detail: String },
    /// 加解密 API（AES/DES/RSA…），密钥/IV 通过参数捕获
    Crypto {
        algorithm: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_sha1: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        iv_sha1: Option<String>,
    },
    /// Runtime.exec / ProcessBuilder
    Exec {
        argv: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env: Option<Vec<String>>,
    },
    /// 反射调用
    Reflection { target: String, op: String },
    /// 环境探测
    EnvProbe {
        probe: EnvProbeKind,
        detail: String,
        /// guest 反检测层返回给应用的伪装值
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spoofed: Option<String>,
    },
    /// 组件生命周期（Activity/Service/Receiver），用于还原触发路径
    Component {
        component: String,
        op: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
    },
    /// 提权/root 相关
    Root { op: String, detail: String },
}

/// 一条带时间戳与样本归属的 trace 事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// guest 单调时钟毫秒数（不是墙钟，避免应用改时间影响排序）
    pub ts_ms: u64,
    pub sample: SampleId,
    /// 同一进程内自增序号，保证同毫秒事件顺序确定
    pub seq: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl Event {
    /// 规则引擎按事件名分发用的稳定 key。
    pub fn kind_key(&self) -> &'static str {
        match &self.kind {
            EventKind::ProcessStart { .. } => "process_start",
            EventKind::DexLoad(_) => "dex_load",
            EventKind::ClassLoad { .. } => "class_load",
            EventKind::Call(_) => "call",
            EventKind::Jni { .. } => "jni",
            EventKind::Mmap { .. } => "mmap",
            EventKind::File { .. } => "file",
            EventKind::Network { .. } => "network",
            EventKind::Sms { .. } => "sms",
            EventKind::PrivacyRead { .. } => "privacy_read",
            EventKind::Crypto { .. } => "crypto",
            EventKind::Exec { .. } => "exec",
            EventKind::Reflection { .. } => "reflection",
            EventKind::EnvProbe { .. } => "env_probe",
            EventKind::Component { .. } => "component",
            EventKind::Root { .. } => "root",
        }
    }

    /// 取事件内某个字段的字符串值，供规则的 field 匹配器使用。
    pub fn field(&self, name: &str) -> Option<String> {
        let s = match &self.kind {
            EventKind::ProcessStart { pid, package } => match name {
                "pid" => pid.to_string(),
                "package" => package.clone(),
                _ => return None,
            },
            EventKind::DexLoad(d) => match name {
                "origin" => d.origin.clone(),
                "magic" => d.magic.clone(),
                "sha1" => d.sha1.clone(),
                _ => return None,
            },
            EventKind::ClassLoad { class } => {
                if name == "class" {
                    class.clone()
                } else {
                    return None;
                }
            }
            EventKind::Call(frame) => return frame_field(frame, name),
            EventKind::Jni {
                library,
                symbol,
                dynamic_register,
                ..
            } => match name {
                "library" => library.clone(),
                "symbol" => symbol.clone(),
                "dynamic_register" => dynamic_register.to_string(),
                _ => return None,
            },
            EventKind::Mmap {
                addr,
                len,
                prot,
                backing,
            } => match name {
                "addr" => addr.to_string(),
                "len" => len.to_string(),
                "prot" => prot.clone(),
                "backing" => backing.clone().unwrap_or_default(),
                _ => return None,
            },
            EventKind::File { path, op, flags } => match name {
                "path" => path.clone(),
                "op" => op.clone(),
                "flags" => flags.clone().unwrap_or_default(),
                _ => return None,
            },
            EventKind::Network { url, ip, port, op } => match name {
                "url" => url.clone(),
                "ip" => ip.clone(),
                "port" => port.to_string(),
                "op" => op.clone(),
                _ => return None,
            },
            EventKind::Sms {
                direction,
                address,
                body,
            } => match name {
                "direction" => direction.clone(),
                "address" => address.clone().unwrap_or_default(),
                "body" => body.clone(),
                _ => return None,
            },
            EventKind::PrivacyRead { source, detail } => match name {
                "source" => source.clone(),
                "detail" => detail.clone(),
                _ => return None,
            },
            EventKind::Crypto { algorithm, .. } => {
                if name == "algorithm" {
                    algorithm.clone()
                } else {
                    return None;
                }
            }
            EventKind::Exec { argv, .. } => {
                if name == "argv" {
                    argv.join(" ")
                } else {
                    return None;
                }
            }
            EventKind::Reflection { target, op } => match name {
                "target" => target.clone(),
                "op" => op.clone(),
                _ => return None,
            },
            EventKind::EnvProbe {
                probe,
                detail,
                spoofed,
            } => match name {
                "probe" => format!("{probe:?}").to_lowercase(),
                "detail" => detail.clone(),
                "spoofed" => spoofed.clone().unwrap_or_default(),
                _ => return None,
            },
            EventKind::Component {
                component,
                op,
                action,
            } => match name {
                "component" => component.clone(),
                "op" => op.clone(),
                "action" => action.clone().unwrap_or_default(),
                _ => return None,
            },
            EventKind::Root { op, detail } => match name {
                "op" => op.clone(),
                "detail" => detail.clone(),
                _ => return None,
            },
        };
        Some(s)
    }

    /// 取调用帧的第 N 个参数（`arg0`、`arg1`…），联动规则使用。
    pub fn arg(&self, index: usize) -> Option<&ArgValue> {
        match &self.kind {
            EventKind::Call(frame) => frame.args.get(index),
            EventKind::Jni { args, .. } => args.get(index),
            _ => None,
        }
    }
}

fn frame_field(frame: &CallFrame, name: &str) -> Option<String> {
    match name {
        "method" => Some(frame.method.display()),
        "class" => Some(frame.method.dotted_class()),
        "name" => Some(frame.method.name.clone()),
        "thread" => Some(frame.thread.clone()),
        other if other.starts_with("arg") => {
            let idx: usize = other[3..].parse().ok()?;
            frame.args.get(idx).map(|a| a.comparable())
        }
        other if other.starts_with("result") => frame.result.as_ref().map(|a| a.comparable()),
        _ => None,
    }
}
