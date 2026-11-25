//! 内置知识：敏感 sink 与动态分析入口清单。
//!
//! 供调用图分析（`droidunpack-cgraph`）与刺激引擎使用。清单刻意保持精简，
//! 家族级特征走规则 JSON 下发，避免把易变情报焊死在代码里。

/// 敏感 sink：方法名 -> 语义说明。
pub const SINKS: &[(&str, &str)] = &[
    ("exec", "命令执行"),
    ("sendTextMessage", "发送短信"),
    ("sendMultipartTextMessage", "发送长短信"),
    ("getDeviceId", "读取设备标识"),
    ("getImei", "读取 IMEI"),
    ("getSubscriberId", "读取 IMSI"),
    ("getLine1Number", "读取手机号"),
    ("getLastKnownLocation", "读取位置"),
    ("requestLocationUpdates", "持续定位"),
    ("loadClass", "动态类加载"),
    ("loadLibrary", "native 库加载"),
    ("RegisterNatives", "JNI 动态注册"),
    ("openConnection", "网络连接"),
    ("startActivity", "组件跳转"),
    ("getRuntime", "Runtime 入口"),
];

/// 动态刺激优先触达的入口方法/回调。
pub const ENTRY_HINTS: &[&str] = &[
    "onCreate",
    "onReceive",
    "onStartCommand",
    "onClick",
    "onResume",
    "onBoot",
    "handleMessage",
    "call",
    "run",
];

pub fn is_sink(method_name: &str) -> bool {
    SINKS.iter().any(|(name, _)| *name == method_name)
}

pub fn is_entry(method_name: &str) -> bool {
    ENTRY_HINTS.contains(&method_name)
}
