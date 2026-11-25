//! 恶意行为规则引擎。
//!
//! 三类检测能力，全部用声明式 JSON 规则表达，新家族以数据下发、无需重编控制面：
//! 1. **单事件匹配**：危险 API + 参数特征（如 `Runtime.exec("su")`）
//! 2. **有序序列**：行为链（如 读短信 → 加密 → 联网外发），支持时间窗
//! 3. **参数联动**：序列中前一步的字段/参数值必须等于后一步（数据流证据）
//!
//! 规则在分析结束后对完整 trace 求值，而不是流式触发——序列与联动需要全局视图，
//! trace 本身有单调时钟保证顺序。

pub mod builtin;
mod eval;
mod model;

pub use eval::{evaluate, Finding};
pub use model::{Link, MatchOp, Matcher, Rule, RuleSet, Step};

use std::path::Path;

/// 从 JSON 文件加载规则集。
pub fn load_set(path: &Path) -> droidunpack_core::Result<RuleSet> {
    let text = std::fs::read_to_string(path)?;
    let set: RuleSet =
        serde_json::from_str(&text).map_err(|e| droidunpack_core::Error::Rule(e.to_string()))?;
    set.validate()?;
    Ok(set)
}

/// 内置规则集（覆盖典型恶意行为，可直接用于离线 trace 分析）。
pub fn builtin_set() -> RuleSet {
    let raw = include_str!("../rules/default_rules.json");
    let set: RuleSet = serde_json::from_str(raw).expect("内置规则必须可解析");
    set.validate().expect("内置规则必须自洽");
    set
}
