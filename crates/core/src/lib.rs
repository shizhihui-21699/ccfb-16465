//! 平台通用基础类型：错误、严重级别、时间预算。
//!
//! 控制面所有 crate 依赖 `droidunpack-core`，guest agent（设备内）是独立工程，
//! 不依赖本 crate，通过 `droidunpack-protocol` 的 JSONL 协议与控制面通信。

pub mod budget;
pub mod error;
pub mod severity;

pub use budget::{Phase, TimeBudget};
pub use error::{Error, Result};
pub use severity::Severity;

/// 样本在整个平台内的稳定标识，通常由 `sha256(apk)` 前 16 字节派生。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SampleId(pub String);

impl std::fmt::Display for SampleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
