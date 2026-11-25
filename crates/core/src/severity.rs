use serde::{Deserialize, Serialize};

/// 分析结论/规则命中的严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// 参考信息（普通生命周期事件）
    Info,
    /// 可疑行为，需要结合上下文判断
    Suspicious,
    /// 高度疑似恶意
    High,
    /// 确定的恶意行为
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Suspicious => "suspicious",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
