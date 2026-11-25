use thiserror::Error;

/// 平台统一错误类型。控制面 crate 用 `Result<T>` 传递错误，
/// 单样本分析失败不应该拖垮整个流水线，因此编排层会把错误降级为样本级结果。
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("APK 解析失败: {0}")]
    Apk(String),

    #[error("协议/数据格式错误: {0}")]
    Format(String),

    #[error("规则引擎错误: {0}")]
    Rule(String),

    #[error("模拟器后端错误: {0}")]
    Emulator(String),

    #[error("分析阶段 `{phase}` 超出时间预算（{limit_ms} ms）")]
    BudgetExceeded { phase: String, limit_ms: u64 },

    #[error("当前平台/后端不支持该能力: {0}")]
    Unsupported(String),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, Error>;
