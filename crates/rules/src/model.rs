use serde::{Deserialize, Serialize};

use droidunpack_core::Severity;

/// 字段匹配操作。`field` 统一通过 [`droidunpack_protocol::Event::field`] 取值。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MatchOp {
    /// 字段等于字面值
    Eq { field: String, value: String },
    /// 子串包含
    Contains { field: String, value: String },
    /// 正则匹配（规则加载时预编译，见 RuleSet::validate）
    Regex { field: String, pattern: String },
    /// 字段存在且非空
    Exists { field: String },
}

impl MatchOp {
    pub fn field(&self) -> &str {
        match self {
            MatchOp::Eq { field, .. }
            | MatchOp::Contains { field, .. }
            | MatchOp::Regex { field, .. }
            | MatchOp::Exists { field } => field,
        }
    }
}

/// 事件匹配器：先按事件 kind 过滤，再要求所有 match 条件成立。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Matcher {
    /// 对应 [`droidunpack_protocol::Event::kind_key`]
    pub kind: String,
    #[serde(default)]
    pub matches: Vec<MatchOp>,
}

/// 序列中的一步。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    #[serde(flatten)]
    pub matcher: Matcher,
    /// 给该步起名字，供 [`Link`] 引用
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
}

/// 跨事件参数联动：`from_step.from_field == to_step.to_field`。
///
/// field 既支持命名字段（`url`、`body`），也支持调用参数（`arg0`、`arg1`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub from_step: String,
    pub from_field: String,
    pub to_step: String,
    pub to_field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    /// MITRE ATT&CK Mobile 技术编号，如 T1636.004
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
    /// 单事件规则：一个匹配器
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<Matcher>,
    /// 序列规则：有序步骤
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sequence: Vec<Step>,
    /// 序列允许的最大时间跨度（毫秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<Link>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleSet {
    pub name: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// 加载后校验：id 唯一、结构完整、正则可编译。
    pub fn validate(&self) -> droidunpack_core::Result<()> {
        let mut ids = std::collections::HashSet::new();
        for rule in &self.rules {
            if !ids.insert(rule.id.clone()) {
                return Err(droidunpack_core::Error::Rule(format!(
                    "规则 id 重复: {}",
                    rule.id
                )));
            }
            let has_detect = rule.detect.is_some();
            let has_seq = !rule.sequence.is_empty();
            if !has_detect && !has_seq {
                return Err(droidunpack_core::Error::Rule(format!(
                    "规则 {} 既无 detect 也无 sequence",
                    rule.id
                )));
            }
            if has_detect && has_seq {
                return Err(droidunpack_core::Error::Rule(format!(
                    "规则 {} 不能同时定义 detect 与 sequence",
                    rule.id
                )));
            }
            for step in &rule.sequence {
                for link in &rule.links {
                    let names: Vec<&str> = rule
                        .sequence
                        .iter()
                        .filter_map(|s| s.as_name.as_deref())
                        .collect();
                    if !names.contains(&link.from_step.as_str())
                        || !names.contains(&link.to_step.as_str())
                    {
                        return Err(droidunpack_core::Error::Rule(format!(
                            "规则 {} 的 link 引用了未命名步骤",
                            rule.id
                        )));
                    }
                }
                let _ = step;
            }
            // 预编译正则
            for m in rule
                .detect
                .iter()
                .flat_map(|d| d.matches.iter())
                .chain(rule.sequence.iter().flat_map(|s| s.matcher.matches.iter()))
            {
                if let MatchOp::Regex { pattern, .. } = m {
                    regex::Regex::new(pattern).map_err(|e| {
                        droidunpack_core::Error::Rule(format!(
                            "规则 {} 正则无效 {pattern:?}: {e}",
                            rule.id
                        ))
                    })?;
                }
            }
        }
        Ok(())
    }
}
