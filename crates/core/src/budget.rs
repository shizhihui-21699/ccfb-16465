use std::time::{Duration, Instant};

/// 分析流水线的阶段。每个样本只有几分钟，必须在各阶段之间硬性分配预算，
/// 避免某个样本卡死模拟器槽位（数万样本/天的吞吐要求）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 静态预筛：识别壳、清单、入口
    Triage,
    /// 冷启动并等待壳完成自解密
    Boot,
    /// UI/事件刺激与行为触发
    Stimulation,
    /// 内存抓取与 DEX/ELO 重构
    Extraction,
    /// 规则评估与调用图分析
    Analysis,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Triage => "triage",
            Phase::Boot => "boot",
            Phase::Stimulation => "stimulation",
            Phase::Extraction => "extraction",
            Phase::Analysis => "analysis",
        }
    }
}

/// 每样本时间预算。默认值对应一个 4 分钟槽位（240s）。
#[derive(Debug, Clone)]
pub struct TimeBudget {
    limits_ms: std::collections::HashMap<&'static str, u64>,
    total: Duration,
    started_at: Option<Instant>,
}

impl Default for TimeBudget {
    fn default() -> Self {
        Self {
            limits_ms: default_limits(),
            total: Duration::from_secs(240),
            started_at: None,
        }
    }
}

fn default_limits() -> std::collections::HashMap<&'static str, u64> {
    let mut limits = std::collections::HashMap::new();
    limits.insert(Phase::Triage.as_str(), 20_000);
    limits.insert(Phase::Boot.as_str(), 45_000);
    limits.insert(Phase::Stimulation.as_str(), 90_000);
    limits.insert(Phase::Extraction.as_str(), 45_000);
    limits.insert(Phase::Analysis.as_str(), 30_000);
    limits
}

impl TimeBudget {
    /// 创建自定义总预算，各阶段按默认比例缩放。
    pub fn new(total: Duration) -> Self {
        let scale = total.as_millis() as f64 / 240_000.0;
        let limits_ms = default_limits()
            .into_iter()
            .map(|(k, v)| (k, (v as f64 * scale).round() as u64))
            .collect();
        Self {
            limits_ms,
            total,
            started_at: None,
        }
    }

    pub fn start(&mut self) {
        self.started_at = Some(Instant::now());
    }

    /// 某阶段是否已耗尽预算。未调用 `start` 时视为未超时，方便单测。
    pub fn is_exhausted(&self, phase: Phase) -> bool {
        let Some(started) = self.started_at else {
            return false;
        };
        let limit = self
            .limits_ms
            .get(phase.as_str())
            .copied()
            .unwrap_or(u64::MAX);
        started.elapsed().as_millis() as u64 >= limit
    }

    /// 某阶段剩余毫秒数。
    pub fn remaining_ms(&self, phase: Phase) -> u64 {
        let Some(started) = self.started_at else {
            return self.limits_ms.get(phase.as_str()).copied().unwrap_or(0);
        };
        let limit = self
            .limits_ms
            .get(phase.as_str())
            .copied()
            .unwrap_or(u64::MAX);
        limit.saturating_sub(started.elapsed().as_millis() as u64)
    }

    /// 整体预算是否耗尽。
    pub fn total_exhausted(&self) -> bool {
        self.started_at
            .map(|t| t.elapsed() >= self.total)
            .unwrap_or(false)
    }

    pub fn total(&self) -> Duration {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_budget_scales_phase_limits() {
        let b = TimeBudget::new(Duration::from_secs(120));
        // 240s -> 120s，阶段预算应减半
        assert_eq!(b.remaining_ms(Phase::Triage), 10_000);
        assert!(!b.is_exhausted(Phase::Boot));
    }

    #[test]
    fn unstarted_budget_never_exhausted() {
        let b = TimeBudget::default();
        assert!(!b.total_exhausted());
        assert!(!b.is_exhausted(Phase::Analysis));
    }
}
