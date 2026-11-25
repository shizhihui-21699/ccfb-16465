//! 单样本分析流水线，把各 crate 串成一条可在时间预算内完成的链路：
//!
//! ```text
//! APK → triage(静态预筛/选车道) → 反检测方案 → 模拟器(刺激+trace+内存)
//!     → unpack(DEX/ELF 抓取重构) → rules(规则求值) → cgraph(入口→sink 路径)
//!     → SampleResult（交给 report 渲染）
//! ```
//!
//! 任何阶段失败都降级为带错误信息的结果，不中断批量任务。

use std::sync::Arc;

use droidunpack_core::{Phase, Result, SampleId, TimeBudget};
use droidunpack_emulator::{AnalysisRequest, Pool};
use droidunpack_evasion::{
    default_pixel_profile, plan_for, probes_from_trace, ClockPolicy, SensorReplay,
};
use droidunpack_rules::{builtin_set, evaluate, Finding, RuleSet};
use droidunpack_triage::{triage_apk, TriageDecision, TriageReport};
use droidunpack_unpack::{extract, ExtractionOutcome};
use serde::{Deserialize, Serialize};

/// 一个样本的完整分析结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    pub sample: SampleId,
    pub decision: TriageDecision,
    pub triage: TriageReport,
    pub extraction: ExtractionOutcome,
    pub findings: Vec<Finding>,
    /// 剪枝后的调用图（只含可达 sink 的部分）
    pub call_graph: droidunpack_cgraph::CallGraph,
    pub sink_paths: Vec<droidunpack_cgraph::SinkPath>,
    pub event_count: usize,
    /// 分析过程中被降级的错误（不致命，但分析员需要知道覆盖缺口）
    pub warnings: Vec<String>,
    pub elapsed_ms: u128,
}

/// 流水线执行器。
pub struct Pipeline {
    pool: Arc<Pool>,
    rules: RuleSet,
}

impl Pipeline {
    pub fn new(pool: Arc<Pool>) -> Self {
        Pipeline {
            pool,
            rules: builtin_set(),
        }
    }

    /// 注入自定义规则集（生产环境按租户/情报源下发）。
    pub fn with_rules(mut self, rules: RuleSet) -> Self {
        self.rules = rules;
        self
    }

    pub fn run(&self, apk_bytes: &[u8]) -> Result<SampleResult> {
        let started = std::time::Instant::now();
        let mut budget = TimeBudget::default();
        budget.start();
        let mut warnings = Vec::new();

        // 1. 静态预筛
        let triage = triage_apk(apk_bytes)?;
        if budget.is_exhausted(Phase::Triage) {
            warnings.push("静态预筛接近预算上限".into());
        }

        let sample = SampleId(format!("sha256:{:016x}", simple_hash(apk_bytes)));

        // 2. 反检测方案（先用默认画像；首轮 trace 回来后可用真实探测结果复跑）
        let plan = plan_for(
            &[],
            default_pixel_profile(),
            ClockPolicy {
                base_epoch_ms: 1_700_000_000_000,
                apparent_rate: 1.0,
                jitter_ms: 12,
            },
            SensorReplay {
                trace_object_key: "sensor-tracks/pixel8-default".into(),
                phase_jitter: true,
            },
        );

        // 3. 动态分析（FastLane 也保留一次轻量动态，代价由刺激事件数控制）
        let req = AnalysisRequest {
            apk_path: format!("inmemory://{}", sample),
            package: triage.package.clone().unwrap_or_else(|| "unknown".into()),
            plan: plan.clone(),
            stimulation_events: match triage.decision {
                TriageDecision::FastLane => 20,
                TriageDecision::FullDynamic => 60,
                TriageDecision::DeepDynamic => 120,
            },
        };

        let lease = self.pool.acquire().map_err(|e| {
            warnings.push(format!("模拟器池获取失败: {e}"));
            e
        })?;
        let (artifact, recycle) = lease.run(&req)?;
        if let Err(e) = recycle {
            warnings.push(format!("实例回收异常（已强制丢弃槽位）: {e}"));
        }

        // 首轮 trace 揭示了真实探测维度：记录覆盖缺口（生产中触发换镜像复跑）
        let probes = probes_from_trace(&artifact.events);
        let refined = plan_for(
            &probes,
            default_pixel_profile(),
            ClockPolicy {
                base_epoch_ms: 1_700_000_000_000,
                apparent_rate: 1.0,
                jitter_ms: 12,
            },
            SensorReplay {
                trace_object_key: "sensor-tracks/pixel8-default".into(),
                phase_jitter: true,
            },
        );
        if !refined.coverage_gaps.is_empty() {
            warnings.push(format!(
                "反检测覆盖缺口（建议升级镜像复跑）: {:?}",
                refined.coverage_gaps
            ));
        }

        // 4. 脱壳：内存抓取重构
        let extraction = extract(
            &artifact.memory_blobs,
            &collect_dex_reports(&artifact.events),
        );
        if !extraction.missing_reports.is_empty() {
            warnings.push(format!(
                "{} 个 hook 上报的 dex 未在快照中找到（壳可能已卸载/抹痕）",
                extraction.missing_reports.len()
            ));
        }

        // 5. 规则求值
        let findings = evaluate(&artifact.events, &self.rules);

        // 6. 调用图与关键路径
        let mut graph = droidunpack_cgraph::build(&artifact.events).pruned_to_sinks();
        let sink_paths = graph.sink_paths(20);

        Ok(SampleResult {
            sample,
            decision: triage.decision,
            triage,
            extraction,
            findings,
            call_graph: graph,
            sink_paths,
            event_count: artifact.events.len(),
            warnings,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }
}

fn collect_dex_reports(
    events: &[droidunpack_protocol::Event],
) -> Vec<droidunpack_protocol::LoadedDex> {
    events
        .iter()
        .filter_map(|e| match &e.kind {
            droidunpack_protocol::EventKind::DexLoad(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

/// 非加密用途的稳定样本哈希（FNV-1a 64），仅用于生成可读 sample id；
/// 生产环境对象存储 key 仍应使用真实 sha256。
fn simple_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use droidunpack_emulator::mock::MockBackend;

    fn apk() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("classes.dex", opts).unwrap();
            std::io::Write::write_all(&mut zip, b"dex\n035\x00padding-data").unwrap();
            zip.start_file("lib/arm64-v8a/libnative.so", opts).unwrap();
            std::io::Write::write_all(&mut zip, b"\x7fELFxxxx").unwrap();
            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn full_pipeline_on_mock_backend() {
        let pool = Arc::new(Pool::new(Arc::new(MockBackend::new(2))));
        let pipeline = Pipeline::new(pool);
        let result = pipeline.run(&apk()).unwrap();

        assert!(result.event_count >= 10);
        // mock trace 包含 su exec / 短信外泄链 / 环境探测
        let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"ROOT-EXEC-SU"), "命中: {ids:?}");
        assert!(ids.contains(&"EXFIL-SMS-CRYPTO-NET"), "命中: {ids:?}");
        assert!(ids.contains(&"ENV-PROBE-CLUSTER"), "命中: {ids:?}");
        // 内存快照里的合成 dex 必须被抓出来
        assert_eq!(result.extraction.dex_count(), 1);
        // 调用图应至少给出一条入口->sink 路径
        assert!(!result.sink_paths.is_empty());
    }

    #[test]
    fn pool_rejects_when_full() {
        let pool = Pool::new(Arc::new(MockBackend::new(1)));
        let _first = pool.acquire().unwrap();
        assert!(pool.acquire().is_err());
    }
}
