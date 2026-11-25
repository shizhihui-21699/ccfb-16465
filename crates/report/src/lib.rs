//! 分析报告渲染：机器可读 JSON 与分析员可读 Markdown。
//!
//! Markdown 报告把「关键恶意调用」放在最前面——分析员每天面对几百份报告，
//! 先给结论和证据事件序号，再给脱壳产物与调用路径，原始数据在附录。

use droidunpack_core::Severity;
use droidunpack_orchestrator::SampleResult;

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Json,
    Markdown,
}

pub fn render(result: &SampleResult, fmt: ReportFormat) -> String {
    match fmt {
        ReportFormat::Json => serde_json::to_string_pretty(result)
            .unwrap_or_else(|e| format!("{{\"error\":\"报告序列化失败: {e}\"}}")),
        ReportFormat::Markdown => render_markdown(result),
    }
}

fn render_markdown(r: &SampleResult) -> String {
    let mut md = String::new();
    let pkg = r.triage.package.as_deref().unwrap_or("(未知包名)");
    md.push_str("# 恶意软件分析报告\n\n");
    md.push_str(&format!("- 样本 ID: `{}`\n", r.sample));
    md.push_str(&format!("- 包名: `{pkg}`\n"));
    md.push_str(&format!("- 分析车道: `{:?}`\n", r.decision));
    md.push_str(&format!("- 事件总数: {}\n", r.event_count));
    md.push_str(&format!("- 耗时: {} ms\n\n", r.elapsed_ms));

    // 1. 结论摘要
    md.push_str("## 1. 关键恶意行为（按严重级别）\n\n");
    if r.findings.is_empty() {
        md.push_str(
            "未命中内置规则。注意：无命中不等于良性，请结合脱壳产物与调用路径人工复核。\n\n",
        );
    } else {
        md.push_str("| 级别 | 规则 | 结论 | ATT&CK | 证据事件# |\n");
        md.push_str("|---|---|---|---|---|\n");
        for f in &r.findings {
            let evs = f
                .evidence_events
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let attack = if f.attack.is_empty() {
                "—".to_string()
            } else {
                f.attack.join(", ")
            };
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | {} |\n",
                severity_zh(f.severity),
                f.rule_id,
                f.title,
                attack,
                evs
            ));
        }
        md.push('\n');
    }

    // 2. 加固与脱壳
    md.push_str("## 2. 加固识别与脱壳产物\n\n");
    match &r.triage.packer {
        Some(h) => md.push_str(&format!(
            "- 加固方案: **{} / {}**（置信度 {:?}）\n  - 证据: {}\n",
            h.vendor,
            h.family,
            h.confidence,
            h.evidence.join("; ")
        )),
        None => md.push_str("- 未命中已知加固厂商指纹\n"),
    }
    if !r.triage.generic_indicators.is_empty() {
        md.push_str("- 通用加固迹象:\n");
        for g in &r.triage.generic_indicators {
            md.push_str(&format!("  - {g}\n"));
        }
    }
    md.push_str(&format!(
        "- 重构代码单元: {} 个 DEX, {} 个 ELF\n",
        r.extraction.dex_count(),
        r.extraction
            .carved
            .iter()
            .filter(|c| matches!(c.kind, droidunpack_unpack::CodeKind::Elf))
            .count()
    ));
    for c in &r.extraction.carved {
        md.push_str(&format!(
            "  - `{:?}` addr={:#x} size={} sha1=`{}`{}\n",
            c.kind,
            c.addr,
            c.size,
            c.sha1,
            if c.repairs.is_empty() {
                String::new()
            } else {
                format!(" ⚠ 修复: {}", c.repairs.join("; "))
            }
        ));
    }
    for missing in &r.extraction.missing_reports {
        md.push_str(&format!("- ⚠ hook 上报但未抓取到: `{missing}`\n"));
    }
    md.push('\n');

    // 3. 关键调用路径
    md.push_str("## 3. 入口 → 敏感 sink 调用路径\n\n");
    if r.sink_paths.is_empty() {
        md.push_str("未发现可达已知 sink 的路径（可能是新 sink，需扩展内置清单）。\n\n");
    } else {
        for p in &r.sink_paths {
            md.push_str(&format!(
                "### {} → {}（{} 跳，线程 {}）\n\n```\n",
                p.entry,
                p.sink,
                p.hops,
                p.threads.join(", ")
            ));
            for (i, node) in p.path.iter().enumerate() {
                if i == 0 {
                    md.push_str(&format!("{node}\n"));
                } else {
                    md.push_str(&format!("  └─ {node}\n"));
                }
            }
            md.push_str("```\n\n");
        }
    }

    // 4. 告警与覆盖缺口
    if !r.warnings.is_empty() {
        md.push_str("## 4. 覆盖缺口与告警\n\n");
        for w in &r.warnings {
            md.push_str(&format!("- ⚠ {w}\n"));
        }
        md.push('\n');
    }

    // 5. 清单速览
    md.push_str("## 5. 清单速览\n\n");
    md.push_str(&format!(
        "- 权限 {} 项，组件 {} 个，native 库 {} 个\n",
        r.triage.permissions.len(),
        r.triage.components.len(),
        r.triage.native_libs.len()
    ));
    if !r.triage.permissions.is_empty() {
        md.push_str(&format!("  - {}\n", r.triage.permissions.join(", ")));
    }

    md
}

fn severity_zh(s: Severity) -> &'static str {
    match s {
        Severity::Info => "信息",
        Severity::Suspicious => "可疑",
        Severity::High => "高危",
        Severity::Critical => "严重",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use droidunpack_emulator::mock::MockBackend;
    use droidunpack_emulator::Pool;
    use droidunpack_orchestrator::Pipeline;
    use std::sync::Arc;

    fn run_pipeline() -> SampleResult {
        let mut apk = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut apk));
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("classes.dex", opts).unwrap();
            std::io::Write::write_all(&mut zip, b"dex\n035\x00xx").unwrap();
            zip.finish().unwrap();
        }
        let pool = Arc::new(Pool::new(Arc::new(MockBackend::new(1))));
        Pipeline::new(pool).run(&apk).unwrap()
    }

    #[test]
    fn markdown_contains_key_sections() {
        let r = run_pipeline();
        let md = render(&r, ReportFormat::Markdown);
        assert!(md.contains("关键恶意行为"));
        assert!(md.contains("脱壳产物"));
        assert!(md.contains("调用路径"));
    }

    #[test]
    fn json_roundtrip() {
        let r = run_pipeline();
        let json = render(&r, ReportFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["event_count"].as_u64().unwrap(), r.event_count as u64);
    }
}
