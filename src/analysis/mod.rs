//! Ranking, attribution and rendering.
//!
//! The report's job is to let an analyst decide in under a minute. That means:
//!
//! * a short, ordered list of *behaviours* (not raw API hits), each with the
//!   concrete evidence that produced it;
//! * the call chain that reached it, including any runtime-decrypted DEX;
//! * the sample's own evasion checks, because a sample that refused to run in
//!   one scenario and fired in another tells you the gate it uses;
//! * an explicit statement of what the emulation could not model, so a quiet
//!   report is not mistaken for a clean one.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use crate::report::{Finding, SampleReport, ScenarioReport, Severity, SinkKind};

/// A behaviour: one or more findings of the same kind that tell the same story.
#[derive(Debug, Clone)]
pub struct Behaviour {
    pub kind: SinkKind,
    pub severity: Severity,
    /// Short imperative title for the analyst, e.g.
    /// "Exfiltrates device identifiers over HTTP".
    pub title: String,
    /// The most informative finding for this behaviour.
    pub representative: Finding,
    /// All observations folded into it.
    pub observations: usize,
    /// Distinct scenarios that observed it.
    pub scenarios: Vec<String>,
    pub tainted_with: Vec<String>,
}

/// Group findings into behaviours, ordered by severity then impact.
pub fn behaviours(findings: &[Finding]) -> Vec<Behaviour> {
    let mut groups: BTreeMap<(u8, String), Vec<Finding>> = BTreeMap::new();
    for f in findings {
        let key = (f.kind as u8, group_key(f));
        groups.entry(key).or_default().push(f.clone());
    }
    let mut out = Vec::new();
    for ((_k, _gk), mut fs) in groups {
        // Prefer a finding with the richest evidence as the representative.
        fs.sort_by_key(|f| std::cmp::Reverse(f.evidence.len() + f.taint.len() * 2));
        let rep = fs[0].clone();
        let mut scenarios: Vec<String> = fs.iter().map(|f| f.scenario.clone()).collect();
        scenarios.sort();
        scenarios.dedup();
        let mut tainted: Vec<String> = fs.iter().flat_map(|f| f.taint.clone()).collect();
        tainted.sort();
        tainted.dedup();
        out.push(Behaviour {
            kind: rep.kind,
            severity: rep.severity,
            title: title_for(&rep, &tainted),
            representative: rep,
            observations: fs.len(),
            scenarios,
            tainted_with: tainted,
        });
    }
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.representative.evidence.len().cmp(&a.representative.evidence.len()))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    out
}

/// Findings about the same target collapse together: the same URL, the same
/// command, the same loaded library. Different URLs stay separate, because an
/// analyst wants to see the C2 list, not "network: 47 observations".
fn group_key(f: &Finding) -> String {
    match f.kind {
        SinkKind::Network | SinkKind::SensitiveFlow | SinkKind::DeviceFingerprint => {
            endpoint_of(&f.detail).unwrap_or_else(|| f.detail.clone())
        }
        SinkKind::CommandExec => f.detail.clone(),
        SinkKind::DynamicCodeLoad => "dynamic-load".into(),
        SinkKind::NativeLoad => f.api.clone(),
        SinkKind::Sms => f.detail.clone(),
        SinkKind::Evasion => f.api.clone(),
        SinkKind::Persistence => f.detail.clone(),
        SinkKind::FileWrite => f.detail.clone(),
        SinkKind::Reflection => f.api.clone(),
        SinkKind::PrivilegedAction => f.api.clone(),
        SinkKind::AssetRead => f.detail.clone(),
    }
}

/// Extract a host or URL from a detail string, for grouping.
fn endpoint_of(detail: &str) -> Option<String> {
    let start = detail.find("http://").or_else(|| detail.find("https://"))?;
    let rest = &detail[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(normalise_endpoint(&rest[..end]))
}

fn normalise_endpoint(url: &str) -> String {
    // Keep scheme://host/path but drop the query: a C2 with an IMEI in the
    // query is the same C2 across victims.
    match url.find('?') {
        Some(p) => url[..p].to_string(),
        None => url.to_string(),
    }
}

fn title_for(f: &Finding, tainted: &[String]) -> String {
    let has_imei = tainted.iter().any(|t| t == "imei" || t == "imsi" || t == "phone-number");
    let has_loc = tainted.iter().any(|t| t == "location");
    let has_contacts = tainted.iter().any(|t| t == "contacts" || t == "sms-inbox");
    match f.kind {
        SinkKind::Network | SinkKind::SensitiveFlow => {
            if has_imei {
                "Sends device identifiers to a remote endpoint".into()
            } else if has_loc {
                "Sends device location to a remote endpoint".into()
            } else if has_contacts {
                "Sends harvested contacts or messages to a remote endpoint".into()
            } else if f.kind == SinkKind::SensitiveFlow {
                "Sends sensitive data to a remote endpoint".into()
            } else {
                "Contacts a remote endpoint".into()
            }
        }
        SinkKind::Sms => "Sends SMS".into(),
        SinkKind::CommandExec => "Executes shell commands".into(),
        SinkKind::DynamicCodeLoad => "Loads code at runtime (packed payload)".into(),
        SinkKind::NativeLoad => "Calls into native code".into(),
        SinkKind::FileWrite => "Writes files outside its sandbox".into(),
        SinkKind::Reflection => "Uses reflection / hidden APIs".into(),
        SinkKind::PrivilegedAction => "Takes a privileged device action".into(),
        SinkKind::Evasion => "Probes the environment (anti-analysis)".into(),
        SinkKind::Persistence => "Registers persistence or launches components".into(),
        SinkKind::DeviceFingerprint => "Reads device identifiers".into(),
        SinkKind::AssetRead => "Reads a bundled asset (possible packed payload)".into(),
    }
}

/// Merge everything into the final report and compute the headline assessment.
pub fn finalize(report: &mut SampleReport) {
    report.merge_findings();
    // Collect dynamic DEX info from the runtime notes.
    let mut notes = Vec::new();
    for sc in &report.scenarios {
        if sc.findings.is_empty() {
            notes.push(format!(
                "scenario '{}' produced no findings ({} steps{})",
                sc.name,
                sc.steps,
                match &sc.stop_reason {
                    Some(r) => format!(", stopped: {r}"),
                    None => String::new(),
                }
            ));
        }
    }
    report.notes.extend(notes);
}

/// Render the analyst-facing markdown brief.
pub fn render_markdown(report: &SampleReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Analysis: {}", report.apk_path);
    let _ = writeln!(out);
    let top = report.top_severity();
    let behs = behaviours(&report.findings);
    let _ = writeln!(out, "**Verdict:** {}", verdict_line(top, &behs));
    let _ = writeln!(out);

    // Identity.
    let _ = writeln!(out, "## Sample");
    let _ = writeln!(out);
    let _ = writeln!(out, "| field | value |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| package | {} |", report.package.as_deref().unwrap_or("(unknown)"));
    let _ = writeln!(out, "| version | {} |", report.version_name.as_deref().unwrap_or("(unknown)"));
    let _ = writeln!(out, "| sha256 | `{}` |", report.apk_sha256);
    let _ = writeln!(out, "| size | {} bytes |", report.apk_size);
    let _ = writeln!(out, "| elapsed | {} ms |", report.total_elapsed_ms);
    if !report.permissions.is_empty() {
        let _ = writeln!(out, "| permissions | {} |", report.permissions.join(", "));
    }
    let _ = writeln!(out);

    // Behaviours.
    let _ = writeln!(out, "## Behaviours");
    let _ = writeln!(out);
    if behs.is_empty() {
        let _ = writeln!(out, "_No malicious behaviour was observed._");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "This is not a clean verdict on its own: see **Coverage** below for what the \
             emulation could not model, and **Environment probes** for the checks the sample made."
        );
        let _ = writeln!(out);
    }
    for (i, b) in behs.iter().enumerate() {
        let _ = writeln!(out, "### {}. {} ({})", i + 1, b.title, b.severity.as_str());
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Sink:** `{}`", b.representative.api);
        let _ = writeln!(out, "- **Detail:** {}", b.representative.detail);
        if !b.tainted_with.is_empty() {
            let _ = writeln!(out, "- **Data involved:** {}", b.tainted_with.join(", "));
        }
        if b.scenarios.len() > 1 {
            let _ = writeln!(out, "- **Seen in scenarios:** {}", b.scenarios.join(", "));
        }
        if b.observations > 1 {
            let _ = writeln!(out, "- **Observations:** {}", b.observations);
        }
        if !b.representative.evidence.is_empty() {
            let _ = writeln!(out, "- **Evidence:**");
            for e in b.representative.evidence.iter().take(8) {
                let trimmed = e.trim();
                let shown = truncate(trimmed, 300);
                let _ = writeln!(out, "  - `{shown}`");
            }
        }
        if !b.representative.stack.is_empty() {
            let _ = writeln!(out, "- **Call chain:**");
            for (depth, frame) in b.representative.stack.iter().enumerate() {
                let _ = writeln!(out, "  {}- `{}`", "  ".repeat(depth), short_frame(frame));
            }
        }
        let _ = writeln!(out);
    }

    // Recovered payloads.
    let dynamic: Vec<_> = report.dexes.iter().filter(|d| d.dynamic).collect();
    if !dynamic.is_empty() {
        let _ = writeln!(out, "## Recovered payloads");
        let _ = writeln!(out);
        let _ = writeln!(out, "These DEX images were decrypted or downloaded by the sample and \
            executed inside the sandbox. They are the code the packer was hiding.");
        let _ = writeln!(out);
        for d in &dynamic {
            let _ = writeln!(
                out,
                "- `{}` — {} bytes, {} classes, sha256 `{}`{}",
                d.origin,
                d.size,
                d.classes,
                &d.sha256[..16],
                d.dump_path.as_deref().map(|p| format!(", dumped to `{p}`")).unwrap_or_default()
            );
        }
        let _ = writeln!(out);
    }

    // Evasion probes.
    let probes = collect_probes(&report.scenarios);
    if !probes.is_empty() {
        let _ = writeln!(out, "## Environment probes");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "The sample read these device facts. Values that differ from a real phone are \
             the usual trigger for a sample to stay dormant."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "| probe | value seen |");
        let _ = writeln!(out, "|---|---|");
        for (api, value) in probes.iter().take(60) {
            let _ = writeln!(out, "| `{}` | `{}` |", api, truncate(value, 120));
        }
        let _ = writeln!(out);
    }

    // Coverage gaps: honesty about what was not modelled.
    let gaps = collect_gaps(&report.scenarios);
    if !gaps.is_empty() {
        let _ = writeln!(out, "## Coverage");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "These framework calls had no model and were answered with a typed default. \
             A behaviour that depends on one of them may be missing from this report."
        );
        let _ = writeln!(out);
        for (name, count) in gaps.iter().take(40) {
            let _ = writeln!(out, "- `{name}` ×{count}");
        }
        let _ = writeln!(out);
    }

    // Scenario summary.
    let _ = writeln!(out, "## Scenarios");
    let _ = writeln!(out);
    let _ = writeln!(out, "| scenario | steps | findings | stop |");
    let _ = writeln!(out, "|---|---|---|---|");
    for sc in &report.scenarios {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            sc.name,
            sc.steps,
            sc.findings.len(),
            sc.stop_reason.as_deref().unwrap_or("completed")
        );
    }
    let _ = writeln!(out);

    if !report.notes.is_empty() {
        let _ = writeln!(out, "## Notes");
        let _ = writeln!(out);
        for n in &report.notes {
            let _ = writeln!(out, "- {n}");
        }
    }
    out
}

fn verdict_line(top: Severity, behs: &[Behaviour]) -> String {
    if behs.is_empty() {
        return "no behaviour recovered — see coverage".into();
    }
    let has_dynamic = behs.iter().any(|b| b.kind == SinkKind::DynamicCodeLoad);
    let has_net = behs.iter().any(|b| matches!(b.kind, SinkKind::Network | SinkKind::SensitiveFlow));
    let has_sms = behs.iter().any(|b| b.kind == SinkKind::Sms);
    let mut parts = Vec::new();
    if has_dynamic {
        parts.push("packed code was unpacked and executed");
    }
    if has_net {
        parts.push("network exfiltration observed");
    }
    if has_sms {
        parts.push("SMS abuse observed");
    }
    let suffix = if parts.is_empty() { String::new() } else { format!(" ({})", parts.join("; ")) };
    format!("{}{suffix}", top.as_str())
}

fn collect_probes(scenarios: &[ScenarioReport]) -> Vec<(String, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for sc in scenarios {
        for p in &sc.probes {
            let key = format!("{}={}", p.api, p.value);
            if seen.insert(key) {
                out.push((p.api.clone(), p.value.clone()));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn collect_gaps(scenarios: &[ScenarioReport]) -> Vec<(String, u64)> {
    let mut merged: HashMap<String, u64> = HashMap::new();
    for sc in scenarios {
        for (k, v) in &sc.coverage_gaps {
            *merged.entry(k.clone()).or_insert(0) += v;
        }
    }
    let mut v: Vec<_> = merged.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

fn short_frame(frame: &str) -> String {
    truncate(frame, 160)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_endpoint_different_query_groups() {
        let f1 = Finding {
            kind: SinkKind::Network,
            severity: Severity::High,
            api: "GET".into(),
            detail: "GET http://c2.example/gate?i=111".into(),
            taint: vec!["imei".into()],
            stack: vec![],
            evidence: vec![],
            scenario: "a".into(),
            dedup_key: String::new(),
        };
        let f2 = Finding {
            detail: "GET http://c2.example/gate?i=222".into(),
            ..f1.clone()
        };
        let bs = behaviours(&[f1, f2]);
        assert_eq!(bs.len(), 1, "same endpoint should fold into one behaviour");
        assert_eq!(bs[0].observations, 2);
        assert!(bs[0].title.contains("identifiers"));
    }

    #[test]
    fn distinct_endpoints_stay_separate() {
        let mk = |u: &str| Finding {
            kind: SinkKind::Network,
            severity: Severity::High,
            api: "GET".into(),
            detail: format!("GET {u}"),
            taint: vec![],
            stack: vec![],
            evidence: vec![],
            scenario: "a".into(),
            dedup_key: String::new(),
        };
        let bs = behaviours(&[mk("http://a.example/x"), mk("http://b.example/y")]);
        assert_eq!(bs.len(), 2);
    }
}
