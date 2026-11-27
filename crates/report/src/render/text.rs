//! The analyst-facing text report.
//!
//! Formatting rules that matter in practice:
//!  * The first screen must answer "what does this thing do" without scrolling
//!    past boilerplate. Findings come before metadata.
//!  * Long identifiers are the norm; wrap with a hanging indent rather than
//!    truncating, because a truncated class name cannot be grepped for.

use crate::findings::overall_score;
use crate::{Report, Severity};

const WIDTH: usize = 96;

pub fn render_text(r: &Report, verbose: bool) -> String {
    let mut o = String::new();
    header(&mut o, r);
    summary(&mut o, r);
    findings(&mut o, r);
    if !r.recovered.is_empty() {
        payloads(&mut o, r);
    }
    if !r.requests.is_empty() {
        network(&mut o, r);
    }
    callgraph(&mut o, r);
    if verbose {
        facts(&mut o, r);
    }
    caveats(&mut o, r);
    o
}

fn rule(o: &mut String, c: char) {
    o.push_str(&c.to_string().repeat(WIDTH));
    o.push('\n');
}

fn header(o: &mut String, r: &Report) {
    rule(o, '=');
    o.push_str(&format!(" unhusk report — {}\n", r.facts.package));
    rule(o, '=');
    o.push_str(&format!(
        " apk sha256 : {}\n label      : {}\n version    : {}   minSdk {} / targetSdk {}\n debuggable : {}\n profile    : {}   runtime {} ms   {} instructions\n stop       : {}\n",
        r.facts.apk_sha256,
        if r.facts.app_label.is_empty() { "-" } else { &r.facts.app_label },
        if r.facts.version_name.is_empty() { "-" } else { &r.facts.version_name },
        r.facts.min_sdk.map(|v| v.to_string()).unwrap_or("-".into()),
        r.facts.target_sdk.map(|v| v.to_string()).unwrap_or("-".into()),
        r.facts.debuggable,
        r.stats.profile,
        r.stats.elapsed_ms,
        r.stats.instructions,
        r.stats.stop,
    ));
    o.push('\n');
}

fn summary(o: &mut String, r: &Report) {
    let score = overall_score(&r.findings);
    let top = r
        .findings
        .first()
        .map(|f| f.severity)
        .unwrap_or(Severity::Info);
    o.push_str(&format!(
        " VERDICT: {} (score {})   {} finding(s)\n",
        verdict(top, &r.findings),
        score,
        r.findings.len()
    ));
    if !r.findings.is_empty() {
        o.push_str(" top behaviours:\n");
        for f in r.findings.iter().take(5) {
            o.push_str(&format!("   [{}] {}\n", f.severity.tag(), f.title));
        }
    }
    o.push('\n');
}

fn verdict(top: Severity, findings: &[crate::Finding]) -> &'static str {
    // A payload that was recovered *and* executed is conclusive even if the
    // individual behaviours are only "high".
    if findings.iter().any(|f| f.title.contains("executed")) {
        return "malicious (runtime code executed)";
    }
    match top {
        Severity::Critical => "malicious",
        Severity::High => "suspicious (high)",
        Severity::Medium => "suspicious",
        Severity::Low => "low risk",
        Severity::Info => "no behaviour observed",
    }
}

fn findings(o: &mut String, r: &Report) {
    if r.findings.is_empty() {
        o.push_str(" No malicious or evasive behaviour was observed within the analysis budget.\n This is not proof of innocence: see the caveats at the end.\n\n");
        return;
    }
    rule(o, '-');
    o.push_str(" FINDINGS\n");
    rule(o, '-');
    for (i, f) in r.findings.iter().enumerate() {
        o.push_str(&format!(
            "\n {}. [{}] {}\n    rule: {}{}\n",
            i + 1,
            f.severity.tag(),
            f.title,
            f.rule,
            f.technique
                .map(|t| format!("   technique: {t}"))
                .unwrap_or_default()
        ));
        wrap(o, &f.summary, 4, WIDTH);
        if !f.indicators.is_empty() {
            o.push_str("    indicators:\n");
            for ind in f.indicators.iter().take(8) {
                wrap_bullet(o, ind, 6, WIDTH);
            }
        }
        if !f.call_path.is_empty() {
            o.push_str("    reached from:\n");
            for m in f.call_path.iter().take(6) {
                wrap(o, &format!("← {m}"), 6, WIDTH);
            }
        }
        if !f.evidence.is_empty() {
            o.push_str("    evidence:\n");
            for e in f.evidence.iter().take(6) {
                let line = e.line.map(|l| format!(":{l}")).unwrap_or_default();
                let txt = format!("#{} {} {}{} :: {}", e.seq, e.caller, line, "", e.detail);
                wrap(o, &txt, 6, WIDTH);
            }
            if f.evidence.len() > 6 {
                o.push_str(&format!("      … {} more event(s)\n", f.evidence.len() - 6));
            }
        }
    }
    o.push('\n');
}

fn payloads(o: &mut String, r: &Report) {
    rule(o, '-');
    o.push_str(" RUNTIME-RECOVERED PAYLOAD\n");
    rule(o, '-');
    for p in &r.recovered {
        o.push_str(&format!(
            "\n {}  ({} bytes, {} classes)\n   sha1: {}\n   obtained: {}\n",
            p.name, p.size, p.classes, p.sha1, p.how
        ));
        if !p.class_names.is_empty() {
            o.push_str("   classes:\n");
            for c in p.class_names.iter().take(12) {
                o.push_str(&format!("     {c}\n"));
            }
        }
    }
    o.push('\n');
}

fn network(o: &mut String, r: &Report) {
    rule(o, '-');
    o.push_str(" NETWORK\n");
    rule(o, '-');
    for q in &r.requests {
        o.push_str(&format!("\n {} {}\n", q.method, q.url));
        if q.body_len > 0 {
            o.push_str(&format!(
                "   body ({} bytes, provenance {}): {:?}\n",
                q.body_len, q.provenance, q.body_preview
            ));
        }
    }
    o.push('\n');
}

fn callgraph(o: &mut String, r: &Report) {
    rule(o, '-');
    o.push_str(&format!(
        " EXECUTED CALL GRAPH ({} methods, {} edges)\n",
        r.graph.method_count(),
        r.graph.edge_count()
    ));
    rule(o, '-');
    // Render a real tree: DFS from each root, pruning already-shown subtrees
    // so a diamond is printed once. A flat (depth, name) list cannot express
    // which parent a node belongs to and reads as invented nesting.
    let roots: Vec<String> = if r.facts.entry_classes.is_empty() {
        r.graph.roots.iter().cloned().collect()
    } else {
        r.facts
            .entry_classes
            .iter()
            .filter(|c| {
                r.graph.order.iter().any(|m| {
                    m.starts_with(
                        &c.trim_start_matches('L')
                            .trim_end_matches(';')
                            .replace('/', "."),
                    )
                })
            })
            .cloned()
            .collect()
    };
    let mut shown: std::collections::BTreeSet<String> = Default::default();
    // `budget` is the shared line allowance; `printed` counts what we emitted
    // so the fallback branch knows whether the manifest-roots pass found
    // anything at all.
    let mut budget = 80usize;
    let mut printed = 0usize;
    for root in &roots {
        let dotted = root
            .trim_start_matches('L')
            .trim_end_matches(';')
            .replace('/', ".");
        let entry = r
            .graph
            .order
            .iter()
            .find(|m| m.starts_with(&dotted))
            .cloned();
        if let Some(entry) = entry {
            printed += render_subtree(o, r, &entry, 0, &mut shown, &mut budget, 3);
        }
        if budget == 0 {
            break;
        }
    }
    if printed == 0 {
        // No manifest entry executed (e.g. a library APK, or the entry point
        // was seeded directly): show real roots, plus `<entry>` children.
        for m in r.graph.order.clone() {
            if budget == 0 {
                break;
            }
            if r.graph.callers(&m).is_empty() || r.graph.callers(&m) == ["<entry>"] {
                render_subtree(o, r, &m, 0, &mut shown, &mut budget, 3);
            }
        }
    }
    o.push('\n');
}

/// Print `method` and its executed callees, indented. Returns lines printed.
fn render_subtree(
    o: &mut String,
    r: &Report,
    method: &str,
    depth: usize,
    shown: &mut std::collections::BTreeSet<String>,
    budget: &mut usize,
    max_depth: usize,
) -> usize {
    if *budget == 0 || depth > max_depth {
        return 0;
    }
    let indent = "  ".repeat(depth);
    let marker = if is_runtime(method) { " [runtime]" } else { "" };
    if shown.contains(method) {
        o.push_str(&format!("{indent}{method}{marker} (see above)\n"));
        *budget = budget.saturating_sub(1);
        return 1;
    }
    shown.insert(method.to_string());
    o.push_str(&format!("{indent}{method}{marker}\n"));
    *budget = budget.saturating_sub(1);
    let mut n = 1;
    for c in r.graph.callees(method) {
        n += render_subtree(o, r, c, depth + 1, shown, budget, max_depth);
        if *budget == 0 {
            break;
        }
    }
    n
}

fn is_runtime(method: &str) -> bool {
    // The recovered payload's classes are reported with their descriptor; the
    // graph uses dotted display names. Match the common payload convention and
    // let the engine pass exact names in `facts` when available.
    method.contains("payload")
}

fn facts(o: &mut String, r: &Report) {
    rule(o, '-');
    o.push_str(" STATIC FACTS\n");
    rule(o, '-');
    o.push_str(&format!(
        " permissions ({}): {}\n",
        r.facts.permissions.len(),
        r.facts.permissions.join(", ")
    ));
    o.push_str(&format!(
        " exported components ({}): {}\n",
        r.facts.exported_components.len(),
        r.facts.exported_components.join(", ")
    ));
    o.push_str(&format!(" dex: {}\n", r.facts.dex_files.join(", ")));
    o.push_str(&format!(" abis: {}\n", r.facts.native_abis.join(", ")));
    if !r.facts.packer_hits.is_empty() {
        o.push_str(" packer fingerprints:\n");
        for (family, ev) in &r.facts.packer_hits {
            o.push_str(&format!("   {family}: {ev}\n"));
        }
    }
    o.push('\n');
}

fn caveats(o: &mut String, r: &Report) {
    if r.caveats.is_empty() {
        return;
    }
    rule(o, '-');
    o.push_str(" CAVEATS\n");
    rule(o, '-');
    for c in &r.caveats {
        wrap(o, &format!("- {c}"), 1, WIDTH);
    }
    o.push('\n');
}

/// Wrap a bullet item so the `- ` marker stays on the first line and the
/// continuation is indented under the text, not under the marker.
fn wrap_bullet(o: &mut String, text: &str, indent: usize, width: usize) {
    let pad = " ".repeat(indent);
    o.push_str(&pad);
    o.push_str("- ");
    let hang = " ".repeat(indent + 2);
    let mut col = indent + 2;
    for word in text.split_whitespace() {
        if col + word.len() + 1 > width && col > indent + 2 {
            o.push('\n');
            o.push_str(&hang);
            col = indent + 2;
        }
        if col > indent + 2 {
            o.push(' ');
            col += 1;
        }
        o.push_str(word);
        col += word.len();
    }
    o.push('\n');
}

/// Wrap `text` to `width`, continuing at `indent` spaces.
fn wrap(o: &mut String, text: &str, indent: usize, width: usize) {
    let pad = " ".repeat(indent);
    let mut col = indent;
    o.push_str(&pad);
    for word in text.split_whitespace() {
        if col + word.len() + 1 > width && col > indent {
            o.push('\n');
            o.push_str(&pad);
            col = indent;
        }
        if col > indent {
            o.push(' ');
            col += 1;
        }
        o.push_str(word);
        col += word.len();
    }
    o.push('\n');
}
