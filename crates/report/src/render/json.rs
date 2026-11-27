//! Machine-readable report. Kept stable: the platform ingests this.

use crate::Report;
use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    schema: &'static str,
    package: &'a str,
    apk_sha256: &'a str,
    verdict: String,
    score: u32,
    stats: JsonStats,
    findings: Vec<JsonFinding>,
    recovered_payloads: Vec<JsonPayload>,
    network: Vec<JsonRequest>,
    call_graph: JsonGraph,
    static_facts: JsonFacts,
    caveats: Vec<String>,
}

#[derive(Serialize)]
struct JsonStats {
    instructions: u64,
    elapsed_ms: u64,
    events: usize,
    methods_entered: usize,
    recovered_dex: usize,
    requests: usize,
    profile: String,
    stop: String,
}

#[derive(Serialize)]
struct JsonFinding {
    rule: &'static str,
    title: String,
    severity: &'static str,
    summary: String,
    indicators: Vec<String>,
    technique: Option<&'static str>,
    call_path: Vec<String>,
    evidence: Vec<JsonEvidence>,
}

#[derive(Serialize)]
struct JsonEvidence {
    seq: u64,
    kind: String,
    caller: String,
    line: Option<u32>,
    detail: String,
}

#[derive(Serialize)]
struct JsonPayload {
    name: String,
    sha1: String,
    size: usize,
    classes: usize,
    how: String,
    class_names: Vec<String>,
}

#[derive(Serialize)]
struct JsonRequest {
    method: String,
    url: String,
    body_preview: String,
    body_len: usize,
    provenance: String,
    caller: String,
}

#[derive(Serialize)]
struct JsonGraph {
    methods: Vec<String>,
    edges: Vec<(String, String)>,
}

#[derive(Serialize)]
struct JsonFacts {
    version_name: String,
    min_sdk: Option<i32>,
    target_sdk: Option<i32>,
    debuggable: bool,
    permissions: Vec<String>,
    exported_components: Vec<String>,
    dex_files: Vec<String>,
    native_libs: Vec<String>,
}

pub fn to_json(r: &Report) -> String {
    let score = crate::findings::overall_score(&r.findings);
    let verdict = r
        .findings
        .iter()
        .any(|f| f.title.contains("executed"))
        .then(|| "malicious".to_string())
        .unwrap_or_else(|| {
            match r.findings.first().map(|f| f.severity) {
                Some(crate::Severity::Critical) => "malicious".into(),
                Some(crate::Severity::High) => "suspicious-high".into(),
                Some(crate::Severity::Medium) => "suspicious".into(),
                Some(crate::Severity::Low) => "low".into(),
                _ => "clean".into(),
            }
        });
    let doc = JsonReport {
        schema: "unhusk/report/v1",
        package: &r.facts.package,
        apk_sha256: &r.facts.apk_sha256,
        verdict,
        score,
        stats: JsonStats {
            instructions: r.stats.instructions,
            elapsed_ms: r.stats.elapsed_ms,
            events: r.stats.events,
            methods_entered: r.stats.methods_entered,
            recovered_dex: r.stats.recovered_dex,
            requests: r.stats.requests,
            profile: r.stats.profile.clone(),
            stop: r.stats.stop.clone(),
        },
        findings: r
            .findings
            .iter()
            .map(|f| JsonFinding {
                rule: f.rule,
                title: f.title.clone(),
                severity: f.severity.as_str(),
                summary: f.summary.clone(),
                indicators: f.indicators.clone(),
                technique: f.technique,
                call_path: f.call_path.clone(),
                evidence: f
                    .evidence
                    .iter()
                    .map(|e| JsonEvidence {
                        seq: e.seq,
                        kind: e.kind.clone(),
                        caller: e.caller.clone(),
                        line: e.line,
                        detail: e.detail.clone(),
                    })
                    .collect(),
            })
            .collect(),
        recovered_payloads: r
            .recovered
            .iter()
            .map(|p| JsonPayload {
                name: p.name.clone(),
                sha1: p.sha1.clone(),
                size: p.size,
                classes: p.classes,
                how: p.how.clone(),
                class_names: p.class_names.clone(),
            })
            .collect(),
        network: r
            .requests
            .iter()
            .map(|q| JsonRequest {
                method: q.method.clone(),
                url: q.url.clone(),
                body_preview: q.body_preview.clone(),
                body_len: q.body_len,
                provenance: q.provenance.clone(),
                caller: q.caller.clone(),
            })
            .collect(),
        call_graph: JsonGraph {
            methods: r.graph.order.clone(),
            edges: r.graph.edges.keys().cloned().collect(),
        },
        static_facts: JsonFacts {
            version_name: r.facts.version_name.clone(),
            min_sdk: r.facts.min_sdk,
            target_sdk: r.facts.target_sdk,
            debuggable: r.facts.debuggable,
            permissions: r.facts.permissions.clone(),
            exported_components: r.facts.exported_components.clone(),
            dex_files: r.facts.dex_files.clone(),
            native_libs: r.facts.native_libs.clone(),
        },
        caveats: r.caveats.clone(),
    };
    serde_json::to_string_pretty(&doc).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}
