//! End-to-end behaviour tests over the synthetic APK corpus.
//!
//! These assert on *conclusions* (a payload was recovered and executed; the
//! beacon was reached with a runtime-built body), not on internal structure, so
//! they keep meaning something when the interpreter changes.

use unhusk_engine::pipeline::{run, PipelineConfig};
use unhusk_report::{render::render_text, Report, ReportInput};
use unhusk_vm::events::EventKind;

struct Fixture {
    report: Report,
    outcome: unhusk_engine::Outcome,
}

fn analyse(name: &str) -> Fixture {
    let path = format!("{}/../../fixtures/{name}.apk", env!("CARGO_MANIFEST_DIR"));
    let apk = unhusk_apk::Apk::open(std::path::Path::new(&path))
        .unwrap_or_else(|e| panic!("open {path}: {e}"));
    let cfg = PipelineConfig {
        total_budget_ms: 30_000,
        windows: 4,
        compare: true,
        verbose: false,
    };
    let merged = run(&apk, &cfg);
    let o = &merged.outcome;
    let report = ReportInput {
        facts: merged.facts.clone(),
        events: o.events(),
        recovered: &o.recovered,
        requests: &o.requests,
        executed: &o.executed,
        stop: o.stop.clone(),
        instructions: o.instructions,
        elapsed_ms: o.elapsed_ms,
        profile: o.profile.clone(),
        trace_truncated: o.trace.is_truncated(),
        classes_in_recovered: Vec::new(),
    }
    .build();
    Fixture { report, outcome: merged.outcome }
}

#[test]
fn benign_app_reports_no_malice() {
    let f = analyse("hello");
    assert!(
        f.report.findings.is_empty(),
        "a plain app must produce no findings, got: {:?}",
        f.report.findings.iter().map(|x| x.title.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn packer_payload_is_recovered_and_executed() {
    let f = analyse("packer");
    assert_eq!(f.report.recovered.len(), 1, "one DEX payload should be recovered");
    let p = &f.report.recovered[0];
    assert_eq!(p.classes, 1);
    assert!(p.size > 0 && p.sha1.len() == 40);

    let ran_recovered = f.outcome.trace.events.iter().any(|e| {
        e.kind == EventKind::MethodEnter && e.layer == unhusk_vm::events::Layer::RecoveredDex
    });
    assert!(ran_recovered, "payload code must execute, not just be recovered");

    let top = f.report.findings.first().expect("a finding");
    assert_eq!(top.severity, unhusk_report::Severity::Critical);
    assert!(top.title.contains("executed"), "title was {:?}", top.title);
}

#[test]
fn evasive_sample_reaches_beacon_only_after_gates_pass() {
    let f = analyse("evasive");
    assert_eq!(f.report.requests.len(), 1, "exactly one distinct request");
    let r = &f.report.requests[0];
    assert_eq!(r.url, "http://203.0.113.9:8443/beacon");
    assert!(
        r.provenance.contains("built"),
        "body was assembled at runtime, provenance was {}",
        r.provenance
    );

    let rules: Vec<&str> = f.report.findings.iter().map(|x| x.rule).collect();
    assert!(rules.contains(&"root-artifact-probe"), "rules: {rules:?}");
    assert!(rules.contains(&"emulator-artifact-probe"), "rules: {rules:?}");
}

#[test]
fn profile_comparison_shows_the_evasion_signal() {
    let f = analyse("evasive");
    let emu = f
        .report
        .findings
        .iter()
        .find(|x| x.rule == "emulator-artifact-probe")
        .expect("emulator finding");
    let has_contrast = emu.indicators.iter().any(|i| i.contains(" vs "));
    assert!(
        has_contrast,
        "expected at least one property with two observed values, got {:?}",
        emu.indicators
    );
}

#[test]
fn report_renders_without_panicking_on_all_fixtures() {
    for name in ["hello", "packer", "evasive"] {
        let f = analyse(name);
        let text = render_text(&f.report, true);
        assert!(text.contains("VERDICT"), "{name}: {text}");
        assert!(text.len() > 200);
        let json = unhusk_report::render::to_json(&f.report);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["schema"], "unhusk/report/v1");
    }
}

#[test]
fn analysis_is_deterministic() {
    let a = analyse("packer");
    let b = analyse("packer");
    let ea: Vec<(&str, &str)> = a
        .report
        .findings
        .iter()
        .map(|f| (f.rule, f.title.as_str()))
        .collect();
    let eb: Vec<(&str, &str)> = b
        .report
        .findings
        .iter()
        .map(|f| (f.rule, f.title.as_str()))
        .collect();
    assert_eq!(ea, eb);
    assert_eq!(
        a.report.recovered.first().map(|p| p.sha1.clone()),
        b.report.recovered.first().map(|p| p.sha1.clone())
    );
}

#[test]
fn small_budget_produces_partial_result_not_hang() {
    let path = format!("{}/../../fixtures/packer.apk", env!("CARGO_MANIFEST_DIR"));
    let apk = unhusk_apk::Apk::open(std::path::Path::new(&path)).unwrap();
    let cfg = PipelineConfig {
        total_budget_ms: 4_000,
        windows: 1,
        compare: false,
        verbose: false,
    };
    let merged = run(&apk, &cfg);
    assert!(merged.outcome.instructions > 0);
    assert!(!merged.outcome.stop.is_empty());
}
