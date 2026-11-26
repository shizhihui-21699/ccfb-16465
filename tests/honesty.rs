//! A quiet report must not read as a clean verdict. When the model cannot
//! follow a sample, that fact must be visible in the output.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::report::{SampleReport, Severity};
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

#[test]
fn unmodelled_calls_appear_in_coverage() {
    // A sample that calls an API the model does not implement: the gap must be
    // reported, not silently answered with a default.
    let src = r#"
package com.example.gap;
public class Gap {
    public static void attach(android.content.Context ctx) {
        // A deliberately obscure framework call the model does not implement.
        android.accounts.AccountManager am = android.accounts.AccountManager.get(ctx);
        am.getAuthenticatorTypes();
    }
}
"#;
    let Some(dex) = compile_sources_to_dex(&[("Gap", src)]) else { return };
    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", dex).unwrap()), false);
    let cfg = RunConfig { step_limit: 2_000_000, per_scenario_ms: 10_000, max_scenarios: 1, ..Default::default() };
    let out = scenario::run(reg, vec![Persona::retail_default()], &cfg);
    let sc = &out.scenarios[0];
    assert!(!sc.coverage_gaps.is_empty(), "an unmodelled call must be counted");
    let mut report = SampleReport::empty("gap.apk");
    report.scenarios = out.scenarios;
    unshroud::analysis::finalize(&mut report);
    let md = unshroud::analysis::render_markdown(&report);
    assert!(md.contains("## Coverage"), "the brief must have a coverage section:\n{md}");
    assert!(md.contains("getAuthenticatorTypes") || md.contains("AccountManager"),
        "the specific gap should be named:\n{md}");
    // A report with no findings must say so explicitly and point at the gaps.
    assert!(md.contains("No malicious behaviour was observed"),
        "empty findings must be stated plainly:\n{md}");
    assert!(report.findings.is_empty());
}

#[test]
fn empty_findings_still_renders_and_says_why() {
    let report = SampleReport::empty("x.apk");
    let md = unshroud::analysis::render_markdown(&report);
    assert!(md.contains("No malicious behaviour was observed"));
    assert!(md.contains("not a clean verdict") || md.contains("coverage"));
    assert_eq!(report.top_severity(), Severity::Info);
}
