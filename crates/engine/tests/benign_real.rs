//! A real, benign, moderately large application must not be flagged.
//!
//! This is the most valuable regression test in the suite: false positives are
//! what destroy an analyst's trust in a triage tool, and every modelling
//! shortcut shows up here first. The sample is a ~20 MB F-Droid build with
//! 25k classes, Kotlin coroutines, a bundling framework and an application
//! class whose `attachBaseContext` runs real startup code.
//!
//! The failure modes this guards against, all found by running it:
//!  * aborting the whole run on the first ClassCastException / NPE caused by an
//!    unmodelled framework method (the run used to stop after 70 methods);
//!  * treating `Build.VERSION.SDK_INT` reads as emulator evasion (almost every
//!    app does this for version gating);
//!  * charging ordinary reflection against the dynamic-load budget.

use unhusk_engine::pipeline::{run, PipelineConfig};

#[test]
fn large_benign_app_is_not_flagged() {
    let path = format!(
        "{}/../../fixtures/benign-real.apk",
        env!("CARGO_MANIFEST_DIR")
    );
    let apk = unhusk_apk::Apk::open(std::path::Path::new(&path)).expect("fixture present");
    let cfg = PipelineConfig {
        // One window: the comparison pass is off and a second parse of a 20 MB
        // APK costs more than it proves here.
        total_budget_ms: 60_000,
        windows: 1,
        compare: false,
        verbose: false,
    };
    let merged = run(&apk, &cfg);
    let o = &merged.outcome;

    // The run must have executed real application code, not bailed out on the
    // first modelling gap. How *much* is not asserted: entry order and the
    // amount of startup code reached varies legitimately with the profile, and
    // pinning an instruction count would make the test fail for the wrong
    // reason. What matters is that startup ran and the run finished.
    let executed_own_code = o.executed.iter().any(|m| m.starts_with("org.fdroid."));
    assert!(
        executed_own_code,
        "the app's own startup code never ran; executed: {:?}",
        o.executed
    );
    assert!(
        !o.stop.starts_with("uncaught"),
        "an uncaught exception means a modelling gap aborted the run: {}",
        o.stop
    );
    assert!(
        o.recovered.is_empty(),
        "a benign app has no runtime-unpacked payload"
    );
    assert!(
        o.requests.is_empty(),
        "no exfiltration expected, got {:?}",
        o.requests.iter().map(|r| r.url.clone()).collect::<Vec<_>>()
    );

    // Finally: the report must be clean.
    let report = unhusk_report::ReportInput {
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
    let titles: Vec<&str> = report.findings.iter().map(|f| f.title.as_str()).collect();
    assert!(
        report.findings.is_empty(),
        "benign app produced findings: {titles:?}"
    );
}

#[test]
fn a_version_check_alone_is_not_emulator_evasion() {
    // `Build.VERSION.SDK_INT` is read by almost every app for version gating.
    // The emulator rule must require breadth (a fingerprint or a sensor probe),
    // not a single SDK comparison.
    let path = format!(
        "{}/../../fixtures/benign-real.apk",
        env!("CARGO_MANIFEST_DIR")
    );
    let apk = unhusk_apk::Apk::open(std::path::Path::new(&path)).unwrap();
    let cfg = PipelineConfig {
        total_budget_ms: 60_000,
        windows: 1,
        compare: false,
        verbose: false,
    };
    let merged = run(&apk, &cfg);
    let saw_sdk_read = merged
        .outcome
        .events()
        .iter()
        .any(|e| e.subject.contains("SDK_INT"));
    let report = unhusk_report::ReportInput {
        facts: merged.facts.clone(),
        events: merged.outcome.events(),
        recovered: &merged.outcome.recovered,
        requests: &merged.outcome.requests,
        executed: &merged.outcome.executed,
        stop: merged.outcome.stop.clone(),
        instructions: merged.outcome.instructions,
        elapsed_ms: merged.outcome.elapsed_ms,
        profile: merged.outcome.profile.clone(),
        trace_truncated: false,
        classes_in_recovered: Vec::new(),
    }
    .build();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.rule == "emulator-artifact-probe"),
        "an SDK_INT read must not raise an emulator finding (saw_sdk_read={saw_sdk_read})"
    );
}
