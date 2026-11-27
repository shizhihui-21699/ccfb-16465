//! Ad-hoc driver: run the interpreter over one APK and print the trace.
//!
//! Usage: cargo run -p unhusk-vm --example run -- --apk=fixtures/evasive.apk [--date=2025-06-01]

use std::time::Instant;
use unhusk_vm::analysis::{analyze, AnalysisConfig};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = AnalysisConfig::default();
    cfg.policy.record_all_apis = args.iter().any(|a| a == "--verbose");

    // Parse every flag before running, so flag order on the command line does
    // not change the result.
    for arg in &args {
        if let Some(v) = arg.strip_prefix("--date=") {
            cfg.clock_offset_ms = parse_date_offset(v);
        }
        if arg == "--naive" {
            cfg.profile = unhusk_vm::env::naive_emulator_profile();
        }
    }

    for arg in &args {
        let Some(path) = arg.strip_prefix("--apk=") else { continue };
        let bytes = std::fs::read(path).unwrap();
        let apk = unhusk_apk::Apk::from_bytes(bytes).unwrap();
        let t = Instant::now();
        let a = analyze(&apk, &cfg);
        println!(
            "== {} package={} profile={} stop={:?} insns={} methods={} in {:?}",
            path,
            a.package,
            a.profile_name,
            a.stop,
            a.machine.budget.instructions,
            a.methods_entered(),
            t.elapsed()
        );
        println!("   entries: {:?}", a.entry_points);
        println!("   executed: {:?}", a.executed);
        for r in &a.recovered {
            println!(
                "   recovered {} sha1={} size={} classes={} recovery={:?}",
                r.name, r.sha1, r.size, r.classes, r.recovery
            );
        }
        println!("   events: {}", a.trace().events.len());
        for e in a.trace().events.iter() {
            println!(
                "     [{:?}] {} :: {} {} -> {:?}",
                e.kind,
                e.caller,
                e.subject,
                e.args.join(", "),
                e.result
            );
        }
        println!("   methods entered: {}", a.machine.entered.len());
        let mut names: Vec<String> = a.machine.entered.iter().map(|h| a.machine.program.method(*h).display()).collect();
        names.sort();
        for n in names { println!("     - {n}"); }
        println!("   requests: {}", a.machine.env.net.requests.len());
        for r in &a.machine.env.net.requests {
            println!(
                "     {} {} body={:?} prov={}",
                r.method,
                r.url,
                String::from_utf8_lossy(&r.body),
                r.body_provenance
            );
        }
        if let Some(d) = a.machine.budget.stop_detail {
            println!("   stop detail: {d}");
        }
    }
}

/// `2025-06-01` -> milliseconds since the default emulated "now" (2024-03-14).
fn parse_date_offset(v: &str) -> i64 {
    if v.len() < 10 {
        return 0;
    }
    let y: i64 = v[0..4].parse().unwrap_or(2024);
    let m: i64 = v[5..7].parse().unwrap_or(3);
    let d: i64 = v[8..10].parse().unwrap_or(14);
    // Mean month length is fine for a coarse shift.
    ((y - 2024) * 365 + (m - 3) * 30 + (d - 14)) * 86_400_000
}
