//! Resource limits: a hostile or merely slow sample must stop cleanly, keep
//! partial results, and stay inside its time and step budgets.

mod support;

use std::sync::Arc;
use std::time::Instant;

use support::javadex::compile_to_dex;
use unshroud::dex::DexFile;
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

fn registry_for(dex: Vec<u8>) -> Registry {
    let mut r = Registry::new();
    r.add_image(Arc::new(DexFile::parse("classes.dex", dex).unwrap()), false);
    r
}

#[test]
fn infinite_loop_is_stopped_by_step_budget() {
    let Some(dex) = compile_to_dex(
        "Spin",
        r#"
public class Spin {
    public static void onCreate() {
        long x = 0;
        while (true) { x++; }
    }
}
"#,
    ) else {
        return;
    };
    let cfg = RunConfig { step_limit: 200_000, per_scenario_ms: 5_000, max_scenarios: 1, ..Default::default() };
    let started = Instant::now();
    let out = scenario::run(registry_for(dex), vec![Persona::retail_default()], &cfg);
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 10, "should stop quickly, took {elapsed:?}");
    let sc = &out.scenarios[0];
    assert!(!sc.completed);
    assert!(sc.stop_reason.is_some(), "a stop reason must be recorded");
    assert!(sc.steps <= 200_000 + 100_000, "steps {} exceeded budget", sc.steps);
}

#[test]
fn deep_recursion_does_not_crash_the_process() {
    let Some(dex) = compile_to_dex(
        "Deep",
        r#"
public class Deep {
    static int dive(int n) {
        return dive(n + 1) + 1;
    }
    public static void onCreate() { dive(0); }
}
"#,
    ) else {
        return;
    };
    let cfg = RunConfig { step_limit: 2_000_000, per_scenario_ms: 5_000, max_scenarios: 1, ..Default::default() };
    let out = scenario::run(registry_for(dex), vec![Persona::retail_default()], &cfg);
    let sc = &out.scenarios[0];
    // Either the depth limit or the step budget stops it; the point is that we
    // come back with a report rather than a stack overflow.
    assert!(sc.stop_reason.is_some() || !sc.completed, "should be truncated: {:?}", sc.stop_reason);
}

#[test]
fn huge_allocation_is_refused_not_oom_killed() {
    let Some(dex) = compile_to_dex(
        "Allo",
        r#"
public class Allo {
    public static void onCreate() {
        try {
            byte[] b = new byte[Integer.MAX_VALUE - 8];
            System.out.println(b.length);
        } catch (OutOfMemoryError e) {
        } catch (NegativeArraySizeException e) {
        }
    }
}
"#,
    ) else {
        return;
    };
    let cfg = RunConfig { step_limit: 2_000_000, per_scenario_ms: 5_000, max_scenarios: 1, ..Default::default() };
    let out = scenario::run(registry_for(dex), vec![Persona::retail_default()], &cfg);
    // Reaching here means the allocation was refused, not attempted.
    assert!(!out.scenarios.is_empty());
}

#[test]
fn malformed_dex_is_rejected_cleanly() {
    // Random bytes with a DEX magic must fail to parse, not panic.
    let mut data = b"dex\n035\0".to_vec();
    data.extend_from_slice(&[0x41u8; 200]);
    let r = DexFile::parse("bad.dex", data);
    assert!(r.is_err());
}

#[test]
fn truncated_dex_tables_are_rejected() {
    // A header claiming huge tables must be refused.
    let mut data = vec![0u8; 0x70];
    data[0..8].copy_from_slice(b"dex\n035\0");
    // class_defs_size = 0x7fffffff at offset 0x60, off = 0x70
    data[0x60..0x64].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    data[0x64..0x68].copy_from_slice(&0x70u32.to_le_bytes());
    let r = DexFile::parse("trunc.dex", data);
    assert!(r.is_err());
}
