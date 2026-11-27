//! Show where the interpreter stopped and why, for debugging a real sample.
use unhusk_vm::analysis::{analyze, AnalysisConfig};
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let apk = unhusk_apk::Apk::open(std::path::Path::new(&path)).unwrap();
    let mut cfg = AnalysisConfig::default();
    cfg.limits.max_wall = std::time::Duration::from_secs(15);
    cfg.policy.record_all_apis = true;
    let a = analyze(&apk, &cfg);
    println!(
        "stop={:?} insns={} methods={}",
        a.stop,
        a.machine.budget.instructions,
        a.methods_entered()
    );
    println!("executed: {:?}", a.executed);
    for e in a
        .trace()
        .events
        .iter()
        .rev()
        .take(14)
        .collect::<Vec<_>>()
        .iter()
        .rev()
    {
        println!(
            "  [{:?}] {} :: {} {:?} -> {:?}",
            e.kind, e.caller, e.subject, e.args, e.result
        );
    }
}
