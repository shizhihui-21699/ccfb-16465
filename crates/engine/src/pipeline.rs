//! The end-to-end pipeline for one APK.
//!
//! Strategy, and why it is shaped this way:
//!
//!  * **Budget first.** A sample gets a fixed instruction and wall-clock
//!    budget. Every pass shares it, so a pathological sample cannot starve the
//!    rest of the queue.
//!  * **Several clock windows.** Malware gates on dates. We run the default
//!    window plus a handful of offsets spanning past and future, and union the
//!    observed behaviour. The union is what the analyst sees; each finding
//!    records which pass produced it.
//!  * **A comparison profile.** Running once as a plausible phone and once as
//!    an obvious emulator tells us which checks gate the payload: the behaviour
//!    that appears only under the hardened profile is exactly what the sample
//!    was hiding.
//!  * **Static triage feeds the dynamic pass.** The packer fingerprints and
//!    the manifest decide which entry points are worth running and how much
//!    budget to give the first pass.

use crate::outcome::Outcome;
use unhusk_report::StaticFacts;
use unhusk_apk::Apk;
use unhusk_vm::analysis::{analyze, Analysis, AnalysisConfig};
use unhusk_vm::env::{naive_emulator_profile, pixel_profile};
use unhusk_vm::events::{Event, EventKind, Trace};
use unhusk_vm::interp::program::RecoveredDex;
use unhusk_vm::limits::Limits;

pub struct PipelineConfig {
    /// Total wall clock the whole sample may consume.
    pub total_budget_ms: u64,
    /// How many clock windows to try.
    pub windows: usize,
    /// Also run the naive-emulator comparison pass.
    pub compare: bool,
    /// Verbose API recording.
    pub verbose: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            total_budget_ms: 120_000,
            windows: 4,
            compare: true,
            verbose: false,
        }
    }
}

/// A merged run: all passes' events, deduplicated, in a single trace.
pub struct Merged {
    pub outcome: Outcome,
    pub facts: StaticFacts,
    /// Subjects observed only under the emulator profile: what the sample hides.
    pub hidden_under_naive: Vec<String>,
}

pub fn run(apk: &Apk, cfg: &PipelineConfig) -> Merged {
    let facts = static_facts(apk);
    let dex_count = apk.dex_names().len().max(1) as u64;

    // Per-pass budget: divide the instruction budget so four window passes plus
    // the comparison run stay inside it.
    let passes = (cfg.windows.max(1) as u64) * if cfg.compare { 2 } else { 1 };
    let per_pass_insns = (200_000_000 / passes).max(4_000_000);
    let per_pass_ms = (cfg.total_budget_ms / passes).max(2_000);

    let mut base = AnalysisConfig {
        limits: Limits {
            max_instructions: per_pass_insns,
            max_wall: std::time::Duration::from_millis(per_pass_ms),
            ..Limits::default()
        },
        policy: Default::default(),
        profile: pixel_profile(),
        seed: 0x5eed_1234,
        extra_entries: Vec::new(),
        compare_naive: false,
        keep_payloads: true,
        clock_offset_ms: 0,
    };
    base.policy.record_all_apis = cfg.verbose;

    // Clock windows: default, +1y, +3y, -1y. Chosen to span the common
    // "activate later" gates without exploding the pass count.
    const DAY: i64 = 86_400_000;
    let offsets: Vec<i64> = match cfg.windows {
        0 | 1 => vec![0],
        n => {
            let base_offsets = [0i64, 365 * DAY, 3 * 365 * DAY, -365 * DAY, 2 * 365 * DAY, 5 * 365 * DAY];
            base_offsets[..(n as usize).min(base_offsets.len())].to_vec()
        }
    };

    let mut all_events: Vec<Event> = Vec::new();
    let mut all_recovered: Vec<RecoveredDex> = Vec::new();
    let mut all_executed: Vec<String> = Vec::new();
    let mut all_requests = Vec::new();
    let mut recovered_classes: Vec<String> = Vec::new();
    let mut total_insns = 0u64;
    let mut total_ms = 0u64;
    let mut last_stop = String::new();
    let mut seq_base = 0u64;
    let mut truncated = false;

    let mut run_pass = |mut c: AnalysisConfig, profile_name: &str| -> Vec<Event> {
        c.profile.name = profile_name.to_string();
        let a = analyze(apk, &c);
        let mut evs = a.trace().events.clone();
        for e in &mut evs {
            e.seq += seq_base;
        }
        seq_base += a.trace().seq;
        total_insns += a.machine.budget.instructions;
        total_ms += a.elapsed.as_millis() as u64;
        last_stop = format!("{}{}", a.stop.as_str(),
            a.machine.budget.stop_detail.as_deref().map(|d| format!(": {d}")).unwrap_or_default());
        if a.trace().is_truncated() {
            truncated = true;
        }
        // Merge recovered payloads by sha1; keep the first provenance.
        for r in a.recovered.iter() {
            if !all_recovered.iter().any(|x| x.sha1 == r.sha1) {
                all_recovered.push(r.clone());
            }
        }
        for m in a.executed.iter() {
            if !all_executed.contains(m) {
                all_executed.push(m.clone());
            }
        }
        for q in a.machine.env.net.requests.iter() {
            if !all_requests.iter().any(|x: &unhusk_vm::env::RecordedRequest| x.url == q.url && x.body == q.body) {
                all_requests.push(q.clone());
            }
        }
        // Collect recovered class names for the report.
        for m in a.machine.entered.iter() {
            let d = a.machine.program.method(*m).class.clone();
            if a.machine.program.origins[m.dex as usize]
                == unhusk_vm::interp::MethodOrigin::Recovered
                && !recovered_classes.contains(&d)
            {
                recovered_classes.push(d);
            }
        }
        evs
    };

    // Pass 1..N: hardened profile across clock windows.
    for (i, off) in offsets.iter().enumerate() {
        let mut c = base.clone();
        c.clock_offset_ms = *off;
        let label = if i == 0 { "pixel6-a13".to_string() } else { format!("pixel6-a13+t{}d", off / DAY) };
        let evs = run_pass(c, &label);
        all_events.extend(evs);
    }

    // Comparison pass under the naive emulator profile.
    let mut hidden = Vec::new();
    if cfg.compare {
        let mut c = base.clone();
        c.profile = naive_emulator_profile();
        let naive_events = run_pass(c, "generic-emulator");
        // Subjects seen under the hardened profile that the naive one misses.
        let naive_subjects: std::collections::HashSet<&str> =
            naive_events.iter().map(|e| e.subject.as_str()).collect();
        let hardened_subjects: std::collections::HashSet<&str> =
            all_events.iter().map(|e| e.subject.as_str()).collect();
        for s in hardened_subjects {
            if !naive_subjects.contains(s) {
                hidden.push(s.to_string());
            }
        }
        all_events.extend(naive_events);
    }

    // Passes rerun the same code, so most events repeat. Collapse them to one
    // per (kind, caller, subject, args, result) — the first occurrence — so the
    // report reads as behaviour rather than as four copies of the same run.
    // Clock-window passes that produce genuinely new behaviour survive intact.
    all_events.sort_by_key(|e| e.seq);
    {
        let mut seen: std::collections::HashSet<(String, String, String, Vec<String>, Option<String>)> =
            std::collections::HashSet::new();
        all_events.retain(|e| {
            let key = (
                format!("{:?}", e.kind),
                e.caller.clone(),
                e.subject.clone(),
                e.args.clone(),
                e.result.clone(),
            );
            seen.insert(key)
        });
    }
    let mut trace = Trace::default();
    trace.events = all_events;
    trace.seq = seq_base;
    trace.dropped = if truncated { 1 } else { 0 };

    let facts = StaticFacts {
        entry_classes: entry_classes(apk),
        ..facts
    };

    let outcome = Outcome {
        package: apk.manifest.package.clone(),
        apk_sha256: apk.sha256(),
        profile: "pixel6-a13 (multi-window)".to_string(),
        stop: last_stop,
        instructions: total_insns,
        elapsed_ms: total_ms,
        trace,
        recovered: all_recovered,
        executed: all_executed,
        requests: all_requests,
        checks: Default::default(),
    };

    Merged {
        outcome,
        facts,
        hidden_under_naive: hidden,
    }
}

/// Static triage: everything we can say without running code.
pub fn static_facts(apk: &Apk) -> StaticFacts {
    let m = &apk.manifest;
    let mut packer_hits = Vec::new();
    let mut suspicious = Vec::new();
    let mut dex_files = Vec::new();
    for (name, dex) in apk.dex_files() {
        match dex {
            Ok(d) => {
                dex_files.push(format!("{name} ({} classes)", d.classes.len()));
                for h in unhusk_apk::heuristics::scan_dex(&d) {
                    packer_hits.push((h.family.to_string(), h.evidence));
                }
                for (sig, why) in unhusk_apk::heuristics::scan_apis(&d) {
                    suspicious.push((sig, why.to_string()));
                }
            }
            Err(e) => dex_files.push(format!("{name} (unparseable: {e})")),
        }
    }
    for h in unhusk_apk::heuristics::scan_native(apk.names().map(|s| s.to_string())) {
        packer_hits.push((h.family.to_string(), h.evidence));
    }
    let mut abis: Vec<String> = apk.native_libs().into_iter().map(|(a, _)| a).collect();
    abis.sort();
    abis.dedup();
    StaticFacts {
        package: m.package.clone(),
        app_label: String::new(),
        version_name: m.version_name.clone().unwrap_or_default(),
        min_sdk: m.min_sdk,
        target_sdk: m.target_sdk,
        debuggable: m.debugabble,
        permissions: m.permissions.clone(),
        exported_components: m
            .components
            .iter()
            .filter(|c| c.effectively_exported)
            .map(|c| format!("{} {}", c.kind.as_str(), c.name))
            .collect(),
        dex_files,
        native_abis: abis,
        native_libs: apk.native_libs().into_iter().map(|(_, p)| p).collect(),
        packer_hits,
        suspicious_apis: suspicious,
        apk_sha256: apk.sha256(),
        apk_size: apk.bytes().len() as u64,
        entry_classes: Vec::new(),
    }
}

fn entry_classes(apk: &Apk) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(main) = &apk.manifest.main_activity {
        out.push(format!("L{};", main.replace('.', "/")));
    }
    for c in &apk.manifest.components {
        let d = format!("L{};", c.name.replace('.', "/"));
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}
