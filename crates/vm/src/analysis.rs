//! One analysis run against one APK: assemble the program, seed the entry
//! points, drive the interpreter, and hand back everything observed.

use crate::env::{naive_emulator_profile, pixel_profile, DeviceProfile, Env};
use crate::events::Trace;
use crate::interp::engine::Machine;
use crate::limits::StopReason;
use crate::interp::program::{Program, RecoveredDex};
use crate::interp::state::Policy;
use crate::limits::Limits;
use crate::value::Value;
use serde::{Deserialize, Serialize};

use std::time::Duration;
use unhusk_apk::Apk;

/// Everything configured before a run.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub limits: Limits,
    pub policy: Policy,
    pub profile: DeviceProfile,
    /// Seed the RNG and clock deterministically.
    pub seed: u64,
    /// Additional entry points: `Lcls;->name(params)ret`, tried after the
    /// manifest entry points.
    pub extra_entries: Vec<String>,
    /// Run under the naive emulator profile as a comparison pass.
    pub compare_naive: bool,
    /// Keep recovered DEX bytes for extraction.
    pub keep_payloads: bool,
    /// Offset applied to the emulated clock, in milliseconds. Samples gated on
    /// a date window ("activate after 2023-06") only fire in some windows, so
    /// the pipeline runs several of these and unions the traces.
    pub clock_offset_ms: i64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            policy: Policy::default(),
            profile: pixel_profile(),
            seed: 0x5eed_1234,
            extra_entries: Vec::new(),
            compare_naive: false,
            keep_payloads: false,
            clock_offset_ms: 0,
        }
    }
}

/// The result of one run.
pub struct Analysis {
    pub machine: Machine,
    pub entry_points: Vec<String>,
    pub stop: StopReason,
    pub detail: Option<String>,
    pub elapsed: Duration,
    pub recovered: Vec<RecoveredDex>,
    pub apk_sha256: String,
    pub package: String,
    pub profile_name: String,
    /// Every method that actually executed, in first-entry order.
    pub executed: Vec<String>,
}

/// Summary of a comparison run under the naive emulator profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDiff {
    pub profile: String,
    pub stop: String,
    pub instructions: u64,
    /// Events present in the hardened run but not here, by (kind, subject).
    pub missing_events: usize,
    /// API subjects reached only in the naive run.
    pub only_here: Vec<String>,
}

impl Analysis {
    pub fn trace(&self) -> &Trace {
        &self.machine.trace
    }

    pub fn methods_entered(&self) -> usize {
        self.machine.methods_entered
    }


}

/// Build the program for an APK: all shipped DEX, in load order.
pub fn load_program(apk: &Apk) -> (Program, Vec<String>) {
    let mut program = Program::new();
    let mut names = Vec::new();
    for (name, parsed) in apk.dex_files() {
        if let Ok(dex) = parsed {
            program.add_dex(dex, None);
            names.push(name);
        }
    }
    (program, names)
}

/// Run a single analysis pass.
pub fn analyze(apk: &Apk, cfg: &AnalysisConfig) -> Analysis {
    let (program, _loaded) = load_program(apk);
    let mut env = Env::new(cfg.profile.clone(), apk.manifest.package.clone(), cfg.seed);
    env.clock.base_ms = env.clock.base_ms.saturating_add(cfg.clock_offset_ms);
    // Expose assets and resources to the model.
    for name in apk.names() {
        if name.starts_with("assets/") {
            if let Ok(Some(data)) = apk.read(name) {
                env.assets.insert(name.trim_start_matches("assets/").to_string(), data);
            }
        }
    }
    let package = apk.manifest.package.clone();
    env.fs.existing.push(env.files_dir());
    env.fs.existing.push(env.cache_dir());
    env.fs.existing.push(env.app_data_dir.clone());

    let mut machine = Machine::new(program, env, cfg.limits.clone(), cfg.policy.clone());
    machine.app_class = apk.manifest.application_class.clone();
    machine.granted_permissions = apk.manifest.permissions.clone();

    let entries = entry_points(apk, &machine, cfg);
    for e in &entries {
        machine.seed_entry(e);
    }

    let started = std::time::Instant::now();
    let stop = machine.run();
    let elapsed = started.elapsed();
    let recovered = machine.recovered.clone();
    let executed = machine.executed.clone();

    Analysis {
        machine,
        entry_points: entries,
        stop,
        detail: None,
        elapsed,
        recovered,
        apk_sha256: apk.sha256(),
        package,
        profile_name: cfg.profile.name.clone(),
        executed,
    }
}

/// Candidate entry points, most specific first.
pub fn entry_points(apk: &Apk, machine: &Machine, cfg: &AnalysisConfig) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(main) = &apk.manifest.main_activity {
        let desc = if main.starts_with('L') {
            main.clone()
        } else {
            format!("L{};", main.replace('.', "/"))
        };
        if machine.program.class_exists(&desc) {
            out.push(desc);
        }
    }
    if let Some(app) = &apk.manifest.application_class {
        let desc = format!("L{};", app.replace('.', "/"));
        if machine.program.class_exists(&desc) && !out.contains(&desc) {
            out.push(desc);
        }
    }
    for extra in &cfg.extra_entries {
        if let Some((class, _)) = extra.split_once("->") {
            if machine.program.class_exists(class) && !out.contains(&class.to_string()) {
                out.push(class.to_string());
            }
        }
    }
    out
}

/// Run the same sample under the naive emulator profile to see which checks the
/// sample would have used to hide.
pub fn compare_profiles(apk: &Apk, cfg: &AnalysisConfig) -> (Analysis, Option<ProfileDiff>) {
    let hardened = analyze(apk, cfg);

    let mut naive = cfg.clone();
    naive.profile = naive_emulator_profile();
    let naive_run = analyze(apk, &naive);

    // Which subjects did the hardened run reach that the naive one did not?
    let h: std::collections::HashSet<String> = hardened
        .trace()
        .events
        .iter()
        .map(|e| e.subject.clone())
        .collect();
    let n: std::collections::HashSet<String> = naive_run
        .trace()
        .events
        .iter()
        .map(|e| e.subject.clone())
        .collect();
    let only_here: Vec<String> = n.difference(&h).cloned().collect();
    let missing = h.difference(&n).count();

    let diff = ProfileDiff {
        profile: naive_run.profile_name.clone(),
        stop: naive_run.stop.as_str().to_string(),
        instructions: naive_run.machine.budget.instructions,
        missing_events: missing,
        only_here,
    };
    (hardened, Some(diff))
}

impl Machine {
    /// Configure and run the entry points of `desc` class, in a defined order:
    /// static initialiser, then Application/Activity lifecycle stubs, then any
    /// `main`/`run`/`start`.
    pub fn seed_entry(&mut self, class_desc: &str) {
        if !self.program.class_exists(class_desc) {
            return;
        }
        let mut order = ["<clinit>", "attachBaseContext", "onCreate", "main", "run", "start", "init"];
        for name in order.iter_mut() {
            let handles: Vec<_> = self.program.methods_named(class_desc, name).to_vec();
            for h in handles {
                let (has_code, is_static, nargs, display) = {
                    let m = self.program.method(h);
                    (m.code.is_some(), m.is_static, m.proto.params.len(), m.display())
                };
                if !has_code || !is_static || !self.frames.is_empty() {
                    continue;
                }
                // Never re-run something the sample already reached.
                if self.entered.contains(&h) {
                    continue;
                }
                if self.budget.is_stopped() {
                    return;
                }
                // Parameters get null/zero defaults.
                let args = vec![Value::NULL; nargs];
                let already = self.entered.contains(&h);
                let _ = self.push_frame(h, args, None, None);
                if !already {
                    self.executed.push(display);
                }
                let _ = self.run();
            }
        }
    }
}
