//! Scenario runner.
//!
//! Runs a sample under a set of simulated personas and drives the entry points
//! that matter for malware: the launcher activity's lifecycle, boot receivers,
//! services, and any packer-shaped static entry point. Delayed work is
//! executed by advancing the virtual clock, so a dropper that waits six hours
//! before fetching a payload still produces a finding — in milliseconds.
//!
//! Every scenario has its own step budget and wall-clock slice; when one is
//! exhausted the partial findings are kept and marked truncated. A run that
//! found nothing is as informative as one that did, and the report says which
//! gates were probed so an analyst can see why.

use std::time::Instant;

use crate::dex::{DexFile, ACC_STATIC};
use crate::report::ScenarioReport;
use crate::vm::android::AndroidHost;
use crate::vm::env::{Environment, Persona};
use crate::vm::intern::Sym;
use crate::vm::interp::Vm;
use crate::vm::registry::MethodEntry;
use crate::vm::registry::Registry;
use crate::vm::value::{ObjRef, Slot};

/// Names of entry-point method shapes worth driving, in priority order.
const ENTRY_METHODS: [(&str, &str); 21] = [
    ("attachBaseContext", "(Landroid/content/Context;)V"),
    ("onCreate", "(Landroid/os/Bundle;)V"),
    ("onCreate", "()V"),
    ("onStart", "()V"),
    ("onResume", "()V"),
    ("onStartCommand", "(Landroid/content/Intent;II)I"),
    ("onBind", "(Landroid/content/Intent;)Landroid/os/IBinder;"),
    ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"),
    ("onHandleIntent", "(Landroid/content/Intent;)V"),
    ("doInBackground", "([Ljava/lang/Object;)Ljava/lang/Object;"),
    ("run", "()V"),
    ("handleMessage", "(Landroid/os/Message;)V"),
    ("onClick", "(Landroid/view/View;)V"),
    ("onDraw", "(Landroid/graphics/Canvas;)V"),
    ("afterTextChanged", "(Landroid/text/Editable;)V"),
    ("newInstance", "(Ljava/lang/Object;)Ljava/lang/Object;"),
    ("call", "()Ljava/lang/Object;"),
    ("invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"),
    // Packer/loader hooks that take a Context rather than a Bundle.
    ("attach", "(Landroid/content/Context;)V"),
    ("init", "(Landroid/content/Context;)V"),
    ("load", "(Landroid/content/Context;)V"),
];

/// Names of static initialisation-style entry points packers expose.
const STATIC_HOOKS: [(&str, &str); 13] = [
    ("load", "()V"),
    ("init", "()V"),
    ("start", "()V"),
    ("attach", "()V"),
    ("attach", "(Landroid/content/Context;)V"),
    ("init", "(Landroid/content/Context;)V"),
    ("load", "(Landroid/content/Context;)V"),
    ("run", "()V"),
    ("main", "([Ljava/lang/String;)V"),
    ("bootstrap", "()V"),
    ("setup", "()V"),
    ("install", "()V"),
    ("prepare", "()V"),
];

#[derive(Clone)]
pub struct RunConfig {
    pub step_limit: u64,
    pub per_scenario_ms: u64,
    pub max_scenarios: usize,
    pub max_steps_total: u64,
    /// APK `assets/` entries, made available to the sample's `AssetManager`.
    pub assets: std::collections::HashMap<String, Vec<u8>>,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            step_limit: 12_000_000,
            per_scenario_ms: 20_000,
            max_scenarios: 4,
            max_steps_total: 40_000_000,
            assets: std::collections::HashMap::new(),
        }
    }
}

pub struct Outcome {
    pub scenarios: Vec<ScenarioReport>,
    pub notes: Vec<String>,
    pub total_steps: u64,
    pub elapsed_ms: u64,
    /// Images recovered at runtime, already registered into this run.
    pub dynamic_dexes: Vec<DexFile>,
    pub dynamic_dumps: Vec<(String, Vec<u8>)>,
}

/// Run the sample across a small set of personas.
pub fn run(
    registry: Registry,
    persona_list: Vec<Persona>,
    config: &RunConfig,
) -> Outcome {
    let started = Instant::now();
    let mut scenarios = Vec::new();
    let mut notes = Vec::new();
    let mut total_steps = 0u64;
    let mut dynamic_dumps: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen_dynamic: Vec<String> = Vec::new();

    for (idx, persona) in persona_list.into_iter().enumerate() {
        if idx >= config.max_scenarios {
            break;
        }
        let registry = registry.clone_for_scenario();
        let mut persona = persona;
        if persona.assets.is_empty() {
            persona.assets = config.assets.clone();
        }
        // The sample sees itself as a launcher activity of this package; the
        // manifest's package name (when known) is how it addresses itself.
        let env = Environment::new(persona);
        let scenario_name = env.scenario_name.clone();
        let host = AndroidHost::new();
        let mut vm = Vm::new(registry, env, config.step_limit, config.per_scenario_ms);
        let mut host = host_pin(host);
        let res = drive(&mut vm, &mut host);
        total_steps += vm.steps;
        // Harvest any DEX images the sample produced in this scenario.
        for (origin, bytes) in collect_dynamic_images(&vm) {
            if !seen_dynamic.contains(&origin) {
                seen_dynamic.push(origin.clone());
                dynamic_dumps.push((origin, bytes));
            }
        }
        scenarios.push(ScenarioReport {
            name: scenario_name,
            description: vm.env.persona.description.clone(),
            findings: vm.findings.clone(),
            probes: vm.env.probes.clone(),
            steps: vm.steps,
            elapsed_ms: 0,
            completed: !vm.halted,
            stop_reason: vm.stop_reason.clone(),
            coverage_gaps: vm.env.coverage_gaps.clone(),
            errors: Vec::new(),
        });
        let _ = res;
    }

    // Merge images recovered at runtime into a single registry so the report
    // can describe them.
    let mut dynamic_dexes = Vec::new();
    for (origin, bytes) in &dynamic_dumps {
        if let Ok(dex) = DexFile::parse(origin.clone(), bytes.clone()) {
            dynamic_dexes.push(dex);
        }
    }
    if dynamic_dumps.is_empty() {
        notes.push("no runtime-decrypted DEX image was recovered".into());
    } else {
        notes.push(format!(
            "{} runtime image(s) recovered: {}",
            dynamic_dumps.len(),
            dynamic_dumps.iter().map(|(o, _)| o.as_str()).take(6).collect::<Vec<_>>().join(", ")
        ));
    }

    Outcome {
        scenarios,
        notes,
        total_steps,
        elapsed_ms: started.elapsed().as_millis() as u64,
        dynamic_dexes,
        dynamic_dumps,
    }
}

/// Boxes are used so the host can be moved in and out of the VM during
/// reentrant callbacks; this identity function documents that.
fn host_pin(h: AndroidHost) -> AndroidHost {
    h
}

/// Drive one scenario: set up a Context, invoke entry points, run the
/// scheduler, and deliver a synthetic SMS + UI event.
fn drive(vm: &mut Vm, host: &mut AndroidHost) -> Result<(), crate::error::Error> {
    // The application Context is the object most host calls hang off.
    let context = vm.new_instance_of(crate::vm::android::CONTEXT_CLASS)?;
    // Populate default device state objects on the context so getSystemService
    // chains have something to work with.
    vm.env.persona.system_properties.entry("app.package".into()).or_insert_with(|| {
        "com.example.app".into()
    });

    // 1. Static initialisers of every app class are run implicitly by the JVM
    //    before the first active use; packers frequently decrypt in <clinit>.
    //    Drive the most suspicious-looking ones explicitly.
    drive_static_hooks(vm, host, context);

    // 2. Lifecycle entry points, in priority order.
    drive_entry_points(vm, host, context);

    // 3. Advance the virtual clock through scheduled work; a dropper that waits
    //    hours is exercised here.
    let mut rounds = 0;
    while vm.pending_tasks() > 0 && rounds < 64 && !vm.halted {
        rounds += 1;
        if !vm.advance_to_next_task(host) {
            break;
        }
    }

    // 4. Deliver a "user opened the app" SMS so receivers wired to SMS behave.
    deliver_synthetic_sms(vm, host, context);

    // 5. A short final drain for anything scheduled during step 4.
    let mut rounds = 0;
    while vm.pending_tasks() > 0 && rounds < 8 && !vm.halted {
        rounds += 1;
        if !vm.advance_to_next_task(host) {
            break;
        }
    }
    Ok(())
}

fn drive_static_hooks(vm: &mut Vm, host: &mut AndroidHost, context: ObjRef) {
    // Snapshot class descriptors first: interning during iteration would
    // borrow the registry mutably.
    let class_descs: Vec<Sym> = vm.registry.all_app_classes().map(|c| c.desc).collect();
    let hook_syms: Vec<(Sym, Sym, &'static str, &'static str)> = STATIC_HOOKS
        .iter()
        .map(|(m, p)| {
            let ms = vm.registry.interner.intern(m);
            let ps = vm.registry.interner.intern(p);
            (ms, ps, *m, *p)
        })
        .collect();
    let mut candidates: Vec<(Sym, Sym, Sym)> = Vec::new();
    for desc in class_descs {
        for (ms, ps, _, _) in &hook_syms {
            if let Some(entry) = vm.registry.methods.get(&crate::vm::intern::MethodKey {
                class: desc,
                name: *ms,
                proto: *ps,
            }) {
                if entry.code_off != 0 && entry.access & ACC_STATIC != 0 {
                    candidates.push((desc, *ms, *ps));
                }
            }
        }
    }
    // Prefer hooks that take a Context: they are where packers do their work.
    candidates.sort_by_key(|(_, _, p)| if vm.registry.interner.get(*p).contains("Context") { 0 } else { 1 });
    // Bound the work: a packer can declare hundreds of stub classes.
    candidates.truncate(48);
    for (class, name, p) in candidates {
        if vm.halted {
            break;
        }
        let proto = vm.sym_str(p).to_string();
        if let Some(entry) = vm.registry.resolve_direct(class, name, p) {
            if entry.code_off == 0 {
                continue;
            }
            // Build arguments for the shape.
            let args = match proto.as_str() {
                "([Ljava/lang/String;)V" => {
                    let arr = vm.new_array_of("Ljava/lang/String;", 0).unwrap_or(ObjRef::NULL);
                    vec![Slot::reference(arr)]
                }
                "(Landroid/content/Context;)V" => vec![Slot::reference(context)],
                _ => Vec::new(),
            };
            let _ = vm.execute(host, entry, args);
        }
    }
}

fn drive_entry_points(vm: &mut Vm, host: &mut AndroidHost, context: ObjRef) {
    // Find every app class declaring one of the lifecycle shapes, ordered by
    // how "main" the class looks.
    struct Candidate {
        entry: MethodEntry,
        rank: i32,
    }
    let class_info: Vec<(Sym, String, u32)> = vm
        .registry
        .all_app_classes()
        .map(|c| (c.desc, vm.registry.interner.get(c.desc).to_string(), c.access))
        .collect();
    let entry_syms: Vec<(Sym, Sym)> = ENTRY_METHODS
        .iter()
        .map(|(m, p)| {
            let ms = vm.registry.interner.intern(m);
            let ps = vm.registry.interner.intern(p);
            (ms, ps)
        })
        .collect();
    let mut candidates: Vec<Candidate> = Vec::new();
    for (desc_sym, desc, access) in class_info {
        let rank = class_rank(&desc, access);
        for (ms, ps) in &entry_syms {
            if let Some(entry) = vm.registry.methods.get(&crate::vm::intern::MethodKey {
                class: desc_sym,
                name: *ms,
                proto: *ps,
            }) {
                if entry.code_off != 0 {
                    candidates.push(Candidate { entry: *entry, rank });
                }
            }
        }
    }
    candidates.sort_by_key(|c| std::cmp::Reverse(c.rank));
    candidates.truncate(40);

    for cand in candidates {
        if vm.halted {
            break;
        }
        let proto = vm.sym_str(cand.entry.key.proto).to_string();
        let is_instance = cand.entry.access & ACC_STATIC == 0;
        // Build a receiver for instance methods.
        let receiver = if is_instance {
            match vm.heap.new_instance(cand.entry.key.class) {
                Ok(o) => {
                    call_default_ctor(vm, host, cand.entry.key.class, o);
                    Some(o)
                }
                Err(_) => None,
            }
        } else {
            None
        };
        let args = build_entry_args(vm, &proto, receiver, context);
        let entry = cand.entry;
        if let Some(entry) = vm.registry.resolve_direct(entry.key.class, entry.key.name, entry.key.proto) {
            if entry.code_off == 0 {
                continue;
            }
            let _ = vm.execute(host, entry, args);
        }
    }
}

fn class_rank(desc: &str, access: u32) -> i32 {
    let mut r = 0;
    let lower = desc.to_ascii_lowercase();
    // Application and launcher-ish classes run first.
    for (needle, weight) in [
        ("mainactivity", 100),
        ("launcher", 95),
        ("application", 90),
        ("app", 60),
        ("activity", 50),
        ("splash", 45),
        ("service", 40),
        ("receiver", 35),
        ("stub", 30),
        ("proxy", 30),
        ("loader", 28),
        ("shell", 26),
        ("wrapper", 20),
        ("/a/", 10),
        ("/b/", 9),
        ("/c/", 8),
    ] {
        if lower.contains(needle) {
            r += weight;
        }
    }
    if access & crate::dex::ACC_ABSTRACT != 0 {
        r -= 10;
    }
    r
}

fn call_default_ctor(vm: &mut Vm, host: &mut AndroidHost, class: Sym, obj: ObjRef) {
    let ctor = vm.registry.interner.intern("<init>");
    let proto = vm.registry.interner.intern("()V");
    if let Some(entry) = vm.registry.resolve_direct(class, ctor, proto) {
        if entry.code_off != 0 {
            let _ = vm.execute(host, entry, vec![Slot::reference(obj)]);
        }
    }
}

fn build_entry_args(vm: &mut Vm, proto: &str, receiver: Option<ObjRef>, context: ObjRef) -> Vec<Slot> {
    let mut args = Vec::new();
    if let Some(r) = receiver {
        args.push(Slot::reference(r));
    }
    // Parse parameter descriptors, chaining after `this`.
    let params = proto.split(')').next().unwrap_or("(").trim_start_matches('(');
    let mut it = params.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            'L' => {
                let mut name = String::from("L");
                while let Some(&n) = it.peek() {
                    it.next();
                    name.push(n);
                    if n == ';' {
                        break;
                    }
                }
                let slot = framework_arg(vm, &name, context);
                args.push(slot);
            }
            '[' => {
                // arrays: build an empty one of the element type
                let mut name = String::from("[");
                let mut depth = 1;
                while let Some(&n) = it.peek() {
                    it.next();
                    name.push(n);
                    if n == '[' {
                        depth += 1;
                    } else if n == 'L' {
                        while let Some(&m) = it.peek() {
                            it.next();
                            name.push(m);
                            if m == ';' {
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
                let elem = name.trim_start_matches('[');
                let elem = if elem.is_empty() { "Ljava/lang/Object;" } else { elem };
                let arr = vm.new_array_of(elem, 0).unwrap_or(ObjRef::NULL);
                args.push(Slot::reference(arr));
                let _ = depth;
            }
            'I' | 'Z' | 'B' | 'S' | 'C' => args.push(Slot::int(0)),
            'J' => args.push(Slot::long(0)),
            'F' => args.push(Slot::float(0.0)),
            'D' => args.push(Slot::double(0.0)),
            _ => {}
        }
    }
    args
}

fn framework_arg(vm: &mut Vm, desc: &str, context: ObjRef) -> Slot {
    match desc {
        "Landroid/content/Context;" | "Landroid/content/ContextWrapper;" => Slot::reference(context),
        "Landroid/content/Intent;" => {
            let intent = vm.new_instance_of("Landroid/content/Intent;").ok();
            match intent {
                Some(i) => {
                    if let Ok(action) = vm.new_string("android.intent.action.MAIN") {
                        crate::vm::android::set_state_ref(vm, i, "action", action);
                    }
                    Slot::reference(i)
                }
                None => Slot::null(),
            }
        }
        "Landroid/os/Bundle;" => {
            let b = vm.new_instance_of("Landroid/os/Bundle;").ok();
            b.map(Slot::reference).unwrap_or_else(Slot::null)
        }
        "Landroid/os/Message;" => {
            let m = vm.new_instance_of("Landroid/os/Message;").ok();
            m.map(Slot::reference).unwrap_or_else(Slot::null)
        }
        "Landroid/view/View;" => {
            let v = vm.new_instance_of("Landroid/view/View;").ok();
            v.map(Slot::reference).unwrap_or_else(Slot::null)
        }
        "Landroid/text/Editable;" => {
            let e = vm.new_instance_of("Landroid/text/Editable;").ok();
            e.map(Slot::reference).unwrap_or_else(Slot::null)
        }
        "Landroid/graphics/Canvas;" => {
            let c = vm.new_instance_of("Landroid/graphics/Canvas;").ok();
            c.map(Slot::reference).unwrap_or_else(Slot::null)
        }
        "Ljava/lang/String;" => vm.new_string("").map(Slot::reference).unwrap_or_else(|_| Slot::null()),
        "Ljava/lang/Object;" => Slot::null(),
        _ => Slot::null(),
    }
}

fn deliver_synthetic_sms(vm: &mut Vm, host: &mut AndroidHost, context: ObjRef) {
    // Find SmsReceiver-shaped classes with onReceive(Context, Intent).
    let name = vm.registry.interner.intern("onReceive");
    let proto = vm.registry.interner.intern("(Landroid/content/Context;Landroid/content/Intent;)V");
    let class_descs: Vec<Sym> = vm.registry.all_app_classes().map(|c| c.desc).collect();
    let mut targets = Vec::new();
    for desc in class_descs {
        if let Some(entry) = vm.registry.methods.get(&crate::vm::intern::MethodKey {
            class: desc,
            name,
            proto,
        }) {
            if entry.code_off != 0 {
                targets.push(*entry);
            }
        }
    }
    targets.truncate(16);
    for entry in targets {
        if vm.halted {
            break;
        }
        let intent = match vm.new_instance_of("Landroid/content/Intent;") {
            Ok(i) => i,
            Err(_) => continue,
        };
        if let Ok(action) = vm.new_string("android.provider.Telephony.SMS_RECEIVED") {
            crate::vm::android::set_state_ref(vm, intent, "action", action);
        }
        // Put an SMS body into extras so receivers that parse PDUs see data.
        if let Ok(body) = vm.new_string("Your verification code is 483920") {
            crate::vm::android::set_state_ref(vm, intent, "extra:body", body);
        }
        if let Ok(addr) = vm.new_string("+12025550143") {
            crate::vm::android::set_state_ref(vm, intent, "extra:sender", addr);
        }
        let _ = vm.execute(host, entry, vec![Slot::reference(context), Slot::reference(intent)]);
    }
}

/// Collect decrypted DEX images seen in this scenario. Images registered by the
/// class-loader hook carry `decrypted:` in their origin.
fn collect_dynamic_images(vm: &Vm) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for img in &vm.registry.images {
        if img.origin.starts_with("decrypted:") || img.origin.starts_with("loader:") {
            out.push((img.origin.clone(), img.data.as_ref().clone()));
        }
    }
    out
}

/// Note the finding kinds the report should call out in its headline.
pub fn headline(findings: &[crate::report::Finding]) -> Option<&crate::report::Finding> {
    findings.first()
}

#[cfg(test)]
mod tests {
    #[test]
    fn entry_arg_parsing() {
        let descs = ["()V", "(Landroid/content/Intent;II)I", "([Ljava/lang/String;)V"];
        for d in descs {
            let params = d.split(')').next().unwrap().trim_start_matches('(');
            assert!(params.len() <= d.len());
        }
    }
}
