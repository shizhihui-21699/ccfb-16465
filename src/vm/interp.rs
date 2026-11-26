//! The Dalvik interpreter.
//!
//! Design notes:
//!
//! * **Host hooks are outside the machine.** `Vm::execute` takes `&mut dyn Host`.
//!   A framework implementation (Android APIs, crypto, networking) therefore
//!   can call back into app code — for example running a `Runnable` posted to a
//!   `Handler`, or a comparator passed to `Collections.sort` — because nothing
//!   is mutably borrowed twice.
//! * **Frames own their registers**, recycled through a pool. A decryptor that
//!   calls a small helper a million times does not allocate a million vectors.
//! * **Budget checks are amortised** over thousands of instructions, so the
//!   inner loop stays tight.
//! * **Unknown framework methods are counted, not guessed.** The host may
//!   decline; the interpreter then returns a typed default and records a
//!   coverage gap, so the report can show where the model was blind.

use std::collections::HashMap;
use std::sync::Arc;

use crate::dex::code::*;
use crate::dex::CodeItem;
use crate::error::{Error, Result};
use crate::report::{Finding, SinkKind};

use super::env::Environment;
use super::heap::{Heap, ObjKind};
use super::intern::{FieldKey, Interner, MethodKey, Sym};
use super::registry::{MethodEntry, Registry, StaticInit};
pub use super::registry::MethodEntry as ExportedMethodEntry;
use super::value::{ObjRef, Slot, Taint, Value};

/// A Java exception in flight.
#[derive(Debug, Clone)]
pub struct JavaException {
    pub class: Sym,
    pub detail: String,
    pub trace: Vec<String>,
}

/// What a host hook did.
#[derive(Debug)]
pub enum CallOutcome {
    Value(Slot),
    Throw(Sym, String),
    /// The host does not model this call.
    Decline,
}

/// Framework model hooks. Implemented by `vm::android`.
pub trait Host {
    /// Invoke a framework method. `key` names the declared API; `args[0]` is
    /// `this` for instance methods.
    fn call(&mut self, vm: &mut Vm, key: &MethodKey, args: &[Slot]) -> CallOutcome;

    /// Read a static field of a framework class (`Build.MODEL`, ...).
    fn static_field(&mut self, vm: &mut Vm, key: &FieldKey) -> CallOutcome;

    /// Construct a framework object (`new Intent()`, `new URL(...)`).
    /// The `<init>` call follows and is delivered through `call`.
    fn construct(&mut self, vm: &mut Vm, class: Sym) -> CallOutcome;

    /// Called when app code declares a native method and it is invoked.
    fn native_call(&mut self, vm: &mut Vm, key: &MethodKey, args: &[Slot]) -> CallOutcome;
}

/// A host that models nothing; used by unit tests and by the static analyzer's
/// dry runs.
pub struct NullHost;
impl Host for NullHost {
    fn call(&mut self, _vm: &mut Vm, _k: &MethodKey, _a: &[Slot]) -> CallOutcome {
        CallOutcome::Decline
    }
    fn static_field(&mut self, _vm: &mut Vm, _k: &FieldKey) -> CallOutcome {
        CallOutcome::Decline
    }
    fn construct(&mut self, _vm: &mut Vm, _c: Sym) -> CallOutcome {
        CallOutcome::Decline
    }
    fn native_call(&mut self, _vm: &mut Vm, _k: &MethodKey, _a: &[Slot]) -> CallOutcome {
        CallOutcome::Decline
    }
}

/// Register storage for one activation.
struct Frame {
    entry: MethodEntry,
    code: Arc<CodeItem>,
    pc: usize,
    regs: Vec<Slot>,
    /// Result of the most recent invoke, consumed by `move-result*`.
    result: Slot,
    /// Exception object delivered by `move-exception` after unwinding.
    pending_exception: Option<ObjRef>,
}

impl Frame {
    fn desc(&self, interner: &Interner) -> String {
        format!(
            "{}->{}{}",
            interner.get(self.entry.key.class),
            interner.get(self.entry.key.name),
            interner.get(self.entry.key.proto)
        )
    }
}

/// Where execution is going after one instruction.
pub enum Flow {
    Continue,
    Goto(usize),
    Return(Slot),
    Throw(JavaException),
}

const BUDGET_INTERVAL: u32 = 8192;
pub const MAX_FRAMES: usize = 900;
const MAX_REGS: usize = 65536;

pub struct Vm {
    pub registry: Registry,
    pub heap: Heap,
    pub env: Environment,

    frames: Vec<Frame>,
    /// Recycled register vectors, indexed by capacity class.
    reg_pool: Vec<Vec<Slot>>,

    pub steps: u64,
    pub step_limit: u64,
    deadline: std::time::Instant,
    pub deadline_ms: u64,
    /// Set when the machine stopped for a resource reason.
    pub halted: bool,
    pub stop_reason: Option<String>,

    pub findings: Vec<Finding>,
    /// Java call chain, rendered, innermost last. Maintained only while the
    /// app-code portion of the chain is executing.
    trace: Vec<String>,
    /// When false the trace is frozen (host internals are not attributed).
    trace_capture: bool,

    /// Static field storage for app classes.
    pub statics: HashMap<FieldKey, Slot>,
    /// Static fields initialised from a class's `static_values`.
    statics_loaded: std::collections::HashSet<Sym>,

    /// Delayed callbacks (Handler.postDelayed, Timer, AlarmManager).
    pub scheduler: Vec<ScheduledTask>,
    pub scheduler_ran: u64,
    next_task_id: u64,

    /// Decrypted strings and blobs observed at runtime, bounded.
    pub decrypted: Vec<String>,
    /// Taint bit -> label, assigned on demand.
    taint_labels: Vec<(u8, String)>,
    label_bits: u64,

    pub exc_null: Sym,
    pub exc_runtime: Sym,
    pub exc_array_oob: Sym,
    pub exc_class_cast: Sym,
    pub exc_arith: Sym,
    pub exc_unsupported: Sym,
    pub exc_out_of_mem: Sym,
    pub exc_illegal_state: Sym,
    pub exc_io: Sym,
    pub exc_generic: Sym,
    pub exc_security: Sym,
    pub exc_negative_array: Sym,

    // Caches, keyed by (image index, member index).
    key_cache: HashMap<(u32, u32), MethodKey>,
    field_key_cache: HashMap<(u32, u32), FieldKey>,
    type_cache: HashMap<(u32, u32), Sym>,

    budget_countdown: u32,
    /// Return value of the most recent frame pop.
    last_return: Option<Slot>,
}

#[derive(Debug, Clone)]
pub struct ScheduledTask {
    pub id: u64,
    pub due_millis: i64,
    pub name: String,
    pub callback: Callback,
}

#[derive(Debug, Clone)]
pub enum Callback {
    Invoke { class: Sym, method: Sym, proto: Sym, args: Vec<Slot> },
    Runnable(ObjRef),
    /// A `Message` delivered to a `Handler`. `what` is the message's
    /// discriminator, which app code switches on.
    Message { handler: ObjRef, what: i32 },
}

impl Vm {
    pub fn new(
        registry: Registry,
        env: Environment,
        step_limit: u64,
        deadline_ms: u64,
    ) -> Vm {
        let mut registry = registry;
        let mut intern = |s: &str| registry.interner.intern(s);
        let exc_null = intern("Ljava/lang/NullPointerException;");
        let exc_runtime = intern("Ljava/lang/RuntimeException;");
        let exc_array_oob = intern("Ljava/lang/ArrayIndexOutOfBoundsException;");
        let exc_class_cast = intern("Ljava/lang/ClassCastException;");
        let exc_arith = intern("Ljava/lang/ArithmeticException;");
        let exc_unsupported = intern("Ljava/lang/UnsupportedOperationException;");
        let exc_out_of_mem = intern("Ljava/lang/OutOfMemoryError;");
        let exc_illegal_state = intern("Ljava/lang/IllegalStateException;");
        let exc_io = intern("Ljava/io/IOException;");
        let exc_generic = intern("Ljava/lang/Exception;");
        let exc_security = intern("Ljava/lang/SecurityException;");
        let exc_negative_array = intern("Ljava/lang/NegativeArraySizeException;");
        Vm {
            registry,
            heap: Heap::new(),
            env,
            frames: Vec::new(),
            reg_pool: Vec::new(),
            steps: 0,
            step_limit,
            deadline: std::time::Instant::now(),
            deadline_ms,
            halted: false,
            stop_reason: None,
            findings: Vec::new(),
            trace: Vec::new(),
            trace_capture: true,
            statics: HashMap::new(),
            statics_loaded: std::collections::HashSet::new(),
            scheduler: Vec::new(),
            scheduler_ran: 0,
            next_task_id: 1,
            decrypted: Vec::new(),
            taint_labels: Vec::new(),
            label_bits: 0,
            exc_null,
            exc_runtime,
            exc_array_oob,
            exc_class_cast,
            exc_arith,
            exc_unsupported,
            exc_out_of_mem,
            exc_illegal_state,
            exc_io,
            exc_generic,
            exc_security,
            exc_negative_array,
            key_cache: HashMap::new(),
            field_key_cache: HashMap::new(),
            type_cache: HashMap::new(),
            budget_countdown: BUDGET_INTERVAL,
            last_return: None,
        }
    }

    // ---------------------------------------------------------------------
    // Symbol helpers
    // ---------------------------------------------------------------------

    pub fn sym(&mut self, s: &str) -> Sym {
        self.registry.interner.intern(s)
    }

    pub fn sym_str(&self, s: Sym) -> &str {
        self.registry.interner.get(s)
    }

    pub fn class_desc(&self, c: Sym) -> &str {
        self.registry.interner.get(c)
    }

    // ---------------------------------------------------------------------
    // Heap convenience
    // ---------------------------------------------------------------------

    pub fn new_string(&mut self, s: impl Into<String>) -> Result<ObjRef> {
        self.heap.new_string(s, Taint::CLEAN)
    }

    pub fn new_string_t(&mut self, s: impl Into<String>, t: Taint) -> Result<ObjRef> {
        self.heap.new_string(s, t)
    }

    pub fn string_of(&self, r: ObjRef) -> String {
        self.heap.string_of(r).unwrap_or("").to_string()
    }

    pub fn str_arg(&self, args: &[Slot], i: usize) -> Option<String> {
        let r = args.get(i).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL);
        if r.is_null() {
            None
        } else {
            self.heap.string_of(r).map(|s| s.to_string())
        }
    }

    /// Convert a value to its Java `toString` form, for building payloads.
    pub fn to_java_string(&self, s: Slot) -> String {
        match s.v {
            Value::Ref(r) if !r.is_null() => match self.heap.get(r).map(|o| &o.kind) {
                Some(ObjKind::Str(x)) | Some(ObjKind::MutableStr(x)) => x.clone(),
                _ => format!("[obj {}]", r.0),
            },
            Value::Ref(_) => "null".into(),
            Value::Int(v) => v.to_string(),
            Value::Long(v) => v.to_string(),
            Value::Float(v) => fmt_float(v as f64),
            Value::Double(v) => fmt_float(v),
            Value::Undef | Value::WideHigh => "0".into(),
        }
    }

    // ---------------------------------------------------------------------
    // Taint labels
    // ---------------------------------------------------------------------

    /// Mint a named taint bit. Names are recorded so findings can print them.
    pub fn mint_taint(&mut self, name: &str) -> Taint {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in name.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let bit = (h % 63) as u8;
        if !self.taint_labels.iter().any(|(b, _)| *b == bit) {
            self.taint_labels.push((bit, name.to_string()));
        }
        self.label_bits |= 1u64 << bit;
        Taint(1u64 << bit)
    }

    pub fn taint_names(&self, t: Taint) -> Vec<String> {
        self.taint_labels
            .iter()
            .filter(|(bit, _)| t.0 & (1u64 << *bit) != 0)
            .map(|(_, n)| n.clone())
            .collect()
    }

    pub fn all_taint_names(&self) -> Vec<String> {
        self.taint_labels.iter().map(|(_, n)| n.clone()).collect()
    }

    // ---------------------------------------------------------------------
    // Reporting
    // ---------------------------------------------------------------------

    pub fn current_stack(&self) -> Vec<String> {
        self.frames
            .iter()
            .map(|f| self.frame_desc(f))
            .collect()
    }

    fn frame_desc(&self, f: &Frame) -> String {
        let base = f.desc(&self.registry.interner);
        match self.registry.image(f.entry.dex) {
            Some(img) if img.origin != "classes.dex" && !img.origin.is_empty() => {
                format!("{base} [{}]", short_origin(&img.origin))
            }
            _ => base,
        }
    }

    /// The reporting trace: app frames only, innermost last.
    fn report_stack(&self) -> Vec<String> {
        let mut stack: Vec<String> = self
            .frames
            .iter()
            .map(|f| self.frame_desc(f))
            .filter(|s| !s.starts_with("Ljava/") && !s.starts_with("Landroid/"))
            .collect();
        if stack.is_empty() {
            stack = self.trace.clone();
        }
        stack
    }

    pub fn report_sink(
        &mut self,
        kind: SinkKind,
        api: impl Into<String>,
        detail: impl Into<String>,
        taint: Taint,
        evidence: Vec<String>,
    ) {
        let api = api.into();
        let detail = detail.into();
        let stack = self.report_stack();
        let taint_names = self.taint_names(taint);
        let finding = Finding {
            kind,
            severity: kind.severity(),
            api: api.clone(),
            detail: detail.clone(),
            taint: taint_names,
            stack,
            evidence,
            scenario: self.env.scenario_name.clone(),
            dedup_key: format!("{}|{}|{}", kind.as_str(), api, detail),
        };
        if self.findings.len() < 50_000 {
            self.findings.push(finding);
        }
    }

    pub fn probe(&mut self, api: &str, value: impl Into<String>) {
        self.env.probe(api, value);
    }

    pub fn note_decrypted(&mut self, s: String) {
        if self.decrypted.len() < 4000
            && (4..=4096).contains(&s.len())
            && !self.decrypted.iter().any(|x| x == &s)
        {
            self.decrypted.push(s);
        }
    }

    // ---------------------------------------------------------------------
    // Scheduling
    // ---------------------------------------------------------------------

    pub fn schedule_in(&mut self, delay_ms: i64, name: String, cb: Callback) -> u64 {
        let id = self.next_task_id;
        self.next_task_id += 1;
        if self.scheduler.len() < 4096 {
            self.scheduler.push(ScheduledTask {
                id,
                due_millis: self.env.now().saturating_add(delay_ms.max(0)),
                name,
                callback: cb,
            });
        }
        id
    }

    /// Run every task due now. Bounded to keep a runaway repost loop finite.
    pub fn run_due_tasks(&mut self, host: &mut dyn Host) {
        let mut ran = 0u32;
        loop {
            let now = self.env.now();
            let Some(pos) = self
                .scheduler
                .iter()
                .enumerate()
                .filter(|(_, t)| t.due_millis <= now)
                .min_by_key(|(_, t)| (t.due_millis, t.id))
                .map(|(i, _)| i)
            else {
                break;
            };
            let task = self.scheduler.remove(pos);
            self.scheduler_ran += 1;
            ran += 1;
            match task.callback {
                Callback::Invoke { class, method, proto, args } => {
                    let r = self.invoke_static(host, class, method, proto, &args);
                    if let Err(e) = r {
                        self.env.gap(&format!("scheduled task {}: {e}", task.name));
                    }
                }
                Callback::Runnable(obj) => {
                    let r = self.invoke_runnable(host, obj);
                    if let Err(e) = r {
                        self.env.gap(&format!("scheduled runnable: {e}"));
                    }
                }
                Callback::Message { handler, what } => {
                    let r = self.deliver_message(host, handler, what);
                    if let Err(e) = r {
                        self.env.gap(&format!("scheduled message: {e}"));
                    }
                }
            }
            if ran > 2048 || self.halted {
                break;
            }
        }
    }

    /// Advance the virtual clock to the next due task and run it.
    pub fn advance_to_next_task(&mut self, host: &mut dyn Host) -> bool {
        let Some(next) = self.scheduler.iter().map(|t| t.due_millis).min() else {
            return false;
        };
        if next > self.env.clock_millis {
            self.env.clock_millis = next;
        }
        self.run_due_tasks(host);
        true
    }

    pub fn pending_tasks(&self) -> usize {
        self.scheduler.len()
    }

    // ---------------------------------------------------------------------
    // Invocation entry points
    // ---------------------------------------------------------------------

    pub fn invoke_static(
        &mut self,
        host: &mut dyn Host,
        class: Sym,
        name: Sym,
        proto: Sym,
        args: &[Slot],
    ) -> Result<Slot> {
        if let Some(entry) = self.registry.resolve_direct(class, name, proto) {
            if entry.code_off != 0 {
                return self.execute(host, entry, args.to_vec());
            }
            let key = entry.key;
            return self.host_call(host, &key, args);
        }
        self.env
            .gap(&format!("{}->{}{}", self.sym_str(class), self.sym_str(name), self.sym_str(proto)));
        Ok(Slot::default())
    }

    /// Deliver a scheduled `Message` to a `Handler` subclass's
    /// `handleMessage` override. Falls back to the framework's own handler
    /// (which does nothing) when the app has not overridden it.
    pub fn deliver_message(&mut self, host: &mut dyn Host, handler: ObjRef, what: i32) -> Result<Slot> {
        if handler.is_null() {
            return Ok(Slot::default());
        }
        let msg_class = self.sym("Landroid/os/Message;");
        let msg = self.heap.new_instance(msg_class)?;
        if let Some(inst) = self.heap.instance_mut(msg) {
            inst.state.insert("what".into(), Slot::int(what));
        }
        let Some(class) = self.heap.class_of(handler) else { return Ok(Slot::default()) };
        let name = self.sym("handleMessage");
        let proto = self.sym("(Landroid/os/Message;)V");
        if let Some(entry) = self.registry.resolve_virtual(class, name, proto) {
            if entry.code_off != 0 {
                return self.execute(host, entry, vec![Slot::reference(handler), Slot::reference(msg)]);
            }
        }
        Ok(Slot::default())
    }

    pub fn invoke_runnable(&mut self, host: &mut dyn Host, obj: ObjRef) -> Result<Slot> {
        let Some(class) = self.heap.class_of(obj) else {
            return Ok(Slot::default());
        };
        let run = self.sym("run");
        let proto = self.sym("()V");
        if let Some(entry) = self.registry.resolve_virtual(class, run, proto) {
            if entry.code_off != 0 {
                return self.execute(host, entry, vec![Slot::reference(obj)]);
            }
            let key = entry.key;
            return self.host_call(host, &key, &[Slot::reference(obj)]);
        }
        Ok(Slot::default())
    }

    /// Public single-shot execution used by the scenario runner.
    pub fn execute(&mut self, host: &mut dyn Host, entry: MethodEntry, args: Vec<Slot>) -> Result<Slot> {
        let stop_depth = self.frames.len();
        self.push_frame(entry, args)?;
        self.run_loop(host, stop_depth)
    }

    /// Run a class's `<clinit>` now (used by reflection and class loaders).
    pub fn ensure_class_initialized(&mut self, class: Sym) {
        let mut host = crate::vm::android::default_host();
        let _ = self.ensure_initialized(class, &mut *host);
        let _ = host;
    }

    /// Stop the whole scenario at the next budget check. Used for `System.exit`
    /// and process kills, which must not let later code run.
    pub fn halt_now(&mut self) {
        self.halted = true;
        self.frames.clear();
    }

    /// Put a string on the heap and return its slot (host convenience).
    pub fn string_slot(&mut self, s: impl Into<String>) -> Result<Slot> {
        Ok(Slot::reference(self.new_string(s)?))
    }

    /// Register a decrypted DEX image. Returns the image index. The caller
    /// (the reflection/class-loader hook) decides the class name mapping.
    pub fn register_payload_image(&mut self, dex: crate::dex::DexFile) -> crate::error::Result<usize> {
        let arc = Arc::new(dex);
        Ok(self.registry.add_image(arc, true))
    }

    /// Look up an app class by dotted or slash name.
    pub fn app_class_by_name(&mut self, name: &str) -> Option<Sym> {
        let desc = if name.starts_with('L') && name.ends_with(';') {
            name.to_string()
        } else {
            format!("L{};", name.replace('.', "/"))
        };
        let sym = self.registry.interner.intern(&desc);
        if self.registry.is_app_class(sym) {
            Some(sym)
        } else {
            None
        }
    }

    /// Resolve a method by descriptor strings. Convenience for host code and
    /// the scenario runner, which work in terms of API names, not symbols.
    pub fn find_method(&mut self, class: &str, name: &str, proto: &str) -> Option<MethodEntry> {
        let c = self.sym(class);
        let n = self.sym(name);
        let p = self.sym(proto);
        self.registry.resolve_direct(c, n, p)
    }

    pub fn find_virtual(&mut self, class: &str, name: &str, proto: &str) -> Option<MethodEntry> {
        let c = self.sym(class);
        let n = self.sym(name);
        let p = self.sym(proto);
        self.registry.resolve_virtual(c, n, p)
    }

    /// Allocate an instance of a class named by descriptor.
    pub fn new_instance_of(&mut self, class: &str) -> Result<ObjRef> {
        let c = self.sym(class);
        self.heap.new_instance(c)
    }

    /// Allocate an array of the given element descriptor.
    pub fn new_array_of(&mut self, elem: &str, len: usize) -> Result<ObjRef> {
        let c = self.sym(elem);
        self.heap.new_array(c, elem, len, Taint::CLEAN)
    }

    /// Convenience for host code: interned string value of a slot.
    pub fn str_of_slot(&self, s: Slot) -> Option<String> {
        let r = s.v.as_ref();
        if r.is_null() {
            None
        } else {
            self.heap.string_of(r).map(|x| x.to_string())
        }
    }

    // ---------------------------------------------------------------------
    // Frame management
    // ---------------------------------------------------------------------

    fn push_frame(&mut self, entry: MethodEntry, args: Vec<Slot>) -> Result<()> {
        if self.frames.len() >= MAX_FRAMES {
            self.stop_reason.get_or_insert_with(|| "call depth limit".into());
            self.halted = true;
            return Err(Error::LimitExceeded("call depth"));
        }
        let Some(code) = self.registry.code_of(&entry) else {
            self.env.gap(&self.registry.method_desc(&entry.key));
            return Err(Error::Unsupported("no code".into()));
        };
        let nregs = code.registers_size as usize;
        if nregs > MAX_REGS {
            return Err(Error::BadFormat("registers_size exceeds limit".into()));
        }
        // Outs are written above the frame's registers as call arguments, but
        // Dalvik callers always have room, so the frame needs exactly `nregs`.
        let mut regs = self.take_regs(nregs);
        regs.resize(nregs, Slot::default());
        for r in regs.iter_mut() {
            *r = Slot::default();
        }
        // Parameters land in the last `ins` registers. `ins` counts *code
        // units*, so a wide argument consumes two.
        let argbase = nregs.saturating_sub(code.ins as usize);
        let mut r = argbase;
        for a in &args {
            if r >= nregs {
                break;
            }
            regs[r] = *a;
            r += 1;
            if a.v.is_wide() {
                if r < nregs {
                    regs[r] = Slot::clean(Value::WideHigh);
                }
                r += 1;
            }
        }
        self.frames.push(Frame {
            entry,
            code,
            pc: 0,
            regs,
            result: Slot::default(),
            pending_exception: None,
        });
        Ok(())
    }

    fn take_regs(&mut self, n: usize) -> Vec<Slot> {
        while let Some(v) = self.reg_pool.pop() {
            if v.capacity() >= n {
                return v;
            }
        }
        Vec::with_capacity(n)
    }

    fn pop_frame(&mut self) -> Option<Frame> {
        let mut f = self.frames.pop()?;
        f.regs.clear();
        if self.reg_pool.len() < 64 && f.regs.capacity() <= 4096 {
            let regs = std::mem::take(&mut f.regs);
            self.reg_pool.push(regs);
        }
        Some(f)
    }

    fn run_loop(&mut self, host: &mut dyn Host, stop_depth: usize) -> Result<Slot> {
        loop {
            if self.frames.len() <= stop_depth {
                // Our frame was popped by a return; value is in `last_return`.
                return Ok(self.last_return.take().unwrap_or_default());
            }
            self.budget_countdown -= 1;
            if self.budget_countdown == 0 {
                self.budget_countdown = BUDGET_INTERVAL;
                if self.budget_exceeded() {
                    self.unwind_all();
                    return Ok(Slot::default());
                }
            }
            let flow = self.exec_top(host)?;
            match flow {
                Flow::Continue => {}
                Flow::Goto(target) => {
                    let f = self.frames.last_mut().expect("frame");
                    if target >= f.code.insns.len() {
                        return Err(Error::BadFormat("branch target outside code".into()));
                    }
                    f.pc = target;
                }
                Flow::Return(v) => {
                    let frame = self.pop_frame().expect("frame");
                    self.last_return = Some(v);
                    if let Some(parent) = self.frames.last_mut() {
                        parent.result = v;
                    }
                    if self.frames.len() <= stop_depth {
                        let _ = frame;
                        return Ok(self.last_return.take().unwrap_or_default());
                    }
                }
                Flow::Throw(exc) => {
                    if !self.deliver_exception(exc)? {
                        return Err(Error::Unsupported("uncaught exception".into()));
                    }
                }
            }
        }
    }

    /// Exception propagation. Returns true when a handler was entered.
    fn deliver_exception(&mut self, exc: JavaException) -> Result<bool> {
        loop {
            let Some(frame) = self.frames.last() else {
                return Ok(false);
            };
            let throw_pc = frame.pc.saturating_sub(1);
            let handler = frame
                .code
                .tries
                .iter()
                .find(|t| {
                    let start = t.start_addr as usize;
                    let end = start + t.insn_count as usize;
                    throw_pc >= start && throw_pc < end
                })
                .cloned();
            if let Some(t) = handler {
                let mut chosen = None;
                let mut fallback = None;
                let image = frame.entry.dex;
                for h in &t.handlers {
                    match h.type_idx {
                        Some(tidx) => {
                            let desc = self.type_name_of(image, tidx).to_string();
                            if self.class_is_assignable_from_str(exc.class, &desc) {
                                chosen = Some(h.addr as usize);
                                break;
                            }
                        }
                        None => fallback = Some(h.addr as usize),
                    }
                }
                if let Some(addr) = chosen.or(fallback) {
                    let obj = self.heap.new_instance(exc.class).ok();
                    let tidx = self.type_cache.get(&(image, 0)).copied();
                    let _ = tidx;
                    let f = self.frames.last_mut().unwrap();
                    f.pc = addr;
                    f.pending_exception = obj;
                    return Ok(true);
                }
            }
            // No handler: discard the frame, record where it escaped.
            let escaped = self
                .frames
                .last()
                .map(|f| f.desc(&self.registry.interner))
                .unwrap_or_default();
            self.pop_frame();
            if self.frames.is_empty() {
                let exc_name = self.sym_str(exc.class).to_string();
                self.env.gap(&format!("uncaught {exc_name} from {escaped}"));
                if self.stop_reason.is_none() {
                    self.stop_reason = Some(format!("uncaught {exc_name} in {escaped}"));
                }
                return Ok(false);
            }
        }
    }

    fn unwind_all(&mut self) {
        while self.pop_frame().is_some() {}
    }

    // ---------------------------------------------------------------------
    // Budget
    // ---------------------------------------------------------------------

    fn budget_exceeded(&mut self) -> bool {
        if self.steps >= self.step_limit {
            self.halted = true;
            self.stop_reason
                .get_or_insert_with(|| format!("instruction budget ({} steps) exhausted", self.step_limit));
            return true;
        }
        if self.deadline.elapsed().as_millis() as u64 >= self.deadline_ms {
            self.halted = true;
            self.stop_reason
                .get_or_insert_with(|| format!("wall-clock budget ({}ms) exhausted", self.deadline_ms));
            return true;
        }
        false
    }

    // ---------------------------------------------------------------------
    // Register access
    // ---------------------------------------------------------------------

    fn reg(&self, i: usize) -> Result<Slot> {
        self.frames
            .last()
            .and_then(|f| f.regs.get(i).copied())
            .ok_or_else(|| Error::BadFormat(format!("register v{i} out of range")))
    }


    fn set_reg(&mut self, i: usize, s: Slot) -> Result<()> {
        let f = self.frames.last_mut().expect("frame");
        if i >= f.regs.len() {
            return Err(Error::BadFormat(format!("register v{i} out of range")));
        }
        f.regs[i] = s;
        Ok(())
    }

    fn set_wide(&mut self, i: usize, v: Value, t: Taint) -> Result<()> {
        self.set_reg(i, Slot { v, t })?;
        self.set_reg(i + 1, Slot { v: Value::WideHigh, t })?;
        Ok(())
    }

    fn read_long(&self, i: usize) -> Result<i64> {
        let a = self.reg(i)?;
        if a.v.is_wide() {
            return Ok(a.v.as_long());
        }
        // Obfuscated code sometimes moves wide halves as 32-bit words.
        if let (Value::Int(lo), Ok(hi)) = (a.v, self.reg(i + 1)) {
            let hi = hi.v.as_int() as u64;
            return Ok(((hi << 32) | (lo as u32 as u64)) as i64);
        }
        Ok(a.v.as_long())
    }

    fn read_double(&self, i: usize) -> Result<f64> {
        let a = self.reg(i)?;
        if matches!(a.v, Value::Double(_)) {
            return Ok(a.v.as_double());
        }
        if let (Value::Int(lo), Ok(hi)) = (a.v, self.reg(i + 1)) {
            let bits = ((hi.v.as_int() as u32 as u64) << 32) | (lo as u32 as u64);
            return Ok(f64::from_bits(bits));
        }
        Ok(a.v.as_double())
    }

    fn reg_pair(&mut self, a: usize, b: usize) -> Result<(Slot, Slot)> {
        Ok((self.reg(a)?, self.reg(b)?))
    }

    // ---------------------------------------------------------------------
    // Instruction execution
    // ---------------------------------------------------------------------

    fn exec_top(&mut self, host: &mut dyn Host) -> Result<Flow> {
        let (code, pc, dex) = {
            let f = self.frames.last().expect("frame");
            (f.code.clone(), f.pc, f.entry.dex)
        };
        let Some(_) = code.insns.get(pc) else {
            // Falling off the end of the code array is a return-void.
            return Ok(Flow::Return(Slot::default()));
        };
        let insn = decode(&code.insns, pc);
        self.steps += 1;
        self.frames.last_mut().unwrap().pc = pc + insn.len;
        self.exec(&insn, &code, dex, host)
    }

    fn exec(&mut self, i: &Insn, code: &Arc<CodeItem>, dex: u32, host: &mut dyn Host) -> Result<Flow> {
        use Value as V;
        match i.op {
            OP_NOP => Ok(Flow::Continue),
            0x01 | 0x07 => {
                // move / move-object
                let (dst, src) = (i.a4() as usize, i.b4() as usize);
                let s = self.reg(src)?;
                self.set_reg(dst, s)?;
                Ok(Flow::Continue)
            }
            0x02 | 0x08 => {
                let dst = i.a8() as usize;
                let s = self.reg(i.u16_1() as usize)?;
                self.set_reg(dst, s)?;
                Ok(Flow::Continue)
            }
            0x03 | 0x09 => {
                let (dst, src) = (i.w[1] as usize, i.w[2] as usize);
                let s = self.reg(src)?;
                self.set_reg(dst, s)?;
                Ok(Flow::Continue)
            }
            0x04..=0x06 => {
                // move-wide: copy the pair as stored
                let (dst, src) = match i.op {
                    0x04 => (i.a4() as usize, i.b4() as usize),
                    0x05 => (i.a8() as usize, i.u16_1() as usize),
                    _ => (i.w[1] as usize, i.w[2] as usize),
                };
                let lo = self.reg(src)?;
                let hi = self.reg(src + 1)?;
                if lo.v.is_wide() {
                    self.set_wide(dst, lo.v, lo.t)?;
                } else {
                    self.set_reg(dst, lo)?;
                    self.set_reg(dst + 1, hi)?;
                }
                Ok(Flow::Continue)
            }
            0x0a..=0x0c => {
                // move-result wide/object variants differ only in width.
                let dst = i.a8() as usize;
                let r = self.frames.last().unwrap().result;
                if i.op == 0x0b {
                    if r.v.is_wide() {
                        self.set_wide(dst, r.v, r.t)?;
                    } else {
                        self.set_wide(dst, V::Long(r.v.as_long()), r.t)?;
                    }
                } else {
                    self.set_reg(dst, r)?;
                }
                Ok(Flow::Continue)
            }
            0x0d => {
                // move-exception
                let dst = i.a8() as usize;
                let obj = self.frames.last_mut().and_then(|f| f.pending_exception.take());
                let obj = obj.map(Slot::reference).unwrap_or_else(|| Slot::reference(ObjRef::NULL));
                self.set_reg(dst, obj)?;
                Ok(Flow::Continue)
            }
            0x0e => Ok(Flow::Return(Slot::default())),
            0x0f | 0x11 => {
                let s = self.reg(i.a8() as usize)?;
                Ok(Flow::Return(s))
            }
            0x10 => {
                let s = self.reg(i.a8() as usize)?;
                let v = V::Long(self.read_long(i.a8() as usize)?);
                Ok(Flow::Return(Slot { v, t: s.t }))
            }
            0x12 => {
                let dst = i.a4() as usize;
                self.set_reg(dst, Slot::int(i.lit4()))?;
                Ok(Flow::Continue)
            }
            0x13 => {
                let dst = i.a8() as usize;
                self.set_reg(dst, Slot::int(i.lit16()))?;
                Ok(Flow::Continue)
            }
            0x14 => {
                let dst = i.a8() as usize;
                self.set_reg(dst, Slot::int(i.s32()))?;
                Ok(Flow::Continue)
            }
            0x15 => {
                let dst = i.a8() as usize;
                let v = (i.w[1] as i32) << 16;
                self.set_reg(dst, Slot::int(v))?;
                Ok(Flow::Continue)
            }
            0x16 => {
                let dst = i.a8() as usize;
                self.set_wide(dst, V::Long(i.lit16() as i64), Taint::CLEAN)?;
                Ok(Flow::Continue)
            }
            0x17 => {
                let dst = i.a8() as usize;
                self.set_wide(dst, V::Long(i.s32() as i64), Taint::CLEAN)?;
                Ok(Flow::Continue)
            }
            0x18 => {
                let dst = i.a8() as usize;
                self.set_wide(dst, V::Long(i.s64()), Taint::CLEAN)?;
                Ok(Flow::Continue)
            }
            0x19 => {
                let dst = i.a8() as usize;
                let v = (i.w[1] as i64) << 48;
                self.set_wide(dst, V::Long(v), Taint::CLEAN)?;
                Ok(Flow::Continue)
            }
            0x1a => {
                let dst = i.a8() as usize;
                let s = self.string_const(dex, i.u16_1() as u32)?;
                self.set_reg(dst, Slot::reference(s))?;
                Ok(Flow::Continue)
            }
            0x1b => {
                let dst = i.a8() as usize;
                let s = self.string_const(dex, i.u32())?;
                self.set_reg(dst, Slot::reference(s))?;
                Ok(Flow::Continue)
            }
            0x1c => {
                let dst = i.a8() as usize;
                let t = self.type_sym(dex, i.u16_1() as u32);
                let obj = self.class_object(t)?;
                self.set_reg(dst, Slot::reference(obj))?;
                Ok(Flow::Continue)
            }
            0x1d | 0x1e => {
                // monitor-enter / exit: null check only
                let r = self.reg(i.a8() as usize)?;
                if r.is_null_ref() {
                    return Ok(self.throw(self.exc_null, "monitor on null".into()));
                }
                Ok(Flow::Continue)
            }
            0x1f => {
                // check-cast: lenient; the object model is not a full verifier.
                Ok(Flow::Continue)
            }
            0x20 => {
                let dst = i.a4() as usize;
                let src = i.b4() as usize;
                let target = self.type_sym(dex, i.u16_1() as u32);
                let obj = self.reg(src)?.v.as_ref();
                let res = self.instance_of(obj, target);
                self.set_reg(dst, Slot::int(if res { 1 } else { 0 }))?;
                Ok(Flow::Continue)
            }
            0x21 => {
                let dst = i.a4() as usize;
                let src = i.b4() as usize;
                let obj = self.reg(src)?.v.as_ref();
                if obj.is_null() {
                    return Ok(self.throw(self.exc_null, "array-length of null".into()));
                }
                let len = self.heap.length_of(obj).unwrap_or(0);
                self.set_reg(dst, Slot::int(len as i32))?;
                Ok(Flow::Continue)
            }
            0x22 => {
                let dst = i.a8() as usize;
                let cls = self.type_sym(dex, i.u16_1() as u32);
                if !self.registry.is_app_class(cls) {
                    // Framework object: let the host prepare state.
                    let outcome = host.construct(self, cls);
                    match outcome {
                        CallOutcome::Value(s) => {
                            self.set_reg(dst, s)?;
                        }
                        CallOutcome::Throw(c, m) => return Ok(self.throw(c, m)),
                        CallOutcome::Decline => {
                            let obj = self.heap.new_instance(cls)?;
                            self.set_reg(dst, Slot::reference(obj))?;
                        }
                    }
                    return Ok(Flow::Continue);
                }
                self.ensure_initialized(cls, host)?;
                let obj = self.heap.new_instance(cls)?;
                self.set_reg(dst, Slot::reference(obj))?;
                Ok(Flow::Continue)
            }
            0x23 => {
                let dst = i.a4() as usize;
                let size_reg = i.b4() as usize;
                let elem = self.type_sym(dex, i.u16_1() as u32);
                let n = self.reg(size_reg)?.v.as_int();
                if n < 0 {
                    return Ok(self.throw(self.exc_negative_array, format!("new-array size {n}")));
                }
                let desc = self.sym_str(elem).to_string();
                let arr = self.heap.new_array(elem, &desc, n as usize, Taint::CLEAN)?;
                self.set_reg(dst, Slot::reference(arr))?;
                Ok(Flow::Continue)
            }
            0x24 | 0x25 => {
                // filled-new-array/range. Format 35c/3rc: `A` is the argument
                // *count*, and the result is not written to a register — it
                // lands in the pending-result slot read by `move-result-object`.
                let elem = self.type_sym(dex, i.u16_1() as u32);
                let args = self.collect_args(i, code)?;
                let desc = self.sym_str(elem).to_string();
                let arr = self.heap.new_array(elem, &desc, args.len(), Taint::CLEAN)?;
                for (idx, a) in args.iter().enumerate() {
                    self.heap.array_set(arr, idx, *a);
                }
                self.set_result(Slot::reference(arr));
                Ok(Flow::Continue)
            }
            0x26 => {
                // fill-array-data
                let arr_reg = i.a8() as usize;
                let off = i.s32();
                let arr = self.reg(arr_reg)?.v.as_ref();
                self.fill_array_data(arr, code, (i.pc as i32 + off) as usize)?;
                Ok(Flow::Continue)
            }
            0x27 => {
                let r = self.reg(i.a8() as usize)?;
                let obj = r.v.as_ref();
                if obj.is_null() {
                    return Ok(self.throw(self.exc_null, "throw null".into()));
                }
                let class = self.heap.class_of(obj).unwrap_or(self.exc_runtime);
                let detail = self.object_describe(obj);
                Ok(Flow::Throw(JavaException {
                    class,
                    detail,
                    trace: self.report_stack(),
                }))
            }
            0x28 => Ok(Flow::Goto(self.branch_target(i, 8))),
            0x29 => Ok(Flow::Goto(self.branch_target(i, 16))),
            0x2a => Ok(Flow::Goto(self.branch_target(i, 32))),
            0x2b | 0x2c => self.exec_switch(i, code),
            0x2d | 0x2e => {
                let (a, b) = (i.a8() as usize, i.b8() as usize);
                let c = i.c8() as usize;
                let (x, y) = (self.reg(b)?.v.as_float(), self.reg(c)?.v.as_float());
                let res = if x.is_nan() || y.is_nan() {
                    if i.op == 0x2d { -1 } else { 1 }
                } else if x < y {
                    -1
                } else if x > y {
                    1
                } else {
                    0
                };
                let t = self.reg(b)?.t.union(self.reg(c)?.t);
                self.set_reg(a, Slot::int(res).with_taint(t))?;
                Ok(Flow::Continue)
            }
            0x2f | 0x30 => {
                let (a, b) = (i.a8() as usize, i.b8() as usize);
                let c = i.c8() as usize;
                let (x, y) = (self.read_double(b)?, self.read_double(c)?);
                let res = if x.is_nan() || y.is_nan() {
                    if i.op == 0x2f { -1 } else { 1 }
                } else if x < y {
                    -1
                } else if x > y {
                    1
                } else {
                    0
                };
                let t = self.reg(b)?.t.union(self.reg(c)?.t);
                self.set_reg(a, Slot::int(res).with_taint(t))?;
                Ok(Flow::Continue)
            }
            0x31 => {
                let (a, b) = (i.a8() as usize, i.b8() as usize);
                let c = i.c8() as usize;
                let x = self.read_long(b)?;
                let y = self.read_long(c)?;
                let res = match x.cmp(&y) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Greater => 1,
                    std::cmp::Ordering::Equal => 0,
                };
                let t = self.reg(b)?.t.union(self.reg(c)?.t);
                self.set_reg(a, Slot::int(res).with_taint(t))?;
                Ok(Flow::Continue)
            }
            0x32..=0x37 => {
                let (a, b) = (i.a4() as usize, i.b4() as usize);
                let off = i.branch_offset();
                let (x, y) = self.reg_pair(a, b)?;
                let (ord, comparable) = compare_slots(x, y);
                let take = match i.op {
                    0x32 => comparable && ord == std::cmp::Ordering::Equal,
                    0x33 => !comparable || ord != std::cmp::Ordering::Equal,
                    0x34 => comparable && ord == std::cmp::Ordering::Less,
                    0x35 => comparable && ord != std::cmp::Ordering::Less,
                    0x36 => comparable && ord == std::cmp::Ordering::Greater,
                    0x37 => comparable && ord != std::cmp::Ordering::Greater,
                    _ => false,
                };
                if take {
                    Ok(Flow::Goto(self.branch_target(i, 16)))
                } else {
                    let _ = off;
                    Ok(Flow::Continue)
                }
            }
            0x38..=0x3d => {
                let a = i.a8() as usize;
                let x = self.reg(a)?;
                let zero = match x.v {
                    V::Ref(r) => r.is_null(),
                    _ => x.v.as_int() == 0,
                };
                let ord = match x.v {
                    V::Ref(_) => {
                        if zero {
                            std::cmp::Ordering::Equal
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    }
                    _ => x.v.as_int().cmp(&0),
                };
                let take = match i.op {
                    0x38 => ord == std::cmp::Ordering::Equal,
                    0x39 => ord != std::cmp::Ordering::Equal,
                    0x3a => ord == std::cmp::Ordering::Less,
                    0x3b => ord != std::cmp::Ordering::Less,
                    0x3c => ord == std::cmp::Ordering::Greater,
                    0x3d => ord != std::cmp::Ordering::Greater,
                    _ => false,
                };
                if take {
                    Ok(Flow::Goto(self.branch_target(i, 16)))
                } else {
                    Ok(Flow::Continue)
                }
            }
            0x44..=0x4a => self.array_get(i),
            0x4b..=0x51 => self.array_put(i),
            0x52..=0x58 => self.instance_field_get(i, dex),
            0x59..=0x5f => self.instance_field_put(i, dex),
            0x60..=0x66 => self.static_field_get(i, dex, host),
            0x67..=0x6d => self.static_field_put(i, dex, host),
            0x6e..=0x72 | 0x74..=0x78 | 0xfa => self.exec_invoke(i, code, dex, host),
            0x7b..=0x8f => self.exec_unop(i),
            0x90..=0xaf => self.exec_binop(i, false),
            0xb0..=0xcf => self.exec_binop(i, true),
            0xd0..=0xd7 => self.exec_lit16(i),
            0xd8..=0xe2 => self.exec_lit8(i),
            // (lit16/lit8 formats are `AA|op CC|BB`: registers are 8-bit.)
            0xfc | 0xfd => self.exec_invoke(i, code, dex, host),
            0xfe | 0xff => {
                let dst = i.a8() as usize;
                self.set_reg(dst, Slot::reference(ObjRef::NULL))?;
                Ok(Flow::Continue)
            }
            other => {
                self.env.gap(&format!("unimplemented opcode {other:#04x}"));
                Ok(Flow::Continue)
            }
        }
    }

    fn branch_target(&self, i: &Insn, _width: u8) -> usize {
        let base = i.pc as isize;
        let target = base + i.branch_offset() as isize;
        target.max(0) as usize
    }

    fn exec_switch(&mut self, i: &Insn, code: &Arc<CodeItem>) -> Result<Flow> {
        let a = i.a8() as usize;
        let key = self.reg(a)?.v.as_int();
        let payload = (i.pc as i32 + i.s32()) as usize;
        let Some(&ident) = code.insns.get(payload) else {
            return Err(Error::BadFormat("switch payload outside code".into()));
        };
        match ident {
            0x0100 => {
                // packed-switch
                let size = *code.insns.get(payload + 1).unwrap_or(&0) as usize;
                let first_key = read_s32(&code.insns, payload + 2);
                let mut chosen = None;
                for k in 0..size.min(1 << 20) {
                    if first_key.wrapping_add(k as i32) == key {
                        let target_off = read_s32(&code.insns, payload + 4 + k * 2);
                        chosen = Some((i.pc as i32 + target_off) as usize);
                        break;
                    }
                }
                Ok(match chosen {
                    Some(t) => Flow::Goto(t),
                    None => Flow::Continue,
                })
            }
            0x0200 => {
                let size = *code.insns.get(payload + 1).unwrap_or(&0) as usize;
                let mut chosen = None;
                for k in 0..size.min(1 << 20) {
                    let kk = read_s32(&code.insns, payload + 2 + k * 2);
                    if kk == key {
                        let target_off = read_s32(&code.insns, payload + 2 + (size * 2) + k * 2);
                        chosen = Some((i.pc as i32 + target_off) as usize);
                        break;
                    }
                }
                Ok(match chosen {
                    Some(t) => Flow::Goto(t),
                    None => Flow::Continue,
                })
            }
            other => {
                self.env.gap(&format!("bad switch ident {other:#x}"));
                Ok(Flow::Continue)
            }
        }
    }

    fn fill_array_data(&mut self, arr: ObjRef, code: &Arc<CodeItem>, payload: usize) -> Result<()> {
        let Some(&ident) = code.insns.get(payload) else {
            return Err(Error::BadFormat("array data payload outside code".into()));
        };
        if ident != 0x0300 {
            return Ok(());
        }
        let elem_width = *code.insns.get(payload + 1).unwrap_or(&1) as usize;
        let size = read_s32(&code.insns, payload + 2) as usize;
        let data_start = payload + 4;
        let Some(elem_desc) = self.heap.get(arr).and_then(|o| match &o.kind {
            ObjKind::Bytes(_) => Some("B".to_string()),
            ObjKind::Array(a) => Some(self.registry.interner.get(a.elem).to_string()),
            _ => None,
        }) else {
            return Ok(());
        };
        for k in 0..size.min(1 << 22) {
            let byte_off = k * elem_width;
            let units = byte_off / 2;
            let hi = code.insns.get(data_start + units).copied().unwrap_or(0) as u32;
            let lo = code.insns.get(data_start + units + 1).copied().unwrap_or(0) as u32;
            let word = (lo << 16) | hi;
            let slot = match elem_width {
                1 => Slot::int(((word >> ((byte_off % 2) * 8)) & 0xff) as i32),
                2 => Slot::int(read_s16_word(&code.insns, data_start + k) as i32),
                4 => Slot::int(read_s32(&code.insns, data_start + k * 2)),
                8 => Slot::long(combine_u32(
                    read_s32(&code.insns, data_start + k * 4),
                    read_s32(&code.insns, data_start + k * 4 + 2),
                )),
                _ => Slot::int(0),
            };
            let slot = match elem_desc.as_str() {
                "J" => Slot::long(slot.v.as_long()),
                "D" => Slot::double(f64::from_bits(slot.v.as_long() as u64)),
                "F" => Slot::float(f32::from_bits(slot.v.as_int() as u32)),
                _ => slot,
            };
            self.heap.array_set(arr, k, slot);
        }
        Ok(())
    }

    // ---- arrays ----------------------------------------------------------

    fn array_get(&mut self, i: &Insn) -> Result<Flow> {
        let (a, b) = (i.a8() as usize, i.b8() as usize);
        let c = i.c8() as usize;
        let arr = self.reg(b)?.v.as_ref();
        let idx = self.reg(c)?.v.as_int();
        if arr.is_null() {
            return Ok(self.throw(self.exc_null, "array read on null".into()));
        }
        if idx < 0 {
            return Ok(self.throw(self.exc_array_oob, format!("index {idx}")));
        }
        let Some(slot) = self.heap.array_get(arr, idx as usize) else {
            return Ok(self.throw(self.exc_array_oob, format!("index {idx} past end")));
        };
        let wide = matches!(i.op, 0x45 | 0x4c);
        if wide {
            let v = match slot.v {
                Value::Long(_) | Value::Double(_) => slot.v,
                _ => Value::Long(slot.v.as_long()),
            };
            self.set_wide(a, v, slot.t)?;
        } else {
            let v = match i.op {
                0x46 => Value::Ref(slot.v.as_ref()),
                0x47 => Value::Int(if slot.v.as_int() != 0 { 1 } else { 0 }),
                0x48 => Value::Int(slot.v.as_int() as i8 as i32),
                0x49 => Value::Int(slot.v.as_int() as u16 as i32),
                0x4a => Value::Int(slot.v.as_int() as i16 as i32),
                _ => Value::Int(slot.v.as_int()),
            };
            self.set_reg(a, Slot { v, t: slot.t })?;
        }
        Ok(Flow::Continue)
    }

    fn array_put(&mut self, i: &Insn) -> Result<Flow> {
        let (a, b) = (i.a8() as usize, i.b8() as usize);
        let c = i.c8() as usize;
        let arr = self.reg(b)?.v.as_ref();
        let idx = self.reg(c)?.v.as_int();
        if arr.is_null() {
            return Ok(self.throw(self.exc_null, "array write on null".into()));
        }
        if idx < 0 {
            return Ok(self.throw(self.exc_array_oob, format!("index {idx}")));
        }
        let slot = match i.op {
            0x4c => {
                // wide
                let lo = self.reg(a)?;
                let v = if lo.v.is_wide() {
                    lo.v
                } else {
                    Value::Long(self.read_long(a)?)
                };
                Slot { v, t: lo.t }
            }
            0x4d => self.reg(a)?,
            _ => {
                let s = self.reg(a)?;
                let v = match i.op {
                    0x4e => Value::Int(if s.v.as_int() != 0 { 1 } else { 0 }),
                    0x4f => Value::Int(s.v.as_int() as i8 as i32),
                    0x50 => Value::Int(s.v.as_int() as u16 as i32),
                    0x51 => Value::Int(s.v.as_int() as i16 as i32),
                    _ => Value::Int(s.v.as_int()),
                };
                Slot { v, t: s.t }
            }
        };
        if !self.heap.array_set(arr, idx as usize, slot) {
            return Ok(self.throw(self.exc_array_oob, format!("index {idx} past end")));
        }
        // Taint flows into the array object itself so later reads see it.
        self.heap.add_taint(arr, slot.t);
        Ok(Flow::Continue)
    }

    // ---- fields ----------------------------------------------------------

    fn instance_field_get(&mut self, i: &Insn, dex: u32) -> Result<Flow> {
        let a = i.a4() as usize;
        let b = i.b4() as usize;
        let key = self.field_key(dex, i.u16_1() as u32);
        let obj = self.reg(b)?.v.as_ref();
        if obj.is_null() {
            return Ok(self.throw(self.exc_null, format!("iget {} on null", self.field_desc(&key))));
        }
        let slot = self.heap.get_field(obj, &key).unwrap_or_default();
        let wide = i.op == 0x53;
        if wide {
            let v = if slot.v.is_wide() {
                slot.v
            } else {
                Value::Long(slot.v.as_long())
            };
            self.set_wide(a, v, slot.t)?;
        } else {
            self.set_reg(a, slot)?;
        }
        Ok(Flow::Continue)
    }

    fn instance_field_put(&mut self, i: &Insn, dex: u32) -> Result<Flow> {
        let a = i.a4() as usize;
        let b = i.b4() as usize;
        let key = self.field_key(dex, i.u16_1() as u32);
        let obj = self.reg(b)?.v.as_ref();
        if obj.is_null() {
            return Ok(self.throw(self.exc_null, format!("iput {} on null", self.field_desc(&key))));
        }
        let slot = if i.op == 0x5a {
            let lo = self.reg(a)?;
            let v = if lo.v.is_wide() {
                lo.v
            } else {
                Value::Long(self.read_long(a)?)
            };
            Slot { v, t: lo.t }
        } else {
            self.reg(a)?
        };
        self.heap.put_field(obj, key, slot);
        Ok(Flow::Continue)
    }

    fn static_field_get(&mut self, i: &Insn, dex: u32, host: &mut dyn Host) -> Result<Flow> {
        let a = i.a8() as usize;
        let key = self.field_key(dex, i.u16_1() as u32);
        let wide = i.op == 0x61;
        let slot = if let Some(s) = self.statics.get(&key).copied() {
            s
        } else if self.registry.is_app_class(key.class) {
            self.ensure_initialized(key.class, host)?;
            self.statics.get(&key).copied().unwrap_or_default()
        } else {
            match host.static_field(self, &key) {
                CallOutcome::Value(s) => s,
                CallOutcome::Throw(c, m) => return Ok(self.throw(c, m)),
                CallOutcome::Decline => {
                    self.env.gap(&format!("sget {}", self.field_desc(&key)));
                    Slot::default()
                }
            }
        };
        if wide {
            let v = if slot.v.is_wide() {
                slot.v
            } else {
                Value::Long(slot.v.as_long())
            };
            self.set_wide(a, v, slot.t)?;
        } else {
            self.set_reg(a, slot)?;
        }
        Ok(Flow::Continue)
    }

    fn static_field_put(&mut self, i: &Insn, dex: u32, host: &mut dyn Host) -> Result<Flow> {
        let a = i.a8() as usize;
        let key = self.field_key(dex, i.u16_1() as u32);
        let slot = if i.op == 0x68 {
            let lo = self.reg(a)?;
            let v = if lo.v.is_wide() {
                lo.v
            } else {
                Value::Long(self.read_long(a)?)
            };
            Slot { v, t: lo.t }
        } else {
            self.reg(a)?
        };
        if self.registry.is_app_class(key.class) {
            self.ensure_initialized(key.class, host)?;
        }
        if self.statics.len() < 500_000 {
            self.statics.insert(key, slot);
        }
        Ok(Flow::Continue)
    }

    // ---- arithmetic ------------------------------------------------------

    fn exec_unop(&mut self, i: &Insn) -> Result<Flow> {
        use Value as V;
        let (a, b) = (i.a4() as usize, i.b4() as usize);
        let s = self.reg(b)?;
        let t = s.t;
        let (v, wide) = match i.op {
            0x7b => (V::Int(s.v.as_int().wrapping_neg()), false),
            0x7c => (V::Int(!s.v.as_int()), false),
            0x7d => (V::Long(self.read_long(b)?.wrapping_neg()), true),
            0x7e => (V::Long(!self.read_long(b)?), true),
            0x7f => (V::Float(-s.v.as_float()), false),
            0x80 => (V::Double(-self.read_double(b)?), true),
            0x81 => (V::Long(s.v.as_int() as i64), true),
            0x82 => (V::Float(s.v.as_int() as f32), false),
            0x83 => (V::Double(s.v.as_int() as f64), true),
            0x84 => (V::Int(self.read_long(b)? as i32), false),
            0x85 => (V::Float(self.read_long(b)? as f32), false),
            0x86 => (V::Double(self.read_long(b)? as f64), true),
            0x87 => (V::Int(f2i(s.v.as_float())), false),
            0x88 => (V::Long(f2l(s.v.as_float())), true),
            0x89 => (V::Double(s.v.as_float() as f64), true),
            0x8a => (V::Int(d2i(self.read_double(b)?)), false),
            0x8b => (V::Long(d2l(self.read_double(b)?)), true),
            0x8c => (V::Float(self.read_double(b)? as f32), false),
            0x8d => (V::Int(s.v.as_int() as i8 as i32), false),
            0x8e => (V::Int(s.v.as_int() as u16 as i32), false),
            0x8f => (V::Int(s.v.as_int() as i16 as i32), false),
            _ => (V::Int(0), false),
        };
        if wide {
            self.set_wide(a, v, t)?;
        } else {
            self.set_reg(a, Slot { v, t })?;
        }
        Ok(Flow::Continue)
    }

    fn exec_binop(&mut self, i: &Insn, two_addr: bool) -> Result<Flow> {
        use Value as V;
        // The 0x90..0xaf and 0xb0..0xcf blocks share an ordering: 11 int ops,
        // 11 long ops, 5 float ops, 5 double ops.
        let opidx = if two_addr { (i.op - 0xb0) as usize } else { (i.op - 0x90) as usize };
        let (a, b, c) = if two_addr {
            (i.a4() as usize, i.a4() as usize, i.b4() as usize)
        } else {
            (i.a8() as usize, i.b8() as usize, i.c8() as usize)
        };
        let t = self.reg(b)?.t.union(self.reg(c)?.t);
        let (v, wide) = match opidx {
            0..=10 => {
                let x = self.reg(b)?.v.as_int();
                let y = self.reg(c)?.v.as_int();
                if matches!(opidx, 3 | 4) && y == 0 {
                    return Ok(self.throw(self.exc_arith, "integer divide by zero".into()));
                }
                (V::Int(int_binop(opidx, x, y)), false)
            }
            11..=21 => {
                let x = self.read_long(b)?;
                let y = self.read_long(c)?;
                let k = opidx - 11;
                if matches!(k, 3 | 4) && y == 0 {
                    return Ok(self.throw(self.exc_arith, "long divide by zero".into()));
                }
                (V::Long(long_binop(k, x, y)), true)
            }
            22..=26 => {
                let x = self.reg(b)?.v.as_float();
                let y = self.reg(c)?.v.as_float();
                let r = match opidx - 22 {
                    0 => x + y,
                    1 => x - y,
                    2 => x * y,
                    3 => x / y,
                    _ => x % y,
                };
                (V::Float(r), false)
            }
            27..=31 => {
                let x = self.read_double(b)?;
                let y = self.read_double(c)?;
                let r = match opidx - 27 {
                    0 => x + y,
                    1 => x - y,
                    2 => x * y,
                    3 => x / y,
                    _ => x % y,
                };
                (V::Double(r), true)
            }
            _ => (V::Int(0), false),
        };
        if wide {
            self.set_wide(a, v, t)?;
        } else {
            self.set_reg(a, Slot { v, t })?;
        }
        Ok(Flow::Continue)
    }

    fn exec_lit16(&mut self, i: &Insn) -> Result<Flow> {
        use Value as V;
        // 22s: `B|A|op CCCC` — 4-bit registers, 16-bit signed literal.
        let (a, b) = (i.a4() as usize, i.b4() as usize);
        let lit = i.lit16();
        let x = self.reg(b)?.v.as_int();
        let t = self.reg(b)?.t;
        let r = match i.op {
            0xd0 => x.wrapping_add(lit),
            0xd1 => lit.wrapping_sub(x),
            0xd2 => x.wrapping_mul(lit),
            0xd3 | 0xd4 => {
                if lit == 0 {
                    return Ok(self.throw(self.exc_arith, "divide by zero".into()));
                }
                if i.op == 0xd3 { x.wrapping_div(lit) } else { x.wrapping_rem(lit) }
            }
            0xd5 => x & lit,
            0xd6 => x | lit,
            _ => x ^ lit,
        };
        self.set_reg(a, Slot { v: V::Int(r), t })?;
        Ok(Flow::Continue)
    }

    fn exec_lit8(&mut self, i: &Insn) -> Result<Flow> {
        use Value as V;
        // 22b: `AA|op CC|BB` — 8-bit dest, 8-bit source, 8-bit signed literal.
        let (a, b) = (i.a8() as usize, i.b8() as usize);
        let lit = i.lit8();
        let x = self.reg(b)?.v.as_int();
        let t = self.reg(b)?.t;
        let r = match i.op {
            0xd8 => x.wrapping_add(lit),
            0xd9 => lit.wrapping_sub(x),
            0xda => x.wrapping_mul(lit),
            0xdb | 0xdc => {
                if lit == 0 {
                    return Ok(self.throw(self.exc_arith, "divide by zero".into()));
                }
                if i.op == 0xdb { x.wrapping_div(lit) } else { x.wrapping_rem(lit) }
            }
            0xdd => x & lit,
            0xde => x | lit,
            0xdf => x ^ lit,
            0xe0 => x.wrapping_shl(lit as u32 & 31),
            0xe1 => x.wrapping_shr(lit as u32 & 31),
            _ => ((x as u32).wrapping_shr(lit as u32 & 31)) as i32,
        };
        self.set_reg(a, Slot { v: V::Int(r), t })?;
        Ok(Flow::Continue)
    }

    // ---- invocation ------------------------------------------------------

    fn exec_invoke(
        &mut self,
        i: &Insn,
        code: &Arc<CodeItem>,
        dex: u32,
        host: &mut dyn Host,
    ) -> Result<Flow> {
        let method_idx = i.u16_1() as u32;
        let key = self.method_key(dex, method_idx);
        let args = self.collect_args(i, code)?;
        let kind = i.op;
        let is_static = matches!(kind, 0x71 | 0x77);
        let is_direct = matches!(kind, 0x70 | 0x76);
        let is_super = matches!(kind, 0x6f | 0x75);
        let name = self.sym_str(key.name).to_string();

        // Constructors of framework classes, and all framework methods, go to
        // the host. App-defined code is executed.
        if is_static {
            if let Some(entry) = self.registry.resolve_direct(key.class, key.name, key.proto) {
                if entry.code_off != 0 {
                    self.ensure_initialized(key.class, host)?;
                    return self.push_call(entry, args);
                }
                // Declared but no code: a native method.
                return self.native_or_host(host, &key, &args);
            }
            self.ensure_initialized(key.class, host)?;
            return self.host_call_flow(host, &key, &args);
        }

        let Some(this) = args.first().map(|s| s.v.as_ref()) else {
            return Err(Error::BadFormat("instance invoke without this".into()));
        };
        if this.is_null() {
            return Ok(self.throw(self.exc_null, format!("invoke {} on null", self.method_desc(&key))));
        }
        let actual_class = self.heap.class_of(this).unwrap_or(key.class);
        // Strings, arrays and framework objects are host-modelled.
        let actual_is_app = self.registry.is_app_class(actual_class)
            && !self.heap.is_string(this)
            && matches!(self.heap.get(this).map(|o| &o.kind), Some(ObjKind::Instance(_)));

        if is_direct {
            // Constructors and private methods resolve on the declared class.
            if let Some(entry) = self.registry.resolve_direct(key.class, key.name, key.proto) {
                if entry.code_off != 0 {
                    if name == "<init>" {
                        self.ensure_initialized(actual_class_or(key.class, actual_class, &self.registry), host)?;
                    }
                    return self.push_call(entry, args);
                }
                return self.native_or_host(host, &key, &args);
            }
            if name == "<init>" && !self.registry.is_app_class(key.class) {
                return self.host_call_flow(host, &key, &args);
            }
            return self.host_call_flow(host, &key, &args);
        }

        let search_class = if is_super {
            self.registry
                .classes
                .get(&self.current_class())
                .and_then(|c| c.superclass)
                .unwrap_or(actual_class)
        } else {
            actual_class
        };

        if actual_is_app {
            if let Some(entry) = self.registry.resolve_virtual(search_class, key.name, key.proto) {
                if entry.code_off != 0 {
                    return self.push_call(entry, args);
                }
            }
            // Reached an unmodelled framework superclass method.
            return self.host_call_flow(host, &key, &args);
        }
        self.host_call_flow(host, &key, &args)
    }

    fn push_call(&mut self, entry: MethodEntry, args: Vec<Slot>) -> Result<Flow> {
        self.push_frame(entry, args)?;
        Ok(Flow::Continue)
    }

    fn native_or_host(&mut self, host: &mut dyn Host, key: &MethodKey, args: &[Slot]) -> Result<Flow> {
        let entry = self.registry.lookup_method(key).copied();
        if let Some(e) = entry {
            if e.code_off == 0 && e.access & crate::dex::ACC_NATIVE != 0 {
                match host.native_call(self, key, args) {
                    CallOutcome::Value(s) => {
                        self.set_result(s);
                        return Ok(Flow::Continue);
                    }
                    CallOutcome::Throw(c, m) => return Ok(self.throw(c, m)),
                    CallOutcome::Decline => {
                        self.env.gap(&self.registry.method_desc(key));
                        let ret = self.return_desc_of(&key.proto);
                        self.set_result(default_for(&ret));
                        return Ok(Flow::Continue);
                    }
                }
            }
        }
        self.host_call_flow(host, key, args)
    }

    fn host_call(&mut self, host: &mut dyn Host, key: &MethodKey, args: &[Slot]) -> Result<Slot> {
        match host.call(self, key, args) {
            CallOutcome::Value(s) => Ok(s),
            CallOutcome::Throw(c, m) => {
                self.env.gap(&format!("host exception {} {}", self.sym_str(c), m));
                Ok(Slot::default())
            }
            CallOutcome::Decline => {
                self.env.gap(&self.registry.method_desc(key));
                let ret = self.return_desc_of(&key.proto);
                Ok(default_for(&ret))
            }
        }
    }

    fn host_call_flow(&mut self, host: &mut dyn Host, key: &MethodKey, args: &[Slot]) -> Result<Flow> {
        match host.call(self, key, args) {
            CallOutcome::Value(s) => {
                self.set_result(s);
                Ok(Flow::Continue)
            }
            CallOutcome::Throw(c, m) => Ok(self.throw(c, m)),
            CallOutcome::Decline => {
                self.env.gap(&self.registry.method_desc(key));
                let ret = self.return_desc_of(&key.proto);
                self.set_result(default_for(&ret));
                Ok(Flow::Continue)
            }
        }
    }

    fn set_result(&mut self, s: Slot) {
        if let Some(f) = self.frames.last_mut() {
            f.result = s;
        }
    }

    fn return_desc_of(&self, proto: &Sym) -> String {
        let d = self.sym_str(*proto);
        match d.rfind(')') {
            Some(p) => d[p + 1..].to_string(),
            None => "V".into(),
        }
    }

    fn current_class(&self) -> Sym {
        self.frames
            .last()
            .map(|f| f.entry.key.class)
            .unwrap_or(Sym::NONE)
    }

    fn collect_args(&self, i: &Insn, _code: &Arc<CodeItem>) -> Result<Vec<Slot>> {
        let mut args = Vec::with_capacity(8);
        match i.fmt {
            Fmt::F35c | Fmt::F45cc => {
                let (regs, count) = i.arg_regs();
                for &r in regs.iter().take(count) {
                    args.push(self.reg(r as usize)?);
                }
            }
            Fmt::F3rc | Fmt::F4rcc => {
                let first = i.w[2] as usize;
                let count = (i.w[0] >> 8) as usize;
                for k in 0..count {
                    args.push(self.reg(first + k)?);
                }
            }
            _ => {}
        }
        // Wide arguments occupy two registers but one slot; drop the high half.
        let mut compact = Vec::with_capacity(args.len());
        for s in args {
            if matches!(s.v, Value::WideHigh) && !compact.is_empty() {
                continue;
            }
            compact.push(s);
        }
        Ok(compact)
    }

    // ---- class initialisation -------------------------------------------

    fn ensure_initialized(&mut self, class: Sym, host: &mut dyn Host) -> Result<()> {
        if self.halted {
            return Ok(());
        }
        let Some(ci) = self.registry.classes.get(&class) else {
            return Ok(());
        };
        match ci.init_state {
            super::registry::InitState::Done | super::registry::InitState::InProgress => {
                return Ok(())
            }
            super::registry::InitState::Failed => return Ok(()),
            super::registry::InitState::Uninitialized => {}
        }
        // Initialise the superclass first, as the JVM does.
        let superclass = ci.superclass;
        let statics = ci.static_fields.clone();
        let has_clinit = {
            let name = self.sym("<clinit>");
            let proto = self.sym("()V");
            self.registry
                .resolve_direct(class, name, proto)
                .map(|e| e.code_off != 0)
                .unwrap_or(false)
        };
        if let Some(s) = superclass {
            if self.registry.is_app_class(s) {
                self.ensure_initialized(s, host)?;
            }
        }
        // Publish the state before running code, so recursive init stops.
        if let Some(ci) = self.registry.classes.get_mut(&class) {
            ci.init_state = super::registry::InitState::InProgress;
        }
        self.load_static_values(class, &statics)?;
        if has_clinit {
            let name = self.sym("<clinit>");
            let proto = self.sym("()V");
            if let Some(entry) = self.registry.resolve_direct(class, name, proto) {
                let base_steps = self.steps;
                match self.execute(host, entry, Vec::new()) {
                    Ok(_) => {}
                    Err(e) => {
                        if let Some(ci) = self.registry.classes.get_mut(&class) {
                            ci.init_state = super::registry::InitState::Failed;
                        }
                        if self.stop_reason.is_none() {
                            let name = self.sym_str(class).to_string();
                            self.stop_reason = Some(format!("<clinit> of {name} failed: {e}"));
                        }
                        let _ = base_steps;
                        return Ok(());
                    }
                }
            }
        }
        if let Some(ci) = self.registry.classes.get_mut(&class) {
            ci.init_state = super::registry::InitState::Done;
        }
        Ok(())
    }

    fn load_static_values(&mut self, class: Sym, fields: &[super::registry::FieldEntry]) -> Result<()> {
        if !self.statics_loaded.insert(class) {
            return Ok(());
        }
        for f in fields {
            let Some(init) = &f.static_init else { continue };
            let slot = match init {
                StaticInit::Value(s) => *s,
                StaticInit::Str { image, idx } => {
                    let s = self
                        .registry
                        .image(*image)
                        .map(|d| d.string(*idx).to_string())
                        .unwrap_or_default();
                    let r = self.new_string(s)?;
                    Slot::reference(r)
                }
                StaticInit::Type { image, idx } => {
                    let t = self.type_sym(*image, *idx);
                    let obj = self.class_object(t)?;
                    Slot::reference(obj)
                }
                StaticInit::Other => Slot::default(),
            };
            self.statics.entry(f.key).or_insert(slot);
        }
        Ok(())
    }

    // ---- helpers ---------------------------------------------------------

    pub fn throw(&mut self, class: Sym, detail: String) -> Flow {
        Flow::Throw(JavaException {
            class,
            detail,
            trace: self.report_stack(),
        })
    }

    fn string_const(&mut self, dex: u32, idx: u32) -> Result<ObjRef> {
        let s = self
            .registry
            .image(dex)
            .map(|d| d.string(idx).to_string())
            .unwrap_or_default();
        self.new_string(s)
    }

    fn class_object(&mut self, class: Sym) -> Result<ObjRef> {
        let cls = self.sym("Ljava/lang/Class;");
        let desc = self.sym_str(class).to_string();
        let obj = self.heap.new_instance(cls)?;
        let desc_obj = self.new_string(desc)?;
        if let Some(inst) = self.heap.instance_mut(obj) {
            inst.state.insert("descriptor".into(), Slot::reference(desc_obj));
        }
        Ok(obj)
    }

    fn instance_of(&self, obj: ObjRef, target: Sym) -> bool {
        if obj.is_null() {
            return false;
        }
        let Some(o) = self.heap.get(obj) else { return false };
        let target_desc = self.registry.interner.get(target);
        if target_desc == "Ljava/lang/Object;" {
            return true;
        }
        match &o.kind {
            ObjKind::Str(_) | ObjKind::MutableStr(_) => {
                matches!(
                    target_desc,
                    "Ljava/lang/String;" | "Ljava/lang/CharSequence;" | "Ljava/lang/Comparable;"
                        | "Ljava/lang/Object;" | "Ljava/io/Serializable;"
                )
            }
            ObjKind::Bytes(_) => target_desc.starts_with("[B") || target_desc == "Ljava/lang/Object;",
            ObjKind::Array(a) => {
                target_desc.starts_with('[')
                    || target_desc == "Ljava/lang/Object;"
                    || target_desc == "Ljava/lang/Cloneable;"
                    || target_desc == "Ljava/io/Serializable;"
                    || target_desc == self.registry.interner.get(a.elem)
            }
            ObjKind::Instance(inst) => {
                let mut cur = Some(inst.class);
                let mut depth = 0;
                while let Some(c) = cur {
                    if self.registry.interner.get(c) == target_desc {
                        return true;
                    }
                    depth += 1;
                    if depth > 128 {
                        return false;
                    }
                    cur = self.registry.classes.get(&c).and_then(|ci| ci.superclass);
                }
                // Unknown hierarchy (framework parent): be permissive so a
                // type check cannot silently divert the sample.
                self.registry.first_framework_superclass(inst.class).is_some()
                    || target_desc == "Ljava/lang/Object;"
            }
        }
    }

    fn class_is_assignable_from_str(&self, class: Sym, target_desc: &str) -> bool {
        if target_desc == "Ljava/lang/Throwable;" || target_desc == "Ljava/lang/Exception;" {
            return true;
        }
        let src = self.sym_str(class);
        if src == target_desc {
            return true;
        }
        if target_desc == "Ljava/lang/RuntimeException;" {
            return !src.contains("Error");
        }
        let mut cur = Some(class);
        let mut depth = 0;
        while let Some(c) = cur {
            if self.sym_str(c) == target_desc {
                return true;
            }
            depth += 1;
            if depth > 64 {
                break;
            }
            cur = self.registry.classes.get(&c).and_then(|ci| ci.superclass);
        }
        false
    }

    pub fn object_describe(&self, r: ObjRef) -> String {
        if r.is_null() {
            return "null".into();
        }
        let Some(o) = self.heap.get(r) else { return "?".into() };
        match &o.kind {
            ObjKind::Str(s) | ObjKind::MutableStr(s) => format!("\"{}\"", truncate(s, 200)),
            ObjKind::Bytes(b) => format!("byte[{}]", b.len()),
            ObjKind::Array(a) => format!("{}[{}]", self.sym_str(a.elem), a.data.len()),
            ObjKind::Instance(inst) => self.sym_str(inst.class).to_string(),
        }
    }

    pub fn method_key(&mut self, image: u32, method_idx: u32) -> MethodKey {
        if let Some(k) = self.key_cache.get(&(image, method_idx)) {
            return *k;
        }
        let dex = self.registry.image(image).cloned();
        let key = match dex {
            Some(dex) => match dex.method(method_idx) {
                Some(m) => {
                    let class = self.class_sym_of(image, m.class_idx);
                    let name_str = dex.string(m.name_idx).to_string();
                    let name = self.registry.interner.intern(&name_str);
                    let proto_desc = dex.proto_descriptor(m.proto_idx);
                    let proto = self.registry.interner.intern(&proto_desc);
                    MethodKey { class, name, proto }
                }
                None => MethodKey {
                    class: Sym::NONE,
                    name: Sym::NONE,
                    proto: Sym::NONE,
                },
            },
            None => MethodKey {
                class: Sym::NONE,
                name: Sym::NONE,
                proto: Sym::NONE,
            },
        };
        self.key_cache.insert((image, method_idx), key);
        key
    }

    pub fn field_key(&mut self, image: u32, field_idx: u32) -> FieldKey {
        if let Some(k) = self.field_key_cache.get(&(image, field_idx)) {
            return *k;
        }
        let dex = self.registry.image(image).cloned();
        let key = match dex {
            Some(dex) => match dex.field(field_idx) {
                Some(f) => {
                    let class = self.class_sym_of(image, f.class_idx);
                    let name_str = dex.string(f.name_idx).to_string();
                    let name = self.registry.interner.intern(&name_str);
                    let ty_desc = dex.type_name(f.type_idx).to_string();
                    let ty = self.registry.interner.intern(&ty_desc);
                    FieldKey { class, name, ty }
                }
                None => FieldKey {
                    class: Sym::NONE,
                    name: Sym::NONE,
                    ty: Sym::NONE,
                },
            },
            None => FieldKey {
                class: Sym::NONE,
                name: Sym::NONE,
                ty: Sym::NONE,
            },
        };
        self.field_key_cache.insert((image, field_idx), key);
        key
    }

    fn class_sym_of(&mut self, image: u32, type_idx: u32) -> Sym {
        self.type_sym(image, type_idx)
    }

    pub fn type_sym(&mut self, image: u32, type_idx: u32) -> Sym {
        if let Some(s) = self.type_cache.get(&(image, type_idx)) {
            return *s;
        }
        let desc = self
            .registry
            .image(image)
            .map(|dex| dex.type_name(type_idx).to_string());
        let sym = match desc {
            Some(desc) => self.registry.interner.intern(&desc),
            None => Sym::NONE,
        };
        self.type_cache.insert((image, type_idx), sym);
        sym
    }

    fn type_name_of(&mut self, image: u32, type_idx: u32) -> &str {
        let sym = self.type_sym(image, type_idx);
        self.registry.interner.get(sym)
    }

    fn field_desc(&self, key: &FieldKey) -> String {
        format!(
            "{}->{}:{}",
            self.registry.interner.get(key.class),
            self.registry.interner.get(key.name),
            self.registry.interner.get(key.ty)
        )
    }

    fn method_desc(&self, key: &MethodKey) -> String {
        self.registry.method_desc(key)
    }

    /// A slot's taint, for a register.
    pub fn reg_taint(&self, idx: usize) -> Taint {
        self.frames
            .last()
            .and_then(|f| f.regs.get(idx))
            .map(|s| s.t)
            .unwrap_or(Taint::CLEAN)
    }

    /// Number of frames currently alive (for the scenario runner's depth cap).
    pub fn frame_depth(&self) -> usize {
        self.frames.len()
    }

    /// The method currently executing, if any.
    pub fn current_method(&self) -> Option<MethodEntry> {
        self.frames.last().map(|f| f.entry)
    }

    /// Snapshot the Java trace for the report, at a host boundary.
    pub fn freeze_trace(&mut self) {
        if self.trace_capture {
            self.trace = self.report_stack();
            self.trace_capture = false;
        }
    }

    pub fn thaw_trace(&mut self) {
        self.trace_capture = true;
        self.trace.clear();
    }

    pub fn cached_trace(&self) -> Vec<String> {
        self.trace.clone()
    }

    /// Candidate entry points (methods with code) whose names match Android
    /// lifecycle or common loader/callback shapes.
    pub fn lifecycle_entries(&self) -> Vec<(MethodEntry, &'static str)> {
        let mut out = Vec::new();
        let lifecycle = [
            ("onCreate", "()V", "activity/create"),
            ("onStart", "()V", "activity/start"),
            ("onResume", "()V", "activity/resume"),
            ("onRestart", "()V", "activity/restart"),
            ("onBind", "(Landroid/content/Intent;)Landroid/os/IBinder;", "service/bind"),
            ("onStartCommand", "(Landroid/content/Intent;II)I", "service/start"),
            ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V", "receiver"),
            ("onHandleIntent", "(Landroid/content/Intent;)V", "intent-service"),
            ("onHandleWork", "(Landroid/content/Intent;)V", "job-service"),
            ("doInBackground", "([Ljava/lang/Object;)Ljava/lang/Object;", "async-task"),
            ("run", "()V", "runnable"),
            ("call", "()Ljava/lang/Object;", "callable"),
            ("attachBaseContext", "(Landroid/content/Context;)V", "activity/attach"),
            ("handleMessage", "(Landroid/os/Message;)V", "handler"),
            ("invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", "proxy"),
            ("newInstance", "(Ljava/lang/Object;)Ljava/lang/Object;", "factory"),
            ("afterTextChanged", "(Landroid/text/Editable;)V", "watcher"),
            ("onClick", "(Landroid/view/View;)V", "click"),
            ("onDraw", "(Landroid/graphics/Canvas;)V", "draw"),
        ];
        for ci in self.registry.all_app_classes() {
            for m in ci.direct_methods.iter().chain(ci.virtual_methods.iter()) {
                if m.code_off == 0 {
                    continue;
                }
                let name = self.registry.interner.get(m.key.name);
                let proto = self.registry.interner.get(m.key.proto);
                for (lname, lproto, label) in lifecycle {
                    if name == lname && proto == lproto {
                        out.push((*m, label));
                    }
                }
                // Native bridge / packer entry shapes.
                if matches!(name, "load" | "init" | "start" | "attach")
                    && m.access & crate::dex::ACC_STATIC != 0
                {
                    out.push((*m, "packer/entry"));
                }
            }
        }
        out
    }
}

fn actual_class_or(declared: Sym, actual: Sym, registry: &Registry) -> Sym {
    if registry.is_app_class(actual) {
        actual
    } else {
        declared
    }
}

fn compare_slots(a: Slot, b: Slot) -> (std::cmp::Ordering, bool) {
    use Value as V;
    match (a.v, b.v) {
        (V::Ref(x), V::Ref(y)) => {
            if x.is_null() || y.is_null() {
                // Reference comparisons: null == null only.
                let eq = x.is_null() && y.is_null();
                (if eq { std::cmp::Ordering::Equal } else { std::cmp::Ordering::Greater }, true)
            } else {
                (x.0.cmp(&y.0), true)
            }
        }
        (V::Long(x), _) | (_, V::Long(x)) => {
            let _ = x;
            (a.v.as_long().cmp(&b.v.as_long()), true)
        }
        _ => (a.v.as_int().cmp(&b.v.as_int()), true),
    }
}

fn read_s32(insns: &[u16], at: usize) -> i32 {
    let lo = *insns.get(at).unwrap_or(&0) as u32;
    let hi = *insns.get(at + 1).unwrap_or(&0) as u32;
    (lo | (hi << 16)) as i32
}

fn read_s16_word(insns: &[u16], at: usize) -> i16 {
    *insns.get(at).unwrap_or(&0) as i16
}

fn combine_u32(lo: i32, hi: i32) -> i64 {
    ((hi as u32 as u64) << 32 | (lo as u32 as u64)) as i64
}

fn fmt_float(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn f2i(v: f32) -> i32 {
    if v.is_nan() {
        0
    } else if v >= i32::MAX as f32 {
        i32::MAX
    } else if v <= i32::MIN as f32 {
        i32::MIN
    } else {
        v as i32
    }
}

fn f2l(v: f32) -> i64 {
    if v.is_nan() {
        0
    } else if v >= i64::MAX as f32 {
        i64::MAX
    } else if v <= i64::MIN as f32 {
        i64::MIN
    } else {
        v as i64
    }
}

fn d2i(v: f64) -> i32 {
    if v.is_nan() {
        0
    } else if v >= i32::MAX as f64 {
        i32::MAX
    } else if v <= i32::MIN as f64 {
        i32::MIN
    } else {
        v as i32
    }
}

fn d2l(v: f64) -> i64 {
    if v.is_nan() {
        0
    } else if v >= i64::MAX as f64 {
        i64::MAX
    } else if v <= i64::MIN as f64 {
        i64::MIN
    } else {
        v as i64
    }
}

pub fn default_for(desc: &str) -> Slot {
    match desc {
        "V" => Slot::default(),
        "J" => Slot::long(0),
        "D" => Slot::double(0.0),
        "F" => Slot::float(0.0),
        "Z" | "B" | "S" | "C" | "I" => Slot::int(0),
        _ => Slot::null(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

fn short_origin(origin: &str) -> String {
    if origin.chars().count() <= 32 {
        origin.to_string()
    } else {
        let tail: String = origin.chars().rev().take(28).collect::<Vec<_>>().into_iter().rev().collect();
        format!("…{tail}")
    }
}

fn int_binop(op: usize, x: i32, y: i32) -> i32 {
    match op {
            0 => x.wrapping_add(y),
            1 => x.wrapping_sub(y),
            2 => x.wrapping_mul(y),
            3 => x.wrapping_div(y),
            4 => x.wrapping_rem(y),
            5 => x & y,
            6 => x | y,
            7 => x ^ y,
            8 => x.wrapping_shl(y as u32 & 31),
            9 => x.wrapping_shr(y as u32 & 31),
        _ => ((x as u32).wrapping_shr(y as u32 & 31)) as i32,
    }
}

    fn long_binop(op: usize, x: i64, y: i64) -> i64 {
    match op {
            0 => x.wrapping_add(y),
            1 => x.wrapping_sub(y),
            2 => x.wrapping_mul(y),
            3 => x.wrapping_div(y),
            4 => x.wrapping_rem(y),
            5 => x & y,
            6 => x | y,
            7 => x ^ y,
            8 => x.wrapping_shl(y as u32 & 63),
            9 => x.wrapping_shr(y as u32 & 63),
        _ => ((x as u64).wrapping_shr(y as u32 & 63)) as i64,
    }
}
