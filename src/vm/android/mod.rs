//! The Android / Java framework model.
//!
//! This is the part that turns "a DEX interpreter" into "a sandbox that follows
//! a packer". Two properties matter:
//!
//! 1. **Fidelity for the APIs malware actually uses** — crypto, Base64, string
//!    building, streams, reflection, dynamic class loading, HTTP, SMS,
//!    telephony/build/sensor probes, handlers and timers.
//! 2. **Never a silent wrong answer.** An unmodelled call returns a typed
//!    default and is counted in `env.coverage_gaps`; the report surfaces those
//!    so an analyst knows where the emulation was blind.
//!
//! Behaviour is dispatched on the *declared* class descriptor and method name,
//! because that is what the DEX constant pool gives us, and because it mirrors
//! how Android's own framework classes are keyed.

mod crypto;
mod io;
mod net;
mod reflect;
mod state;
mod system;
mod ui;

use crate::report::SinkKind;
use crate::vm::heap::ObjKind;
use crate::vm::intern::{FieldKey, MethodKey, Sym};
use crate::vm::interp::{CallOutcome, Host, Vm};
use crate::vm::value::{ObjRef, Slot, Taint, Value};

pub use state::{TaintSource, DEX_LOADER_CLASSES};
pub use ui::CONTEXT_CLASS;

/// Which subsystem a framework call belongs to. Kept explicit so coverage
/// reports can say "crypto: 3 calls, all modelled" rather than just a count.
pub struct AndroidHost {
    /// Set once the sample has been observed trying to load code.
    pub seen_dynamic_load: bool,
    /// Cipher objects under construction, keyed by state on the object.
    pub eval_env: VmEnvFlags,
}

#[derive(Default)]
pub struct VmEnvFlags {
    pub gms_failures: u32,
}

impl Default for AndroidHost {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidHost {
    pub fn new() -> Self {
        AndroidHost {
            seen_dynamic_load: false,
            eval_env: VmEnvFlags::default(),
        }
    }
}

/// A fresh host for host-internal reentry (class initialisation, reflection).
/// Framework state lives on heap objects, so a distinct host instance is fine.
pub fn default_host() -> Box<AndroidHost> {
    Box::new(AndroidHost::new())
}

/// Invoke a framework method from inside host code (reflection). Dispatches to
/// the same model as a normal call and returns the outcome.
pub fn android_call(vm: &mut Vm, host: &mut AndroidHost, key: &MethodKey, args: &[Slot]) -> CallOutcome {
    let class = vm.sym_str(key.class).to_string();
    let name = vm.sym_str(key.name).to_string();
    let out = dispatch(vm, host, &class, &name, key, args);
    if let CallOutcome::Decline = out {
        vm.env.gap(&format!("{}->{}{}", class, name, vm.sym_str(key.proto)));
        return CallOutcome::Decline;
    }
    out
}

impl Host for AndroidHost {
    fn call(&mut self, vm: &mut Vm, key: &MethodKey, args: &[Slot]) -> CallOutcome {
        let class = vm.sym_str(key.class).to_string();
        let name = vm.sym_str(key.name).to_string();
        // `super.<init>` on a framework parent of an app class arrives here.
        let outcome = dispatch(vm, self, &class, &name, key, args);
        if let CallOutcome::Decline = outcome {
            // Not modelled: surface in coverage and return a typed default.
            vm.env.gap(&format!("{}->{}{}", class, name, vm.sym_str(key.proto)));
            return CallOutcome::Decline;
        }
        outcome
    }

    fn static_field(&mut self, vm: &mut Vm, key: &FieldKey) -> CallOutcome {
        let class = vm.sym_str(key.class).to_string();
        let name = vm.sym_str(key.name).to_string();
        let out = static_field_value(vm, self, &class, &name);
        match out {
            Some(v) => CallOutcome::Value(v),
            None => {
                vm.env.gap(&format!("sget {class}->{name}"));
                CallOutcome::Decline
            }
        }
    }

    fn construct(&mut self, vm: &mut Vm, class: Sym) -> CallOutcome {
        // Framework object: allocate it. Its `<init>` runs through `call`.
        match vm.heap.new_instance(class) {
            Ok(o) => CallOutcome::Value(Slot::reference(o)),
            Err(_) => CallOutcome::Throw(vm.exc_out_of_mem, "object allocation".into()),
        }
    }

    fn native_call(&mut self, vm: &mut Vm, key: &MethodKey, args: &[Slot]) -> CallOutcome {
        let class = vm.sym_str(key.class).to_string();
        let name = vm.sym_str(key.name).to_string();
        let desc = format!("{}->{}{}", class, name, vm.sym_str(key.proto));
        // A native method invoked from app code. Record it with arguments; the
        // body is not executed.
        vm.report_sink(
            SinkKind::NativeLoad,
            desc.clone(),
            format!("NATIVE entry invoked with {} args", args.len()),
            Taint::CLEAN,
            native_arg_evidence(vm, args),
        );
        vm.env.gap(&format!("native body: {desc}"));
        // Return a typed default for the declared return type.
        let ret = vm.sym_str(key.proto);
        let ret = ret.rsplit(')').next().unwrap_or("V").to_string();
        CallOutcome::Value(crate::vm::interp::default_for(&ret))
    }
}

fn native_arg_evidence(vm: &Vm, args: &[Slot]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate().take(8) {
        match a.v {
            Value::Ref(r) if !r.is_null() => {
                out.push(format!("arg{i}={}", vm.object_describe(r)));
            }
            Value::Ref(_) => out.push(format!("arg{i}=null")),
            Value::Int(x) => out.push(format!("arg{i}={x}")),
            Value::Long(x) => out.push(format!("arg{i}={x}L")),
            _ => {}
        }
    }
    out
}

/// Router. Split by package prefix so each subsystem owns its own file.
fn dispatch(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    key: &MethodKey,
    args: &[Slot],
) -> CallOutcome {
    // Order matters only for speed; prefixes do not overlap.
    if class.starts_with("Landroid/") {
        return ui::dispatch(vm, host, class, name, key, args);
    }
    if class.starts_with("Ljavax/crypto/")
        || class.starts_with("Ljava/security/")
        || class.starts_with("Lorg/bouncycastle/")
    {
        return crypto::dispatch(vm, host, class, name, key, args);
    }
    if class.starts_with("Ljava/io/")
        || class.starts_with("Ljava/nio/")
        || class.starts_with("Ljava/util/zip/")
        || class.starts_with("Ljava/util/jar/")
    {
        return io::dispatch(vm, host, class, name, key, args);
    }
    if class.starts_with("Ljava/net/") || class.starts_with("Ljavax/net/") || class.starts_with("Lokhttp3/") {
        return net::dispatch(vm, host, class, name, key, args);
    }
    if class.starts_with("Ljava/lang/reflect/") || class.starts_with("Ljava/lang/Class")
        || class.starts_with("Ljava/lang/ClassLoader")
        || class.starts_with("Ldalvik/system/")
    {
        return reflect::dispatch(vm, host, class, name, key, args);
    }
    if class.starts_with("Ljava/util/")
        || class.starts_with("Lorg/json/")
        || class.starts_with("Ljava/text/")
        || class.starts_with("Ljava/lang/String")
        || class.starts_with("Ljava/lang/Integer")
        || class.starts_with("Ljava/lang/Long")
        || class.starts_with("Ljava/lang/Boolean")
        || class.starts_with("Ljava/lang/Byte")
        || class.starts_with("Ljava/lang/Short")
        || class.starts_with("Ljava/lang/Character")
        || class.starts_with("Ljava/lang/Double")
        || class.starts_with("Ljava/lang/Float")
        || class.starts_with("Ljava/lang/Math")
        || class.starts_with("Ljava/lang/System")
        || class.starts_with("Ljava/lang/Object")
        || class.starts_with("Ljava/lang/Thread")
        || class.starts_with("Ljava/lang/Throwable")
        || class.starts_with("Ljava/lang/Exception")
        || class.starts_with("Ljava/lang/Runtime")
        || class.starts_with("Ljava/lang/Process")
        || class.starts_with("Ljava/lang/ProcessBuilder")
        || class.starts_with("Ljava/lang/StackTrace")
        || class.starts_with("Ljava/lang/StringBuilder")
        || class.starts_with("Ljava/lang/StringBuffer")
        || class.starts_with("Ljava/lang/CharSequence")
        || class.starts_with("Ljava/lang/Enum")
        || class.starts_with("Ljava/lang/Iterable")
        || class.starts_with("Ljava/lang/Runnable")
        || class.starts_with("Ljava/lang/Number")
    {
        return system::dispatch(vm, host, class, name, key, args);
    }
    // Everything else: an Android library family we do not know.
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// Shared helpers used by all subsystems
// ---------------------------------------------------------------------------

pub(crate) fn arg_ref(args: &[Slot], i: usize) -> ObjRef {
    args.get(i).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL)
}

pub(crate) fn arg_int(args: &[Slot], i: usize) -> i32 {
    args.get(i).map(|s| s.v.as_int()).unwrap_or(0)
}

pub(crate) fn arg_long(args: &[Slot], i: usize) -> i64 {
    args.get(i).map(|s| s.v.as_long()).unwrap_or(0)
}

pub(crate) fn arg_str(vm: &Vm, args: &[Slot], i: usize) -> Option<String> {
    vm.str_arg(args, i)
}

pub(crate) fn arg_taint(args: &[Slot], i: usize) -> Taint {
    args.get(i).map(|s| s.t).unwrap_or(Taint::CLEAN)
}

/// Effective taint of an argument: the register's own labels plus whatever
/// the referenced heap object carries. A `String` returned by
/// `getDeviceId()` keeps its label on the object, so any sink that takes a
/// string reference must consult both.
pub(crate) fn eff_taint(vm: &Vm, args: &[Slot], i: usize) -> Taint {
    let Some(s) = args.get(i) else { return Taint::CLEAN };
    let obj = s.v.as_ref();
    s.t.union(vm.heap.taint_of(obj))
}

/// Union of taints across all arguments, used by "pass-through" operations.
pub(crate) fn union_taint(args: &[Slot]) -> Taint {
    args.iter().fold(Taint::CLEAN, |acc, s| acc.union(s.t))
}

/// The bytes behind a `byte[]` argument, or None.
pub(crate) fn arg_bytes(vm: &Vm, args: &[Slot], i: usize) -> Option<Vec<u8>> {
    let r = arg_ref(args, i);
    vm.heap.bytes_of(r).map(|b| b.to_vec())
}

pub(crate) fn ret_obj(r: ObjRef) -> CallOutcome {
    CallOutcome::Value(Slot::reference(r))
}

pub(crate) fn ret_void() -> CallOutcome {
    CallOutcome::Value(Slot::default())
}

pub(crate) fn ret_int(v: i32) -> CallOutcome {
    CallOutcome::Value(Slot::int(v))
}

pub(crate) fn ret_bool(v: bool) -> CallOutcome {
    CallOutcome::Value(Slot::int(if v { 1 } else { 0 }))
}

pub(crate) fn ret_long(v: i64) -> CallOutcome {
    CallOutcome::Value(Slot::long(v))
}

/// Read a state value stored on an object as an int.
pub(crate) fn state_int(vm: &Vm, obj: ObjRef, key: &str) -> i32 {
    vm.heap
        .instance(obj)
        .and_then(|i| i.state.get(key))
        .map(|s| s.v.as_int())
        .unwrap_or(0)
}

pub fn set_state_int(vm: &mut Vm, obj: ObjRef, key: &str, v: i32) {
    if let Some(inst) = vm.heap.instance_mut(obj) {
        inst.state.insert(key.into(), Slot::int(v));
    }
}

pub fn state_ref(vm: &Vm, obj: ObjRef, key: &str) -> ObjRef {
    vm.heap
        .instance(obj)
        .and_then(|i| i.state.get(key))
        .map(|s| s.v.as_ref())
        .unwrap_or(ObjRef::NULL)
}

pub fn set_state_ref(vm: &mut Vm, obj: ObjRef, key: &str, r: ObjRef) {
    if let Some(inst) = vm.heap.instance_mut(obj) {
        inst.state.insert(key.into(), Slot::reference(r));
    }
}

pub(crate) fn state_str(vm: &Vm, obj: ObjRef, key: &str) -> Option<String> {
    let r = state_ref(vm, obj, key);
    if r.is_null() {
        None
    } else {
        vm.heap.string_of(r).map(|s| s.to_string())
    }
}

pub(crate) fn set_state_str(vm: &mut Vm, obj: ObjRef, key: &str, s: impl Into<String>) {
    if let Ok(r) = vm.new_string(s) {
        set_state_ref(vm, obj, key, r);
    }
}

/// Store a freshly-built string in an object's model state. Allocating first
/// and inserting second avoids holding a heap borrow across an allocation.
pub(crate) fn put_state_str(vm: &mut Vm, obj: ObjRef, key: &str, s: impl Into<String>) {
    let slot = match vm.new_string(s) {
        Ok(r) => Slot::reference(r),
        Err(_) => Slot::null(),
    };
    if let Some(inst) = vm.heap.instance_mut(obj) {
        inst.state.insert(key.to_string(), slot);
    }
}

pub(crate) fn put_state_slot(vm: &mut Vm, obj: ObjRef, key: &str, slot: Slot) {
    if let Some(inst) = vm.heap.instance_mut(obj) {
        inst.state.insert(key.to_string(), slot);
    }
}

pub(crate) fn put_state_int(vm: &mut Vm, obj: ObjRef, key: &str, v: i32) {
    put_state_slot(vm, obj, key, Slot::int(v));
}

pub(crate) fn put_state_float(vm: &mut Vm, obj: ObjRef, key: &str, v: f32) {
    put_state_slot(vm, obj, key, Slot::float(v));
}

pub(crate) fn put_state_double(vm: &mut Vm, obj: ObjRef, key: &str, v: f64) {
    put_state_slot(vm, obj, key, Slot::double(v));
}

/// Turn a slot into Java's `toString` rendering, used by string concatenation
/// and by payload builders.
pub(crate) fn java_to_string(vm: &Vm, s: Slot) -> String {
    match s.v {
        Value::Ref(r) if !r.is_null() => match vm.heap.get(r).map(|o| &o.kind) {
            Some(ObjKind::Str(x)) | Some(ObjKind::MutableStr(x)) => x.clone(),
            Some(ObjKind::Bytes(b)) => String::from_utf8_lossy(b).to_string(),
            Some(ObjKind::Array(_)) => "[array]".into(),
            Some(ObjKind::Instance(i)) => {
                // Respect an explicit toString override stored on model objects.
                format!("[{}]", vm.sym_str(i.class).trim_start_matches('L').trim_end_matches(';'))
            }
            None => "null".into(),
        },
        Value::Ref(_) => "null".into(),
        Value::Int(v) => v.to_string(),
        Value::Long(v) => v.to_string(),
        Value::Float(v) => fmt_float(v as f64),
        Value::Double(v) => fmt_float(v),
        Value::Undef | Value::WideHigh => "0".into(),
    }
}

pub(crate) fn fmt_float(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Convert a JVM dotted class name to a descriptor.
/// `com.x.Y` -> `Lcom/x/Y;`; arrays (`[B`, `[Ljava.lang.String;`) pass through.
pub(crate) fn dotted_to_desc(name: &str) -> String {
    if name.starts_with('[') {
        return name.replace('.', "/");
    }
    if name.starts_with('L') && name.ends_with(';') {
        return name.to_string();
    }
    format!("L{};", name.replace('.', "/"))
}

/// Inverse of `dotted_to_desc`, for `Class.getName()`.
pub(crate) fn desc_to_dotted(desc: &str) -> String {
    if desc.starts_with('L') && desc.ends_with(';') {
        desc[1..desc.len() - 1].replace('/', ".")
    } else {
        desc.to_string()
    }
}

// ---------------------------------------------------------------------------
// Static field answers for framework classes
// ---------------------------------------------------------------------------

fn static_field_value(vm: &mut Vm, host: &mut AndroidHost, class: &str, name: &str) -> Option<Slot> {
    system::static_field_value(vm, host, class, name)
        .or_else(|| ui::static_field_value(vm, host, class, name))
        .or_else(|| crypto::static_field_value(vm, host, class, name))
}
