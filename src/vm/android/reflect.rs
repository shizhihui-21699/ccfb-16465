//! Reflection and dynamic class loading — the core of unpacking.
//!
//! A packer's shell does two things with its payload: it decrypts it, and it
//! makes it executable. This module watches for both. Whenever a class loader
//! is given bytes (or a path that resolves to bytes in the simulated
//! filesystem), those bytes are:
//!
//! 1. tried as a DEX image and parsed;
//! 2. tried as a zip/apk and every `classes*.dex` inside is parsed;
//! 3. tried as a plain dex-shaped blob at some offset (packers like to prepend
//!    headers or nest a dex inside another container);
//!
//! Any image recovered this way is registered with *priority*, so its classes
//! override the shell's decoys, and a finding is emitted that names the loader
//! call and the recovered classes. That is the moment an obfuscated sample
//! becomes readable, and it is exactly what the analyst needs to see.

use std::sync::Arc;

use crate::dex::DexFile;
use crate::report::SinkKind;
use crate::vm::android::{arg_int, arg_ref, arg_str, ret_int, ret_obj, ret_void, set_state_int, set_state_ref, state_int, state_ref, state_str};
use crate::vm::heap::ObjKind;
use crate::vm::intern::{MethodKey, Sym};
use crate::vm::interp::{CallOutcome, Vm};
use crate::vm::registry::MethodEntry;
use crate::vm::value::{ObjRef, Slot, Taint, Value};

use super::AndroidHost;

/// A deferred callback target, for the scheduler.
#[derive(Debug, Clone)]
pub enum CallbackTarget {
    Runnable(ObjRef),
    /// A message for a `Handler`; the discriminator is delivered to
    /// `handleMessage`.
    Message { handler: ObjRef, what: i32 },
}

/// Schedule app work on the virtual clock.
pub fn schedule(vm: &mut Vm, delay_ms: i64, label: String, target: CallbackTarget) -> u64 {
    use crate::vm::interp::{Callback, ScheduledTask};
    let id = vm
        .scheduler
        .iter()
        .map(|t: &ScheduledTask| t.id)
        .max()
        .unwrap_or(0)
        + 1;
    let cb = match target {
        CallbackTarget::Runnable(r) => Callback::Runnable(r),
        CallbackTarget::Message { handler, what } => Callback::Message { handler, what },
    };
    if vm.scheduler.len() < 4096 {
        vm.scheduler.push(ScheduledTask {
            id,
            due_millis: vm.env.now() + delay_ms.max(0),
            name: label,
            callback: cb,
        });
    }
    id
}

pub fn dispatch(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    key: &MethodKey,
    args: &[Slot],
) -> CallOutcome {
    if class.starts_with("Ldalvik/system/") {
        return loader_ops(vm, host, class, name, args);
    }
    if class.starts_with("Ljava/lang/reflect/") {
        return reflect_ops(vm, host, class, name, args);
    }
    if class.starts_with("Ljava/lang/ClassLoader") || class == "Ljava/lang/ClassLoader;" {
        return classloader_base(vm, name, args);
    }
    if class.starts_with("Ljava/lang/Class;") {
        return super::system::dispatch(vm, host, class, name, key, args);
    }
    if class.starts_with("Ljava/lang/StackTraceElement;") {
        let this = arg_ref(args, 0);
        return match name {
            "getClassName" | "getMethodName" | "getFileName" => ret_obj(state_ref(vm, this, "text")),
            "toString" => ret_obj(state_ref(vm, this, "text")),
            _ => ret_void(),
        };
    }
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// Class loaders
// ---------------------------------------------------------------------------

fn classloader_base(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" | "getParent" => ret_obj(this),
        "getSystemClassLoader" => {
            match vm.new_instance_of("Ljava/lang/ClassLoader;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            }
        }
        "loadClass" => {
            let dotted = arg_str(vm, args, 1).unwrap_or_default();
            match resolve_or_throw(vm, host_for_loader(), &dotted) {
                Ok(class_obj) => ret_obj(class_obj),
                Err(e) => CallOutcome::Throw(vm.exc_generic, e),
            }
        }
        "findClass" | "findSystemClass" => ret_obj(ObjRef::NULL),
        "getResourceAsStream" | "getResource" => {
            let res = arg_str(vm, args, 1).unwrap_or_default();
            let data = vm.env.read_file(&res).map(|b| b.to_vec()).unwrap_or_default();
            match vm.heap.new_bytes(data, Taint::CLEAN) {
                Ok(b) => {
                    let s = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                        Ok(o) => o,
                        Err(_) => return ret_void(),
                    };
                    set_state_ref(vm, s, "buf", b);
                    set_state_int(vm, s, "pos", 0);
                    ret_obj(s)
                }
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn host_for_loader() -> &'static mut AndroidHost {
    // The loader path does not need host state; a thread-local scratch host
    // would be overkill, so allocate one. This is called rarely.
    Box::leak(Box::new(AndroidHost::new()))
}

fn resolve_or_throw(vm: &mut Vm, _host: &mut AndroidHost, dotted: &str) -> Result<ObjRef, String> {
    let desc = super::dotted_to_desc(dotted);
    let sym = vm.sym(&desc);
    if vm.registry.is_app_class(sym) {
        vm.ensure_class_initialized(sym);
        if let Some(o) = super::system::make_class_obj(vm, &desc) {
            return Ok(o);
        }
    }
    // Framework class: still return a Class object so reflection chains work.
    if let Some(o) = super::system::make_class_obj(vm, &desc) {
        return Ok(o);
    }
    Err(format!("ClassNotFoundException: {dotted}"))
}

fn loader_ops(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    args: &[Slot],
) -> CallOutcome {
    let this = arg_ref(args, 0);
    if name == "<init>" {
        // DexClassLoader(String dexPath, String optimizedDir, String libPath, ClassLoader parent)
        // InMemoryDexClassLoader(ByteBuffer, ClassLoader) / (ByteBuffer[], ClassLoader)
        let mut cx: Vec<(String, Taint)> = Vec::new();
        for a in args.iter().skip(1) {
            let r = a.v.as_ref();
            if r.is_null() {
                continue;
            }
            if vm.heap.is_string(r) {
                cx.push((vm.string_of(r), a.t));
            } else if let Some(bytes) = vm.heap.bytes_of(r) {
                cx.push((String::from_utf8_lossy(bytes).to_string(), a.t));
            }
        }
        // Stash parent, optimized dir, etc.
        for (s, _) in &cx {
            if s.ends_with('/') || s.contains("dex") || s.contains("apk") || s.contains("jar") {
                if let Ok(r) = vm.new_string(s.clone()) {
                    set_state_ref(vm, this, "paths", r);
                }
            }
        }
        let joined: String = cx.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>().join(":");
        let t = args.iter().skip(1).fold(Taint::CLEAN, |a, s| a.union(s.t));
        vm.report_sink(
            SinkKind::DynamicCodeLoad,
            format!("{class}-><init>"),
            format!("loader created with paths=[{joined}]"),
            t,
            cx.iter().map(|(s, _)| s.chars().take(200).collect::<String>()).collect(),
        );
        // Try to unpack the referenced path now.
        if !joined.is_empty() {
            let candidate = joined
                .split(':')
                .next()
                .unwrap_or("")
                .to_string();
            if candidate.ends_with(".dex") || candidate.ends_with(".apk") || candidate.ends_with(".jar") {
                unpack_from_path(vm, host, &candidate);
            }
        }
        // Also try byte-buffer form.
        for a in args.iter().skip(1) {
            if let Value::Ref(r) = a.v {
                if r.is_null() {
                    continue;
                }
                if vm.heap.is_string(r) {
                    let s = vm.string_of(r);
                    // Path form may reference a real file the sample wrote.
                    if s.starts_with('/') {
                        unpack_from_path(vm, host, &s);
                    }
                } else if let Some(bytes) = vm.heap.bytes_of(r) {
                    let bytes = bytes.to_vec();
                    if looks_like_dex(&bytes) || looks_like_zip(&bytes) {
                        unpack_from_bytes(vm, host, &bytes, "InMemoryDex");
                    }
                }
            }
        }
        return ret_void();
    }
    match name {
        "loadClass" => {
            let dotted = arg_str(vm, args, 1).unwrap_or_default();
            // Before resolving, retry the paths we were constructed with.
            if let Some(paths) = state_str(vm, this, "paths") {
                for p in paths.split(':') {
                    if !p.is_empty() {
                        unpack_from_path(vm, host, p);
                    }
                }
            }
            match resolve_or_throw(vm, host, &dotted) {
                Ok(o) => ret_obj(o),
                Err(e) => CallOutcome::Throw(vm.exc_generic, e),
            }
        }
        "findClass" | "findSystemClass" => {
            let dotted = arg_str(vm, args, 1).unwrap_or_default();
            match resolve_or_throw(vm, host, &dotted) {
                Ok(o) => ret_obj(o),
                Err(e) => CallOutcome::Throw(vm.exc_generic, e),
            }
        }
        "getResourceAsStream" | "getResource" => {
            let res = arg_str(vm, args, 1).unwrap_or_default();
            let data = vm.env.read_file(&res).map(|b| b.to_vec()).unwrap_or_default();
            match vm.heap.new_bytes(data, Taint::CLEAN) {
                Ok(b) => {
                    let s = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                        Ok(o) => o,
                        Err(_) => return ret_void(),
                    };
                    set_state_ref(vm, s, "buf", b);
                    set_state_int(vm, s, "pos", 0);
                    ret_obj(s)
                }
                Err(_) => ret_void(),
            }
        }
        "getClassLoader" | "getParent" => ret_obj(this),
        _ => CallOutcome::Decline,
    }
}

fn looks_like_dex(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[0..4] == b"dex\n"
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && (bytes[0..2] == [0x50, 0x4b] || bytes[0..4] == [0x50, 0x4b, 0x03, 0x04])
}

fn unpack_from_path(vm: &mut Vm, host: &mut AndroidHost, path: &str) {
    let data = vm.env.read_file(path).map(|b| b.to_vec()).unwrap_or_default();
    if data.is_empty() {
        vm.env.gap(&format!("dynamic loader path not present: {path}"));
        return;
    }
    try_unpack(vm, host, &data, path);
}

fn unpack_from_bytes(vm: &mut Vm, host: &mut AndroidHost, bytes: &[u8], origin: &str) {
    try_unpack(vm, host, bytes, origin);
}

/// Parse and register any DEX images found in `data`, whether it is a raw DEX,
/// a zip/apk, or a nested container. Emits a finding per recovered image.
pub fn try_unpack(vm: &mut Vm, _host: &mut AndroidHost, data: &[u8], origin: &str) {
    let mut recovered = 0usize;
    let mut names: Vec<String> = Vec::new();

    if looks_like_zip(data) {
        if let Ok(mut ar) = zip::ZipArchive::new(std::io::Cursor::new(data.to_vec())) {
            let entries: Vec<String> = ar.file_names().map(|s| s.to_string()).collect();
            for entry in entries {
                if !(entry.ends_with(".dex") || entry.ends_with(".apk") || entry.ends_with(".jar")) {
                    continue;
                }
                let Ok(mut f) = ar.by_name(&entry) else { continue };
                use std::io::Read;
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_err() {
                    continue;
                }
                if looks_like_dex(&buf) {
                    match DexFile::parse(format!("decrypted:{origin}/{entry}"), buf) {
                        Ok(dex) => {
                            names.extend(dex_classes(&dex));
                            let _ = vm.registry.add_image(Arc::new(dex), true);
                            recovered += 1;
                        }
                        Err(e) => vm.env.gap(&format!("pickup parse {entry}: {e}")),
                    }
                } else if looks_like_zip(&buf) {
                    // nested apk; recurse one level
                    before_nested(vm, &buf, &format!("{origin}/{entry}"), &mut recovered, &mut names);
                }
            }
        }
    } else if looks_like_dex(data) {
        match DexFile::parse(format!("decrypted:{origin}"), data.to_vec()) {
            Ok(dex) => {
                names.extend(dex_classes(&dex));
                let _ = vm.registry.add_image(Arc::new(dex), true);
                recovered += 1;
            }
            Err(e) => vm.env.gap(&format!("payload dex parse: {e}")),
        }
    } else {
        // Scan for an embedded DEX header, common in hand-rolled packers.
        if let Some(off) = find_subslice(data, b"dex\n035\0")
            .or_else(|| find_subslice(data, b"dex\n036\0"))
            .or_else(|| find_subslice(data, b"dex\n037\0"))
            .or_else(|| find_subslice(data, b"dex\n038\0"))
            .or_else(|| find_subslice(data, b"dex\n039\0"))
        {
            match DexFile::parse(format!("decrypted:{origin}+{off}"), data[off..].to_vec()) {
                Ok(dex) => {
                    names.extend(dex_classes(&dex));
                    let _ = vm.registry.add_image(Arc::new(dex), true);
                    recovered += 1;
                }
                Err(e) => vm.env.gap(&format!("embedded dex parse: {e}")),
            }
        }
    }

    if recovered > 0 {
        vm.note_decrypted(format!("recovered {recovered} DEX image(s) from {origin}"));
        vm.report_sink(
            SinkKind::DynamicCodeLoad,
            "dynamic-loader",
            format!("recovered {recovered} DEX image(s) from {origin}"),
            Taint::CLEAN,
            names.iter().take(50).cloned().collect(),
        );
    } else {
        vm.env.gap(&format!("no DEX recovered from {origin} ({} bytes)", data.len()));
    }
}

fn before_nested(
    vm: &mut Vm,
    buf: &[u8],
    origin: &str,
    recovered: &mut usize,
    names: &mut Vec<String>,
) {
    if let Ok(mut ar) = zip::ZipArchive::new(std::io::Cursor::new(buf.to_vec())) {
        let entries: Vec<String> = ar.file_names().map(|s| s.to_string()).collect();
        for entry in entries {
            if !entry.ends_with(".dex") {
                continue;
            }
            use std::io::Read;
            let Ok(mut f) = ar.by_name(&entry) else { continue };
            let mut b = Vec::new();
            if f.read_to_end(&mut b).is_ok() && looks_like_dex(&b) {
                if let Ok(dex) = DexFile::parse(format!("decrypted:{origin}!{entry}"), b) {
                    names.extend(dex_classes(&dex));
                    let _ = vm.registry.add_image(Arc::new(dex), true);
                    *recovered += 1;
                }
            }
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Class descriptors an image defines, for the finding's evidence.
fn dex_classes(dex: &DexFile) -> Vec<String> {
    let mut out = Vec::new();
    for cd in &dex.classes {
        let name = dex.type_name(cd.class_idx);
        if !name.starts_with("Ljava/") && !name.starts_with("Landroid/") {
            out.push(name.to_string());
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// java.lang.reflect
// ---------------------------------------------------------------------------

fn reflect_ops(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    args: &[Slot],
) -> CallOutcome {
    let this = arg_ref(args, 0);
    match class {
        "Ljava/lang/reflect/Method;" => match name {
            // (see per-branch handling)
            // (diagnostics handled below)
            "invoke" => {
                // invoke(Object receiver, Object[] args)
                let target_desc = state_str(vm, this, "class").unwrap_or_default();
                let target_name = state_str(vm, this, "name").unwrap_or_default();
                let target_proto = state_str(vm, this, "proto").unwrap_or_default();
                let receiver = arg_ref(args, 1);
                let argarr = arg_ref(args, 2);
                let mut call_args: Vec<Slot> = Vec::new();
                // Whether the target is static decides if the receiver is the
                // first argument or absent. Look the method up rather than
                // trusting the `static` flag recorded at lookup time, which is a
                // guess.
                let declared_static = is_static_state(vm, this);
                let is_static_target = declared_static
                    || is_method_static(vm, &target_desc, &target_name, &target_proto);
                if !is_static_target {
                    call_args.push(Slot::reference(receiver));
                }
                // Unpack object[] arguments.
                if let Some(o) = vm.heap.get(argarr) {
                    if let ObjKind::Array(a) = &o.kind {
                        let items = a.data.clone();
                        for s in items {
                            call_args.push(s);
                        }
                    }
                }
                invoke_reflective(vm, host, &target_desc, &target_name, &target_proto, &call_args)
            }
            "setAccessible" => ret_void(),
            "getName" => ret_obj(state_ref(vm, this, "name")),
            "getReturnType" => match vm.new_instance_of("Ljava/lang/Class;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            },
            "getParameterTypes" => empty_class_array(vm),
            _ => CallOutcome::Decline,
        },
        "Ljava/lang/reflect/Field;" => match name {
            "get" | "getInt" | "getLong" | "getBoolean" | "getObject" => {
                let target_desc = state_str(vm, this, "class").unwrap_or_default();
                let field_name = state_str(vm, this, "name").unwrap_or_default();
                let receiver = arg_ref(args, 1);
                read_reflective_field(vm, &target_desc, &field_name, receiver, name)
            }
            "set" | "setInt" | "setLong" | "setBoolean" | "setObject" => {
                let target_desc = state_str(vm, this, "class").unwrap_or_default();
                let field_name = state_str(vm, this, "name").unwrap_or_default();
                let receiver = arg_ref(args, 1);
                write_reflective_field(vm, &target_desc, &field_name, receiver, args.get(2).copied().unwrap_or_default())
            }
            "setAccessible" => ret_void(),
            "getName" => ret_obj(state_ref(vm, this, "name")),
            _ => CallOutcome::Decline,
        },
        "Ljava/lang/reflect/Constructor;" => match name {
            "newInstance" => {
                let target_desc = state_str(vm, this, "class").unwrap_or_default();
                let argarr = arg_ref(args, 1);
                let mut call_args: Vec<Slot> = Vec::new();
                if let Some(o) = vm.heap.get(argarr) {
                    if let ObjKind::Array(a) = &o.kind {
                        call_args.extend(a.data.iter().copied());
                    }
                }
                construct_by_descriptor(vm, &target_desc, &call_args)
            }
            "getParameterTypes" => empty_class_array(vm),
            _ => CallOutcome::Decline,
        },
        "Ljava/lang/reflect/Array;" => match name {
            "newInstance" => {
                let clazz = arg_ref(args, 0);
                let desc = super::system::class_descriptor_of(vm, clazz).unwrap_or_else(|| "Ljava/lang/Object;".into());
                let len = arg_int(args, 1).max(0) as usize;
                let sym = vm.sym(&desc);
                match vm.heap.new_array(sym, &desc, len, Taint::CLEAN) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                }
            }
            "get" => {
                let arr = arg_ref(args, 0);
                let idx = arg_int(args, 1).max(0) as usize;
                match vm.heap.array_get(arr, idx) {
                    Some(s) => CallOutcome::Value(s),
                    None => ret_void(),
                }
            }
            "set" => {
                let arr = arg_ref(args, 0);
                let idx = arg_int(args, 1).max(0) as usize;
                if let Some(v) = args.get(2) {
                    vm.heap.array_set(arr, idx, *v);
                }
                ret_void()
            }
            "getLength" => {
                let arr = arg_ref(args, 0);
                ret_int(vm.heap.length_of(arr).unwrap_or(0) as i32)
            }
            _ => CallOutcome::Decline,
        },
        "Ljava/lang/reflect/Proxy;" => match name {
            "newProxyInstance" => {
                // Return a placeholder; handlers are app code but their
                // `invoke` is only reachable through a real proxy, which we do
                // not synthesise. Record the gap.
                vm.env.gap("Proxy.newProxyInstance");
                ret_obj(ObjRef::NULL)
            }
            _ => CallOutcome::Decline,
        },
        _ => {
            let _ = name;
            CallOutcome::Decline
        }
    }
}

/// Find a method of `class` (or its ancestors) with `name` whose parameter
/// count matches the supplied arguments. Used only as a fallback when the exact
/// prototype recorded at lookup time is unavailable.
fn resolve_by_shape(
    vm: &Vm,
    class: Sym,
    name: Sym,
    argc: usize,
) -> Option<MethodEntry> {
    let params_of = |proto: &str| -> Option<usize> {
        let inner = proto.strip_prefix('(')?;
        let inner = inner.split(')').next()?;
        Some(count_params(inner))
    };
    let mut cur = Some(class);
    let mut depth = 0;
    while let Some(c) = cur {
        if let Some(ci) = vm.registry.class(c) {
            for m in ci.direct_methods.iter().chain(ci.virtual_methods.iter()) {
                if m.key.name == name && m.code_off != 0 {
                    if let Some(n) = params_of(vm.sym_str(m.key.proto)) {
                        // `argc` includes the receiver for instance methods.
                        let want = if m.access & crate::dex::ACC_STATIC != 0 { argc } else { argc.saturating_sub(1) };
                        if n == want {
                            return Some(*m);
                        }
                    }
                }
            }
        }
        depth += 1;
        if depth > 64 {
            break;
        }
        cur = vm.registry.class(c).and_then(|ci| ci.superclass);
    }
    None
}

/// Count parameters in a descriptor fragment like `Landroid/content/Context;I`.
fn count_params(mut s: &str) -> usize {
    let mut n = 0;
    while let Some(c) = s.chars().next() {
        match c {
            '[' => {
                s = &s[1..];
            }
            'L' => {
                if let Some(p) = s.find(';') {
                    s = &s[p + 1..];
                    n += 1;
                } else {
                    break;
                }
            }
            _ => {
                s = &s[1..];
                n += 1;
            }
        }
    }
    n
}

/// Whether the real method behind a reflected handle is static. Falls back to
/// the recorded flag when the method cannot be resolved.
fn is_method_static(vm: &mut Vm, class_desc: &str, name: &str, proto: &str) -> bool {
    let class = vm.sym(class_desc);
    let mname = vm.sym(name);
    let mproto = vm.sym(proto);
    if let Some(e) = vm.registry.resolve_direct(class, mname, mproto) {
        return e.access & crate::dex::ACC_STATIC != 0;
    }
    if let Some(ci) = vm.registry.class(class) {
        for m in ci.direct_methods.iter() {
            if m.key.name == mname && m.access & crate::dex::ACC_STATIC != 0 {
                return true;
            }
        }
    }
    false
}

fn is_static_state(vm: &Vm, this: ObjRef) -> bool {
    state_int(vm, this, "static") != 0
}

fn empty_class_array(vm: &mut Vm) -> CallOutcome {
    let elem = vm.sym("Ljava/lang/Class;");
    match vm.heap.new_array(elem, "Ljava/lang/Class;", 0, Taint::CLEAN) {
        Ok(r) => ret_obj(r),
        Err(_) => ret_void(),
    }
}

/// Resolve and invoke `class->name(proto)` reflectively.
pub fn invoke_reflective(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class_desc: &str,
    name: &str,
    proto: &str,
    args: &[Slot],
) -> CallOutcome {
    let class = vm.sym(class_desc);
    let mname = vm.sym(name);
    let mproto = vm.sym(proto);
    if vm.registry.is_app_class(class) {
        // Dispatch virtual if there is a receiver, direct otherwise. The
        // prototype recorded by `getMethod` may be approximate (its return type
        // is guessed), so fall back to matching by name and argument shape.
        let entry = if args.first().map(|s| !s.is_null_ref()).unwrap_or(false)
            && vm.heap.class_of(args[0].v.as_ref()).map(|c| vm.registry.is_app_class(c)).unwrap_or(false)
        {
            let actual = vm.heap.class_of(args[0].v.as_ref()).unwrap_or(class);
            vm.registry.resolve_virtual(actual, mname, mproto)
                .or_else(|| vm.registry.resolve_direct(class, mname, mproto))
                .or_else(|| resolve_by_shape(vm, actual, mname, args.len()))
        } else {
            vm.registry.resolve_direct(class, mname, mproto)
                .or_else(|| resolve_by_shape(vm, class, mname, args.len()))
        };
        if let Some(entry) = entry {
            if entry.code_off != 0 {
                return match vm.execute(host, entry, args.to_vec()) {
                    Ok(slot) => CallOutcome::Value(slot),
                    Err(e) => {
                        vm.env.gap(&format!("reflective invoke {class_desc}.{name}: {e}"));
                        CallOutcome::Value(Slot::default())
                    }
                };
            }
        }
    }
    // Framework target: route through the host dispatcher.
    let key = MethodKey { class, name: mname, proto: mproto };
    super::android_call(vm, host, &key, args)
}

/// Build an instance and run its `<init>`, for `Constructor.newInstance` and
/// `Class.newInstance`.
pub fn construct_by_descriptor(vm: &mut Vm, desc: &str, args: &[Slot]) -> CallOutcome {
    let class = vm.sym(desc);
    let obj = if vm.registry.is_app_class(class) {
        vm.ensure_class_initialized(class);
        match vm.heap.new_instance(class) {
            Ok(o) => o,
            Err(_) => return ret_void(),
        }
    } else {
        match vm.heap.new_instance(class) {
            Ok(o) => o,
            Err(_) => return ret_void(),
        }
    };
    const CTOR: &str = "<init>";
    let ctor = vm.sym(CTOR);
    let proto_str = match args.len() {
        0 => "()V".to_string(),
        _ => {
            let mut p = String::from("(");
            for a in args {
                p.push_str(&descriptor_of_slot(vm, a));
            }
            p.push_str(")V");
            p
        }
    };
    let proto = vm.sym(&proto_str);
    if vm.registry.is_app_class(class) {
        // Try the exact prototype, then the no-arg constructor.
        let mut host = super::default_host();
        if let Some(entry) = vm.registry.resolve_direct(class, ctor, proto) {
            if entry.code_off != 0 {
                let mut a = vec![Slot::reference(obj)];
                a.extend_from_slice(args);
                let _ = vm.execute(&mut *host, entry, a);
            }
        } else if let Some(entry) = { let p0 = vm.sym("()V"); vm.registry.resolve_direct(class, ctor, p0) } {
            if entry.code_off != 0 {
                let _ = vm.execute(&mut *host, entry, vec![Slot::reference(obj)]);
            }
        }
    }
    CallOutcome::Value(Slot::reference(obj))
}

pub fn descriptor_of_slot(vm: &Vm, s: &Slot) -> String {
    match s.v {
        Value::Int(_) => "I".into(),
        Value::Long(_) => "J".into(),
        Value::Float(_) => "F".into(),
        Value::Double(_) => "D".into(),
        Value::Ref(r) if !r.is_null() => vm
            .heap
            .class_of(r)
            .map(|c| vm.sym_str(c).to_string())
            .unwrap_or_else(|| "Ljava/lang/Object;".into()),
        _ => "Ljava/lang/Object;".into(),
    }
}

fn read_reflective_field(
    vm: &mut Vm,
    class_desc: &str,
    field_name: &str,
    receiver: ObjRef,
    kind: &str,
) -> CallOutcome {
    // Static field on an app class: read from statics.
    if receiver.is_null() {
        let class = vm.sym(class_desc);
        let name = vm.sym(field_name);
        if let Some(entry) = vm
            .registry
            .fields
            .values()
            .find(|f| f.key.class == class && f.key.name == name)
            .copied()
        {
            let v = vm.statics.get(&entry.key).copied().unwrap_or_default();
            return CallOutcome::Value(match kind {
                "getInt" => Slot::int(v.v.as_int()),
                "getLong" => Slot::long(v.v.as_long()),
                "getBoolean" => Slot::int(if v.v.truthy() { 1 } else { 0 }),
                _ => v,
            });
        }
        return ret_obj(ObjRef::NULL);
    }
    // Instance field.
    let name = vm.sym(field_name);
    if let Some(inst) = vm.heap.instance(receiver) {
        for (k, v) in inst.fields.iter() {
            if k.name == name {
                return CallOutcome::Value(*v);
            }
        }
        // Framework state keys are addressable by name.
        if let Some(v) = inst.state.get(field_name) {
            return CallOutcome::Value(*v);
        }
    }
    ret_obj(ObjRef::NULL)
}

fn write_reflective_field(
    vm: &mut Vm,
    class_desc: &str,
    field_name: &str,
    receiver: ObjRef,
    value: Slot,
) -> CallOutcome {
    if receiver.is_null() {
        let class = vm.sym(class_desc);
        let name = vm.sym(field_name);
        if let Some(entry) = vm
            .registry
            .fields
            .values()
            .find(|f| f.key.class == class && f.key.name == name)
            .copied()
        {
            vm.statics.insert(entry.key, value);
        }
        return ret_void();
    }
    let name = vm.sym(field_name);
    if let Some(inst) = vm.heap.instance_mut(receiver) {
        if let Some(key) = inst.fields.keys().find(|k| k.name == name).copied() {
            inst.fields.insert(key, value);
        } else {
            inst.state.insert(field_name.to_string(), value);
        }
    }
    ret_void()
}

