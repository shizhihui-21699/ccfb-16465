//! Dynamic code loading: the part of the sandbox that makes a packer confess.
//!
//! A loader has to hand its decrypted payload to *something* the runtime will
//! execute. In Dalvik that is one of a small set of APIs:
//!
//!   * `new DexClassLoader(path, ...)` / `PathClassLoader` -> a file we watched
//!     being written
//!   * `DexFile.loadDex(path, ...)`                      -> the same
//!   * `InMemoryDexClassLoader(ByteBuffer, ...)`         -> bytes still in RAM
//!   * `ClassLoader.loadClass("...")`                    -> by name, in-process
//!
//! We intercept all of them, parse the payload as a DEX, add it to the program,
//! and (for class loads) resolve and execute the requested class's static
//! initializer plus any explicitly invoked entry point.

use crate::events::{EventKind, Layer};
use crate::heap::ObjectValue;
use crate::interp::program::Recovery;
use crate::interp::state::Machine;
use crate::limits::StopReason;
use crate::value::Value;

impl Machine {
    /// A DEX-shaped file was written to the virtual filesystem.
    pub(crate) fn note_dynamic_file(&mut self, path: String, data: Vec<u8>) {
        self.pending_files.insert(path, data);
    }

    /// A payload we decoded in memory (from a cipher or base64 operation).
    pub(crate) fn note_payload(&mut self, data: Vec<u8>, source: &str, category: &'static str) {
        if !crate::crypto::looks_like_dex(&data) {
            return;
        }
        if self.recovered.len() as u32 >= self.policy.max_recovered_dex {
            self.budget.stop(StopReason::Budget, "recovered DEX limit");
            return;
        }
        let name = format!("decoded@{:x}.dex", self.budget.instructions);
        self.recover_dex_bytes(
            data,
            name,
            Recovery::DecryptedInApk,
            source.to_string(),
            category,
        );
    }

    /// A classloader was constructed over `path`. If we saw a DEX written
    /// there, recover it now.
    pub(crate) fn load_dex_from_path(&mut self, path: &str, loader: &str) {
        if !self.budget.charge_dynamic_load() {
            return;
        }
        let normalized = crate::env::normalize_path(path);
        let data = self
            .env
            .fs
            .read(&normalized)
            .map(|d| d.to_vec())
            .or_else(|| self.pending_files.get(&normalized).cloned())
            .or_else(|| {
                // The APK's own assets may be the payload.
                self.env
                    .assets
                    .get(normalized.trim_start_matches('/'))
                    .cloned()
            });
        let Some(data) = data else {
            self.emit(
                EventKind::DynamicLoad,
                Layer::Framework,
                self.current_method_display(),
                format!("{loader}({path})"),
                vec![path.to_string()],
                Some("no such file in virtual filesystem".into()),
            );
            return;
        };
        if !crate::crypto::looks_like_dex(&data) {
            // A ZIP of classes*.dex (a nested APK/jar) is the other common form.
            if crate::crypto::looks_like_zip(&data) {
                if let Some(inner) = self.dex_from_zip(&data) {
                    let base = normalized
                        .rsplit('/')
                        .next()
                        .unwrap_or(&normalized)
                        .to_string();
                    self.recover_dex_bytes(
                        inner,
                        format!("{base}!"),
                        Recovery::WrittenToDisk(normalized),
                        format!("{loader}({path})"),
                        "load",
                    );
                    return;
                }
            }
            self.emit(
                EventKind::DynamicLoad,
                Layer::Framework,
                self.current_method_display(),
                format!("{loader}({path})"),
                vec![path.to_string()],
                Some(format!("payload is not DEX ({} bytes)", data.len())),
            );
            return;
        }
        let base = normalized
            .rsplit('/')
            .next()
            .unwrap_or(&normalized)
            .to_string();
        self.recover_dex_bytes(
            data,
            base,
            Recovery::WrittenToDisk(normalized),
            format!("{loader}({path})"),
            "load",
        );
    }

    /// An in-memory DEX payload is being turned into a classloader.
    pub(crate) fn load_dex_from_bytes(&mut self, bytes: Vec<u8>, source: String) {
        if !self.budget.charge_dynamic_load() {
            return;
        }
        if crate::crypto::looks_like_zip(&bytes) {
            if let Some(inner) = self.dex_from_zip(&bytes) {
                self.recover_dex_bytes(
                    inner,
                    source.clone(),
                    Recovery::Downloaded(source.clone()),
                    source,
                    "load",
                );
                return;
            }
        }
        self.recover_dex_bytes(
            bytes,
            source.clone(),
            Recovery::Downloaded(source.clone()),
            source,
            "load",
        );
    }

    fn dex_from_zip(&self, zip_bytes: &[u8]) -> Option<Vec<u8>> {
        let cursor = std::io::Cursor::new(zip_bytes);
        let mut archive = zip::ZipArchive::new(cursor).ok()?;
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).ok()?;
            let name = f.name().to_string();
            if name.ends_with(".dex") {
                let mut out = Vec::new();
                use std::io::Read;
                f.read_to_end(&mut out).ok()?;
                if crate::crypto::looks_like_dex(&out) {
                    return Some(out);
                }
            }
        }
        None
    }

    /// Parse `data` as a DEX and add it to the program. The recovered DEX is
    /// reported even when it fails to parse: a malformed payload is itself a
    /// finding (custom format, second stage, or a decoy).
    pub(crate) fn recover_dex_bytes(
        &mut self,
        data: Vec<u8>,
        name: String,
        recovery: Recovery,
        source: String,
        category: &'static str,
    ) -> Option<u32> {
        use sha1::{Digest, Sha1};
        if self.recovered.len() as u32 >= self.policy.max_recovered_dex {
            return None;
        }
        let mut h = Sha1::new();
        h.update(&data);
        let sha1 = h
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let parsed = unhusk_dex::parse(&data);
        match parsed {
            Ok(dex) => {
                let classes = dex.classes.len();
                let methods = dex.all_methods().len();
                let seq = self.trace.seq;
                self.recovered.push(crate::interp::program::RecoveredDex {
                    name: name.clone(),
                    sha1: sha1.clone(),
                    size: data.len(),
                    classes,
                    recovery: recovery.clone(),
                    event_seq: seq,
                });
                let mut payloads = self.recovered_payloads.clone();
                payloads.push((name.clone(), data.clone()));
                self.recovered_payloads = payloads;
                let dex_idx = self.program.add_dex(dex, Some(recovery.clone()));
                self.emit(
                    EventKind::DynamicLoad,
                    Layer::RecoveredDex,
                    self.current_method_display(),
                    source.clone(),
                    vec![format!(
                        "{name} ({classes} classes, {methods} methods, sha1 {sha1})"
                    )],
                    Some(format!("recovered DEX added as dex#{dex_idx}")),
                );
                Some(dex_idx)
            }
            Err(e) => {
                self.emit(
                    EventKind::DynamicLoad,
                    Layer::Framework,
                    self.current_method_display(),
                    source.clone(),
                    vec![format!("{name} ({} bytes, sha1 {sha1})", data.len())],
                    Some(format!("payload rejected as DEX: {e}")),
                );
                let _ = category;
                None
            }
        }
    }

    /// Dispatch `ClassLoader.loadClass("name")` into freshly recovered code and
    /// run its static initialiser. This is what a packer does immediately after
    /// installing its loader, and it is where the real entry point lives.
    pub(crate) fn invoke_loaded_class(&mut self, descriptor: &str) -> bool {
        if self.budget.is_stopped() {
            return false;
        }
        let Some((dex, ci)) = self.program.find_class(descriptor) else {
            return false;
        };
        // Static initialiser, then any public static `run`/`start`/`init`.
        let mut to_run = Vec::new();
        let class = self.program.class_at(dex, ci);
        for m in class.methods() {
            if m.name == "<clinit>" && m.code.is_some() {
                to_run.push((m.name.clone(), Vec::new()));
            }
        }
        for m in class.methods() {
            if m.is_static
                && m.code.is_some()
                && m.name != "<clinit>"
                && matches!(
                    m.name.as_str(),
                    "run" | "start" | "init" | "attachBaseContext" | "onCreate"
                )
            {
                to_run.push((m.name.clone(), m.proto.params.clone()));
            }
        }
        let mut started = false;
        for (name, params) in to_run {
            let handles = self.program.methods_named(descriptor, &name).to_vec();
            for h in handles {
                let m = self.program.method(h);
                if m.proto.params != params || m.code.is_none() {
                    continue;
                }
                if self.budget.is_stopped() {
                    return started;
                }
                let _ = self.push_frame(h, Vec::new(), None, None);
                started = true;
            }
        }
        started
    }

    /// `ClassLoader.loadClass` / reflection: note the class, and run it only if
    /// it came from a payload recovered at runtime.
    ///
    /// A reflective `forName`/`getDeclaredMethod` inside one of the app's *own*
    /// shipped DEX files is a library doing normal work. Treating every one as
    /// a dynamic load would both burn the budget on a benign app and inflate
    /// the trace with launches the sample never requested.
    pub(crate) fn note_class_load(&mut self, name: &str) {
        let desc = if name.starts_with('L') {
            name.to_string()
        } else {
            format!("L{};", name.replace('.', "/"))
        };
        let exists = self.program.class_exists(&desc);
        if exists {
            let from_payload = self
                .program
                .find_class(&desc)
                .map(|(dex, _)| {
                    self.program.origins[dex as usize]
                        == crate::interp::program::MethodOrigin::Recovered
                })
                .unwrap_or(false);
            if from_payload {
                self.invoke_loaded_class(&desc);
            }
        } else {
            self.emit(
                EventKind::DynamicLoad,
                Layer::Framework,
                self.current_method_display(),
                format!("loadClass({name})"),
                vec![desc.clone()],
                Some("class not present in any known DEX (yet)".into()),
            );
        }
    }

    /// Model for `InMemoryDexClassLoader(ByteBuffer)` and friends.
    pub(crate) fn in_memory_loader(&mut self, buffer: Option<Value>, source: String) {
        let data = buffer
            .and_then(|v| v.as_obj())
            .and_then(|id| match self.heap.get(id) {
                Some(crate::heap::Object::Model { fields, .. }) => match fields.get("buf") {
                    Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                    _ => None,
                },
                Some(crate::heap::Object::Array { bytes, .. }) => Some(bytes.clone()),
                _ => None,
            });
        match data {
            Some(d) => self.load_dex_from_bytes(d, source),
            None => self.emit(
                EventKind::DynamicLoad,
                Layer::Framework,
                self.current_method_display(),
                source,
                vec![],
                Some("in-memory loader constructed with unknown buffer".into()),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Native layer
// ---------------------------------------------------------------------------

use crate::native::{NativeLimits, NativeOutcome};

impl Machine {
    /// A `System.loadLibrary("foo")` was called. Record it and remember the
    /// library so a later `native` method declaration can be dispatched to it.
    pub(crate) fn note_native_library(&mut self, name: &str) {
        let lib = if name.ends_with(".so") {
            name.to_string()
        } else {
            format!("lib{name}.so")
        };
        if !self.loaded_libraries.contains(&lib) {
            self.loaded_libraries.push(lib.clone());
        }
        self.emit(
            crate::events::EventKind::DynamicLoad,
            crate::events::Layer::Native,
            self.current_method_display(),
            format!("System.loadLibrary({name})"),
            vec![lib.clone()],
            Some("library registered for native dispatch".into()),
        );
    }

    /// Invoke a `native` method declared by a sample class.
    ///
    /// This is where most real packers do their work: the DEX declares
    /// `private static native byte[] decrypt(byte[])` and the body is in the
    /// `.so`. We find the library that exports the JNI entry point, load its
    /// executable segment, and run the AArch64 interpreter over it with the
    /// Java arguments mapped into the flat address space.
    pub(crate) fn call_native(
        &mut self,
        mr: &unhusk_dex::model::MethodRef,
        args: &[crate::value::Value],
    ) -> Option<crate::value::Value> {
        if !self.policy.emulate_native {
            return None;
        }
        if self.loaded_libraries.is_empty() && self.program.class_exists(&mr.class) {
            // A native method in a class that never loaded a library: it may
            // still be in a shipped .so, found by the JNI mangled name.
        }
        let jni_name = jni_symbol(&mr.class, &mr.name);
        let libs = self.native_libraries.clone();
        let mut found: Option<(String, Vec<u8>)> = None;
        for (path, data) in &libs {
            if elf_exports(data, &jni_name) {
                found = Some((path.clone(), data.clone()));
                break;
            }
        }
        let (path, elf) = match found {
            Some(f) => f,
            None => {
                self.emit(
                    crate::events::EventKind::DynamicLoad,
                    crate::events::Layer::Native,
                    self.current_method_display(),
                    mr.signature(),
                    vec![format!(
                        "looked for export {jni_name} in {} library(ies)",
                        libs.len()
                    )],
                    Some("native method not resolvable to a shipped library".into()),
                );
                return None;
            }
        };
        let entry = crate::native::aarch64::find_export(&elf, &jni_name);
        let code = match entry
            .and_then(|(file_off, _)| crate::native::aarch64::Code::from_elf_at(&elf, file_off))
            .or_else(|| crate::native::aarch64::Code::from_elf(&elf))
        {
            Some(c) => (c.bytes.to_vec(), c.vaddr),
            None => {
                self.emit(
                    crate::events::EventKind::DynamicLoad,
                    crate::events::Layer::Native,
                    self.current_method_display(),
                    mr.signature(),
                    vec![format!("{path}: no executable AArch64 segment")],
                    Some("library is not an AArch64 executable".into()),
                );
                return None;
            }
        };
        let (code_bytes, code_vaddr) = code;
        // The segment was extracted starting at its own `p_offset`, so a
        // virtual address maps to `mem_base + (va - segment_vaddr)`.
        let entry_vaddr = entry.map(|(_, va)| va).unwrap_or(code_vaddr);

        // Map arguments using the JNI calling convention:
        //   x0 = JNIEnv*, x1 = jclass (static) or jobject (instance),
        //   x2.. = the Java arguments in order.
        //
        // Arrays are modelled as raw pointers into the emulated address space.
        // That is a deliberate simplification: a real stub fetches the element
        // pointer with `GetByteArrayElements`, which we answer in the import
        // table by returning the same buffer. Either route ends at the bytes
        // the stub operates on, which is what matters for recovery.
        let mut m = crate::native::aarch64::Machine::new(NativeLimits {
            max_steps: self.policy.native_steps,
        });
        m.write_mem(m.mem_base, &code_bytes);
        const ARENA: u64 = 0x1010_0000;
        const HANDLES: u64 = 0x1018_0000;
        let mut next = ARENA;
        // (java heap object, native address, length) for every array argument,
        // so writes can be copied back afterwards.
        let mut handles: Vec<(u32, u64, usize)> = Vec::new();
        for (i, a) in args.iter().enumerate().take(6) {
            let slot = i + 2;
            match a {
                crate::value::Value::Obj(id) if *id != 0 => {
                    let bytes = match self.heap.get(*id) {
                        Some(crate::heap::Object::Array { bytes, .. }) => Some(bytes.clone()),
                        Some(crate::heap::Object::Str { value, .. }) => {
                            Some(value.clone().into_bytes())
                        }
                        _ => None,
                    };
                    match bytes {
                        Some(b) => {
                            m.write_mem(next, &b);
                            handles.push((*id, next, b.len()));
                            m.regs[slot] = next;
                            next += (b.len() as u64).div_ceil(16) * 16 + 16;
                        }
                        None => m.regs[slot] = 0x7000_0000 + i as u64,
                    }
                }
                crate::value::Value::Obj(_) => m.regs[slot] = 0,
                v => m.regs[slot] = v.as_i64() as u64,
            }
        }
        m.regs[0] = HANDLES;
        m.regs[1] = 0x7000_0000;

        let entry_off = entry_vaddr.saturating_sub(code_vaddr);
        let outcome = m.run(
            m.mem_base + entry_off,
            &NativeLimits {
                max_steps: self.policy.native_steps,
            },
        );
        let steps = outcome.steps();
        let detail = match &outcome {
            NativeOutcome::Returned { .. } => "returned".to_string(),
            NativeOutcome::Unsupported { pc, reason, .. } => {
                format!("stopped at pc 0x{pc:x}: {reason}")
            }
            NativeOutcome::Budget { .. } => "step budget exhausted".to_string(),
            NativeOutcome::Halted { reason, .. } => format!("halted: {reason}"),
        };
        let complete = outcome.is_complete();

        // Write the possibly-modified argument buffers back into the Java
        // heap objects. This is the crucial step for void-returning decryptors:
        // the sample allocated `byte[] buf`, handed it to native code, and will
        // now use it directly. Without the write-back the caller's array keeps
        // its ciphertext and the unpacking chain stops here.
        let mut recovered_here: Vec<(Vec<u8>, String)> = Vec::new();
        for (id, addr, len) in handles.clone() {
            let Some(written) = m.read_mem(addr, len).map(|b| b.to_vec()) else {
                continue;
            };
            if let Some(crate::heap::Object::Array { bytes, prov, .. }) = self.heap.get_mut(id) {
                if bytes.len() == written.len() && bytes[..] != written[..] {
                    bytes.copy_from_slice(&written);
                    prov.add(crate::value::Tag::Decoded);
                    prov.add(crate::value::Tag::Built);
                }
            }
            if crate::crypto::looks_like_dex(&written) {
                recovered_here.push((written, format!("native:{jni_name}")));
            }
        }
        // Also check the whole arena tail for a DEX header, in case the stub
        // allocated its own output buffer.
        for off in (ARENA..next).step_by(16) {
            if let Some(b) = m.read_mem(off, 8) {
                if &b[..4] == b"dex\n" {
                    let mut len = 0usize;
                    if let Some(hdr) = m.read_mem(off, 32) {
                        len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
                    }
                    if len > 8 && len < 32 * 1024 * 1024 {
                        if let Some(full) = m.read_mem(off, len) {
                            if crate::crypto::looks_like_dex(full) {
                                recovered_here
                                    .push((full.to_vec(), format!("native:{jni_name}@0x{off:x}")));
                            }
                        }
                    }
                }
            }
        }

        self.emit(
            crate::events::EventKind::DynamicLoad,
            crate::events::Layer::Native,
            self.current_method_display(),
            mr.signature(),
            vec![format!("{path} :: {jni_name}, {steps} steps")],
            Some(if complete {
                format!(
                    "native returned; {detail}{}",
                    if recovered_here.is_empty() {
                        String::new()
                    } else {
                        format!(", {} payload(s) produced", recovered_here.len())
                    }
                )
            } else {
                format!("native emulation incomplete: {detail}")
            }),
        );
        for (bytes, src) in recovered_here {
            // The payload came out of this library, so record it as such rather
            // than as something downloaded.
            self.budget.charge_dynamic_load();
            let seq = self.trace.seq;
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(&bytes);
            let sha1 = h
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            match unhusk_dex::parse(&bytes) {
                Ok(dex) => {
                    let classes = dex.classes.len();
                    let methods = dex.all_methods().len();
                    // Name it after the library, which is what the analyst
                    // needs to point at; the mangled symbol is in the event.
                    let lib_base = path.rsplit('/').next().unwrap_or(&path).to_string();
                    let name = format!("{lib_base}::{jni_name}.dex");
                    self.recovered.push(crate::interp::program::RecoveredDex {
                        name: name.clone(),
                        sha1: sha1.clone(),
                        size: bytes.len(),
                        classes,
                        recovery: crate::interp::program::Recovery::NativeExtracted(path.clone()),
                        event_seq: seq,
                    });
                    self.recovered_payloads.push((name.clone(), bytes.clone()));
                    let dex_idx = self.program.add_dex(
                        dex,
                        Some(crate::interp::program::Recovery::NativeExtracted(
                            path.clone(),
                        )),
                    );
                    self.emit(
                        crate::events::EventKind::DynamicLoad,
                        crate::events::Layer::RecoveredDex,
                        self.current_method_display(),
                        format!("{path} :: {jni_name}"),
                        vec![format!(
                            "{name} ({classes} classes, {methods} methods, sha1 {sha1})"
                        )],
                        Some(format!("recovered DEX added as dex#{dex_idx}")),
                    );
                }
                Err(e) => self.emit(
                    crate::events::EventKind::DynamicLoad,
                    crate::events::Layer::Native,
                    self.current_method_display(),
                    format!("{path} :: {jni_name}"),
                    vec![format!("{src} ({} bytes, sha1 {sha1})", bytes.len())],
                    Some(format!("native output rejected as DEX: {e}")),
                ),
            }
        }

        // Deliver a null/default: the return value of a native decryptor is
        // almost always an array we have already inspected, and we cannot
        // reconstruct a Java ByteArray from the AArch64 calling convention
        // without the stub's own JNI calls.
        None
    }
}

/// Mangled JNI symbol for `class#method`.
pub fn jni_symbol(class_desc: &str, name: &str) -> String {
    let c = class_desc.trim_start_matches('L').trim_end_matches(';');
    let mut s = String::with_capacity(c.len() + name.len() + 8);
    s.push_str("Java_");
    for ch in c.bytes() {
        match ch {
            b'/' => s.push('_'),
            b'_' => s.push_str("_1"),
            b';' => s.push_str("_2"),
            b'[' => s.push_str("_3"),
            b'.' => s.push('_'),
            other => s.push(other as char),
        }
    }
    s.push('_');
    for ch in name.bytes() {
        match ch {
            b'_' => s.push_str("_1"),
            other => s.push(other as char),
        }
    }
    s
}

/// Does this ELF's dynamic symbol table contain `symbol`?
fn elf_exports(data: &[u8], symbol: &str) -> bool {
    // Cheap and robust enough: a JNI export name appears verbatim in .dynstr.
    data.windows(symbol.len()).any(|w| w == symbol.as_bytes())
}
