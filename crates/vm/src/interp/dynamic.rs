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
        let name = format!("runtime:{}", source.rsplit("->").next().unwrap_or("payload").trim());
        self.recover_dex_bytes(data, name, Recovery::DecryptedInApk, source.to_string(), category);
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
                self.env.assets.get(normalized.trim_start_matches('/')).cloned()
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
                    self.recover_dex_bytes(
                        inner,
                        format!("zip:{path}"),
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
        self.recover_dex_bytes(
            data,
            format!("file:{path}"),
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
                self.recover_dex_bytes(inner, source.clone(), Recovery::Downloaded(source.clone()), source, "load");
                return;
            }
        }
        self.recover_dex_bytes(bytes, source.clone(), Recovery::Downloaded(source.clone()), source, "load");
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
                    vec![format!("{name} ({classes} classes, {methods} methods, sha1 {sha1})")],
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
                && matches!(m.name.as_str(), "run" | "start" | "init" | "attachBaseContext" | "onCreate")
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

    /// `ClassLoader.loadClass` / reflection: recover the class if its defining
    /// DEX has been loaded, then run it.
    pub(crate) fn note_class_load(&mut self, name: &str) {
        let desc = if name.starts_with('L') { name.to_string() } else { format!("L{};", name.replace('.', "/")) };
        let exists = self.program.class_exists(&desc);
        if exists {
            self.invoke_loaded_class(&desc);
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
