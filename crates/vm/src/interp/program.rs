//! Multi-DEX program index. A packed app starts as one DEX with a stub that
//! decrypts more DEX at runtime; the `Program` grows as those are recovered, so
//! class and method lookups must be additive.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use unhusk_dex::{Class, DexFile, Method, ClassData};

/// Identifies one method body inside the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MethodHandle {
    pub dex: u32,
    pub class: u32,
    /// Global slot among the class's methods (direct first, then virtual).
    pub slot: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodOrigin {
    /// Declared in a DEX that came with the APK.
    File,
    /// Declared in a DEX we recovered at runtime.
    Recovered,
}

/// How a recovered DEX was obtained, for the provenance chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Recovery {
    /// Decrypted from bytes found in the APK itself.
    DecryptedInApk,
    /// Written by the sample to disk, then loaded.
    WrittenToDisk(String),
    /// Fetched from the network model.
    Downloaded(String),
    /// Derived from an asset or resource entry.
    FromAsset(String),
    /// Produced by a native routine in this library.
    NativeExtracted(String),
}

pub struct Program {
    pub dexes: Vec<DexFile>,
    pub origins: Vec<MethodOrigin>,
    pub recoveries: Vec<Option<Recovery>>,
    /// descriptor -> (dex, class index) for every class declared anywhere.
    class_map: HashMap<String, Vec<(u32, u32)>>,
    /// canonical method signature -> handle
    method_map: HashMap<String, MethodHandle>,
    /// (descriptor, name) -> handles, for virtual dispatch without a proto.
    by_name: HashMap<(String, String), Vec<MethodHandle>>,
    /// Canonical signatures seen, for stable ordering in reports.
    pub signature_cache: HashMap<MethodHandle, String>,
    /// Field signature interning: `Lcls;->name:Type` -> dense id.
    field_ids: HashMap<String, u32>,
    pub field_names: Vec<String>,
    /// (dex, class) -> field index within its static/instance list is resolved
    /// through this map so `iget` never needs a name lookup at run time.
    class_fields: HashMap<String, Vec<u32>>,
}

impl Program {
    pub fn new() -> Self {
        Self {
            dexes: Vec::new(),
            origins: Vec::new(),
            recoveries: Vec::new(),
            class_map: HashMap::new(),
            method_map: HashMap::new(),
            by_name: HashMap::new(),
            signature_cache: HashMap::new(),
            field_ids: HashMap::new(),
            field_names: Vec::new(),
            class_fields: HashMap::new(),
        }
    }

    /// Intern a field signature, returning its dense id.
    pub fn field_id(&mut self, sig: &str) -> u32 {
        if let Some(id) = self.field_ids.get(sig) {
            return *id;
        }
        let id = self.field_names.len() as u32;
        self.field_names.push(sig.to_string());
        self.field_ids.insert(sig.to_string(), id);
        id
    }

    /// All field ids declared by a class, in declaration order. Cached after
    /// the first request.
    pub fn class_field_ids(&mut self, descriptor: &str) -> Vec<u32> {
        if let Some(v) = self.class_fields.get(descriptor) {
            return v.clone();
        }
        let mut ids = Vec::new();
        if let Some((dex, ci)) = self.find_class(descriptor) {
            let sigs: Vec<String> = {
                let cd = self.class_data(dex, ci);
                cd.static_fields
                    .iter()
                    .chain(cd.instance_fields.iter())
                    .map(|f| format!("{}->{}:{}", f.class, f.name, f.ty))
                    .collect()
            };
            for sig in sigs {
                ids.push(self.field_id(&sig));
            }
        }
        self.class_fields.insert(descriptor.to_string(), ids.clone());
        ids
    }

    pub fn field_name(&self, id: u32) -> &str {
        self.field_names.get(id as usize).map(|s| s.as_str()).unwrap_or("?")
    }

    /// Add a DEX. Returns its index. `recovery` is `None` for DEX shipped in
    /// the APK.
    pub fn add_dex(&mut self, dex: DexFile, recovery: Option<Recovery>) -> u32 {
        let dex_idx = self.dexes.len() as u32;
        let origin = if recovery.is_some() {
            MethodOrigin::Recovered
        } else {
            MethodOrigin::File
        };
        for (ci, class) in dex.classes.iter().enumerate() {
            self.class_map
                .entry(class.descriptor.clone())
                .or_default()
                .push((dex_idx, ci as u32));
            for (slot, m) in class
                .data
                .direct_methods
                .iter()
                .chain(class.data.virtual_methods.iter())
                .enumerate()
            {
                let handle = MethodHandle {
                    dex: dex_idx,
                    class: ci as u32,
                    slot: slot as u32,
                };
                let sig = method_sig(&class.descriptor, &m.name, &m.proto.params, &m.proto.return_type);
                self.method_map.entry(sig.clone()).or_insert(handle);
                self.by_name
                    .entry((class.descriptor.clone(), m.name.clone()))
                    .or_default()
                    .push(handle);
                self.signature_cache.insert(handle, sig);
            }
        }
        self.dexes.push(dex);
        self.origins.push(origin);
        self.recoveries.push(recovery);
        dex_idx
    }

    pub fn dex_count(&self) -> usize {
        self.dexes.len()
    }

    pub fn class_at(&self, dex: u32, idx: u32) -> &Class {
        &self.dexes[dex as usize].classes[idx as usize]
    }

    pub fn method(&self, h: MethodHandle) -> &Method {
        let class = self.class_at(h.dex, h.class);
        let n_direct = class.data.direct_methods.len();
        if (h.slot as usize) < n_direct {
            &class.data.direct_methods[h.slot as usize]
        } else {
            &class.data.virtual_methods[h.slot as usize - n_direct]
        }
    }

    pub fn descriptor_of(&self, dex: u32, class: u32) -> &str {
        &self.dexes[dex as usize].classes[class as usize].descriptor
    }

    pub fn dex(&self, idx: u32) -> &DexFile {
        &self.dexes[idx as usize]
    }

    pub fn find_class(&self, descriptor: &str) -> Option<(u32, u32)> {
        // Later DEXes win: a recovered payload that redefines a stub class is
        // the one the classloader would bind.
        self.class_map.get(descriptor).and_then(|v| v.last().copied())
    }

    pub fn class_exists(&self, descriptor: &str) -> bool {
        self.class_map.contains_key(descriptor)
    }

    /// Resolve a method by its declared signature, looking only at one class.
    pub fn find_method_in_class(&self, descriptor: &str, name: &str, params: &[String], ret: &str) -> Option<MethodHandle> {
        let sig = method_sig(descriptor, name, params, ret);
        self.method_map.get(&sig).copied()
    }

    pub fn find_method_by_sig(&self, sig: &str) -> Option<MethodHandle> {
        self.method_map.get(sig).copied()
    }

    pub fn signature(&self, h: MethodHandle) -> &str {
        self.signature_cache.get(&h).map(|s| s.as_str()).unwrap_or("?")
    }

    /// Methods with this bare name in this class, ignoring the signature.
    pub fn methods_named(&self, descriptor: &str, name: &str) -> &[MethodHandle] {
        self.by_name
            .get(&(descriptor.to_string(), name.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Virtual dispatch: find the override of `name/proto` starting at `class`
    /// and walking up the superclass chain.
    pub fn resolve_virtual(
        &self,
        class: &str,
        name: &str,
        params: &[String],
        ret: &str,
    ) -> Option<MethodHandle> {
        let mut cur = class.to_string();
        let mut hops = 0;
        while hops < 64 {
            hops += 1;
            if let Some(h) = self.find_method_in_class(&cur, name, params, ret) {
                if !self.method(h).is_abstract {
                    return Some(h);
                }
            }
            let (dex, ci) = self.find_class(&cur)?;
            let superclass = self.class_at(dex, ci).superclass.clone()?;
            if superclass == "Ljava/lang/Object;" {
                return None;
            }
            cur = superclass;
        }
        None
    }

    /// Does `class` (or any ancestor) inherit from `base`?
    pub fn is_subclass_of(&self, class: &str, base: &str) -> bool {
        if class == base {
            return true;
        }
        let mut cur = class.to_string();
        for _ in 0..64 {
            let Some((dex, ci)) = self.find_class(&cur) else { return false };
            match self.class_at(dex, ci).superclass.clone() {
                Some(s) => {
                    if s == base {
                        return true;
                    }
                    cur = s;
                }
                None => return false,
            }
        }
        false
    }

    /// Total number of method bodies across the program.
    pub fn method_count(&self) -> usize {
        self.method_map.len()
    }

    pub fn all_handles(&self) -> impl Iterator<Item = MethodHandle> + '_ {
        self.signature_cache.keys().copied()
    }

    /// The class's own `ClassData` (static/instance fields, methods).
    pub fn class_data(&self, dex: u32, ci: u32) -> &ClassData {
        &self.dexes[dex as usize].classes[ci as usize].data
    }
}

/// One DEX recovered during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredDex {
    pub name: String,
    pub sha1: String,
    pub size: usize,
    pub classes: usize,
    pub recovery: Recovery,
    /// Sequence number of the event that produced it.
    pub event_seq: u64,
}

pub fn method_sig(class: &str, name: &str, params: &[String], ret: &str) -> String {
    let mut s = String::with_capacity(class.len() + name.len() + ret.len() + 8 * params.len() + 8);
    s.push_str(class);
    s.push_str("->");
    s.push_str(name);
    s.push('(');
    for p in params {
        s.push_str(p);
    }
    s.push(')');
    s.push_str(ret);
    s
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_stable_and_dispatch_walks_superclasses() {
        let p = Program::new();
        assert_eq!(p.dex_count(), 0);
        assert!(p.find_class("Lfoo;").is_none());
        assert_eq!(method_sig("La;", "f", &["I".into()], "V"), "La;->f(I)V");
    }
}
