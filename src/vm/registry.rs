//! Class registry and linker across DEX images.
//!
//! Static multidex APKs and packers that decrypt DEX at runtime both end up
//! here: every parsed image is registered into one symbol space keyed by
//! descriptor, so a method defined in a decrypted image can call one from the
//! shell image and vice versa. Dynamic images are registered with *priority*:
//! a packer's shell typically ships a stub class with the same name as the real
//! one in its payload, and Android's child-first `DexClassLoader` therefore runs
//! the payload's version. Registering the payload later must replace the stub,
//! or the analysis would keep executing the packer's decoy.

use std::collections::HashMap;
use std::sync::Arc;

use crate::dex::{DexFile, EncodedValue, NO_INDEX};

use super::intern::{FieldKey, Interner, MethodKey, Sym};
use super::value::{ObjRef, Slot, Value};

/// One method implementation: which image, which code item.
#[derive(Debug, Clone, Copy)]
pub struct MethodEntry {
    pub key: MethodKey,
    pub access: u32,
    pub dex: u32,
    pub method_idx: u32,
    pub code_off: u32,
}

/// Initial value of a static field. String/class values are stored as indices
/// into the defining image so the VM can materialise them on the heap, where
/// they need a `ObjRef`.
#[derive(Debug, Clone, Copy)]
pub enum StaticInit {
    Value(Slot),
    Str { image: u32, idx: u32 },
    Type { image: u32, idx: u32 },
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldEntry {
    pub key: FieldKey,
    pub access: u32,
    pub static_init: Option<StaticInit>,
}

#[derive(Debug, Clone)]
pub struct ProtoInfo {
    pub desc: Sym,
    pub params: Vec<Sym>,
    pub ret: Sym,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub desc: Sym,
    pub superclass: Option<Sym>,
    pub interfaces: Vec<Sym>,
    pub access: u32,
    /// Image that defines the class.
    pub dex: u32,
    pub static_fields: Vec<FieldEntry>,
    pub instance_fields: Vec<FieldEntry>,
    pub direct_methods: Vec<MethodEntry>,
    pub virtual_methods: Vec<MethodEntry>,
    /// Whether `<clinit>` has been run in this scenario. Reset per scenario by
    /// cloning the registry.
    pub initialized: bool,
    pub init_state: InitState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitState {
    Uninitialized,
    InProgress,
    Done,
    Failed,
}

/// Static field storage is per-scenario; the registry is cloned per scenario so
/// one scenario's `<clinit>` effects cannot leak into another.
#[derive(Default)]
pub struct Statics {
    /// (class, field) -> value
    pub values: HashMap<FieldKey, Slot>,
}

pub struct Registry {
    pub interner: Interner,
    pub images: Vec<Arc<DexFile>>,
    pub classes: HashMap<Sym, ClassInfo>,
    /// Method key -> entry, across every registered image.
    pub methods: HashMap<MethodKey, MethodEntry>,
    /// Field key -> entry.
    pub fields: HashMap<FieldKey, FieldEntry>,
    pub protos: HashMap<Sym, ProtoInfo>,
    /// Ratio of method bodies we failed to index, for the coverage note.
    pub skipped_methods: usize,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            interner: Interner::new(),
            images: Vec::new(),
            classes: HashMap::new(),
            methods: HashMap::new(),
            fields: HashMap::new(),
            protos: HashMap::new(),
            skipped_methods: 0,
        }
    }

    /// Register a parsed image. `priority` images (decrypted payloads) replace
    /// existing definitions of the same descriptor.
    pub fn add_image(&mut self, dex: Arc<DexFile>, priority: bool) -> usize {
        let image_index = self.images.len() as u32;
        self.images.push(dex.clone());
        self.register_image(image_index, priority);
        image_index as usize
    }

    fn register_image(&mut self, image_index: u32, priority: bool) {
        let dex = self.images[image_index as usize].clone();
        // Prototypes first, so method keys can be built.
        for p in &dex.protos {
            let desc = self.proto_desc(&dex, p);
            let desc_sym = self.interner.intern(&desc);
            if self.protos.contains_key(&desc_sym) {
                continue;
            }
            let mut params = Vec::new();
            if p.parameters_off != 0 {
                if let Ok(list) = dex.type_list(p.parameters_off) {
                    for t in list {
                        let d = dex.type_name(t).to_string();
                        params.push(self.interner.intern(&d));
                    }
                }
            }
            let ret_desc = dex.type_name(p.return_type_idx).to_string();
            let ret = self.interner.intern(&ret_desc);
            self.protos.insert(desc_sym, ProtoInfo { desc: desc_sym, params, ret });
        }

        for (ci, cd) in dex.classes.iter().enumerate() {
            let desc_str = dex.type_name(cd.class_idx).to_string();
            let desc = self.interner.intern(&desc_str);
            if self.classes.contains_key(&desc) && !priority {
                continue;
            }
            let superclass = if cd.superclass_idx == NO_INDEX {
                None
            } else {
                let s = dex.type_name(cd.superclass_idx).to_string();
                Some(self.interner.intern(&s))
            };
            let interfaces: Vec<Sym> = cd
                .interfaces
                .iter()
                .map(|t| {
                    let s = dex.type_name(*t).to_string();
                    self.interner.intern(&s)
                })
                .collect();

            // Static values, in the order static fields are declared.
            let static_vals = dex.static_values(cd.class_idx).unwrap_or_default();

            let data = &dex.class_data[ci];
            let mut static_fields = Vec::with_capacity(data.static_fields.len());
            for (fi, f) in data.static_fields.iter().enumerate() {
                let Some(fid) = dex.field(f.field_idx) else { continue };
                let key = FieldKey {
                    class: desc,
                    name: self.interner.intern(dex.string(fid.name_idx)),
                    ty: {
                        let t = dex.type_name(fid.type_idx).to_string();
                        self.interner.intern(&t)
                    },
                };
                let sv = static_vals.get(fi).map(|ev| static_init_from(image_index, ev));
                static_fields.push(FieldEntry { key, access: f.access_flags, static_init: sv });
                self.fields.entry(key).or_insert(FieldEntry {
                    key,
                    access: f.access_flags,
                    static_init: None,
                });
            }
            let mut instance_fields = Vec::with_capacity(data.instance_fields.len());
            for f in &data.instance_fields {
                let Some(fid) = dex.field(f.field_idx) else { continue };
                let key = FieldKey {
                    class: desc,
                    name: self.interner.intern(dex.string(fid.name_idx)),
                    ty: {
                        let t = dex.type_name(fid.type_idx).to_string();
                        self.interner.intern(&t)
                    },
                };
                instance_fields.push(FieldEntry { key, access: f.access_flags, static_init: None });
                self.fields.entry(key).or_insert(FieldEntry {
                    key,
                    access: f.access_flags,
                    static_init: None,
                });
            }

            let index_method = |m: &crate::dex::EncodedMethod, this: &mut Registry| {
                let Some(mid) = dex.method(m.method_idx) else {
                    this.skipped_methods += 1;
                    return None;
                };
                let name = this.interner.intern(dex.string(mid.name_idx));
                let proto = {
                    let desc = dex.proto_descriptor(mid.proto_idx);
                    this.interner.intern(&desc)
                };
                let key = MethodKey { class: desc, name, proto };
                if m.code_off == 0 {
                    // Abstract or native: record the declaration for virtual
                    // dispatch and framework overrides, but with code_off 0.
                    this.methods.entry(key).or_insert(MethodEntry {
                        key,
                        access: m.access_flags,
                        dex: image_index,
                        method_idx: m.method_idx,
                        code_off: 0,
                    });
                    return Some(MethodEntry {
                        key,
                        access: m.access_flags,
                        dex: image_index,
                        method_idx: m.method_idx,
                        code_off: 0,
                    });
                }
                let entry = MethodEntry {
                    key,
                    access: m.access_flags,
                    dex: image_index,
                    method_idx: m.method_idx,
                    code_off: m.code_off,
                };
                this.methods.insert(key, entry);
                Some(entry)
            };

            let mut direct_methods = Vec::with_capacity(data.direct_methods.len());
            for m in &data.direct_methods {
                if let Some(e) = index_method(m, self) {
                    direct_methods.push(e);
                }
            }
            let mut virtual_methods = Vec::with_capacity(data.virtual_methods.len());
            for m in &data.virtual_methods {
                if let Some(e) = index_method(m, self) {
                    virtual_methods.push(e);
                }
            }

            self.classes.insert(
                desc,
                ClassInfo {
                    desc,
                    superclass,
                    interfaces,
                    access: cd.access_flags,
                    dex: image_index,
                    static_fields,
                    instance_fields,
                    direct_methods,
                    virtual_methods,
                    initialized: false,
                    init_state: InitState::Uninitialized,
                },
            );
        }
    }

    fn proto_desc(&self, dex: &DexFile, p: &crate::dex::ProtoId) -> String {
        let mut s = String::from("(");
        if p.parameters_off != 0 {
            if let Ok(list) = dex.type_list(p.parameters_off) {
                for t in list {
                    s.push_str(dex.type_name(t));
                }
            }
        }
        s.push(')');
        s.push_str(dex.type_name(p.return_type_idx));
        s
    }

    pub fn class(&self, sym: Sym) -> Option<&ClassInfo> {
        self.classes.get(&sym)
    }

    pub fn class_desc(&self, sym: Sym) -> &str {
        self.interner.get(sym)
    }

    pub fn lookup_method(&self, key: &MethodKey) -> Option<&MethodEntry> {
        self.methods.get(key)
    }

    /// Resolve a virtual call on `class` walking the superclass chain and then
    /// interfaces, returning the most-derived implementation.
    pub fn resolve_virtual(&self, class: Sym, name: Sym, proto: Sym) -> Option<MethodEntry> {
        let mut cur = Some(class);
        let mut depth = 0;
        while let Some(c) = cur {
            let key = MethodKey { class: c, name, proto };
            if let Some(e) = self.methods.get(&key) {
                if e.code_off != 0 {
                    return Some(*e);
                }
            }
            depth += 1;
            if depth > 128 {
                return None;
            }
            cur = self.classes.get(&c).and_then(|ci| ci.superclass);
        }
        // Interfaces, breadth-limited.
        let mut stack = vec![class];
        let mut seen = 0;
        let mut ifaces = Vec::new();
        while let Some(c) = stack.pop() {
            seen += 1;
            if seen > 256 {
                break;
            }
            if let Some(ci) = self.classes.get(&c) {
                for i in &ci.interfaces {
                    ifaces.push(*i);
                    stack.push(*i);
                }
                if let Some(s) = ci.superclass {
                    if !self.classes.contains_key(&s) {
                        // A framework superclass may have interfaces we do not
                        // model; stop rather than guess.
                    }
                }
            }
        }
        for i in ifaces {
            let key = MethodKey { class: i, name, proto };
            if let Some(e) = self.methods.get(&key) {
                if e.code_off != 0 {
                    return Some(*e);
                }
            }
        }
        None
    }

    /// Direct (non-virtual) resolution: exact class only.
    pub fn resolve_direct(&self, class: Sym, name: Sym, proto: Sym) -> Option<MethodEntry> {
        self.methods
            .get(&MethodKey { class, name, proto })
            .copied()
    }

    /// Resolve a field, walking the superclass chain for inherited fields.
    pub fn resolve_field(&self, class: Sym, name: Sym, ty: Sym) -> Option<FieldEntry> {
        let mut cur = Some(class);
        let mut depth = 0;
        while let Some(c) = cur {
            let key = FieldKey { class: c, name, ty };
            if let Some(e) = self.fields.get(&key) {
                return Some(*e);
            }
            depth += 1;
            if depth > 128 {
                return None;
            }
            cur = self.classes.get(&c).and_then(|ci| ci.superclass);
        }
        None
    }

    pub fn code_of(&self, e: &MethodEntry) -> Option<Arc<crate::dex::CodeItem>> {
        let dex = self.images.get(e.dex as usize)?;
        dex.code_item(e.code_off)
    }

    pub fn image(&self, idx: u32) -> Option<&Arc<DexFile>> {
        self.images.get(idx as usize)
    }

    /// True when `class` is defined in one of the sample's own images (as
    /// opposed to a framework class we model in host code).
    pub fn is_app_class(&self, class: Sym) -> bool {
        self.classes.contains_key(&class)
    }

    /// Walk superclasses until a descriptor that is not defined in the app.
    pub fn first_framework_superclass(&self, class: Sym) -> Option<Sym> {
        let mut cur = self.classes.get(&class).and_then(|c| c.superclass);
        let mut depth = 0;
        while let Some(c) = cur {
            if !self.classes.contains_key(&c) {
                return Some(c);
            }
            depth += 1;
            if depth > 128 {
                return None;
            }
            cur = self.classes.get(&c).and_then(|ci| ci.superclass);
        }
        None
    }

    /// Does `class` (or an ancestor) eventually extend/implement `target`?
    pub fn is_subclass_of(&self, class: Sym, target_desc: &str) -> bool {
        let mut cur = Some(class);
        let mut depth = 0;
        while let Some(c) = cur {
            if self.interner.get(c) == target_desc {
                return true;
            }
            let Some(ci) = self.classes.get(&c) else {
                return false;
            };
            depth += 1;
            if depth > 128 {
                return false;
            }
            cur = ci.superclass;
        }
        false
    }

    pub fn method_desc(&self, key: &MethodKey) -> String {
        format!(
            "{}->{}{}",
            self.interner.get(key.class),
            self.interner.get(key.name),
            self.interner.get(key.proto)
        )
    }

    pub fn all_app_classes(&self) -> impl Iterator<Item = &ClassInfo> {
        self.classes.values()
    }

    /// A per-scenario copy: static-field effects and `<clinit>` state must not
    /// leak between scenarios, but the images, class table and method index are
    /// expensive to rebuild and are shared by value.
    pub fn clone_for_scenario(&self) -> Registry {
        let mut classes = self.classes.clone();
        for ci in classes.values_mut() {
            ci.init_state = InitState::Uninitialized;
            ci.initialized = false;
        }
        Registry {
            interner: self.interner.clone(),
            images: self.images.clone(),
            classes,
            methods: self.methods.clone(),
            fields: self.fields.clone(),
            protos: self.protos.clone(),
            skipped_methods: self.skipped_methods,
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

fn static_init_from(image: u32, v: &EncodedValue) -> StaticInit {
    match v {
        EncodedValue::String(idx) => StaticInit::Str { image, idx: *idx },
        EncodedValue::Type(idx) => StaticInit::Type { image, idx: *idx },
        EncodedValue::Null => StaticInit::Value(Slot::null()),
        EncodedValue::Boolean(_)
        | EncodedValue::Byte(_)
        | EncodedValue::Short(_)
        | EncodedValue::Char(_)
        | EncodedValue::Int(_)
        | EncodedValue::Long(_)
        | EncodedValue::Float(_)
        | EncodedValue::Double(_) => StaticInit::Value(encoded_to_slot(v)),
        _ => StaticInit::Other,
    }
}

/// Convert a decoded DEX encoded value into a runtime slot. String/type
/// encoded values need the heap and are handled through `StaticInit`.
pub fn encoded_to_slot(v: &EncodedValue) -> Slot {
    match v {
        EncodedValue::Byte(b) => Slot::int(*b as i32),
        EncodedValue::Short(s) => Slot::int(*s as i32),
        EncodedValue::Char(c) => Slot::int(*c as i32),
        EncodedValue::Int(i) => Slot::int(*i),
        EncodedValue::Long(l) => Slot::long(*l),
        EncodedValue::Float(f) => Slot::float(*f),
        EncodedValue::Double(d) => Slot::double(*d),
        EncodedValue::Boolean(b) => Slot::int(if *b { 1 } else { 0 }),
        EncodedValue::Null => Slot::null(),
        _ => Slot::clean(Value::Undef),
    }
}

/// Where a class came from, for the report.
pub fn origin_of(registry: &Registry, class: Sym) -> String {
    registry
        .class(class)
        .and_then(|ci| registry.image(ci.dex))
        .map(|d| d.origin.clone())
        .unwrap_or_else(|| "<framework>".into())
}

/// Unused helper kept for API symmetry with ObjRef inspection.
pub fn is_null_ref(r: ObjRef) -> bool {
    r.is_null()
}
