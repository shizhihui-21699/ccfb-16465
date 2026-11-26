//! Heap: strings, arrays and objects.
//!
//! Objects are never freed during a scenario. Scenarios are bounded in steps,
//! and a hard object/byte cap turns runaway allocation into a clean
//! `LimitExceeded` instead of an OOM. This removes the need for a collector,
//! and with it any possibility of a dangling reference fooling the interpreter
//! into executing stale code.
//!
//! Reference *arrays* hold tainted `Slot`s so a `String[]` of harvested
//! contacts keeps its labels. `byte[]` is stored compactly with one taint set
//! for the whole buffer, which is what the code we care about (XOR/Base64/AES
//! over blobs) actually needs.

use std::collections::HashMap;

use super::intern::{FieldKey, Sym};
use super::value::{ObjRef, Slot, Taint, Value};
use crate::error::{Error, Result};

/// Model state attached to an object created by the framework layer. This is
/// how a `java.net.URL` remembers its string, or a `DexClassLoader` remembers
/// its path list, without executing real Android code.
#[derive(Debug, Clone)]
pub enum Model {
    /// java.lang.String's companion Class object (holds the descriptor).
    Class(Sym),
    /// An instance of a class whose behaviour is modelled by a host hook.
    Tagged(String),
    /// StringBuilder / StringBuffer: mutable contents kept in `Str` instead.
    None,
}

#[derive(Debug)]
pub struct InstObj {
    /// Concrete class descriptor, interned.
    pub class: Sym,
    pub fields: HashMap<FieldKey, Slot>,
    /// Framework state, keyed by short name ("url", "body", "path", ...).
    pub state: HashMap<String, Slot>,
    pub model: Model,
}

impl InstObj {
    pub fn new(class: Sym) -> Self {
        InstObj {
            class,
            fields: HashMap::new(),
            state: HashMap::new(),
            model: Model::None,
        }
    }
}

#[derive(Debug)]
pub struct ArrayObj {
    /// Element type descriptor, e.g. `Ljava/lang/String;` or `I`.
    pub elem: Sym,
    pub data: Vec<Slot>,
}

#[derive(Debug)]
pub enum ObjKind {
    Str(String),
    /// StringBuilder / StringBuffer; appends mutate in place.
    MutableStr(String),
    /// byte[] / Byte[] compact storage.
    Bytes(Vec<u8>),
    Array(ArrayObj),
    Instance(InstObj),
}

#[derive(Debug)]
pub struct HeapObj {
    /// Taint for the *whole* object: strings, byte buffers and arrays inherit
    /// it when read. Instance fields carry their own slot taint.
    pub taint: Taint,
    pub kind: ObjKind,
}

pub struct Heap {
    objs: Vec<Option<HeapObj>>,
    pub live: usize,
    pub byte_budget: usize,
    pub bytes_used: usize,
    pub max_objects: usize,
    pub max_bytes: usize,
}

impl Default for Heap {
    fn default() -> Self {
        Heap {
            objs: Vec::new(),
            live: 0,
            byte_budget: 0,
            bytes_used: 0,
            max_objects: 2_000_000,
            max_bytes: 512 * 1024 * 1024,
        }
    }
}

impl Heap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate an object, returning a fresh non-null reference.
    pub fn alloc(&mut self, taint: Taint, kind: ObjKind) -> Result<ObjRef> {
        if self.live >= self.max_objects {
            return Err(Error::LimitExceeded("heap object cap"));
        }
        let bytes = match &kind {
            ObjKind::Str(s) | ObjKind::MutableStr(s) => s.len(),
            ObjKind::Bytes(b) => b.len(),
            ObjKind::Array(a) => a.data.len() * std::mem::size_of::<Slot>(),
            ObjKind::Instance(_) => 128,
        };
        if self.bytes_used.saturating_add(bytes) > self.max_bytes {
            return Err(Error::LimitExceeded("heap byte budget"));
        }
        self.bytes_used += bytes;
        self.byte_budget = self.byte_budget.max(self.bytes_used);
        let obj = HeapObj { taint, kind };
        // Reuse a slot only if it was cleared; slots are never cleared during a
        // scenario except by an explicit `release` used for large transient
        // buffers. Indices remain stable, which keeps references valid.
        self.objs.push(Some(obj));
        self.live += 1;
        Ok(ObjRef(self.objs.len() as u32))
    }

    pub fn get(&self, r: ObjRef) -> Option<&HeapObj> {
        r.index().and_then(|i| self.objs.get(i)).and_then(|o| o.as_ref())
    }

    pub fn get_mut(&mut self, r: ObjRef) -> Option<&mut HeapObj> {
        r.index()
            .and_then(move |i| self.objs.get_mut(i))
            .and_then(|o| o.as_mut())
    }

    pub fn is_live(&self, r: ObjRef) -> bool {
        self.get(r).is_some()
    }

    /// Taint attached to the object itself (0 for null / missing).
    pub fn taint_of(&self, r: ObjRef) -> Taint {
        self.get(r).map(|o| o.taint).unwrap_or(Taint::CLEAN)
    }

    pub fn add_taint(&mut self, r: ObjRef, t: Taint) {
        if let Some(o) = self.get_mut(r) {
            o.taint = o.taint.union(t);
        }
    }

    pub fn set_taint(&mut self, r: ObjRef, t: Taint) {
        if let Some(o) = self.get_mut(r) {
            o.taint = t;
        }
    }

    /// Read a string object's contents, or "" if not a string.
    pub fn string_of(&self, r: ObjRef) -> Option<&str> {
        match &self.get(r)?.kind {
            ObjKind::Str(s) | ObjKind::MutableStr(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn is_string(&self, r: ObjRef) -> bool {
        matches!(
            self.get(r).map(|o| &o.kind),
            Some(ObjKind::Str(_)) | Some(ObjKind::MutableStr(_))
        )
    }

    pub fn bytes_of(&self, r: ObjRef) -> Option<&[u8]> {
        match &self.get(r)?.kind {
            ObjKind::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn class_of(&self, r: ObjRef) -> Option<Sym> {
        match &self.get(r)?.kind {
            ObjKind::Instance(i) => Some(i.class),
            ObjKind::Str(_) | ObjKind::MutableStr(_) => Some(Sym::NONE),
            ObjKind::Bytes(_) => Some(Sym::NONE),
            ObjKind::Array(a) => Some(a.elem),
        }
    }

    pub fn instance(&self, r: ObjRef) -> Option<&InstObj> {
        match &self.get(r)?.kind {
            ObjKind::Instance(i) => Some(i),
            _ => None,
        }
    }

    pub fn instance_mut(&mut self, r: ObjRef) -> Option<&mut InstObj> {
        match &mut self.get_mut(r)?.kind {
            ObjKind::Instance(i) => Some(i),
            _ => None,
        }
    }

    /// Read an instance field, falling back to framework state.
    pub fn get_field(&self, r: ObjRef, key: &FieldKey) -> Option<Slot> {
        self.instance(r).and_then(|i| i.fields.get(key).copied())
    }

    pub fn put_field(&mut self, r: ObjRef, key: FieldKey, slot: Slot) -> bool {
        match self.instance_mut(r) {
            Some(i) => {
                i.fields.insert(key, slot);
                true
            }
            None => false,
        }
    }

    /// Allocate a java/lang/String with contents and taint.
    pub fn new_string(&mut self, s: impl Into<String>, taint: Taint) -> Result<ObjRef> {
        self.alloc(taint, ObjKind::Str(s.into()))
    }

    pub fn new_mutable_string(&mut self, s: impl Into<String>, taint: Taint) -> Result<ObjRef> {
        self.alloc(taint, ObjKind::MutableStr(s.into()))
    }

    pub fn new_bytes(&mut self, data: Vec<u8>, taint: Taint) -> Result<ObjRef> {
        self.alloc(taint, ObjKind::Bytes(data))
    }

    pub fn new_instance(&mut self, class: Sym) -> Result<ObjRef> {
        self.alloc(Taint::CLEAN, ObjKind::Instance(InstObj::new(class)))
    }

    /// Allocate an array. `elem` is a descriptor; `len` elements initialised to
    /// the type's default value. A byte array is stored compactly.
    pub fn new_array(&mut self, elem: Sym, elem_desc: &str, len: usize, taint: Taint) -> Result<ObjRef> {
        if len > 64 * 1024 * 1024 {
            return Err(Error::LimitExceeded("array length"));
        }
        if elem_desc == "B" || elem_desc == "[B" || elem_desc == "Ljava/lang/Byte;" {
            self.alloc(taint, ObjKind::Bytes(vec![0u8; len]))
        } else {
            let default = default_slot_for(elem_desc);
            self.alloc(
                taint,
                ObjKind::Array(ArrayObj { elem, data: vec![default; len] }),
            )
        }
    }

    /// Length of a string/array/byte[] object.
    pub fn length_of(&self, r: ObjRef) -> Option<usize> {
        match &self.get(r)?.kind {
            ObjKind::Str(s) | ObjKind::MutableStr(s) => Some(s.chars().count()),
            ObjKind::Bytes(b) => Some(b.len()),
            ObjKind::Array(a) => Some(a.data.len()),
            ObjKind::Instance(_) => None,
        }
    }

    /// Array read. Returns `None` when out of range or not an array.
    pub fn array_get(&self, r: ObjRef, idx: usize) -> Option<Slot> {
        let o = self.get(r)?;
        match &o.kind {
            ObjKind::Bytes(b) => b.get(idx).map(|v| {
                Slot::word(*v as i8 as i32).with_taint(o.taint)
            }),
            ObjKind::Array(a) => a.data.get(idx).map(|s| {
                let mut s = *s;
                s.t = s.t.union(o.taint);
                s
            }),
            _ => None,
        }
    }

    pub fn array_set(&mut self, r: ObjRef, idx: usize, slot: Slot) -> bool {
        let Some(o) = self.get_mut(r) else { return false };
        match &mut o.kind {
            ObjKind::Bytes(b) => {
                if idx >= b.len() {
                    return false;
                }
                b[idx] = slot.v.as_int() as u8;
                o.taint = o.taint.union(slot.t);
                true
            }
            ObjKind::Array(a) => {
                if idx >= a.data.len() {
                    return false;
                }
                a.data[idx] = slot;
                o.taint = o.taint.union(slot.t);
                true
            }
            _ => false,
        }
    }

    /// Append to a StringBuilder, propagating taint.
    pub fn append_mutable(&mut self, r: ObjRef, s: &str, t: Taint) -> bool {
        let Some(o) = self.get_mut(r) else { return false };
        if let ObjKind::MutableStr(buf) = &mut o.kind {
            if buf.len().saturating_add(s.len()) > 64 * 1024 * 1024 {
                return false;
            }
            buf.push_str(s);
            o.taint = o.taint.union(t);
            true
        } else {
            false
        }
    }

    /// Convert a StringBuilder into an immutable String object.
    pub fn builder_to_string(&mut self, r: ObjRef) -> Result<ObjRef> {
        let (s, t) = match &self.get(r).map(|o| (&o.kind, o.taint)) {
            Some((ObjKind::MutableStr(s), t)) => (s.clone(), *t),
            Some((ObjKind::Str(s), t)) => (s.clone(), *t),
            _ => (String::new(), Taint::CLEAN),
        };
        self.new_string(s, t)
    }

    /// Concatenate two string objects, unioning taint.
    pub fn concat(&mut self, a: ObjRef, b: ObjRef) -> Result<ObjRef> {
        let sa = self.string_of(a).unwrap_or("").to_string();
        let sb = self.string_of(b).unwrap_or("").to_string();
        let t = self.taint_of(a).union(self.taint_of(b));
        let mut s = sa;
        s.push_str(&sb);
        self.new_string(s, t)
    }

    /// Deterministic pseudo-identity for objects across scenarios, used only
    /// for rendering ("<String@42>"). Not stable across runs by design.
    pub fn describe(&self, r: ObjRef, interner: &super::intern::Interner) -> String {
        let Some(o) = self.get(r) else { return "null".into() };
        match &o.kind {
            ObjKind::Str(s) => {
                let trunc = truncate_for_log(s, 96);
                format!("\"{trunc}\"")
            }
            ObjKind::MutableStr(s) => {
                let trunc = truncate_for_log(s, 96);
                format!("StringBuilder(\"{trunc}\")")
            }
            ObjKind::Bytes(b) => format!("byte[{}]", b.len()),
            ObjKind::Array(a) => format!("{}[{}]", interner.get(a.elem), a.data.len()),
            ObjKind::Instance(i) => interner.get(i.class).to_string(),
        }
    }
}

fn truncate_for_log(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let t: String = s.chars().take(max).collect();
    format!("{t}…")
}

fn default_slot_for(desc: &str) -> Slot {
    match desc {
        "J" => Slot::long(0),
        "D" => Slot::double(0.0),
        "F" => Slot::float(0.0),
        "Z" | "B" | "S" | "C" | "I" => Slot::int(0),
        _ => Slot::null(),
    }
}

/// Convenience: a fresh object whose `Value` is a reference.
pub fn ref_slot(r: ObjRef) -> Value {
    Value::Ref(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::intern::Interner;

    #[test]
    fn strings_and_taint() {
        let mut h = Heap::new();
        let mut i = Interner::new();
        let s = h.new_string("hello", Taint(0b10)).unwrap();
        assert_eq!(h.string_of(s), Some("hello"));
        assert!(h.taint_of(s).contains(Taint(0b10)));
        let t = h.new_string(" world", Taint(0b1)).unwrap();
        let c = h.concat(s, t).unwrap();
        assert_eq!(h.string_of(c), Some("hello world"));
        assert!(h.taint_of(c).contains(Taint(0b11)));
        assert_eq!(h.describe(c, &i), "\"hello world\"");
        let _ = i.intern("I");
    }

    #[test]
    fn byte_arrays_are_compact_and_tainted() {
        let mut h = Heap::new();
        let i = Interner::new();
        let elem = h.new_array(Sym::NONE, "B", 4, Taint::CLEAN).unwrap();
        assert!(h.array_set(elem, 0, Slot::int(0x41)));
        assert_eq!(h.array_get(elem, 0).unwrap().v.as_int(), 0x41);
        assert!(h.bytes_of(elem).unwrap().len() == 4);
        // Writing tainted data makes the whole buffer tainted: a later
        // exfiltration of any slice is then still attributed.
        h.array_set(elem, 1, Slot::int(1).with_taint(Taint(0b100)));
        assert!(h.taint_of(elem).contains(Taint(0b100)));
        assert!(h.array_get(elem, 0).unwrap().t.contains(Taint(0b100)));
        assert_eq!(i.len(), 0);
    }

    #[test]
    fn arrays_of_strings_keep_element_taint() {
        let mut h = Heap::new();
        let elem = h.new_array(Sym::NONE, "Ljava/lang/String;", 2, Taint::CLEAN).unwrap();
        let s = h.new_string("x", Taint(0b1000)).unwrap();
        assert!(h.array_set(elem, 1, Slot::reference(s)));
        assert!(h.array_get(elem, 0).unwrap().is_null_ref());
        assert_eq!(h.array_get(elem, 1).unwrap().v.as_ref(), s);
    }
}
