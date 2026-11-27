//! A tiny managed heap: strings, arrays, StringBuilders and opaque "model
//! objects" (Context, File, Cipher, ...). Enough for bytecode that decrypts,
//! parses and exfiltrates data; deliberately not a full Java runtime.

use crate::value::{ObjId, Provenance};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Object {
    Str {
        value: String,
        prov: Provenance,
    },
    /// `byte[]` and friends. `bytes` is canonical, `elem_width` only matters
    /// for typed arrays.
    Array {
        elem: String,
        bytes: Vec<u8>,
        prov: Provenance,
    },
    /// An array of references (`[Ljava/lang/Object;` etc).
    ObjArray {
        elem: String,
        items: Vec<crate::value::Value>,
        prov: Provenance,
    },
    /// `java.lang.StringBuilder` / `StringBuffer`.
    Builder {
        buf: String,
        prov: Provenance,
    },
    /// An object we model as an opaque dictionary of fields: package manager,
    /// context, file handle, cipher state, etc.
    Model {
        class: String,
        fields: HashMap<String, ObjectValue>,
        prov: Provenance,
    },
    /// A `java.lang.Class` object holding a descriptor.
    Class {
        descriptor: String,
    },
    /// An instance of a class declared in the sample. Field keys are DEX field
    /// indices so the interpreter never has to map names at runtime.
    Instance {
        class: String,
        fields: HashMap<u32, crate::value::Value>,
        prov: Provenance,
    },
    /// An uncaught-but-represented exception object.
    Throwable {
        class: String,
        message: String,
    },
}

/// Values stored in `Object::Model::fields`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectValue {
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    Obj(ObjId),
    Bool(bool),
    Null,
}

impl ObjectValue {
    pub fn as_i64(&self) -> i64 {
        match self {
            ObjectValue::Int(v) => *v,
            ObjectValue::Bool(b) => *b as i64,
            ObjectValue::Str(s) => s.parse().unwrap_or(0),
            _ => 0,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ObjectValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

impl Object {
    pub fn prov(&self) -> Option<&Provenance> {
        match self {
            Object::Str { prov, .. } => Some(prov),
            Object::Array { prov, .. } => Some(prov),
            Object::ObjArray { prov, .. } => Some(prov),
            Object::Builder { prov, .. } => Some(prov),
            Object::Model { prov, .. } => Some(prov),
            Object::Class { .. } | Object::Throwable { .. } => None,
            Object::Instance { prov, .. } => Some(prov),
        }
    }

    pub fn prov_mut(&mut self) -> Option<&mut Provenance> {
        match self {
            Object::Str { prov, .. } => Some(prov),
            Object::Array { prov, .. } => Some(prov),
            Object::ObjArray { prov, .. } => Some(prov),
            Object::Builder { prov, .. } => Some(prov),
            Object::Model { prov, .. } => Some(prov),
            Object::Instance { prov, .. } => Some(prov),
            Object::Class { .. } | Object::Throwable { .. } => None,
        }
    }

    pub fn class_name(&self) -> &str {
        match self {
            Object::Str { .. } => "Ljava/lang/String;",
            Object::Array { elem, .. } => elem,
            Object::ObjArray { elem, .. } => elem,
            Object::Builder { .. } => "Ljava/lang/StringBuilder;",
            Object::Model { class, .. } => class,
            Object::Class { .. } => "Ljava/lang/Class;",
            Object::Instance { class, .. } => class,
            Object::Throwable { class, .. } => class,
        }
    }

    /// Treat the object as a string when it reasonably can be one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Object::Str { value, .. } => Some(value),
            Object::Builder { buf, .. } => Some(buf),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Object::Array { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
}

/// The object table. Ids are never reused within a run so provenance recorded
/// against an id stays meaningful in the trace.
#[derive(Debug, Default)]
pub struct Heap {
    objects: Vec<Option<Object>>,
    /// Cap on live objects; hitting it is reported, not silent.
    pub limit: usize,
    pub allocation_failures: u64,
}

pub const DEFAULT_HEAP_LIMIT: usize = 4_000_000;

impl Heap {
    pub fn new(limit: usize) -> Self {
        Self { objects: Vec::new(), limit, allocation_failures: 0 }
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    pub fn alloc(&mut self, obj: Object) -> Option<ObjId> {
        if self.objects.len() >= self.limit {
            self.allocation_failures += 1;
            return None;
        }
        self.objects.push(Some(obj));
        Some(self.objects.len() as ObjId)
    }

    /// Ids are 1-based so that `0` can mean null; the table index is `id - 1`.
    pub fn get(&self, id: ObjId) -> Option<&Object> {
        if id == 0 {
            return None;
        }
        self.objects.get(id as usize - 1).and_then(|o| o.as_ref())
    }

    pub fn get_mut(&mut self, id: ObjId) -> Option<&mut Object> {
        if id == 0 {
            return None;
        }
        self.objects.get_mut(id as usize - 1).and_then(|o| o.as_mut())
    }

    pub fn new_string(&mut self, s: impl Into<String>, prov: Provenance) -> Option<ObjId> {
        self.alloc(Object::Str { value: s.into(), prov })
    }

    pub fn new_bytes(&mut self, bytes: Vec<u8>, prov: Provenance) -> Option<ObjId> {
        self.alloc(Object::Array { elem: "[B".into(), bytes, prov })
    }

    pub fn new_array(&mut self, elem: impl Into<String>, bytes: Vec<u8>, prov: Provenance) -> Option<ObjId> {
        self.alloc(Object::Array { elem: elem.into(), bytes, prov })
    }

    pub fn new_model(&mut self, class: impl Into<String>, prov: Provenance) -> Option<ObjId> {
        self.alloc(Object::Model {
            class: class.into(),
            fields: HashMap::new(),
            prov,
        })
    }

    pub fn new_obj_array(&mut self, elem: impl Into<String>, items: Vec<crate::value::Value>, prov: Provenance) -> Option<ObjId> {
        self.alloc(Object::ObjArray { elem: elem.into(), items, prov })
    }

    pub fn new_builder(&mut self, prov: Provenance) -> Option<ObjId> {
        self.alloc(Object::Builder { buf: String::new(), prov })
    }

    /// Live object count (for diagnostics).
    pub fn live(&self) -> usize {
        self.objects.iter().filter(|o| o.is_some()).count()
    }

    /// Resolve a string-ish object to an owned String.
    pub fn string_of(&self, id: ObjId) -> Option<String> {
        self.get(id).and_then(|o| o.as_str()).map(|s| s.to_string())
    }

    /// Parse a Java `String` value into raw bytes using the DEX's charset
    /// conventions. Latin-1 is used when the string is pure ASCII; otherwise
    /// UTF-8, which is what Android's default charset does.
    pub fn string_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }
}
