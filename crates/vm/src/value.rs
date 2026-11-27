//! Register values, object handles and the lightweight provenance tags that
//! let the report say "this URL was decrypted at runtime" rather than merely
//! "this string exists".

use serde::{Deserialize, Serialize};

/// An object handle. `0` is the null reference.
pub type ObjId = u32;

/// One Dalvik register slot. Dalvik is untyped at the register level: the
/// instruction decides how the 64 bits are interpreted, so we keep the raw
/// interpretation alongside the bits.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// 32-bit integer / boolean / char / any reference-typed data we did not
    /// lift to an object.
    I(i32),
    /// 64-bit integer.
    J(i64),
    /// IEEE-754 single, stored as raw bits so NaN payloads survive.
    F(u32),
    /// IEEE-754 double, stored as raw bits.
    D(u64),
    /// Object reference (0 = null).
    Obj(ObjId),
}

impl Default for Value {
    fn default() -> Self {
        Value::I(0)
    }
}

impl Value {
    pub const NULL: Value = Value::Obj(0);

    pub fn int(v: i32) -> Self {
        Value::I(v)
    }

    pub fn boolean(v: bool) -> Self {
        Value::I(v as i32)
    }

    pub fn obj(id: ObjId) -> Self {
        Value::Obj(id)
    }

    /// 32-bit view. Objects become a small integer handle only for diagnostics;
    /// instructions that need an object must call `as_obj` first.
    pub fn as_i32(self) -> i32 {
        match self {
            Value::I(v) => v,
            Value::J(v) => v as i32,
            Value::F(v) => v as i32,
            Value::D(v) => v as i32,
            Value::Obj(v) => v as i32,
        }
    }

    pub fn as_i64(self) -> i64 {
        match self {
            Value::I(v) => v as i64,
            Value::J(v) => v,
            Value::F(v) => v as i64,
            Value::D(v) => v as i64,
            Value::Obj(v) => v as i64,
        }
    }

    pub fn as_f32(self) -> f32 {
        match self {
            Value::F(bits) => f32::from_bits(bits),
            Value::D(bits) => f64::from_bits(bits) as f32,
            Value::I(v) => v as f32,
            Value::J(v) => v as f32,
            Value::Obj(v) => v as f32,
        }
    }

    pub fn as_f64(self) -> f64 {
        match self {
            Value::D(bits) => f64::from_bits(bits),
            Value::F(bits) => f32::from_bits(bits) as f64,
            Value::I(v) => v as f64,
            Value::J(v) => v as f64,
            Value::Obj(v) => v as f64,
        }
    }

    pub fn as_obj(self) -> Option<ObjId> {
        match self {
            Value::Obj(0) => None,
            Value::Obj(id) => Some(id),
            Value::I(0) => None,
            _ => None,
        }
    }

    pub fn is_null(self) -> bool {
        matches!(self, Value::Obj(0)) || matches!(self, Value::I(0))
    }

    pub fn f32(v: f32) -> Self {
        Value::F(v.to_bits())
    }

    pub fn f64(v: f64) -> Self {
        Value::D(v.to_bits())
    }
}

/// Where a value came from. Tags are a coarse taint: we only need enough to
/// tell constant strings from decoded ones and to spot data that reached a
/// network/telephony sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    /// Literal from the DEX string pool.
    Constant,
    /// Assembled by string concatenation or StringBuilder.
    Built,
    /// Produced by an operation on data read from the APK (assets/resources).
    PackedData,
    /// Produced by an operation we classify as cryptographic / decoding.
    Decoded,
    /// Bytes that arrived from the network model.
    Network,
    /// Read from a device API (IDs, sensors, build fields).
    Device,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub tags: Vec<Tag>,
    pub note: Option<String>,
}

impl Provenance {
    pub fn of(tag: Tag) -> Self {
        Self { tags: vec![tag], note: None }
    }

    pub fn constant() -> Self {
        Self::of(Tag::Constant)
    }

    pub fn merge(&mut self, other: &Provenance) {
        for t in &other.tags {
            self.add(*t);
        }
    }

    pub fn add(&mut self, tag: Tag) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    pub fn has(&self, tag: Tag) -> bool {
        self.tags.contains(&tag)
    }

    pub fn is_runtime_derived(&self) -> bool {
        self.tags
            .iter()
            .any(|t| matches!(t, Tag::Built | Tag::Decoded | Tag::PackedData))
    }

    pub fn label(&self) -> String {
        if self.tags.is_empty() {
            return "unknown".into();
        }
        let mut parts: Vec<&str> = self.tags.iter().map(|t| tag_str(*t)).collect();
        parts.sort_unstable();
        parts.dedup();
        parts.join("+")
    }
}

fn tag_str(t: Tag) -> &'static str {
    match t {
        Tag::Constant => "const",
        Tag::Built => "built",
        Tag::PackedData => "packed",
        Tag::Decoded => "decoded",
        Tag::Network => "network",
        Tag::Device => "device",
    }
}
