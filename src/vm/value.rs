//! Value representation, register slots and dynamic taint bits.
//!
//! A register slot is a `Slot`: a value plus the taint labels it carries.
//! Strings and objects also carry taint (in the heap), so taint survives a
//! value being stored into a field, passed through a StringBuilder, or
//! decoded from Base64 provided the relevant API is modelled to propagate it.

use std::fmt;

/// Reference to a heap object. `0` is the null reference.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ObjRef(pub u32);

impl ObjRef {
    pub const NULL: ObjRef = ObjRef(0);
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
    pub fn index(self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some((self.0 - 1) as usize)
        }
    }
}

impl fmt::Debug for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "null")
        } else {
            write!(f, "@{}", self.0)
        }
    }
}

/// A Dalvik value. Wide values (long/double) live in the *first* register of
/// their pair; the second register holds `WideHigh`. This keeps register
/// addressing identical to the Dalvik spec while making wide moves a single
/// two-slot copy.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Value {
    #[default]
    Undef,
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Ref(ObjRef),
    /// Upper half of a wide value stored in the preceding register.
    WideHigh,
}

impl Value {
    pub fn null() -> Value {
        Value::Ref(ObjRef::NULL)
    }
    pub fn is_wide(&self) -> bool {
        matches!(self, Value::Long(_) | Value::Double(_))
    }
    pub fn as_int(self) -> i32 {
        match self {
            Value::Int(v) => v,
            Value::Long(v) => v as i32,
            Value::Float(v) => v as i32,
            Value::Double(v) => v as i32,
            Value::Ref(r) => r.0 as i32,
            Value::Undef | Value::WideHigh => 0,
        }
    }
    pub fn as_long(self) -> i64 {
        match self {
            Value::Int(v) => v as i64,
            Value::Long(v) => v,
            Value::Float(v) => v as i64,
            Value::Double(v) => v as i64,
            _ => 0,
        }
    }
    pub fn as_float(self) -> f32 {
        match self {
            Value::Float(v) => v,
            Value::Double(v) => v as f32,
            Value::Int(v) => v as f32,
            Value::Long(v) => v as f32,
            _ => 0.0,
        }
    }
    pub fn as_double(self) -> f64 {
        match self {
            Value::Double(v) => v,
            Value::Float(v) => v as f64,
            Value::Int(v) => v as f64,
            Value::Long(v) => v as f64,
            _ => 0.0,
        }
    }
    pub fn as_ref(self) -> ObjRef {
        match self {
            Value::Ref(r) => r,
            _ => ObjRef::NULL,
        }
    }
    pub fn truthy(self) -> bool {
        match self {
            Value::Ref(r) => !r.is_null(),
            Value::Int(v) => v != 0,
            Value::Long(v) => v != 0,
            Value::Float(v) => v != 0.0,
            Value::Double(v) => v != 0.0,
            _ => false,
        }
    }
}

/// A taint label set. Bits are minted by `TaintMinter` and rendered back to
/// names for the report.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Taint(pub u64);

impl Taint {
    pub const CLEAN: Taint = Taint(0);
    pub fn is_clean(self) -> bool {
        self.0 == 0
    }
    pub fn union(self, other: Taint) -> Taint {
        Taint(self.0 | other.0)
    }
    pub fn contains(self, other: Taint) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn bits(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for Taint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Taint({:#x})", self.0)
    }
}

/// A register / field / array element: value plus taint.
#[derive(Clone, Copy, Debug, Default)]
pub struct Slot {
    pub v: Value,
    pub t: Taint,
}

impl Slot {
    pub fn clean(v: Value) -> Slot {
        Slot { v, t: Taint::CLEAN }
    }
    pub fn int(v: i32) -> Slot {
        Slot { v: Value::Int(v), t: Taint::CLEAN }
    }
    pub fn long(v: i64) -> Slot {
        Slot { v: Value::Long(v), t: Taint::CLEAN }
    }
    pub fn float(v: f32) -> Slot {
        Slot { v: Value::Float(v), t: Taint::CLEAN }
    }
    pub fn double(v: f64) -> Slot {
        Slot { v: Value::Double(v), t: Taint::CLEAN }
    }
    pub fn reference(r: ObjRef) -> Slot {
        Slot { v: Value::Ref(r), t: Taint::CLEAN }
    }
    pub fn null() -> Slot {
        Slot { v: Value::Ref(ObjRef::NULL), t: Taint::CLEAN }
    }
    /// A raw 32-bit word as stored in a register (used by `move` of unknown
    /// halves and by array copies of primitive types).
    pub fn word(v: i32) -> Slot {
        Slot { v: Value::Int(v), t: Taint::CLEAN }
    }
    pub fn with_taint(mut self, t: Taint) -> Slot {
        self.t = self.t.union(t);
        self
    }
    pub fn is_null_ref(&self) -> bool {
        matches!(self.v, Value::Ref(r) if r.is_null())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_value_semantics() {
        let v = Value::Long(0x1_0000_0001);
        assert_eq!(v.as_int(), 1);
        assert_eq!(v.as_long(), 0x1_0000_0001);
        assert!(v.is_wide());
        assert!(!Value::Int(1).is_wide());
    }

    #[test]
    fn taint_union() {
        let a = Taint(0b0011);
        let b = Taint(0b0100);
        assert_eq!(a.union(b), Taint(0b0111));
        assert!(a.union(b).contains(Taint(0b0001)));
        assert!(!a.contains(Taint(0b0100)));
    }
}
