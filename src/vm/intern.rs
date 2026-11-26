//! Global string interning for class descriptors, member names and prototypes.
//!
//! DEX files reference everything by per-file index. Once decrypted DEX images
//! start arriving at runtime, indices from different files collide. Every
//! reference is therefore canonicalised to a `Sym` (a dense u32 id), so classes
//! loaded from any image can be linked by name.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sym(pub u32);

impl Sym {
    /// The unused/default symbol. Never corresponds to a real string.
    pub const NONE: Sym = Sym(u32::MAX);
}

#[derive(Default, Clone)]
pub struct Interner {
    map: HashMap<Box<str>, Sym>,
    strings: Vec<Box<str>>,
}

impl Interner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, s: &str) -> Sym {
        if let Some(sym) = self.map.get(s) {
            return *sym;
        }
        let id = Sym(self.strings.len() as u32);
        let boxed: Box<str> = s.into();
        self.strings.push(boxed.clone());
        self.map.insert(boxed, id);
        id
    }

    pub fn get(&self, sym: Sym) -> &str {
        self.strings
            .get(sym.0 as usize)
            .map(|s| s.as_ref())
            .unwrap_or("")
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Interned class descriptors in load order (for reporting).
    pub fn all(&self) -> impl Iterator<Item = &str> {
        self.strings.iter().map(|s| s.as_ref())
    }
}

/// A canonical method reference: (declaring class, name, prototype).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MethodKey {
    pub class: Sym,
    pub name: Sym,
    pub proto: Sym,
}

/// A canonical field reference: (declaring class, name, type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldKey {
    pub class: Sym,
    pub name: Sym,
    pub ty: Sym,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_is_stable() {
        let mut i = Interner::new();
        let a = i.intern("Ljava/lang/String;");
        let b = i.intern("Ljava/lang/String;");
        let c = i.intern("Ljava/lang/Object;");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(i.get(a), "Ljava/lang/String;");
        assert_eq!(i.len(), 2);
    }
}
