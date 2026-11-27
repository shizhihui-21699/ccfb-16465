//! A dependency-free Dalvik executable (`classes.dex`) decoder.
//!
//! The crate deliberately exposes a *resolved* model: every reference is an
//! index into an owned table, so higher layers never chase file offsets. All
//! reads are bounds checked and every structural inconsistency becomes a typed
//! error rather than a panic, because the input is attacker controlled.

pub mod error;
pub mod insn;
pub mod model;
pub mod reader;

pub use error::{DexError, ErrorKind, Result};
pub use model::parse;
pub use model::{
    Class, ClassData, Code, DexFile, EncodedValue, Field, FieldRef, InsnTable, Method, MethodRef,
    ProtoRef, Type,
};

/// DEX magic as it appears in every file.
pub const DEX_MAGIC: &[u8; 8] = b"dex\n035\0";
