//! A bounded Dalvik interpreter plus the Android/JDK model it runs against.
//!
//! Layering:
//!   * `value`/`heap`  — registers and objects
//!   * `crypto`        — primitives and the "did this decode?" detectors
//!   * `env`           — the emulated phone, filesystem, clock and network
//!   * `events`        — the observation stream the report is built from
//!   * `interp`        — decode-free execution over `unhusk-dex` instructions
//!   * `framework`     — the Android/JDK methods the interpreter models

pub mod analysis;
pub mod crypto;
pub mod env;
pub mod events;
pub mod framework;
pub mod heap;
pub mod interp;
pub mod limits;
pub mod native;
pub mod value;

pub use value::{ObjId, Provenance, Tag, Value};
