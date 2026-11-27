//! The Dalvik interpreter.

pub mod classinit;
pub mod dynamic;
pub mod engine;
pub mod invoke;
pub mod ops;
pub mod program;
pub mod state;

pub use program::{MethodHandle, MethodOrigin, Program, RecoveredDex, Recovery};
