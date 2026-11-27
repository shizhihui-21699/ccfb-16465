//! Native (AArch64) emulation for packer stubs.
//!
//! The DEX decryptor in a real packer is almost always in the `.so`, reached
//! through JNI. That code does ordinary things — XOR loops, RC4, AES, memcpy,
//! string building — but on register operands instead of Dalvik registers. We
//! therefore run the same *primitives* over a small ARM64 interpreter.
//!
//! Scope is deliberate: this emulates a **fraction** of AArch64, chosen to
//! cover compiled C that copies and transforms bytes. It refuses anything it
//! does not understand rather than guessing, and every refusal is reported with
//! the instruction that caused it, so an analyst can see exactly where the
//! native layer stopped.

pub mod aarch64;
pub mod jni;

use std::collections::BTreeMap;

/// Outcome of a native call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeOutcome {
    Returned { value: u64, steps: u64 },
    Unsupported { pc: u64, reason: String, steps: u64 },
    Budget { steps: u64 },
    Halted { reason: String, steps: u64 },
}

impl NativeOutcome {
    pub fn steps(&self) -> u64 {
        match self {
            NativeOutcome::Returned { steps, .. }
            | NativeOutcome::Unsupported { steps, .. }
            | NativeOutcome::Budget { steps }
            | NativeOutcome::Halted { steps, .. } => *steps,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, NativeOutcome::Returned { .. })
    }
}

/// A JNI call observed from native code.
#[derive(Debug, Clone)]
pub struct JniCall {
    pub function: String,
    pub args: Vec<String>,
    pub step: u64,
}

/// Everything a native call observed, surfaced into the trace.
#[derive(Debug, Clone, Default)]
pub struct NativeReport {
    pub calls: Vec<JniCall>,
    /// Bytes copied out through `memcpy`-like operations, useful as payloads.
    pub writable_bytes: BTreeMap<u64, Vec<u8>>,
    /// Regions the code asked to allocate.
    pub allocations: Vec<(u64, u64)>,
}

/// Configuration for a native run.
#[derive(Debug, Clone)]
pub struct NativeLimits {
    pub max_steps: u64,
}

impl Default for NativeLimits {
    fn default() -> Self {
        Self {
            max_steps: 5_000_000,
        }
    }
}
