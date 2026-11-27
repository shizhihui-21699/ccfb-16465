//! The analysis engine: turns an APK into a report-ready `Outcome`.
//!
//! This crate owns the *pipeline* — triage, budget allocation, multi-pass
//! strategy — while `unhusk-vm` owns execution semantics.

pub mod outcome;

pub use outcome::{Outcome, RecoveredPayloadSummary};
