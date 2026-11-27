//! The neutral, serialisable result of an analysis run.

use serde::{Deserialize, Serialize};
use unhusk_vm::env::RecordedRequest;
use unhusk_vm::events::{Event, Trace};
use unhusk_vm::interp::program::RecoveredDex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredPayloadSummary {
    pub name: String,
    pub sha1: String,
    pub size: usize,
    pub classes: usize,
    pub recovery: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub package: String,
    pub apk_sha256: String,
    pub profile: String,
    pub stop: String,
    pub instructions: u64,
    pub elapsed_ms: u64,
    pub trace: Trace,
    pub recovered: Vec<RecoveredDex>,
    pub executed: Vec<String>,
    pub requests: Vec<RecordedRequest>,
    pub checks: std::collections::BTreeMap<String, String>,
    /// Raw bytes of every DEX recovered during the run, in discovery order.
    /// Kept off the wire (not serialised) because it can be large; extraction
    /// and re-analysis read it from here.
    #[serde(skip)]
    pub recovered_payloads: Vec<(String, Vec<u8>)>,
}

impl Outcome {
    pub fn events(&self) -> &[Event] {
        &self.trace.events
    }

    pub fn payload_summaries(&self) -> Vec<RecoveredPayloadSummary> {
        self.recovered
            .iter()
            .map(|r| RecoveredPayloadSummary {
                name: r.name.clone(),
                sha1: r.sha1.clone(),
                size: r.size,
                classes: r.classes,
                recovery: format!("{:?}", r.recovery),
            })
            .collect()
    }
}
