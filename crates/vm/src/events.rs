//! Everything the interpreter observes is recorded as an `Event`. The report is
//! a projection of this stream; nothing is re-derived later from guesswork.

use crate::value::Provenance;
use serde::{Deserialize, Serialize};

/// Which layer produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Layer {
    /// Dalvik bytecode from the APK.
    Dex,
    /// Dalvik bytecode we recovered at runtime (decrypted / downloaded).
    RecoveredDex,
    /// A modelled framework API.
    Framework,
    /// Native library emulation.
    Native,
    /// The sandbox itself (budget, policy).
    Sandbox,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// Entry into a method we had not seen before.
    MethodEnter,
    /// A framework API was called with these arguments.
    ApiCall,
    /// Something was loaded dynamically (DEX, class, SO, script).
    DynamicLoad,
    /// A byte buffer was transformed and the result looks decoded.
    Decode,
    /// Data left the process (or would have).
    Egress,
    /// The sample probed the environment in a way that looks like evasion.
    Evasion,
    /// A file was written / read / deleted.
    FileOp,
    /// A command was executed in the emulated shell.
    Exec,
    /// A permission-gated API was reached.
    PrivilegedApi,
    /// A budget or policy decision changed execution.
    Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic sequence number, used to order the report.
    pub seq: u64,
    /// Instruction count when this happened.
    pub insn: u64,
    pub kind: EventKind,
    pub layer: Layer,
    /// Fully qualified caller, e.g. `com.x.Loader.unpack([B)V`.
    pub caller: String,
    /// API or subject, e.g. `java.lang.Runtime.exec`.
    pub subject: String,
    /// Human-readable argument summary (already truncated for size).
    pub args: Vec<String>,
    /// Human-readable result summary.
    pub result: Option<String>,
    /// Provenance of the primary value involved, if any.
    pub prov: Option<Provenance>,
    /// Source line in the sample's source file, when debug info has it.
    pub line: Option<u32>,
}

/// Truncate a value for the report without losing its shape.
pub fn summarize_bytes(data: &[u8], max: usize) -> String {
    if data.is_empty() {
        return "<empty>".to_string();
    }
    let shown = data.len().min(max);
    let mut s = String::with_capacity(shown * 2 + 32);
    for b in &data[..shown] {
        if (0x20..0x7f).contains(b) {
            s.push(*b as char);
        } else {
            s.push('.');
        }
    }
    if data.len() > shown {
        s.push_str(&format!("… (+{} bytes)", data.len() - shown));
    }
    s
}

/// Render bytes as hex, truncated.
pub fn summarize_hex(data: &[u8], max: usize) -> String {
    let shown = data.len().min(max);
    let mut s = String::with_capacity(shown * 3 + 16);
    for (i, b) in data[..shown].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    if data.len() > shown {
        s.push_str(&format!(" … (+{} bytes)", data.len() - shown));
    }
    s
}

/// A collected trace with a hard cap so a pathological sample cannot exhaust
/// memory through pure logging.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub events: Vec<Event>,
    pub cap: usize,
    pub dropped: u64,
    pub seq: u64,
}

pub const DEFAULT_TRACE_CAP: usize = 200_000;

impl Trace {
    pub fn new(cap: usize) -> Self {
        Self {
            events: Vec::new(),
            cap,
            dropped: 0,
            seq: 0,
        }
    }

    pub fn push(&mut self, mut ev: Event) -> u64 {
        self.seq += 1;
        ev.seq = self.seq;
        if self.events.len() < self.cap {
            self.events.push(ev);
        } else {
            self.dropped += 1;
        }
        self.seq
    }

    pub fn is_truncated(&self) -> bool {
        self.dropped > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_caps_and_counts_drops() {
        let mut t = Trace::new(2);
        for i in 0..5 {
            t.push(Event {
                seq: 0,
                insn: i,
                kind: EventKind::ApiCall,
                layer: Layer::Framework,
                caller: "x".into(),
                subject: "y".into(),
                args: vec![],
                result: None,
                prov: None,
                line: None,
            });
        }
        assert_eq!(t.events.len(), 2);
        assert_eq!(t.dropped, 3);
        assert!(t.is_truncated());
        assert_eq!(t.events[0].seq, 1);
    }

    #[test]
    fn byte_summaries_are_bounded() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let s = summarize_bytes(&data, 8);
        assert!(s.len() < 60);
        assert!(s.contains("+92"));
        let h = summarize_hex(&data, 4);
        assert!(h.starts_with("00 01 02 03"));
    }
}
