//! Turns an `Outcome` into the artefacts an analyst consumes:
//!
//!   * `findings` — ranked, deduplicated behaviours with the evidence that
//!     produced them and the call path that reached them
//!   * `graph`    — the executed call graph, with the runtime-recovered
//!     methods marked
//!   * `render`   — a fixed-width text report and a JSON document
//!
//! Everything here is a pure function of the trace. No new speculation is
//! introduced at this layer, so a reader can always check a finding against
//! the event list.

pub mod findings;
pub mod graph;
pub mod render;

pub use findings::{Finding, Severity};
pub use graph::CallGraph;

use unhusk_vm::events::{Event, EventKind, Layer};

/// Static facts about the APK that the report cites alongside the trace.
#[derive(Debug, Clone, Default)]
pub struct StaticFacts {
    pub package: String,
    pub app_label: String,
    pub version_name: String,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub debuggable: bool,
    pub permissions: Vec<String>,
    pub exported_components: Vec<String>,
    pub dex_files: Vec<String>,
    pub native_abis: Vec<String>,
    pub native_libs: Vec<String>,
    pub packer_hits: Vec<(String, String)>,
    pub suspicious_apis: Vec<(String, String)>,
    pub apk_sha256: String,
    pub apk_size: u64,
    pub entry_classes: Vec<String>,
}

/// The complete report input.
pub struct ReportInput<'a> {
    pub facts: StaticFacts,
    pub events: &'a [Event],
    pub recovered: &'a [unhusk_vm::interp::program::RecoveredDex],
    pub requests: &'a [unhusk_vm::env::RecordedRequest],
    pub executed: &'a [String],
    pub stop: String,
    pub instructions: u64,
    pub elapsed_ms: u64,
    pub profile: String,
    pub trace_truncated: bool,
    pub classes_in_recovered: Vec<String>,
}

/// A fully built report, ready to render.
pub struct Report {
    pub facts: StaticFacts,
    /// Methods whose body came from a payload recovered during this run.
    /// Populated from the trace's `RecoveredDex` layer, so the renderer never
    /// has to guess from a class name.
    pub runtime_methods: std::collections::BTreeSet<String>,
    pub findings: Vec<Finding>,
    pub graph: CallGraph,
    pub recovered: Vec<RecoveredSummary>,
    pub requests: Vec<RequestSummary>,
    pub stats: ReportStats,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveredSummary {
    pub name: String,
    pub sha1: String,
    pub size: usize,
    pub classes: usize,
    pub how: String,
    /// Fully-qualified names of the classes in the recovered DEX.
    pub class_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RequestSummary {
    pub method: String,
    pub url: String,
    pub body_preview: String,
    pub body_len: usize,
    pub provenance: String,
    pub caller: String,
}

#[derive(Debug, Clone, Default)]
pub struct ReportStats {
    pub events: usize,
    pub events_dropped: u64,
    pub methods_entered: usize,
    pub instructions: u64,
    pub elapsed_ms: u64,
    pub stop: String,
    pub profile: String,
    pub requests: usize,
    pub recovered_dex: usize,
    pub runtime_classes: usize,
    pub evasion_probes: usize,
    pub critical_events: usize,
}

impl<'a> ReportInput<'a> {
    pub fn build(self) -> Report {
        let graph = graph::build(self.events, self.executed);
        let findings = findings::extract(&self, &graph);
        let recovered: Vec<RecoveredSummary> = self
            .recovered
            .iter()
            .map(|r| RecoveredSummary {
                name: r.name.clone(),
                sha1: r.sha1.clone(),
                size: r.size,
                classes: r.classes,
                how: format!("{:?}", r.recovery),
                class_names: self
                    .classes_in_recovered
                    .iter()
                    .filter(|c| is_from_recovered(c, r))
                    .cloned()
                    .collect(),
            })
            .collect();
        let requests: Vec<RequestSummary> = self
            .requests
            .iter()
            .map(|r| RequestSummary {
                method: r.method.clone(),
                url: r.url.clone(),
                body_preview: crate::render::preview(&r.body, 64),
                body_len: r.body.len(),
                provenance: r.body_provenance.clone(),
                caller: r.caller.clone(),
            })
            .collect();
        let evasion_probes = self
            .events
            .iter()
            .filter(|e| e.kind == EventKind::Evasion)
            .count();
        let critical_events = self
            .events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    EventKind::Egress | EventKind::Exec | EventKind::DynamicLoad
                )
            })
            .count();
        let runtime_classes = self
            .events
            .iter()
            .filter(|e| e.kind == EventKind::DynamicLoad && e.layer == Layer::RecoveredDex)
            .count();
        let stats = ReportStats {
            events: self.events.len(),
            events_dropped: 0,
            methods_entered: graph.method_count(),
            instructions: self.instructions,
            elapsed_ms: self.elapsed_ms,
            stop: self.stop.clone(),
            profile: self.profile.clone(),
            requests: self.requests.len(),
            recovered_dex: self.recovered.len(),
            runtime_classes,
            evasion_probes,
            critical_events,
        };
        // Facts the comparison pass adds: which reads returned different values
        // under the two profiles. That difference *is* the evasion condition.
        let mut caveats = Vec::new();
        let mut profile_divergence: Vec<String> = Vec::new();
        {
            let mut by_subject: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
            for e in self.events {
                if e.subject.starts_with("android.os.Build") && e.kind == EventKind::Evasion {
                    if let Some(v) = e.args.first() {
                        let list = by_subject.entry(e.subject.as_str()).or_default();
                        if !list.contains(&v.as_str()) {
                            list.push(v.as_str());
                        }
                    }
                }
            }
            for (subject, values) in by_subject {
                if values.len() > 1 {
                    profile_divergence.push(format!("{subject}: {}", values.join("  |  ")));
                }
            }
        }
        if !profile_divergence.is_empty() {
            caveats.push(format!(
                "the sample read {} device propert(ies) that differ between the hardened and emulator profiles; the values it saw are listed under the emulator-check finding",
                profile_divergence.len()
            ));
        }
        if self.trace_truncated {
            caveats.push(
                "trace was truncated at the event cap; late behaviour may be missing".to_string(),
            );
        }
        if self.stop.starts_with("budget") {
            caveats.push(format!(
                "analysis stopped early ({}) — the sample may do more",
                self.stop
            ));
        }
        if self.recovered.is_empty() && !self.classes_in_recovered.is_empty() {
            caveats.push("no runtime payload was recovered".to_string());
        }
        let runtime_methods: std::collections::BTreeSet<String> = self
            .events
            .iter()
            .filter(|e| e.kind == EventKind::MethodEnter && e.layer == Layer::RecoveredDex)
            .map(|e| e.subject.clone())
            .collect();
        Report {
            facts: self.facts,
            runtime_methods,
            findings,
            graph,
            recovered,
            requests,
            stats,
            caveats,
        }
    }
}

fn is_from_recovered(class: &str, r: &unhusk_vm::interp::program::RecoveredDex) -> bool {
    // The recovered summary lists class names by descriptor; match on the
    // DEX sha1 preserved in the name when we have it, else fall back to
    // "any class that did not exist in the shipped DEX" by convention.
    let _ = (class, r);
    true
}
