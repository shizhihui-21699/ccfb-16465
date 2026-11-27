//! Behaviour findings: what the analyst reads first.
//!
//! A finding is a *conclusion* with evidence attached, not an event. Many
//! events collapse into one finding (three `File.exists` probes on root paths
//! are one "checks for root" finding). Everything here is derived from the
//! trace by rules that are explicit and reviewable; the rules never claim more
//! than the corresponding events show.

use crate::ReportInput;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use unhusk_vm::events::{Event, EventKind, Layer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }

    pub fn score(self) -> u32 {
        match self {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 8,
            Severity::High => 20,
            Severity::Critical => 40,
        }
    }
}

/// One piece of evidence backing a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub caller: String,
    pub detail: String,
    pub line: Option<u32>,
    /// Event sequence number, so the reader can find it in the raw trace.
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier for the rule, e.g. "runtime-dex-recovered".
    pub rule: &'static str,
    pub title: String,
    pub severity: Severity,
    /// One-paragraph statement of what was observed and why it matters.
    pub summary: String,
    /// Concrete artefacts: URLs, hashes, paths, class names.
    pub indicators: Vec<String>,
    pub evidence: Vec<Evidence>,
    /// Methods that reach the behaviour, innermost first.
    pub call_path: Vec<String>,
    /// MITRE ATT&CK-style tag, when the behaviour maps cleanly.
    pub technique: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    RuntimeDex,
    ReflectiveInvoke,
    DexWrite,
    Egress,
    Sms,
    ShellExec,
    RootProbe,
    EmulatorProbe,
    SensorProbe,
    TimeGate,
    DeviceFingerprint,
    PermissionDenied,
    NativeLoad,
    DynamicLoad,
}

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Rule::RuntimeDex => "runtime-dex-recovered",
            Rule::ReflectiveInvoke => "reflective-invoke",
            Rule::DexWrite => "dex-written-to-disk",
            Rule::Egress => "network-egress",
            Rule::Sms => "sms-send",
            Rule::ShellExec => "shell-exec",
            Rule::RootProbe => "root-artifact-probe",
            Rule::EmulatorProbe => "emulator-artifact-probe",
            Rule::SensorProbe => "sensor-probe",
            Rule::TimeGate => "time-gate",
            Rule::DeviceFingerprint => "device-fingerprint",
            Rule::PermissionDenied => "permission-check",
            Rule::NativeLoad => "native-library-load",
            Rule::DynamicLoad => "dynamic-class-load",
        }
    }
}

/// Extract findings from the trace.
pub fn extract(input: &ReportInput<'_>, graph: &crate::CallGraph) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    runtime_payload(input, graph, &mut findings);
    egress(input, graph, &mut findings);
    sms(input, graph, &mut findings);
    shell(input, graph, &mut findings);
    probes(input, graph, &mut findings);
    time_gates(input, graph, &mut findings);
    native(input, graph, &mut findings);
    reflection(input, graph, &mut findings);

    // Evidence can repeat across passes (same call, different clock window).
    // Keep the first occurrence of each distinct (caller, detail) pair.
    for f in &mut findings {
        let mut seen = std::collections::BTreeSet::new();
        f.evidence
            .retain(|e| seen.insert((e.caller.clone(), e.detail.clone())));
    }
    // Rank: severity first, then evidence count, then earliest event.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.evidence.len().cmp(&a.evidence.len()))
            .then_with(|| {
                let ea = a.evidence.first().map(|e| e.seq).unwrap_or(0);
                let eb = b.evidence.first().map(|e| e.seq).unwrap_or(0);
                ea.cmp(&eb)
            })
    });
    findings
}

fn ev(e: &Event, detail: String) -> Evidence {
    Evidence {
        kind: format!("{:?}", e.kind),
        caller: e.caller.clone(),
        detail,
        line: e.line,
        seq: e.seq,
    }
}

/// The shortest executed path from an entry point down to `method`, walked
/// backwards through real call edges. This is the "how did we get here" line
/// the analyst needs; unrelated calls that merely happened to be in the same
/// method are deliberately excluded.
fn call_path(graph: &crate::CallGraph, method: &str) -> Vec<String> {
    let mut path = vec![method.to_string()];
    let mut cur = method.to_string();
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(cur.clone());
    // Walk up to the first caller that is itself a root; bounded to avoid a
    // pathological cycle.
    for _ in 0..12 {
        let mut callers = graph.callers(&cur);
        // Prefer a caller that is not an entry we synthesised.
        callers.sort();
        let Some(parent) = callers.into_iter().next() else {
            break;
        };
        if !seen.insert(parent.to_string()) {
            break;
        }
        path.push(parent.to_string());
        cur = parent.to_string();
    }
    path
}

/// A DEX that only exists at runtime was recovered and executed.
fn runtime_payload(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    // Only classloader-shaped events count as "dynamic code loading". A
    // `native method not emulated` note or a lambda call site is not.
    let is_loader_event = |e: &Event| {
        e.kind == EventKind::DynamicLoad
            && (e.subject.contains("ClassLoader")
                || e.subject.contains("loadClass")
                || e.subject.contains("loadDex")
                || e.subject.contains("loadLibrary")
                || e.subject.contains("Method.invoke")
                || e.layer == Layer::RecoveredDex
                || e.result
                    .as_deref()
                    .map(|r| r.contains("recovered DEX"))
                    .unwrap_or(false))
    };
    let loads: Vec<&Event> = input.events.iter().filter(|e| is_loader_event(e)).collect();
    if loads.is_empty() && input.recovered.is_empty() {
        return;
    }
    let mut indicators = Vec::new();
    for r in input.recovered {
        indicators.push(format!(
            "{} (sha1 {}, {} classes, {} bytes)",
            r.name, r.sha1, r.classes, r.size
        ));
    }
    // Only classes that were actually executed count as "recovered and run".
    let runtime_methods: Vec<String> = input
        .events
        .iter()
        .filter(|e| e.kind == EventKind::MethodEnter && e.layer == Layer::RecoveredDex)
        .map(|e| e.subject.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let ran_runtime_code = !runtime_methods.is_empty();
    let severity = if input.recovered.is_empty() {
        Severity::Medium
    } else if ran_runtime_code {
        Severity::Critical
    } else {
        Severity::High
    };
    let title = if input.recovered.is_empty() {
        "Dynamic code loading attempted".to_string()
    } else if ran_runtime_code {
        format!(
            "Runtime-unpacked DEX recovered and executed ({} method(s))",
            runtime_methods.len()
        )
    } else {
        "Runtime-unpacked DEX recovered (not observed executing)".to_string()
    };
    let summary = build_runtime_summary(input, ran_runtime_code);
    out.push(Finding {
        rule: Rule::RuntimeDex.id(),
        title,
        severity,
        summary,
        indicators,
        evidence: loads
            .iter()
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect(),
        call_path: loads
            .first()
            .map(|e| call_path(graph, &e.caller))
            .unwrap_or_default(),
        technique: Some("T1406 Obfuscated Files or Information"),
    });
}

fn build_runtime_summary(input: &ReportInput<'_>, ran: bool) -> String {
    if input.recovered.is_empty() {
        return "The sample attempted to load code that is not part of the APK \
                (a classloader over a path or buffer). No payload was recovered, \
                so the loaded code's behaviour is unknown. This is typical of \
                packers whose payload needs native support we could not emulate."
            .to_string();
    }
    let mut s = format!(
        "The sample decrypted {} DEX payload(s) at runtime and installed them through a \
         classloader. This is the signature of a packer: the shipped DEX is only a stub \
         and the behaviour an analyst would need to review is not in it.",
        input.recovered.len()
    );
    if ran {
        s.push_str(" Code from the recovered payload was observed executing (see the call graph); its behaviour is included in the findings below.");
    }
    s
}

fn egress(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    if input.requests.is_empty() {
        // Still surface an attempted-but-unmodelled egress if we saw one.
        let any = input.events.iter().find(|e| e.kind == EventKind::Egress);
        if let Some(e) = any {
            out.push(Finding {
                rule: Rule::Egress.id(),
                title: "Outbound network request attempted".into(),
                severity: Severity::High,
                summary: "The sample issued a network request whose target or body \
                          could not be fully reconstructed. The event below records \
                          the API and arguments that were observed."
                    .into(),
                indicators: e.args.clone(),
                evidence: vec![ev(e, e.result.clone().unwrap_or_default())],
                call_path: call_path(graph, &e.caller),
                technique: Some("T1071 Application Layer Protocol"),
            });
        }
        return;
    }
    let mut indicators: Vec<String> = Vec::new();
    for r in input.requests {
        indicators.push(r.url.clone());
    }
    indicators.sort();
    indicators.dedup();
    // One finding per distinct target: a beacon and a C2 POST deserve separate
    // rows, and deduping by URL keeps a retry loop from flooding the report.
    let mut by_url: BTreeMap<String, Vec<&unhusk_vm::env::RecordedRequest>> = BTreeMap::new();
    for r in input.requests {
        by_url.entry(r.url.clone()).or_default().push(r);
    }
    for (url, reqs) in by_url {
        let first = reqs[0];
        let bodies: Vec<String> = reqs
            .iter()
            .map(|r| format!("{:?}", crate::render::preview(&r.body, 48)))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let prov: Vec<String> = reqs
            .iter()
            .map(|r| r.body_provenance.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let runtime_derived = prov
            .iter()
            .any(|p| p.contains("decoded") || p.contains("built"));
        let severity = if runtime_derived {
            Severity::Critical
        } else {
            Severity::High
        };
        let evidence: Vec<Evidence> = input
            .events
            .iter()
            .filter(|e| e.kind == EventKind::Egress && e.args.iter().any(|a| a.contains(&url)))
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect();
        out.push(Finding {
            rule: Rule::Egress.id(),
            title: format!("Network request to {url}"),
            severity,
            summary: format!(
                "{} request(s) to {url}. Body: {}{}. Provenance of the body data: {}.",
                reqs.len(),
                bodies.join(" / "),
                if runtime_derived {
                    " — the body was assembled or decrypted at runtime, not a constant in the APK"
                } else {
                    ""
                },
                prov.join(", ")
            ),
            indicators: vec![url.to_string()],
            evidence,
            call_path: call_path(graph, &first.caller),
            technique: Some("T1071 Application Layer Protocol"),
        });
    }
}

fn sms(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    let hits: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| e.kind == EventKind::PrivilegedApi && e.subject.contains("SmsManager"))
        .collect();
    if hits.is_empty() {
        return;
    }
    let dests: Vec<String> = hits.iter().filter_map(|e| e.args.get(1).cloned()).collect();
    out.push(Finding {
        rule: Rule::Sms.id(),
        title: format!("Sends SMS to {}", dests.join(", ")),
        severity: Severity::Critical,
        summary: "The sample used SmsManager to send a message. On a real device this \
                  can subscribe the user to a premium number or spread links to contacts."
            .into(),
        indicators: dests,
        evidence: hits
            .iter()
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect(),
        call_path: call_path(graph, &hits[0].caller),
        technique: Some("T1582 SMS Control"),
    });
}

fn shell(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    let hits: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Exec)
        .collect();
    if hits.is_empty() {
        return;
    }
    let cmds: Vec<String> = hits.iter().map(|e| e.args.join(" ")).collect();
    out.push(Finding {
        rule: Rule::ShellExec.id(),
        title: "Executes shell commands".into(),
        severity: Severity::Critical,
        summary: "The sample invoked the shell. Command execution is how malware \
                  escalates to root, drops payloads and reads protected state."
            .into(),
        indicators: cmds,
        evidence: hits
            .iter()
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect(),
        call_path: call_path(graph, &hits[0].caller),
        technique: Some("T1623 Command and Scripting Interpreter"),
    });
}

fn probes(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    let mutations: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Evasion)
        .collect();
    if mutations.is_empty() {
        return;
    }
    // Split the two rules cleanly: file probes are "root artefacts", and
    // Build/sensor reads are "emulator / virtual device". A path that happens
    // to mention qemu is still a filesystem probe, so it belongs to the first
    // rule only — the reader sees it once.
    let root: Vec<&Event> = mutations
        .iter()
        .filter(|e| e.subject.contains("File;->exists") || e.subject.contains("File;->canRead"))
        .copied()
        .collect();
    // Emulator detection is a *combination* of signals, not one read.
    //
    // Every Android app reads `Build.VERSION.SDK_INT` and compares it; treating
    // that as evasion makes the rule fire on almost every real application.
    // The distinguishing property is breadth: a sample that fingerprints the
    // device reads several identifying properties, or probes sensors and build
    // fields together. So the rule requires either a sensor probe, or enough
    // *distinct identifying* Build reads to constitute a fingerprint.
    let identifying_reads: std::collections::BTreeSet<&str> = mutations
        .iter()
        .filter(|e| e.subject.starts_with("android.os.Build."))
        .filter_map(|e| e.subject.strip_prefix("android.os.Build."))
        .filter(|name| {
            !matches!(
                *name,
                "VERSION.SDK_INT"
                    | "VERSION.RELEASE"
                    | "VERSION.CODENAME"
                    | "VERSION.INCREMENTAL"
                    | "VERSION.PREVIEW_SDK_INT"
                    | "TYPE"
                    | "TAGS"
            )
        })
        .collect();
    let sensor_probe = mutations.iter().any(|e| {
        e.subject.contains("getSensorList")
            || e.subject.contains("getDefaultSensor")
            || e.subject.contains("registerListener")
    });
    let fingerprinting = identifying_reads.len() >= 3;
    let emu: Vec<&Event> = if sensor_probe || fingerprinting {
        mutations
            .iter()
            .filter(|e| {
                e.subject.starts_with("android.os.Build")
                    || e.subject.contains("getSensorList")
                    || e.subject.contains("getDefaultSensor")
                    || e.subject.contains("registerListener")
            })
            .copied()
            .collect()
    } else {
        Vec::new()
    };
    if !root.is_empty() {
        // The path probed is in the result text ("... path probe: /system/bin/su");
        // the argument is only the File object, which is useless to a reader.
        let mut paths: Vec<String> = root
            .iter()
            .filter_map(|e| e.result.as_deref())
            .filter_map(|r| r.rsplit(": ").next())
            .map(|p| p.to_string())
            .collect();
        paths.sort();
        paths.dedup();
        out.push(Finding {
            rule: Rule::RootProbe.id(),
            title: "Checks for root / analysis artefacts".into(),
            severity: Severity::High,
            summary: "The sample probes well-known root and emulator artefact paths. \
                      This is the first stage of most anti-analysis: if any of these exist \
                      it takes a benign path and the real behaviour never runs."
                .into(),
            indicators: paths,
            evidence: root
                .iter()
                .map(|e| ev(e, e.result.clone().unwrap_or_default()))
                .collect(),
            call_path: call_path(graph, &root[0].caller),
            technique: Some("T1497 Virtualization/Sandbox Evasion"),
        });
    }
    if !emu.is_empty() {
        // Summarise by property: which ones were read, and what the sample saw
        // under each profile. Showing both values is the point — it is the
        // evidence that the sample was looking for a difference.
        let mut props: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            Default::default();
        for e in &emu {
            for a in &e.args {
                if let Some((k, v)) = a.split_once(" = ") {
                    props
                        .entry(k.to_string())
                        .or_default()
                        .insert(v.to_string());
                }
            }
            if !e.subject.starts_with("android.os.Build") {
                props
                    .entry(e.subject.clone())
                    .or_default()
                    .insert("observed".into());
            }
        }
        let mut indicators: Vec<String> = Vec::new();
        for (prop, values) in props {
            if values.len() == 1 {
                indicators.push(prop);
            } else {
                indicators.push(format!(
                    "{prop}: {}",
                    values.into_iter().collect::<Vec<_>>().join(" vs ")
                ));
            }
        }
        out.push(Finding {
            rule: Rule::EmulatorProbe.id(),
            title: "Checks for emulator / virtual device".into(),
            severity: Severity::High,
            summary: "The sample inspects device properties and sensor availability \
                      to decide whether it is running on a real phone. These checks \
                      determine whether the payload below would ever run in production."
                .into(),
            indicators,
            evidence: emu
                .iter()
                .map(|e| ev(e, e.result.clone().unwrap_or_default()))
                .collect(),
            call_path: call_path(graph, &emu[0].caller),
            technique: Some("T1497.001 System Checks"),
        });
    }
}

fn time_gates(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    let time_reads: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| {
            e.subject.contains("currentTimeMillis")
                || e.subject.contains("elapsedRealtime")
                || e.subject.contains("nanoTime")
                || e.subject.contains("SystemClock")
        })
        .collect();
    if time_reads.is_empty() {
        return;
    }
    out.push(Finding {
        rule: Rule::TimeGate.id(),
        title: "Reads the device clock".into(),
        severity: Severity::Medium,
        summary: "The sample read the system clock. Malware commonly gates its payload on a \
                  date window so that analysis performed outside that window sees nothing. \
                  The pipeline runs several clock offsets and unions the results for this reason."
            .into(),
        indicators: time_reads.iter().map(|e| e.subject.clone()).collect(),
        evidence: time_reads
            .iter()
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect(),
        call_path: call_path(graph, &time_reads[0].caller),
        technique: Some("T1497.003 Time Based Evasion"),
    });
}

fn native(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    // Loading a library is a finding; a *framework* native we could not model
    // is a coverage gap, not sample behaviour, and belongs in the caveats.
    let hits: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| e.kind == EventKind::DynamicLoad && e.subject.contains("loadLibrary"))
        .collect();
    if hits.is_empty() {
        return;
    }
    out.push(Finding {
        rule: Rule::NativeLoad.id(),
        title: "Loads or calls native code".into(),
        severity: Severity::High,
        summary: "The sample hands control to a native library. Packers put the \
                  decryption routine in the SO file precisely so that DEX-level \
                  analysis does not see it."
            .into(),
        indicators: hits.iter().map(|e| e.args.join(" ")).collect(),
        evidence: hits
            .iter()
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect(),
        call_path: call_path(graph, &hits[0].caller),
        technique: Some("T1027 Obfuscated Files or Information"),
    });
}

fn reflection(input: &ReportInput<'_>, graph: &crate::CallGraph, out: &mut Vec<Finding>) {
    let hits: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| {
            e.kind == EventKind::DynamicLoad
                && (e.subject.contains("getDeclaredMethod")
                    || e.subject.contains("Method;->invoke")
                    || e.subject.contains("Class;->forName")
                    || e.subject.contains("getDeclaredField"))
        })
        .collect();
    if hits.is_empty() {
        return;
    }
    out.push(Finding {
        rule: Rule::ReflectiveInvoke.id(),
        title: "Invokes code reflectively".into(),
        severity: Severity::Medium,
        summary: "The sample resolves methods and fields by name at runtime. Reflection \
                  hides the call target from static analysis; here it also marks the \
                  hand-off into recovered code."
            .into(),
        indicators: hits.iter().map(|e| e.subject.clone()).collect(),
        evidence: hits
            .iter()
            .map(|e| ev(e, e.result.clone().unwrap_or_default()))
            .collect(),
        call_path: call_path(graph, &hits[0].caller),
        technique: Some("T1620 Reflective Code Loading"),
    });
}

/// Aggregate severity for a report headline.
pub fn overall_score(findings: &[Finding]) -> u32 {
    findings.iter().map(|f| f.severity.score()).sum()
}
