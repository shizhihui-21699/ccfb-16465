//! Human- and machine-readable analysis output.
//!
//! Everything the pipeline learns is recorded here; the CLI renders it as JSON
//! and as an analyst-facing markdown brief. Findings are ordered by severity so
//! that a triage run's first screen is the actionable part.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// What kind of dangerous operation was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// HTTP(S) request / socket connection to a remote endpoint.
    Network,
    /// SMS send / intercept.
    Sms,
    /// Shell command execution.
    CommandExec,
    /// Dynamic code loading (DEX/AAR/APK from memory or disk).
    DynamicCodeLoad,
    /// Native library load or JNI call into unknown native code.
    NativeLoad,
    /// File write outside the app's private sandbox.
    FileWrite,
    /// Reflection used to reach hidden APIs.
    Reflection,
    /// Install/remove package, device admin, accessibility abuse.
    PrivilegedAction,
    /// Data exfiltration-shaped flow: sensitive source -> encoded payload.
    SensitiveFlow,
    /// Deliberate anti-analysis / emulator detection.
    Evasion,
    /// Persistence registration (receiver, service, alarm, boot).
    Persistence,
    /// Information disclosure of device identity.
    DeviceFingerprint,
    /// Reading a bundled asset; low signal alone, but it is where packed
    /// payloads live, so it is worth listing next to a dynamic load.
    AssetRead,
}

impl SinkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SinkKind::Network => "network",
            SinkKind::Sms => "sms",
            SinkKind::CommandExec => "command_exec",
            SinkKind::DynamicCodeLoad => "dynamic_code_load",
            SinkKind::NativeLoad => "native_load",
            SinkKind::FileWrite => "file_write",
            SinkKind::Reflection => "reflection",
            SinkKind::PrivilegedAction => "privileged_action",
            SinkKind::SensitiveFlow => "sensitive_flow",
            SinkKind::Evasion => "evasion",
            SinkKind::Persistence => "persistence",
            SinkKind::DeviceFingerprint => "device_fingerprint",
            SinkKind::AssetRead => "asset_read",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            SinkKind::Network => Severity::High,
            SinkKind::Sms => Severity::Critical,
            SinkKind::CommandExec => Severity::Critical,
            SinkKind::DynamicCodeLoad => Severity::High,
            SinkKind::NativeLoad => Severity::Medium,
            SinkKind::FileWrite => Severity::Low,
            SinkKind::Reflection => Severity::Low,
            SinkKind::PrivilegedAction => Severity::High,
            SinkKind::SensitiveFlow => Severity::High,
            SinkKind::Evasion => Severity::Info,
            SinkKind::Persistence => Severity::Medium,
            SinkKind::DeviceFingerprint => Severity::Low,
            SinkKind::AssetRead => Severity::Low,
        }
    }
}

/// A concrete observation: a dangerous API was reached with this data, from
/// this call stack, in this scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: SinkKind,
    pub severity: Severity,
    /// Fully qualified API, e.g. `java/net/HttpURLConnection->connect()V`.
    pub api: String,
    /// One-line summary of what was seen (endpoint, command, payload size...).
    pub detail: String,
    /// Taint labels carried by the payload.
    pub taint: Vec<String>,
    /// Interpreter call stack, innermost last.
    pub stack: Vec<String>,
    /// Decrypted strings / bytes that explain the finding.
    pub evidence: Vec<String>,
    /// Scenario in which it was observed.
    pub scenario: String,
    /// Deduplication key (kind + api + detail + stack shape).
    #[serde(skip)]
    pub dedup_key: String,
}

/// An environment probe whose answer could gate malicious behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub api: String,
    pub value: String,
    pub scenario: String,
}

/// A DEX image that was parsed, whether from the APK or decrypted at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexInfo {
    pub origin: String,
    pub size: usize,
    pub sha256: String,
    pub strings: usize,
    pub methods: usize,
    pub classes: usize,
    /// True when the image was produced by the sample at runtime.
    pub dynamic: bool,
    /// Where the recovered image was written, if anywhere.
    pub dump_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub name: String,
    pub description: String,
    pub findings: Vec<Finding>,
    pub probes: Vec<Probe>,
    pub steps: u64,
    pub elapsed_ms: u64,
    pub completed: bool,
    pub stop_reason: Option<String>,
    /// Framework methods that had no model and were answered with defaults.
    pub coverage_gaps: BTreeMap<String, u64>,
    /// Exceptions that killed an entry point.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleReport {
    pub apk_path: String,
    pub apk_sha256: String,
    pub apk_size: u64,
    pub package: Option<String>,
    pub version_name: Option<String>,
    pub launcher: Vec<String>,
    pub permissions: Vec<String>,
    pub receivers: Vec<String>,
    pub services: Vec<String>,
    pub dexes: Vec<DexInfo>,
    pub native_libs: Vec<NativeLib>,
    pub embedded_payloads: Vec<EmbeddedPayload>,
    pub scenarios: Vec<ScenarioReport>,
    /// Merged, de-duplicated, severity-sorted findings.
    pub findings: Vec<Finding>,
    pub total_elapsed_ms: u64,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLib {
    pub path: String,
    pub arch: String,
    pub size: usize,
    pub sha256: String,
    /// JNI entry points exported with `Java_` or registered via
    /// `RegisterNatives`; empty when the library is stripped/encrypted.
    pub exports: Vec<String>,
    /// High-entropy blobs are usually encrypted payloads or packed libraries.
    pub suspicious_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedPayload {
    /// Zip entry or asset path.
    pub path: String,
    /// `dex`, `jar`, `apk`, `elf`, `base64-dex`, `encrypted`, ...
    pub kind: String,
    pub size: usize,
    pub sha256: String,
    /// How the payload was recognised (magic, entropy, structure).
    pub reason: String,
}

impl SampleReport {
    pub fn empty(apk_path: &str) -> Self {
        SampleReport {
            apk_path: apk_path.to_string(),
            apk_sha256: String::new(),
            apk_size: 0,
            package: None,
            version_name: None,
            launcher: Vec::new(),
            permissions: Vec::new(),
            receivers: Vec::new(),
            services: Vec::new(),
            dexes: Vec::new(),
            native_libs: Vec::new(),
            embedded_payloads: Vec::new(),
            scenarios: Vec::new(),
            findings: Vec::new(),
            total_elapsed_ms: 0,
            notes: Vec::new(),
        }
    }

    /// Merge per-scenario findings into the top-level list, de-duplicating on
    /// kind/API/detail/stack and keeping the earliest scenario that saw each.
    pub fn merge_findings(&mut self) {
        let mut seen = std::collections::HashSet::new();
        let mut all: Vec<Finding> = Vec::new();
        for sc in &self.scenarios {
            for f in &sc.findings {
                let key = format!(
                    "{}|{}|{}|{}",
                    f.kind.as_str(),
                    f.api,
                    f.detail,
                    f.stack.join(">")
                );
                if seen.insert(key) {
                    all.push(f.clone());
                }
            }
        }
        all.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.api.cmp(&b.api))
        });
        self.findings = all;
    }

    /// Highest severity across all findings.
    pub fn top_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }
}
