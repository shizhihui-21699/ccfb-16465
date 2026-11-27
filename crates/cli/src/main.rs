//! `unhusk` — analyse one or many APKs and print the report.
//!
//! Exit codes are part of the contract so the tool can gate a pipeline:
//!   0  no findings at or above the failure threshold
//!   1  a finding met the threshold
//!   2  the input could not be analysed at all

use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use unhusk_engine::pipeline::{self, PipelineConfig};
use unhusk_report::render::{render_text, to_json};
use unhusk_report::{Report, ReportInput};

#[derive(Parser)]
#[command(
    name = "unhusk",
    version,
    about = "Static + dynamic analysis for packed Android samples",
    long_about = "unhusk parses an APK, executes its Dalvik bytecode in a bounded \
                  sandbox that models the Android framework, recovers code decrypted \
                  at runtime, and reports the malicious behaviour with the call path \
                  that reached it."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyse an APK and print the report.
    Scan {
        /// APK file(s).
        #[arg(required = true)]
        apk: Vec<PathBuf>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Include static facts and routine API traffic.
        #[arg(long, short)]
        verbose: bool,
        /// Total wall-clock budget in seconds, shared across all passes.
        #[arg(long, default_value_t = 120)]
        budget_secs: u64,
        /// How many emulated clock windows to try.
        #[arg(long, default_value_t = 4)]
        windows: usize,
        /// Skip the naive-emulator comparison pass.
        #[arg(long)]
        no_compare: bool,
        /// Fail (exit 1) when any finding reaches this severity.
        #[arg(long, value_enum, default_value_t = Threshold::High)]
        fail_on: Threshold,
        /// Write a copy of every recovered DEX payload to this directory.
        #[arg(long)]
        extract: Option<PathBuf>,
    },
    /// Print only the static triage (manifest, packers, interesting APIs).
    Triage {
        #[arg(required = true)]
        apk: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Analyse every APK under a directory, in parallel, with a per-sample budget.
    Batch {
        dir: PathBuf,
        /// Per-sample wall-clock budget in seconds.
        #[arg(long, default_value_t = 90)]
        budget_secs: u64,
        #[arg(long)]
        json: bool,
        /// Write one JSON report per sample here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Only report samples at or above this severity.
        #[arg(long, value_enum, default_value_t = Threshold::Medium)]
        min_severity: Threshold,
        #[arg(long, short)]
        verbose: bool,
    },
    /// Print the decoded call graph for one APK as DOT.
    Graph {
        apk: PathBuf,
        #[arg(long, default_value_t = 120)]
        budget_secs: u64,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Threshold {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Threshold {
    fn severity(self) -> unhusk_report::Severity {
        match self {
            Threshold::Info => unhusk_report::Severity::Info,
            Threshold::Low => unhusk_report::Severity::Low,
            Threshold::Medium => unhusk_report::Severity::Medium,
            Threshold::High => unhusk_report::Severity::High,
            Threshold::Critical => unhusk_report::Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan {
            apk,
            json,
            verbose,
            budget_secs,
            windows,
            no_compare,
            fail_on,
            extract,
        } => {
            let cfg = PipelineConfig {
                total_budget_ms: budget_secs * 1000,
                windows,
                compare: !no_compare,
                verbose,
            };
            let mut worst = unhusk_report::Severity::Info;
            let mut any_ok = false;
            for path in &apk {
                match analyse_one(path, &cfg) {
                    Ok(report) => {
                        any_ok = true;
                        if let Some(dir) = &extract {
                            if let Err(e) = extract_payloads(path, &cfg, dir) {
                                eprintln!("warning: extraction failed: {e}");
                            }
                        }
                        if json {
                            println!("{}", to_json(&report));
                        } else {
                            if apk.len() > 1 {
                                println!("--- {}", path.display());
                            }
                            print!("{}", render_text(&report, verbose));
                        }
                        if let Some(f) = report.findings.first() {
                            worst = worst.max(f.severity);
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {}: {e}", path.display());
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({"schema":"unhusk/report/v1","error":e.to_string(),"path":path.display().to_string()})
                            );
                        }
                    }
                }
            }
            if !any_ok {
                return ExitCode::from(2);
            }
            if worst >= fail_on.severity() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Cmd::Triage { apk, json } => {
            for path in &apk {
                match unhusk_apk::Apk::open(path) {
                    Ok(a) => {
                        let f = pipeline::static_facts(&a);
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&triage_json(&f)).unwrap_or_default()
                            );
                        } else {
                            print!("{}", triage_text(&f, path));
                        }
                    }
                    Err(e) => eprintln!("error: {}: {e}", path.display()),
                }
            }
            ExitCode::SUCCESS
        }
        Cmd::Batch {
            dir,
            budget_secs,
            json,
            out,
            min_severity,
            verbose,
        } => {
            let paths: Vec<PathBuf> = walkdir::WalkDir::new(&dir)
                .max_depth(4)
                .into_iter()
                .filter_map(|e| e.ok())
                .map(|e| e.into_path())
                .filter(|p| p.extension().map(|x| x == "apk").unwrap_or(false))
                .collect();
            let cfg = PipelineConfig {
                total_budget_ms: budget_secs * 1000,
                windows: 3,
                compare: true,
                verbose,
            };
            let results: Vec<_> = {
                use rayon::prelude::*;
                paths
                    .par_iter()
                    .map(|p| (p.clone(), analyse_one(p, &cfg)))
                    .collect()
            };
            let mut flagged = 0usize;
            let mut failed = 0usize;
            if let Some(d) = &out {
                let _ = std::fs::create_dir_all(d);
            }
            for (path, r) in &results {
                match r {
                    Ok(report) => {
                        let sev = report
                            .findings
                            .first()
                            .map(|f| f.severity)
                            .unwrap_or(unhusk_report::Severity::Info);
                        if sev >= min_severity.severity() {
                            flagged += 1;
                            if json {
                                println!("{}", to_json(report));
                            } else {
                                println!(
                                    "{}  {}  {} finding(s)  {}",
                                    sev.tag(),
                                    report.facts.package,
                                    report.findings.len(),
                                    path.display()
                                );
                            }
                        }
                        if let Some(d) = &out {
                            let name = path
                                .file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_else(|| "sample".into());
                            let _ = std::fs::write(d.join(format!("{name}.json")), to_json(report));
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        eprintln!("error: {}: {e}", path.display());
                    }
                }
            }
            eprintln!(
                "{} sample(s), {} flagged at >= {}, {} failed, {} clean",
                results.len(),
                flagged,
                min_severity.severity().as_str(),
                failed,
                results.len() - flagged - failed
            );
            if failed > 0 && failed == results.len() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Cmd::Graph { apk, budget_secs } => {
            let cfg = PipelineConfig {
                total_budget_ms: budget_secs * 1000,
                windows: 1,
                compare: false,
                verbose: false,
            };
            match analyse_one(&apk, &cfg) {
                Ok(report) => {
                    print!("{}", dot(&report));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

fn analyse_one(path: &Path, cfg: &PipelineConfig) -> Result<Report, BoxErr> {
    let apk = unhusk_apk::Apk::open(path)?;
    let merged = pipeline::run(&apk, cfg);
    let o = &merged.outcome;
    let recovered_classes = collect_recovered_classes(&o.recovered);
    let input = ReportInput {
        facts: merged.facts.clone(),
        events: o.events(),
        recovered: &o.recovered,
        requests: &o.requests,
        executed: &o.executed,
        stop: o.stop.clone(),
        instructions: o.instructions,
        elapsed_ms: o.elapsed_ms,
        profile: o.profile.clone(),
        trace_truncated: o.trace.is_truncated(),
        classes_in_recovered: recovered_classes,
    };
    Ok(input.build())
}

fn collect_recovered_classes(
    recovered: &[unhusk_vm::interp::program::RecoveredDex],
) -> Vec<String> {
    // Class names are recorded when the payload is registered; the summaries
    // carry counts, and the graph carries the executed names.
    let _ = recovered;
    Vec::new()
}

struct ExtractErr(String);

impl std::fmt::Display for ExtractErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn extract_payloads(path: &Path, cfg: &PipelineConfig, dir: &Path) -> Result<(), BoxErr> {
    let apk = unhusk_apk::Apk::open(path)?;
    let a = unhusk_vm::analysis::analyze(&apk, &analysis_config(cfg));
    std::fs::create_dir_all(dir)?;
    for (name, bytes) in a.machine.recovered_payloads.iter() {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        std::fs::write(dir.join(format!("{safe}.dex")), bytes)?;
        println!("extracted {} -> {}/{}.dex", name, dir.display(), safe);
    }
    let _ = ExtractErr(String::new());
    Ok(())
}

fn analysis_config(cfg: &PipelineConfig) -> unhusk_vm::analysis::AnalysisConfig {
    let mut c = unhusk_vm::analysis::AnalysisConfig::default();
    c.policy.record_all_apis = cfg.verbose;
    c.limits.max_instructions = 60_000_000;
    c.limits.max_wall = std::time::Duration::from_millis(cfg.total_budget_ms.min(120_000));
    c.keep_payloads = true;
    c
}

fn triage_json(f: &unhusk_report::StaticFacts) -> serde_json::Value {
    serde_json::json!({
        "package": f.package,
        "version": f.version_name,
        "min_sdk": f.min_sdk,
        "target_sdk": f.target_sdk,
        "debuggable": f.debuggable,
        "apk_sha256": f.apk_sha256,
        "apk_size": f.apk_size,
        "permissions": f.permissions,
        "exported_components": f.exported_components,
        "dex_files": f.dex_files,
        "native_abis": f.native_abis,
        "native_libs": f.native_libs,
        "packer_fingerprints": f.packer_hits,
        "interesting_apis": f.suspicious_apis,
    })
}

fn triage_text(f: &unhusk_report::StaticFacts, path: &Path) -> String {
    let mut o = String::new();
    o.push_str(&format!("{} ({})\n", path.display(), f.apk_sha256));
    o.push_str(&format!(
        "  package {}  version {}\n",
        f.package, f.version_name
    ));
    o.push_str(&format!(
        "  minSdk {}  targetSdk {}  debuggable {}\n",
        f.min_sdk.map(|v| v.to_string()).unwrap_or_default(),
        f.target_sdk.map(|v| v.to_string()).unwrap_or_default(),
        f.debuggable
    ));
    o.push_str(&format!("  dex: {}\n", f.dex_files.join(", ")));
    o.push_str(&format!("  permissions: {}\n", f.permissions.join(", ")));
    if !f.exported_components.is_empty() {
        o.push_str(&format!(
            "  exported: {}\n",
            f.exported_components.join(", ")
        ));
    }
    if !f.packer_hits.is_empty() {
        o.push_str("  packer fingerprints:\n");
        for (fam, ev) in &f.packer_hits {
            o.push_str(&format!("    {fam}: {ev}\n"));
        }
    }
    if !f.suspicious_apis.is_empty() {
        o.push_str("  interesting APIs:\n");
        let mut seen = std::collections::BTreeSet::new();
        for (sig, why) in &f.suspicious_apis {
            if seen.insert(why.clone()) {
                o.push_str(&format!("    {why}: {sig}\n"));
            }
        }
    }
    o
}

fn dot(r: &Report) -> String {
    let mut o = String::from("digraph unhusk {\n  rankdir=LR;\n  node [shape=box,fontsize=9];\n");
    for m in &r.graph.order {
        o.push_str(&format!("  \"{}\";\n", esc(m)));
    }
    for (c, e) in &r.graph.edges {
        o.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
            esc(&c.0),
            esc(&c.1),
            e.calls
        ));
    }
    o.push_str("}\n");
    o
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
