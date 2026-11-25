//! droidunpack 命令行入口。
//!
//! 子命令：
//! - `triage <apk>`        只做静态预筛，输出壳指纹与分析车道
//! - `analyze <apk>`       完整流水线（默认 mock 后端，生产用 --backend cuttlefish）
//! - `trace <file.jsonl>`  离线分析已有事件流（规则 + 调用图 + 报告）
//! - `rules`               打印内置规则清单

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use droidunpack_core::{Result, SampleId};
use droidunpack_emulator::mock::MockBackend;
use droidunpack_emulator::{cuttlefish::CuttlefishBackend, Pool};
use droidunpack_orchestrator::Pipeline;
use droidunpack_report::{render, ReportFormat};
use droidunpack_rules::{builtin_set, evaluate};
use droidunpack_triage::triage_apk;

#[derive(Parser)]
#[command(
    name = "droidunpack",
    version,
    about = "安卓自动脱壳与隐藏行为还原工具"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 静态预筛：壳指纹、清单、分析车道
    Triage {
        apk: PathBuf,
        #[arg(long, value_enum, default_value_t = Out::Json)]
        format: Out,
    },
    /// 完整分析流水线
    Analyze {
        apk: PathBuf,
        #[arg(long, default_value_t = BackendKind::Mock)]
        backend: BackendKind,
        /// 模拟器池大小
        #[arg(long, default_value_t = 4)]
        pool: usize,
        #[arg(long, value_enum, default_value_t = Out::Markdown)]
        format: Out,
    },
    /// 离线分析 JSONL 事件流
    Trace {
        file: PathBuf,
        /// 自定义规则 JSON（默认内置规则）
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Out::Markdown)]
        format: Out,
    },
    /// 列出内置规则
    Rules,
}

#[derive(Clone, ValueEnum)]
enum BackendKind {
    Mock,
    Cuttlefish,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendKind::Mock => f.write_str("mock"),
            BackendKind::Cuttlefish => f.write_str("cuttlefish"),
        }
    }
}

#[derive(Clone, ValueEnum)]
enum Out {
    Json,
    Markdown,
}

impl Out {
    fn report_format(&self) -> ReportFormat {
        match self {
            Out::Json => ReportFormat::Json,
            Out::Markdown => ReportFormat::Markdown,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli) {
        eprintln!("错误: {e}");
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Cmd::Triage { apk, format } => {
            let bytes = std::fs::read(&apk)?;
            let report = triage_apk(&bytes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|e| droidunpack_core::Error::Other(Box::new(e)))?
            );
            let _ = format;
        }
        Cmd::Analyze {
            apk,
            backend,
            pool,
            format,
        } => {
            let bytes = std::fs::read(&apk)?;
            let pool = match backend {
                BackendKind::Mock => Arc::new(Pool::new(Arc::new(MockBackend::new(pool)))),
                BackendKind::Cuttlefish => {
                    Arc::new(Pool::new(Arc::new(CuttlefishBackend { pool_size: pool })))
                }
            };
            let result = Pipeline::new(pool).run(&bytes)?;
            println!("{}", render(&result, format.report_format()));
        }
        Cmd::Trace {
            file,
            rules,
            format,
        } => {
            let reader = std::fs::File::open(&file)?;
            let events = droidunpack_protocol::read_jsonl(reader)?;
            let set = match rules {
                Some(p) => droidunpack_rules::load_set(&p)?,
                None => builtin_set(),
            };
            let findings = evaluate(&events, &set);
            let mut graph = droidunpack_cgraph::build(&events).pruned_to_sinks();
            let sink_paths = graph.sink_paths(20);
            let package = events.iter().find_map(|e| match &e.kind {
                droidunpack_protocol::EventKind::ProcessStart { package, .. } => {
                    Some(package.clone())
                }
                _ => None,
            });
            let result = droidunpack_orchestrator::SampleResult {
                sample: events
                    .first()
                    .map(|e| e.sample.clone())
                    .unwrap_or(SampleId("offline".into())),
                decision: droidunpack_triage::TriageDecision::FullDynamic,
                triage: droidunpack_triage::TriageReport {
                    package,
                    min_sdk: None,
                    target_sdk: None,
                    permissions: vec![],
                    components: vec![],
                    dex_files: vec![],
                    native_libs: vec![],
                    packer: None,
                    generic_indicators: vec![],
                    decision: droidunpack_triage::TriageDecision::FullDynamic,
                },
                extraction: droidunpack_unpack::ExtractionOutcome::default(),
                findings,
                call_graph: graph,
                sink_paths,
                event_count: events.len(),
                warnings: vec!["离线 trace 分析：无内存快照，脱壳产物为空".into()],
                elapsed_ms: 0,
            };
            println!("{}", render(&result, format.report_format()));
        }
        Cmd::Rules => {
            let set = builtin_set();
            for r in &set.rules {
                println!(
                    "[{}] {} ({}) — {}",
                    r.severity, r.id, r.title, r.description
                );
            }
        }
    }
    Ok(())
}
