//! The `unshroud` command-line entry point.

use std::collections::HashMap;
use std::path::Path;

use clap::Parser;

use unshroud::analysis;
use unshroud::scenario::RunConfig;

/// Command-line options.
#[derive(Parser, Debug)]
#[command(
    name = "unshroud",
    about = "Unpack and analyse an Android APK in a Rust emulation sandbox",
    version
)]
pub struct Cli {
    /// The APK to analyse.
    pub apk: String,

    /// Write the full JSON report here.
    #[arg(long)]
    pub json: Option<String>,

    /// Write the analyst markdown brief here.
    #[arg(long)]
    pub markdown: Option<String>,

    /// Directory to write recovered (decrypted) DEX images to.
    #[arg(long)]
    pub dump_dir: Option<String>,

    /// Total wall-clock budget for the run, milliseconds.
    #[arg(long, default_value_t = 240_000)]
    pub timeout_ms: u64,

    /// Instruction budget per scenario.
    #[arg(long, default_value_t = 12_000_000)]
    pub step_limit: u64,

    /// Maximum number of scenarios to run.
    #[arg(long, default_value_t = 4)]
    pub max_scenarios: usize,

    /// Run only the default retail-device scenario (no device or time sweep).
    #[arg(long)]
    pub fast: bool,

    /// Suppress the markdown summary; only write machine-readable output.
    #[arg(long)]
    pub quiet: bool,
}

fn main() {
    let cli = Cli::parse();
    let path = Path::new(&cli.apk);
    if !path.exists() {
        eprintln!("error: {} not found", cli.apk);
        std::process::exit(2);
    }

    let config = RunConfig {
        step_limit: cli.step_limit,
        per_scenario_ms: (cli.timeout_ms / cli.max_scenarios.max(1) as u64).max(2_000),
        max_scenarios: cli.max_scenarios,
        max_steps_total: cli.step_limit.saturating_mul(cli.max_scenarios as u64),
        assets: HashMap::new(),
    };
    let personas = unshroud::personas(cli.fast);

    let (mut report, dumps) = match unshroud::analyze_apk(path, config, personas) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    // Dump recovered images and record where they went.
    if let Some(dir) = &cli.dump_dir {
        if std::fs::create_dir_all(dir).is_ok() {
            for (i, (origin, bytes)) in dumps.iter().enumerate() {
                let safe = sanitise_filename(origin);
                let p = format!("{dir}/{i:02}-{safe}.dex");
                if std::fs::write(&p, bytes).is_ok() {
                    for d in &mut report.dexes {
                        if &d.origin == origin {
                            d.dump_path = Some(p.clone());
                        }
                    }
                }
            }
        }
    }

    let md = analysis::render_markdown(&report);
    if let Some(out) = &cli.markdown {
        if let Err(e) = std::fs::write(out, &md) {
            eprintln!("error writing markdown: {e}");
        }
    }
    if let Some(out) = &cli.json {
        match serde_json::to_string_pretty(&report) {
            Ok(j) => {
                if let Err(e) = std::fs::write(out, j) {
                    eprintln!("error writing JSON: {e}");
                }
            }
            Err(e) => eprintln!("error serialising report: {e}"),
        }
    }

    if cli.quiet {
        return;
    }
    print!("{md}");
    if cli.json.is_none() {
        match serde_json::to_string_pretty(&report) {
            Ok(j) => println!("\n---\n\n<details><summary>JSON report</summary>\n\n```json\n{j}\n```\n\n</details>"),
            Err(e) => eprintln!("error serialising report: {e}"),
        }
    }
}

fn sanitise_filename(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
        if out.len() > 80 {
            break;
        }
    }
    out
}
