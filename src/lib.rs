//! `unshroud` — Android malware unpacking and hidden-behaviour recovery.
//!
//! The pipeline is: unpack the APK and triage it statically, execute the
//! sample's own bytecode in a Dalvik interpreter with an Android framework
//! model, follow any code it decrypts or downloads into execution, and report
//! the concrete call chains that reach dangerous sinks.
//!
//! See `DESIGN.md` for why the design is built around executing the sample
//! rather than pattern-matching packers.

pub mod analysis;
pub mod apk;
pub mod dex;
pub mod error;
pub mod report;
pub mod scenario;
pub mod vm;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;


use crate::report::SampleReport;
use crate::vm::env::Persona;
use crate::vm::registry::Registry;

/// Recovered runtime DEX images: `(origin label, raw bytes)`.
pub type RecoveredImages = Vec<(String, Vec<u8>)>;

/// Run the whole pipeline for one APK. Returns the report plus any recovered
/// DEX images (already parsed) so callers can dump them.
pub fn analyze_apk(
    path: &Path,
    config: scenario::RunConfig,
    personas: Vec<Persona>,
) -> anyhow::Result<(SampleReport, RecoveredImages)> {
    let started = Instant::now();
    let data = std::fs::read(path)?;
    let mut report = SampleReport::empty(&path.display().to_string());

    // --- static ---
    let statics = apk::analyze(&data, &mut report)?;
    report.notes.extend(statics.notes.clone());

    // --- build the class registry from every static DEX ---
    let mut registry = Registry::new();
    let mut parse_errors = 0usize;
    for loaded in &statics.dexes {
        match DexFileParse(&loaded.origin, loaded.dex.data.as_ref()) {
            Ok(dex) => {
                registry.add_image(Arc::new(dex), false);
            }
            Err(e) => {
                parse_errors += 1;
                report.notes.push(format!("{}: {e}", loaded.origin));
            }
        }
    }
    if parse_errors > 0 {
        report.notes.push(format!("{parse_errors} DEX image(s) failed to parse"));
    }

    // --- dynamic ---
    let mut cfg = config.clone();
    cfg.assets = statics.assets.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let outcome = scenario::run(registry, personas, &cfg);

    // Fold scenario results into the report.
    report.scenarios = outcome.scenarios;
    report.notes.extend(outcome.notes);
    let mut dumps = outcome.dynamic_dumps.clone();
    for dex in outcome.dynamic_dexes {
        report.dexes.push(report::DexInfo {
            origin: dex.origin.clone(),
            size: dex.data.len(),
            sha256: apk::Apk::sha256(&dex.data),
            strings: dex.strings.len(),
            methods: dex.methods.len(),
            classes: dex.classes.len(),
            dynamic: true,
            dump_path: None,
        });
    }
    analysis::finalize(&mut report);
    report.total_elapsed_ms = started.elapsed().as_millis() as u64;

    // Stable order for dumps: sort by origin.
    dumps.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((report, dumps))
}

#[allow(non_snake_case)]
fn DexFileParse(origin: &str, data: &[u8]) -> error::Result<dex::DexFile> {
    // The static stage already parsed each image once; re-parsing from bytes
    // keeps the registry owning its own copy.
    dex::DexFile::parse(origin.to_string(), data.to_vec())
}

/// The persona set: one realistic phone, plus variations that trip common
/// anti-emulator and "wait for the right conditions" gates.
pub fn personas(fast: bool) -> Vec<Persona> {
    let base = Persona::retail_default();
    if fast {
        return vec![base];
    }
    let mut list = vec![
        base.clone(),
        base.clone().battery_charging(),
        base.clone().at_offset_hours(26),
    ];
    let sparse = Persona::sparse_device();
    list.push(sparse.clone());
    list.push(sparse.at_offset_hours(72));
    list
}
