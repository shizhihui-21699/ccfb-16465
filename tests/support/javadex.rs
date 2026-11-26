//! Compile a Java source snippet into a DEX file using the local Android
//! build-tools, for tests that need real bytecode. Skipped (returns None) when
//! the toolchain is not present, so the suite still runs elsewhere.


#![allow(dead_code)]
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_tool(name: &str) -> Option<PathBuf> {
    let bases = [
        "/opt/homebrew/share/android-commandlinetools/build-tools",
        "/usr/local/share/android-commandlinetools/build-tools",
        "/opt/android-sdk/build-tools",
    ];
    for base in bases {
        let Ok(rd) = std::fs::read_dir(base) else { continue };
        let mut versions: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        versions.sort();
        for v in versions.into_iter().rev() {
            let p = v.join(name);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn find_javac() -> Option<PathBuf> {
    for base in ["/opt/homebrew/opt/openjdk@17/bin", "/opt/homebrew/opt/openjdk/bin"] {
        let p = Path::new(base).join("javac");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn find_android_jar() -> Option<PathBuf> {
    let base = "/opt/homebrew/share/android-commandlinetools/platforms";
    let Ok(rd) = std::fs::read_dir(base) else { return None };
    let mut vs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    vs.sort();
    vs.into_iter().rev().map(|v| v.join("android.jar")).find(|p| p.exists())
}

/// Compile `source` (one public class) and return DEX bytes.
pub fn compile_to_dex(class_name: &str, source: &str) -> Option<Vec<u8>> {
    let d8 = find_tool("d8")?;
    let javac = find_javac()?;
    // Unique per call: integration tests run on several threads in one
    // process and reuse class names, so the pid alone is not enough.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "unshroud-dex-{}-{}-{}",
        std::process::id(),
        n,
        class_name
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join(format!("{class_name}.java"));
    std::fs::write(&src, source).ok()?;
    let out = dir.join("classes");
    std::fs::create_dir_all(&out).ok()?;
    let mut cmd = Command::new(&javac);
    cmd.arg("-d").arg(&out).arg("--release").arg("8").arg("-nowarn");
    if let Some(jar) = find_android_jar() {
        cmd.arg("-classpath").arg(jar);
    }
    let status = cmd.arg(&src).output().ok()?;
    if !status.status.success() {
        panic!(
            "javac failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }
    // javac places a packaged class at `<out>/<pkg path>/<Class>.class`.
    let mut class_file = out.join(format!("{class_name}.class"));
    if !class_file.exists() {
        // Find it by name anywhere under the output tree.
        let mut found = Vec::new();
        fn walk(dir: &Path, want: &str, out: &mut Vec<PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, want, out);
                } else if p.file_name().and_then(|n| n.to_str()) == Some(want) {
                    out.push(p);
                }
            }
        }
        let want = format!("{class_name}.class");
        walk(&out, &want, &mut found);
        if let Some(p) = found.into_iter().next() {
            class_file = p;
        }
    }
    let status = Command::new(&d8)
        .arg("--min-api")
        .arg("26")
        .arg("--output")
        .arg(&dir)
        .arg(&class_file)
        .env("JAVA_HOME", javac.parent().unwrap().parent().unwrap())
        .output()
        .ok()?;
    if !status.status.success() {
        panic!("d8 failed: {}", String::from_utf8_lossy(&status.stderr));
    }
    let dex = std::fs::read(dir.join("classes.dex")).ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    Some(dex)
}
