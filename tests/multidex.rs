//! Multidex: a static APK can ship several `classesN.dex`. Classes must link
//! across images, and the loader must not assume index spaces agree.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::vm::env::{Environment, Persona};
use unshroud::vm::interp::Vm;
use unshroud::vm::registry::Registry;
use unshroud::vm::value::Slot;

use unshroud::vm::android::AndroidHost;

/// Compile `Caller` against a classpath that already contains `Helper`, then
/// emit a DEX that references but does not define the helper.
fn compile_caller_with_helper(helper_dex: &[u8]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("unshroud-md-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let helper_dir = dir.join("helper");
    std::fs::create_dir_all(&helper_dir).ok()?;
    // Turn the helper dex back into a class file by compiling its source again.
    std::fs::write(
        helper_dir.join("Helper.java"),
        "package com.example.multi; public class Helper { public static int twice(int x) { return x*2; } }",
    ).ok()?;
    let javac = ["/opt/homebrew/opt/openjdk@17/bin/javac", "/opt/homebrew/opt/openjdk/bin/javac"]
        .iter().map(std::path::PathBuf::from).find(|p| p.exists())?;
    let o = std::process::Command::new(&javac)
        .arg("-d").arg(&helper_dir).arg("--release").arg("8").arg("-nowarn")
        .arg(helper_dir.join("Helper.java")).output().ok()?;
    if !o.status.success() { return None; }
    let caller_src = dir.join("Caller.java");
    std::fs::write(&caller_src, "package com.example.multi; public class Caller { public static int run() { return Helper.twice(21); } }").ok()?;
    let o = std::process::Command::new(&javac)
        .arg("-d").arg(&helper_dir).arg("--release").arg("8").arg("-nowarn")
        .arg("-classpath").arg(&helper_dir)
        .arg(&caller_src).output().ok()?;
    if !o.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&o.stderr));
        return None;
    }
    let d8 = find_d8()?;
    let o = std::process::Command::new(&d8)
        .arg("--min-api").arg("26").arg("--output").arg(&dir)
        .arg(helper_dir.join("com/example/multi/Caller.class"))
        .env("JAVA_HOME", javac.parent()?.parent()?)
        .output().ok()?;
    if !o.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&o.stderr));
        return None;
    }
    let dex = std::fs::read(dir.join("classes.dex")).ok()?;
    let _ = helper_dex;
    let _ = std::fs::remove_dir_all(&dir);
    Some(dex)
}

fn find_d8() -> Option<std::path::PathBuf> {
    let base = "/opt/homebrew/share/android-commandlinetools/build-tools";
    let rd = std::fs::read_dir(base).ok()?;
    let mut vs: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).collect();
    vs.sort();
    vs.into_iter().rev().map(|v| v.join("d8")).find(|p| p.exists())
}

#[test]
fn cross_dex_calls_resolve() {
    // Image 1 defines a helper; image 2 calls it. In a real multidex APK the
    // call sites reference classes in a *different* dex, and per-file index
    // spaces are unrelated.
    let Some(helper) = compile_sources_to_dex(&[(
        "Helper",
        r#"
package com.example.multi;
public class Helper {
    public static int twice(int x) { return x * 2; }
}
"#,
    )]) else { return };
    // javac needs the helper on the classpath, but the two classes must end up
    // in *different* dex files, so compile the caller against the helper dex's
    // classpath via a stub compile.
    let Some(caller) = compile_caller_with_helper(&helper) else { return };

    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", helper).unwrap()), false);
    reg.add_image(Arc::new(DexFile::parse("classes2.dex", caller).unwrap()), false);
    let mut vm = Vm::new(reg, Environment::new(Persona::retail_default()), 1_000_000, 5_000);
    let mut host = AndroidHost::new();
    let e = vm.find_method("Lcom/example/multi/Caller;", "run", "()I").unwrap();
    let r = vm.execute(&mut host, e, vec![]).unwrap();
    assert_eq!(r.v.as_int(), 42);
}

#[test]
fn decrypted_image_overrides_shell_decoy() {
    // The shell ships a decoy `Payload.answer()` returning 1; the decrypted
    // payload defines the same class returning 2. Registering the payload
    // with priority must make the real one win, as Android's child-first
    // DexClassLoader does.
    let Some(shell) = compile_sources_to_dex(&[(
        "Payload",
        r#"
package com.example.dec;
public class Payload { public static int answer() { return 1; } }
"#,
    )]) else { return };
    let Some(real) = compile_sources_to_dex(&[(
        "Payload",
        r#"
package com.example.dec;
public class Payload { public static int answer() { return 2; } }
"#,
    )]) else { return };

    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", shell).unwrap()), false);
    // Before: decoy answers.
    {
        let mut vm = Vm::new(reg.clone_for_scenario(), Environment::new(Persona::retail_default()), 1_000_000, 5_000);
        let mut host = AndroidHost::new();
        let e = vm.find_method("Lcom/example/dec/Payload;", "answer", "()I").unwrap();
        assert_eq!(vm.execute(&mut host, e, vec![]).unwrap().v.as_int(), 1);
    }
    // Register the recovered payload with priority; the real class wins.
    reg.add_image(Arc::new(DexFile::parse("decrypted:payload.dex", real).unwrap()), true);
    let mut vm = Vm::new(reg, Environment::new(Persona::retail_default()), 1_000_000, 5_000);
    let mut host = AndroidHost::new();
    let e = vm.find_method("Lcom/example/dec/Payload;", "answer", "()I").unwrap();
    assert_eq!(vm.execute(&mut host, e, vec![]).unwrap().v.as_int(), 2);
    let _ = Slot::default();
}
