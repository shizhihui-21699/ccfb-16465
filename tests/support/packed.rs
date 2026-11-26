//! Build a synthetic "packed" APK for end-to-end tests.
//!
//! The shell class decrypts its payload at runtime with a real crypto loop
//! (mimicking a packer), hands the bytes to a `DexClassLoader`, and gates the
//! work behind a couple of anti-emulator checks. The payload class exfiltrates
//! the device's IMEI to an endpoint. If the emulator follows the shell, it must
//! end up reporting the network sink with an `imei` taint — that is exactly the
//! capability the real tool depends on.


#![allow(dead_code)]
use std::path::PathBuf;
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

fn find_android_jar() -> Option<PathBuf> {
    let bases = [
        "/opt/homebrew/share/android-commandlinetools/platforms",
        "/usr/local/share/android-commandlinetools/platforms",
        "/opt/android-sdk/platforms",
    ];
    for base in bases {
        let Ok(rd) = std::fs::read_dir(base) else { continue };
        let mut versions: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        versions.sort();
        for v in versions.into_iter().rev() {
            let p = v.join("android.jar");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn find_javac() -> Option<PathBuf> {
    for base in ["/opt/homebrew/opt/openjdk@17/bin", "/opt/homebrew/opt/openjdk/bin"] {
        let p = std::path::Path::new(base).join("javac");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Compile one or more `(class_name, source)` pairs into a single DEX.
pub fn compile_sources_to_dex(sources: &[(&str, &str)]) -> Option<Vec<u8>> {
    let d8 = find_tool("d8")?;
    let javac = find_javac()?;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("unshroud-pack-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let mut srcs = Vec::new();
    for (name, src) in sources {
        let p = dir.join(format!("{name}.java"));
        std::fs::write(&p, src).ok()?;
        srcs.push(p);
    }
    let out = dir.join("classes");
    std::fs::create_dir_all(&out).ok()?;
    let mut cmd = Command::new(&javac);
    cmd.arg("-d").arg(&out).arg("--release").arg("8").arg("-nowarn");
    // Android sources need android.jar on the compile classpath. Fall back to
    // the JVM-only compile path when the SDK is absent.
    if let Some(jar) = find_android_jar() {
        cmd.arg("-classpath").arg(jar);
    }
    for s in &srcs {
        cmd.arg(s);
    }
    let status = cmd.output().ok()?;
    if !status.status.success() {
        panic!("javac failed: {}", String::from_utf8_lossy(&status.stderr));
    }
    // Every .class file in the output tree.
    let mut class_files = Vec::new();
    collect_class_files(&out, &mut class_files);
    let status = Command::new(&d8)
        .arg("--min-api")
        .arg("26")
        .arg("--output")
        .arg(&dir)
        .args(&class_files)
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

fn collect_class_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_class_files(&p, out);
        } else if p.extension().map(|x| x == "class").unwrap_or(false) {
            out.push(p);
        }
    }
}

/// Build an APK-shaped zip containing a shell DEX and an encrypted payload
/// asset. Returns the zip bytes.
pub fn build_packed_apk(shell_dex: &[u8], payload_dex: &[u8], key: u8) -> Vec<u8> {
    let mut encrypted = payload_dex.to_vec();
    for b in encrypted.iter_mut() {
        *b ^= key;
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        use zip::write::SimpleFileOptions;
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        w.start_file("classes.dex", opts).unwrap();
        use std::io::Write;
        w.write_all(shell_dex).unwrap();
        w.start_file("assets/payload.dat", opts).unwrap();
        w.write_all(&encrypted).unwrap();
        w.start_file("AndroidManifest.xml", opts).unwrap();
        w.write_all(&minimal_manifest()).unwrap();
        w.finish().unwrap();
    }
    buf.into_inner()
}

/// A binary AXML manifest naming a launcher activity and a couple of
/// permissions. Hand-built so tests do not need aapt.
pub fn minimal_manifest_pub() -> Vec<u8> { minimal_manifest() }

fn minimal_manifest() -> Vec<u8> {
    // Rather than hand-encode AXML (error-prone), emit a minimal but well-formed
    // chunk stream with a string pool carrying the names we assert on.
    let strings = [
        "manifest",
        "package",
        "com.example.packed",
        "versionName",
        "1.0",
        "uses-permission",
        "name",
        "android.permission.READ_PHONE_STATE",
        "android.permission.SEND_SMS",
        "android.permission.INTERNET",
        "activity",
        "com.example.packed.MainActivity",
    ];
    let mut pool_data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(pool_data.len() as u32);
        // utf8 pool string: u16len, u8len, bytes, NUL
        pool_data.push(s.chars().count() as u8);
        pool_data.push(s.len() as u8);
        pool_data.extend_from_slice(s.as_bytes());
        pool_data.push(0);
    }
    while pool_data.len() % 4 != 0 {
        pool_data.push(0);
    }
    let string_count = strings.len() as u32;
    let strings_start = 28 + string_count * 4;
    let pool_size = strings_start as usize + pool_data.len();
    let mut pool = Vec::new();
    pool.extend_from_slice(&0x0001u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&(pool_size as u32).to_le_bytes());
    pool.extend_from_slice(&string_count.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // style count
    pool.extend_from_slice(&0x0000_0100u32.to_le_bytes()); // UTF8 flag
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for off in &offsets {
        pool.extend_from_slice(&off.to_le_bytes());
    }
    pool.extend_from_slice(&pool_data);

    let mut out = Vec::new();
    // File header: type 0x0003, headerSize 8, size (patched later)
    out.extend_from_slice(&0x0003u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&pool);
    // Append a START_ELEMENT for <manifest package="com.example.packed" ...>
    for (tag_name_idx, attr_name_idx, value_idx) in [
        (0u32, 1u32, 2u32), // manifest package="com.example.packed"
        (0u32, 3u32, 4u32), // manifest versionName="1.0"
    ] {
        out.extend_from_slice(&start_element(tag_name_idx, attr_name_idx, value_idx));
    }
    // uses-permission name="..."
    for value in [7u32, 8, 9] {
        out.extend_from_slice(&start_element(5, 6, value));
    }
    // activity name="..."
    out.extend_from_slice(&start_element(10, 6, 11));
    let total = out.len() as u32;
    out[4..8].copy_from_slice(&total.to_le_bytes());
    out
}

fn start_element(tag: u32, attr_name: u32, attr_value: u32) -> Vec<u8> {
    // ResXMLTree_node(16) + ResXMLTree_attrExt(20) + one attribute(20)
    let mut v = Vec::new();
    let size = 56u32;
    v.extend_from_slice(&0x0102u16.to_le_bytes());
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // line
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
    v.extend_from_slice(&tag.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    v.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    v.extend_from_slice(&1u16.to_le_bytes()); // attributeCount
    v.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    v.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    v.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    // attribute
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
    v.extend_from_slice(&attr_name.to_le_bytes());
    v.extend_from_slice(&attr_value.to_le_bytes()); // rawValue
    v.extend_from_slice(&8u16.to_le_bytes()); // typedValue size
    v.push(0); // res0
    v.push(0x03); // dataType = TYPE_STRING
    v.extend_from_slice(&attr_value.to_le_bytes());
    v
}
