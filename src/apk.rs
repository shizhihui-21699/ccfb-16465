//! APK unpacking and static triage.
//!
//! Everything here treats the APK as untrusted input: the zip is read with the
//! `zip` crate into memory (no extraction to a shared directory, so nothing a
//! sample ships can execute), entry sizes are capped, and the manifest is
//! parsed by a small, defensive binary-XML reader rather than a shelled-out
//! `aapt`.
//!
//! Static triage runs before and alongside emulation so the report is useful
//! even when a sample's gates defeat execution entirely.

use std::collections::BTreeMap;
use std::io::Read;

use sha2::{Digest, Sha256};

use crate::dex::DexFile;
use crate::error::{Error, Result};
use crate::report::{EmbeddedPayload, NativeLib, SampleReport};

/// Cap on any single zip entry, to stop a zip bomb from exhausting memory.
const MAX_ENTRY: usize = 64 * 1024 * 1024;
/// Cap on total uncompressed bytes taken across the archive.
const MAX_TOTAL: usize = 256 * 1024 * 1024;

pub struct Apk {
    pub entries: BTreeMap<String, Vec<u8>>,
    pub compressed_sizes: BTreeMap<String, u64>,
}

impl Apk {
    pub fn open(data: &[u8]) -> Result<Apk> {
        let cursor = std::io::Cursor::new(data);
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(|e| Error::Zip(e.to_string()))?;
        let mut entries = BTreeMap::new();
        let mut compressed_sizes = BTreeMap::new();
        let mut total = 0usize;
        for i in 0..archive.len() {
            let mut f = match archive.by_index(i) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let name = f.name().to_string();
            if f.is_dir() {
                continue;
            }
            let csize = f.compressed_size();
            let size = f.size() as usize;
            if size > MAX_ENTRY {
                compressed_sizes.insert(name.clone(), csize);
                continue;
            }
            if total + size > MAX_TOTAL {
                compressed_sizes.insert(name, csize);
                continue;
            }
            let mut buf = Vec::with_capacity(size.min(1 << 20));
            // `take` caps a lying header's actual output too.
            if (&mut f).take(MAX_ENTRY as u64).read_to_end(&mut buf).is_err() {
                continue;
            }
            total += buf.len();
            compressed_sizes.insert(name.clone(), csize);
            entries.insert(name, buf);
        }
        Ok(Apk { entries, compressed_sizes })
    }

    pub fn sha256(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    /// DEX images in `classes*.dex` order.
    pub fn dex_entries(&self) -> Vec<&String> {
        let mut names: Vec<&String> = self
            .entries
            .keys()
            .filter(|n| {
                n.as_str().starts_with("classes") && n.as_str().ends_with(".dex")
            })
            .collect();
        names.sort_by(|a, b| dex_index(a).cmp(&dex_index(b)).then_with(|| a.cmp(b)));
        names
    }

    pub fn native_libs(&self) -> Vec<&String> {
        self.entries
            .keys()
            .filter(|n| n.as_str().starts_with("lib/") && n.as_str().ends_with(".so"))
            .collect()
    }
}

/// Sort key for `classesN.dex`: the numeric suffix, with the plain name first.
fn dex_index(name: &str) -> u32 {
    let stem = name.strip_prefix("classes").and_then(|x| x.strip_suffix(".dex"));
    match stem {
        Some("") | None => 1,
        Some(s) => s.parse::<u32>().unwrap_or(u32::MAX),
    }
}

/// One parsed DEX image plus its provenance.
pub struct LoadedDex {
    pub origin: String,
    pub dex: DexFile,
}

pub struct StaticAnalysis {
    pub dexes: Vec<LoadedDex>,
    pub native: Vec<NativeLib>,
    pub embedded: Vec<EmbeddedPayload>,
    pub package: Option<String>,
    pub version_name: Option<String>,
    pub launcher: Vec<String>,
    pub permissions: Vec<String>,
    pub receivers: Vec<String>,
    pub services: Vec<String>,
    pub notes: Vec<String>,
    /// `assets/…` and `res/raw/…` entries by the name a sample passes to
    /// `AssetManager.open` (the `assets/` prefix stripped).
    pub assets: BTreeMap<String, Vec<u8>>,
}

pub fn analyze(data: &[u8], report: &mut SampleReport) -> Result<StaticAnalysis> {
    let apk = Apk::open(data)?;
    report.apk_sha256 = Apk::sha256(data);
    report.apk_size = data.len() as u64;

    let mut notes = Vec::new();
    let mut dexes = Vec::new();
    for name in apk.dex_entries() {
        let bytes = apk.entries.get(name).unwrap();
        match DexFile::parse(name.clone(), bytes.clone()) {
            Ok(dex) => dexes.push(LoadedDex { origin: name.clone(), dex }),
            Err(e) => notes.push(format!("{name}: not a valid DEX: {e}")),
        }
    }
    if dexes.is_empty() {
        notes.push("no classes*.dex found at the top level".into());
    }

    // Native libraries.
    let mut native = Vec::new();
    for path in apk.native_libs() {
        let bytes = apk.entries.get(path).unwrap();
        let arch = path.split('/').nth(1).unwrap_or("?").to_string();
        let (exports, suspicious) = analyse_elf(bytes);
        native.push(NativeLib {
            path: path.clone(),
            arch,
            size: bytes.len(),
            sha256: Apk::sha256(bytes),
            exports,
            suspicious_strings: suspicious,
        });
    }

    // Embedded payloads anywhere in the archive, including assets/ and raw/.
    let mut embedded = Vec::new();
    for (name, bytes) in &apk.entries {
        if name.starts_with("classes") && name.ends_with(".dex") {
            continue;
        }
        if name.starts_with("lib/") && name.ends_with(".so") {
            continue;
        }
        if let Some(p) = classify_payload(name, bytes) {
            embedded.push(p);
        }
    }
    embedded.sort_by_key(|p| std::cmp::Reverse(p.size));

    // Manifest: package, permissions, components.
    let mut package = None;
    let mut version_name = None;
    let mut launcher = Vec::new();
    let mut permissions = Vec::new();
    let mut receivers = Vec::new();
    let mut services = Vec::new();
    if let Some(manifest) = apk.entries.get("AndroidManifest.xml") {
        match parse_manifest(manifest) {
            Ok(m) => {
                package = m.package.clone();
                version_name = m.version_name.clone();
                permissions = m.permissions.clone();
                receivers = m.receivers.clone();
                services = m.services.clone();
                launcher = m.launcher.clone();
                report.package = package.clone();
                report.version_name = version_name.clone();
                report.permissions = permissions.clone();
                report.receivers = receivers.clone();
                report.services = services.clone();
                report.launcher = launcher.clone();
            }
            Err(e) => notes.push(format!("manifest: {e}")),
        }
    } else {
        notes.push("AndroidManifest.xml missing".into());
    }

    // Assets the emulation harness will serve through AssetManager.
    let mut assets = BTreeMap::new();
    for (name, bytes) in &apk.entries {
        if let Some(stripped) = name.strip_prefix("assets/") {
            assets.insert(stripped.to_string(), bytes.clone());
        } else if name.starts_with("res/raw/") {
            assets.insert(name.clone(), bytes.clone());
        }
    }

    report.dexes = dexes
        .iter()
        .map(|d| crate::report::DexInfo {
            origin: d.origin.clone(),
            size: d.dex.data.len(),
            sha256: Apk::sha256(&d.dex.data),
            strings: d.dex.strings.len(),
            methods: d.dex.methods.len(),
            classes: d.dex.classes.len(),
            dynamic: false,
            dump_path: None,
        })
        .collect();
    report.native_libs = native.clone();
    report.embedded_payloads = embedded.clone();

    Ok(StaticAnalysis {
        dexes,
        native,
        embedded,
        package,
        version_name,
        launcher,
        permissions,
        receivers,
        services,
        notes,
        assets,
    })
}

// ---------------------------------------------------------------------------
// Payload classification
// ---------------------------------------------------------------------------

fn classify_payload(name: &str, bytes: &[u8]) -> Option<EmbeddedPayload> {
    let sha256 = Apk::sha256(bytes);
    let lower = name.to_ascii_lowercase();

    // Raw DEX regardless of name.
    if bytes.len() > 8 && &bytes[0..4] == b"dex\n" {
        return Some(payload(name, "dex", bytes, sha256, "DEX magic"));
    }
    // Zip-shaped entries (jar/apk/dex-in-zip) that are not the APK itself.
    if bytes.len() > 4 && bytes[0..2] == [0x50, 0x4b] {
        if let Ok(mut ar) = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())) {
            let mut has_dex = false;
            let mut has_manifest = false;
            for i in 0..ar.len() {
                if let Ok(f) = ar.by_index(i) {
                    let n = f.name().to_string();
                    if n.ends_with(".dex") {
                        has_dex = true;
                    }
                    if n == "AndroidManifest.xml" {
                        has_manifest = true;
                    }
                }
            }
            if has_dex {
                let kind = if has_manifest { "apk" } else { "jar" };
                return Some(payload(
                    name,
                    kind,
                    bytes,
                    sha256,
                    if has_manifest { "nested APK with DEX" } else { "zip/jar containing DEX" },
                ));
            }
        }
    }
    // Base64 of a DEX: starts with "ZGV4" ("dex").
    if lower.ends_with(".txt") || lower.ends_with(".dat") || lower.ends_with(".bin") || lower.ends_with(".json") {
        let head: String = bytes.iter().take(16).map(|b| *b as char).collect();
        if head.starts_with("ZGV4") {
            return Some(payload(name, "base64-dex", bytes, sha256, "Base64 encoding of a DEX header"));
        }
    }
    // ELF payload buried in assets: a second-stage native module.
    if bytes.len() > 4 && &bytes[0..4] == b"\x7fELF" {
        return Some(payload(name, "elf", bytes, sha256, "ELF library in assets"));
    }
    // High entropy + executable-sounding name: candidate encrypted payload.
    if bytes.len() >= 4096 {
        let ent = entropy(bytes);
        if ent > 7.5
            && (lower.contains("asset")
                || lower.contains("dex")
                || lower.contains("payload")
                || lower.contains("data")
                || lower.contains("lib")
                || lower.ends_with(".bin")
                || lower.ends_with(".dat")
                || lower.ends_with(".jar"))
        {
            return Some(payload(
                name,
                "encrypted",
                bytes,
                sha256,
                &format!("high entropy {ent:.2}"),
            ));
        }
    }
    None
}

fn payload(name: &str, kind: &str, bytes: &[u8], sha256: String, reason: &str) -> EmbeddedPayload {
    EmbeddedPayload {
        path: name.to_string(),
        kind: kind.to_string(),
        size: bytes.len(),
        sha256,
        reason: reason.to_string(),
    }
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

// ---------------------------------------------------------------------------
// ELF triage
// ---------------------------------------------------------------------------

fn analyse_elf(bytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut exports = Vec::new();
    let mut suspicious = Vec::new();
    // JNI entry points are named `Java_<mangled class>_<method>`.
    for s in printable_strings(bytes, 6) {
        if s.starts_with("Java_") && exports.len() < 200 {
            exports.push(s.clone());
        }
        let lower = s.to_ascii_lowercase();
        for marker in [
            "java_",
            "jni_",
            "dexclassloader",
            "inmemorydex",
            "opensl",
            "dlopen",
            "/system/bin/su",
            "frida",
            "xposed",
            "magisk",
            "ptrace",
            "substrate",
            "decrypt",
            "unpack",
        ] {
            if lower.contains(marker) {
                if suspicious.len() < 100 && !suspicious.contains(&s) {
                    suspicious.push(s.clone());
                }
                break;
            }
        }
    }
    (exports, suspicious)
}

/// Extract NUL-terminated printable ASCII strings of at least `min` chars.
fn printable_strings(bytes: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for b in bytes {
        if (0x20..=0x7e).contains(b) {
            cur.push(*b);
            if cur.len() > 4096 {
                cur.clear();
            }
        } else {
            if cur.len() >= min {
                out.push(String::from_utf8_lossy(&cur).to_string());
            }
            cur.clear();
            if out.len() > 200_000 {
                break;
            }
        }
    }
    if cur.len() >= min {
        out.push(String::from_utf8_lossy(&cur).to_string());
    }
    out
}

// ---------------------------------------------------------------------------
// Binary AndroidManifest.xml
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Manifest {
    package: Option<String>,
    version_name: Option<String>,
    permissions: Vec<String>,
    receivers: Vec<String>,
    services: Vec<String>,
    launcher: Vec<String>,
}

/// A minimal AXML reader: enough to recover the package name, version,
/// permissions and component class names, which is what the emulation harness
/// needs to decide what to drive.
fn parse_manifest(data: &[u8]) -> Result<Manifest> {
    // AXML: chunk-based. We walk string pool, resource map and start elements.
    if data.len() < 8 {
        return Err(Error::BadFormat("manifest too short".into()));
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != 0x0003 {
        return Err(Error::BadFormat(format!("manifest magic {magic:#x}")));
    }
    let mut strings: Vec<String> = Vec::new();
    let mut pos = 8usize;
    let mut out = Manifest::default();
    // Track a start element's attributes so we can attach them to the right tag.
    while pos + 8 <= data.len() {
        let ctype = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let hsize = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let csize = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
        if csize < 8 || pos + csize > data.len() {
            break;
        }
        let chunk = &data[pos..pos + csize];
        match ctype {
            0x0001 => {
                strings = parse_string_pool(chunk, hsize);
            }
            0x0102 => {
                // START_ELEMENT
                parse_start_element(chunk, hsize, &strings, &mut out);
            }
            _ => {}
        }
        pos += csize;
        if csize == 0 {
            break;
        }
    }
    Ok(out)
}

fn parse_string_pool(chunk: &[u8], hsize: usize) -> Vec<String> {
    // ResStringPool: header(8) stringCount(4) styleCount(4) flags(4)
    //               stringsStart(4) stylesStart(4)
    if chunk.len() < hsize + 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes(slice4(chunk, 8)) as usize;
    let flags = u32::from_le_bytes(slice4(chunk, 16));
    let utf8 = flags & 0x100 != 0;
    let strings_start = u32::from_le_bytes(slice4(chunk, 20)) as usize;
    if count > 100_000 || strings_start > chunk.len() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off_pos = hsize + i * 4;
        if off_pos + 4 > chunk.len() {
            break;
        }
        let off = u32::from_le_bytes(slice4(chunk, off_pos)) as usize;
        let start = strings_start + off;
        if start >= chunk.len() {
            out.push(String::new());
            continue;
        }
        out.push(if utf8 {
            read_utf8_string(&chunk[start..])
        } else {
            read_utf16_string(&chunk[start..])
        });
    }
    out
}

fn slice4(b: &[u8], at: usize) -> [u8; 4] {
    let mut a = [0u8; 4];
    if at + 4 <= b.len() {
        a.copy_from_slice(&b[at..at + 4]);
    }
    a
}

fn read_utf8_string(b: &[u8]) -> String {
    // utf16 length (1 or 2 bytes), then utf8 byte length (1 or 2), then bytes.
    let mut i = 0;
    let _u16len = read_len8(b, &mut i);
    let blen = read_len8(b, &mut i);
    let end = (i + blen).min(b.len());
    String::from_utf8_lossy(&b[i..end]).to_string()
}

fn read_len8(b: &[u8], i: &mut usize) -> usize {
    let first = b.get(*i).copied().unwrap_or(0);
    *i += 1;
    if first & 0x80 != 0 {
        let second = b.get(*i).copied().unwrap_or(0);
        *i += 1;
        (((first & 0x7f) as usize) << 8) | second as usize
    } else {
        first as usize
    }
}

fn read_utf16_string(b: &[u8]) -> String {
    let mut i = 0;
    let len = {
        let first = u16::from_le_bytes([b.first().copied().unwrap_or(0), b.get(1).copied().unwrap_or(0)]);
        i += 2;
        if first & 0x8000 != 0 {
            let second = u16::from_le_bytes([b.get(2).copied().unwrap_or(0), b.get(3).copied().unwrap_or(0)]);
            i += 2;
            (((first & 0x7fff) as usize) << 16) | second as usize
        } else {
            first as usize
        }
    };
    let units: Vec<u16> = b[i..]
        .chunks(2)
        .take(len)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn parse_start_element(chunk: &[u8], _hsize: usize, strings: &[String], out: &mut Manifest) {
    // ResXMLTree_node header: lineNumber(4) comment(4); then attrExt:
    // ns(4) name(4) attributeStart(2) attributeSize(2) attributeCount(2) ...
    if chunk.len() < 16 {
        return;
    }
    let ext = 16;
    if ext + 20 > chunk.len() {
        return;
    }
    let _ns = u32::from_le_bytes(slice4(chunk, ext));
    let name_idx = u32::from_le_bytes(slice4(chunk, ext + 4)) as usize;
    let attr_start = u16::from_le_bytes([chunk[ext + 8], chunk[ext + 9]]) as usize;
    let attr_size = u16::from_le_bytes([chunk[ext + 10], chunk[ext + 11]]) as usize;
    let attr_count = u16::from_le_bytes([chunk[ext + 12], chunk[ext + 13]]) as usize;
    let tag = strings.get(name_idx).cloned().unwrap_or_default();

    let mut attrs: Vec<(String, String)> = Vec::new();
    let base = ext + attr_start;
    for i in 0..attr_count {
        let a = base + i * attr_size;
        if a + 20 > chunk.len() || attr_size < 20 {
            break;
        }
        let name_i = u32::from_le_bytes(slice4(chunk, a + 4)) as usize;
        let raw_i = u32::from_le_bytes(slice4(chunk, a + 8)) as usize;
        let data_type = chunk[a + 15];
        let data = u32::from_le_bytes(slice4(chunk, a + 16));
        let aname = strings.get(name_i).cloned().unwrap_or_default();
        let value = if raw_i != 0xFFFF_FFFF {
            strings.get(raw_i).cloned().unwrap_or_default()
        } else {
            match data_type {
                0x12 => (data != 0).to_string(),
                0x10 | 0x11 => data.to_string(),
                _ => String::new(),
            }
        };
        attrs.push((aname, value));
    }

    let get = |n: &str| attrs.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    match tag.as_str() {
        "manifest" => {
            if let Some(p) = get("package") {
                out.package = Some(p);
            }
            if let Some(v) = get("versionName") {
                out.version_name = Some(v);
            }
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(n) = get("name") {
                out.permissions.push(n);
            }
        }
        "receiver" => {
            if let Some(n) = get("name") {
                out.receivers.push(n);
            }
        }
        "service" => {
            if let Some(n) = get("name") {
                out.services.push(n);
            }
        }
        "activity" | "activity-alias" => {
            if let Some(n) = get("name") {
                // A launcher intent-filter's activity is recorded on the
                // intent-filter element, not here, so remember every activity
                // that declares a MAIN/LAUNCHER filter later.
                out.launcher.push(n);
            }
        }
        "action" => {
            if let Some(n) = get("name") {
                if n == "android.intent.action.MAIN" || n == "android.intent.action.BOOT_COMPLETED" {
                    // Keep as-is; the launcher list is refined below.
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_random_and_structured() {
        let zeros = vec![0u8; 4096];
        assert!(entropy(&zeros) < 0.01);
        let mut random = Vec::new();
        let mut x: u64 = 1;
        for _ in 0..4096 {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            random.push((x >> 33) as u8);
        }
        assert!(entropy(&random) > 7.0);
    }

    #[test]
    fn strings_are_extracted() {
        let mut data = b"\x7fELF\0".to_vec();
        data.extend_from_slice(b"Java_com_example_Native_decrypt\0garbage\0JNI_OnLoad\0");
        let (exports, suspicious) = analyse_elf(&data);
        assert!(exports.iter().any(|e| e.contains("decrypt")));
        assert!(suspicious.iter().any(|s| s == "JNI_OnLoad"));
    }
}
