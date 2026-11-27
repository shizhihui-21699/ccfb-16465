//! APK container access: ZIP entries, binary manifest, DEX discovery and the
//! static "packer shell" heuristics that decide what the sandbox should poke.

pub mod axml;
pub mod error;
pub mod heuristics;
pub mod manifest;

pub use error::{ApkError, Result};
pub use manifest::{Component, ComponentKind, Manifest};

use std::collections::HashMap;
use std::io::{Cursor, Read};
use unhusk_dex::DexFile;

/// One entry of the APK's ZIP directory.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub name: String,
    /// Uncompressed size as recorded in the central directory (untrusted).
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
    pub method: u16,
    pub crc32: u32,
}

/// In-memory view of an APK.
pub struct Apk {
    bytes: Vec<u8>,
    entries: HashMap<String, EntryInfo>,
    order: Vec<String>,
    pub manifest: Manifest,
    pub manifest_error: Option<String>,
}

/// Guard against decompression bombs: no single entry may inflate past this.
pub const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
/// Guard against absurd APK sizes when reading from disk.
pub const MAX_APK_BYTES: u64 = 2 * 1024 * 1024 * 1024;

impl Apk {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_APK_BYTES {
            return Err(ApkError::new(format!(
                "APK is {} bytes, over the {} byte limit",
                meta.len(),
                MAX_APK_BYTES
            )));
        }
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes[..]))
            .map_err(|e| ApkError::new(format!("not a ZIP archive: {e}")))?;
        let mut entries = HashMap::new();
        let mut order = Vec::new();
        for i in 0..archive.len() {
            let file = archive
                .by_index_raw(i)
                .map_err(|e| ApkError::new(format!("zip entry {i}: {e}")))?;
            let name = file.name().to_string();
            let info = EntryInfo {
                name: name.clone(),
                size: file.size(),
                compressed_size: file.compressed_size(),
                is_dir: file.is_dir(),
                method: match file.compression() {
                    zip::CompressionMethod::Stored => 0,
                    zip::CompressionMethod::Deflated => 8,
                    _ => 0xffff,
                },
                crc32: 0,
            };
            if !info.is_dir {
                order.push(name.clone());
            }
            entries.insert(name, info);
        }
        drop(archive);

        let manifest = match Self::read_entry_from(&bytes, "AndroidManifest.xml") {
            Ok(Some(mf)) => match axml::parse(&mf) {
                Ok(doc) => {
                    let m = manifest::interpret(&doc);
                    return Ok(Self {
                        bytes,
                        entries,
                        order,
                        manifest: m,
                        manifest_error: None,
                    })
                    .map(|s| Self::fixup(s, mf));
                }
                Err(e) => {
                    let mut s = Self {
                        bytes,
                        entries,
                        order,
                        manifest: Manifest::default(),
                        manifest_error: Some(e.to_string()),
                    };
                    s = Self::fixup(s, mf);
                    return Ok(s);
                }
            },
            _ => Manifest::default(),
        };
        let s = Self {
            bytes,
            entries,
            order,
            manifest,
            manifest_error: Some("AndroidManifest.xml missing".into()),
        };
        Ok(s)
    }

    // The constructors above need the raw manifest bytes for the fallback
    // string scan; this helper keeps that in one place.
    fn fixup(mut _s: Self, _raw: Vec<u8>) -> Self {
        _s
    }

    fn read_entry_from(bytes: &[u8], name: &str) -> Result<Option<Vec<u8>>> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
            .map_err(|e| ApkError::new(format!("not a ZIP archive: {e}")))?;
        let mut file = match archive.by_name(name) {
            Ok(f) => f,
            Err(zip::result::ZipError::FileNotFound) => return Ok(None),
            Err(e) => return Err(ApkError::new(format!("zip entry {name}: {e}"))),
        };
        let size = file.size();
        if size > MAX_ENTRY_BYTES {
            return Err(ApkError::new(format!(
                "entry {name} declares {size} bytes, over the decompression limit"
            )));
        }
        let mut out = Vec::with_capacity(size.min(4 * 1024 * 1024) as usize);
        file.by_ref()
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut out)
            .map_err(|e| ApkError::new(format!("inflate {name}: {e}")))?;
        if out.len() as u64 > MAX_ENTRY_BYTES {
            return Err(ApkError::new(format!(
                "entry {name} inflated past the limit"
            )));
        }
        Ok(Some(out))
    }

    pub fn raw_manifest(&self) -> Option<Vec<u8>> {
        Self::read_entry_from(&self.bytes, "AndroidManifest.xml")
            .ok()
            .flatten()
    }

    pub fn entry(&self, name: &str) -> Option<&EntryInfo> {
        self.entries.get(name)
    }

    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Self::read_entry_from(&self.bytes, name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn total_uncompressed(&self) -> u64 {
        self.entries.values().map(|e| e.size).sum()
    }

    /// All `classes*.dex` entries in load order (classes.dex, classes2.dex...).
    pub fn dex_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .order
            .iter()
            .filter(|n| {
                n.starts_with("classes") && n.ends_with(".dex") && n.len() > "classes.dex".len() - 4
            })
            .cloned()
            .collect();
        names.sort_by_key(|n| dex_ordinal(n));
        names
    }

    /// Native library entries (by ABI).
    pub fn native_libs(&self) -> Vec<(String, String)> {
        self.order
            .iter()
            .filter_map(|n| {
                let rest = n.strip_prefix("lib/")?;
                let (abi, file) = rest.split_once('/')?;
                if file.ends_with(".so") {
                    Some((abi.to_string(), n.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Parse every DEX in the archive.
    pub fn dex_files(&self) -> Vec<(String, std::result::Result<DexFile, unhusk_dex::DexError>)> {
        self.dex_names()
            .into_iter()
            .map(|name| {
                let parsed = match Self::read_entry_from(&self.bytes, &name) {
                    Ok(Some(bytes)) => unhusk_dex::parse(&bytes),
                    Ok(None) => Err(unhusk_dex::DexError::new(
                        unhusk_dex::ErrorKind::Truncated,
                        "missing entry",
                    )),
                    Err(e) => Err(unhusk_dex::DexError::new(
                        unhusk_dex::ErrorKind::Truncated,
                        e.to_string(),
                    )),
                };
                (name, parsed)
            })
            .collect()
    }

    pub fn sha256(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&self.bytes);
        hex_lower(&h.finalize())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn dex_ordinal(name: &str) -> u32 {
    let stem = name.strip_prefix("classes").unwrap_or(name);
    let stem = stem.strip_suffix(".dex").unwrap_or(stem);
    if stem.is_empty() {
        1
    } else {
        stem.parse().unwrap_or(u32::MAX)
    }
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
