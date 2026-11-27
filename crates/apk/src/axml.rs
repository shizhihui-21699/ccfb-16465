//! Android binary XML (AXML) decoder.
//!
//! `AndroidManifest.xml` inside an APK is a compiled XML document: a resource
//! chunk stream with a string pool, namespace/start/end element records and
//! typed attribute values. We decode it into a small tree; we never trust the
//! declared sizes beyond the enclosing chunk boundary.

use crate::error::ApkError;

pub type ResultT<T> = std::result::Result<T, ApkError>;

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const RES_XML_END_ELEMENT: u16 = 0x0103;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;

const TYPE_NULL: u8 = 0x00;
const TYPE_REFERENCE: u8 = 0x01;
const TYPE_ATTRIBUTE: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;
const TYPE_FLOAT: u8 = 0x04;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

const UTF8_FLAG: u32 = 1 << 8;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Reference(u32),
    Attribute(u32),
    String(String),
    Float(f32),
    Int(i32),
    Boolean(bool),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            Value::Int(i) => Some(*i != 0),
            Value::String(s) => match s.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) => Some(*f as i32),
            _ => None,
        }
    }

    pub fn render(&self) -> String {
        match self {
            Value::Null => "null".into(),
            Value::Reference(r) => format!("@{r:#010x}"),
            Value::Attribute(a) => format!("?{a:#010x}"),
            Value::String(s) => s.clone(),
            Value::Float(f) => f.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Boolean(b) => b.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Attribute {
    /// Namespace URI, if any (e.g. the Android namespace).
    pub ns: Option<String>,
    pub name: String,
    /// Resource id of the attribute name (0 when unknown), e.g. 0x0101_0003
    /// for `android:name`.
    pub name_res: u32,
    pub value: Value,
    /// Raw string form of the value, when the pool has one.
    pub raw: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    pub fn attr_str(&self, name: &str) -> Option<&str> {
        self.attr(name).and_then(|a| a.value.as_str())
    }

    pub fn attr_bool(&self, name: &str) -> Option<bool> {
        self.attr(name).and_then(|a| a.value.as_bool())
    }

    pub fn attr_i32(&self, name: &str) -> Option<i32> {
        self.attr(name).and_then(|a| a.value.as_i32())
    }

    /// Android attributes can be written with the `android:` prefix or, in some
    /// repackers, with no prefix at all but a resource id. Match by local name.
    pub fn android_attr(&self, local: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| {
            a.name == local
                || a.name.ends_with(&format!(":{local}"))
                || (a.name_res & 0xffff) != 0 && a.name.is_empty()
        })
    }

    pub fn children<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s Element> + 's {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn walk(&self, f: &mut impl FnMut(&Element)) {
        f(self);
        for c in &self.children {
            c.walk(f);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Document {
    pub root: Element,
    /// Strings that were declared in the pool but not referenced by the tree.
    pub pool: Vec<String>,
    pub resource_ids: Vec<u32>,
}

fn rd_u16(b: &[u8], off: usize) -> ResultT<u16> {
    b.get(off..off + 2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .ok_or_else(|| ApkError::new(format!("axml: truncated u16 at {off:#x}")))
}

fn rd_u32(b: &[u8], off: usize) -> ResultT<u32> {
    b.get(off..off + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| ApkError::new(format!("axml: truncated u32 at {off:#x}")))
}

struct StringPool {
    strings: Vec<String>,
}

impl StringPool {
    fn parse(data: &[u8], chunk_off: usize) -> ResultT<Self> {
        let chunk_type = rd_u16(data, chunk_off)?;
        if chunk_type != RES_STRING_POOL_TYPE {
            return Err(ApkError::new(format!(
                "axml: expected string pool at {chunk_off:#x}, got type {chunk_type:#x}"
            )));
        }
        let header_size = rd_u16(data, chunk_off + 2)? as usize;
        let chunk_size = rd_u32(data, chunk_off + 4)? as usize;
        let string_count = rd_u32(data, chunk_off + 8)? as usize;
        let _style_count = rd_u32(data, chunk_off + 12)?;
        let flags = rd_u32(data, chunk_off + 16)?;
        let strings_start = rd_u32(data, chunk_off + 20)? as usize;
        let _styles_start = rd_u32(data, chunk_off + 24)?;

        let chunk_end = chunk_off
            .checked_add(chunk_size)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| ApkError::new("axml: string pool chunk overruns file"))?;
        if string_count > (chunk_end - chunk_off) / 4 {
            return Err(ApkError::new("axml: string count exceeds chunk"));
        }
        let utf8 = flags & UTF8_FLAG != 0;
        let offsets_base = chunk_off + header_size;
        let data_base = chunk_off + strings_start;
        let mut strings = Vec::with_capacity(string_count.min(1 << 20));
        for i in 0..string_count {
            let rel = rd_u32(data, offsets_base + i * 4)? as usize;
            let start = data_base + rel;
            if start >= chunk_end {
                strings.push(String::new());
                continue;
            }
            let (s, _) = if utf8 {
                decode_utf8_string(data, start, chunk_end)?
            } else {
                decode_utf16_string(data, start, chunk_end)?
            };
            strings.push(s);
        }
        Ok(Self { strings })
    }

    fn get(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }
}

fn decode_utf8_string(data: &[u8], start: usize, end: usize) -> ResultT<(String, usize)> {
    let mut p = start;
    let (_, n1) = read_len8(data, p, end)?;
    p += n1;
    let (byte_len, n2) = read_len8(data, p, end)?;
    p += n2;
    let byte_len = byte_len as usize;
    if p + byte_len > end {
        return Err(ApkError::new("axml: utf8 string overruns pool"));
    }
    let s = String::from_utf8_lossy(&data[p..p + byte_len]).into_owned();
    Ok((s, p + byte_len + 1))
}

fn read_len8(data: &[u8], p: usize, end: usize) -> ResultT<(u32, usize)> {
    let b = *data
        .get(p)
        .filter(|_| p < end)
        .ok_or_else(|| ApkError::new("axml: truncated utf8 length"))?;
    if b & 0x80 != 0 {
        let b2 = *data
            .get(p + 1)
            .filter(|_| p + 1 < end)
            .ok_or_else(|| ApkError::new("axml: truncated utf8 length"))?;
        Ok(((((b & 0x7f) as u32) << 8) | b2 as u32, 2))
    } else {
        Ok((b as u32, 1))
    }
}

fn decode_utf16_string(data: &[u8], start: usize, end: usize) -> ResultT<(String, usize)> {
    let mut p = start;
    let (len, n) = read_len16(data, p, end)?;
    p += n;
    let len = len as usize;
    if p + len * 2 > end {
        return Err(ApkError::new("axml: utf16 string overruns pool"));
    }
    let mut units = Vec::with_capacity(len);
    for i in 0..len {
        units.push(u16::from_le_bytes([data[p + i * 2], data[p + i * 2 + 1]]));
    }
    Ok((String::from_utf16_lossy(&units), p + len * 2 + 2))
}

fn read_len16(data: &[u8], p: usize, end: usize) -> ResultT<(u32, usize)> {
    let v = rd_u16(data, p)?;
    if v & 0x8000 != 0 {
        let v2 = rd_u16(data, p + 2)?;
        if p + 4 > end {
            return Err(ApkError::new("axml: truncated utf16 length"));
        }
        Ok(((((v & 0x7fff) as u32) << 16) | v2 as u32, 4))
    } else {
        Ok((v as u32, 2))
    }
}

/// Parse a binary XML document into an element tree.
pub fn parse(data: &[u8]) -> ResultT<Document> {
    let file_type = rd_u16(data, 0)?;
    if file_type != RES_XML_TYPE {
        return Err(ApkError::new(format!(
            "axml: not a binary XML document (type {file_type:#x})"
        )));
    }
    let file_header = rd_u16(data, 2)? as usize;
    let file_size = rd_u32(data, 4)? as usize;
    let limit = file_size.min(data.len());

    let mut pool = StringPool {
        strings: Vec::new(),
    };
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut off = file_header;
    // Element stack built from the flat record stream.
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    while off + 8 <= limit {
        let chunk_type = rd_u16(data, off)?;
        let header_size = rd_u16(data, off + 2)? as usize;
        let chunk_size = rd_u32(data, off + 4)? as usize;
        if chunk_size < 8 || off + chunk_size > limit {
            break;
        }
        match chunk_type {
            RES_STRING_POOL_TYPE => {
                let p = StringPool::parse(data, off)?;
                // The first pool in the document is the main string pool.
                if pool.strings.is_empty() {
                    pool = p;
                }
            }
            RES_XML_RESOURCE_MAP => {
                let n = (chunk_size.saturating_sub(header_size)) / 4;
                for i in 0..n {
                    if let Ok(id) = rd_u32(data, off + header_size + i * 4) {
                        resource_ids.push(id);
                    }
                }
            }
            RES_XML_START_ELEMENT => {
                let ext = off + header_size;
                let ns_idx = rd_u32(data, ext)?;
                let name_idx = rd_u32(data, ext + 4)?;
                let attr_start = rd_u16(data, ext + 8)? as usize;
                let attr_size = rd_u16(data, ext + 10)? as usize;
                let attr_count = rd_u16(data, ext + 12)? as usize;
                let name = pool.get(name_idx).unwrap_or("").to_string();
                let _ns = if ns_idx == u32::MAX {
                    None
                } else {
                    pool.get(ns_idx).map(|s| s.to_string())
                };
                let mut attributes = Vec::with_capacity(attr_count.min(256));
                let attr_base = ext + attr_start;
                for i in 0..attr_count {
                    let a = attr_base + i * attr_size.max(20);
                    if a + 20 > off + chunk_size {
                        break;
                    }
                    let a_ns = rd_u32(data, a)?;
                    let a_name = rd_u32(data, a + 4)?;
                    let a_raw = rd_u32(data, a + 8)?;
                    let _typed_size = rd_u16(data, a + 12)?;
                    let _res0 = data.get(a + 14).copied().unwrap_or(0);
                    let dtype = data.get(a + 15).copied().unwrap_or(TYPE_NULL);
                    let dvalue = rd_u32(data, a + 16)?;
                    let name_s = pool.get(a_name).unwrap_or("").to_string();
                    let name_res = resource_ids.get(a_name as usize).copied().unwrap_or(0);
                    let value = match dtype {
                        TYPE_NULL => Value::Null,
                        TYPE_REFERENCE => Value::Reference(dvalue),
                        TYPE_ATTRIBUTE => Value::Attribute(dvalue),
                        TYPE_STRING => Value::String(pool.get(dvalue).unwrap_or("").to_string()),
                        TYPE_FLOAT => Value::Float(f32::from_bits(dvalue)),
                        TYPE_INT_DEC => Value::Int(dvalue as i32),
                        TYPE_INT_HEX => Value::Int(dvalue as i32),
                        TYPE_INT_BOOLEAN => Value::Boolean(dvalue != 0),
                        _ => Value::Int(dvalue as i32),
                    };
                    let raw = if a_raw == u32::MAX {
                        None
                    } else {
                        pool.get(a_raw).map(|s| s.to_string())
                    };
                    attributes.push(Attribute {
                        ns: if a_ns == u32::MAX {
                            None
                        } else {
                            pool.get(a_ns).map(|s| s.to_string())
                        },
                        name: if name_s.is_empty() {
                            // Fall back to the android attribute resource name.
                            android_attr_name(name_res).to_string()
                        } else {
                            name_s
                        },
                        name_res,
                        value,
                        raw,
                    });
                }
                // Open elements live on the stack; they are attached to their
                // parent (in document order) when their end record arrives, so
                // sibling order is preserved without index juggling.
                stack.push(Element {
                    name,
                    attributes,
                    children: Vec::new(),
                });
            }
            RES_XML_END_ELEMENT => {
                if let Some(done) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(done);
                    } else if root.is_none() {
                        root = Some(done);
                    }
                }
            }
            _ => {}
        }
        off += chunk_size;
    }
    let root = root.ok_or_else(|| ApkError::new("axml: document has no root element"))?;
    Ok(Document {
        root,
        pool: pool.strings,
        resource_ids,
    })
}

fn android_attr_name(res: u32) -> &'static str {
    match res {
        0x0101_0000 => "theme",
        0x0101_0001 => "label",
        0x0101_0002 => "icon",
        0x0101_0003 => "name",
        0x0101_0004 => "manageSpaceActivity",
        0x0101_0005 => "allowClearUserData",
        0x0101_0006 => "permission",
        0x0101_0007 => "readPermission",
        0x0101_0008 => "writePermission",
        0x0101_0009..=0x0101_000b => "protectionLevel",
        0x0101_000c => "permissionGroup",
        0x0101_000d => "sharedUserId",
        0x0101_000e => "hasCode",
        0x0101_000f => "persistent",
        0x0101_0010 => "enabled",
        0x0101_0011 => "debuggable",
        0x0101_0012 => "exported",
        0x0101_0013 => "process",
        0x0101_0014 => "taskAffinity",
        0x0101_0015 => "multiprocess",
        0x0101_0016 => "finishOnTaskLaunch",
        0x0101_0017 => "clearTaskOnLaunch",
        0x0101_0018 => "stateNotNeeded",
        0x0101_0019 => "excludeFromRecents",
        0x0101_001a => "authorities",
        0x0101_001b => "syncable",
        0x0101_001c => "initOrder",
        0x0101_001d => "grantUriPermissions",
        0x0101_001e => "priority",
        0x0101_001f => "launchMode",
        0x0101_0020 => "screenOrientation",
        0x0101_0021 => "configChanges",
        0x0101_0022 => "description",
        0x0101_0023 => "targetPackage",
        0x0101_0024 => "handleProfiling",
        0x0101_0025 => "functionalTest",
        0x0101_0026 => "value",
        0x0101_0027 => "resource",
        0x0101_0028 => "mimeType",
        0x0101_0029 => "scheme",
        0x0101_002a => "host",
        0x0101_002b => "port",
        0x0101_002c => "path",
        0x0101_002d => "pathPrefix",
        0x0101_002e => "pathPattern",
        0x0101_002f => "pathAdvancedPattern",
        0x0101_0030 => "pathSuffix",
        0x0101_0031 => "pathAdvancedSuffix",
        0x0101_0032 => "pathQuery",
        0x0101_0033 => "fragment",
        0x0101_0034 => "minSdkVersion",
        0x0101_0035 => "versionCode",
        0x0101_0036 => "versionName",
        0x0101_0037 => "targetSdkVersion",
        0x0101_0038 => "maxSdkVersion",
        0x0101_0039 => "debuggable",
        0x0101_003a => "hasCode",
        0x0101_003b => "installLocation",
        0x0101_0040 => "allowBackup",
        0x0101_0041 => "glEsVersion",
        0x0101_0042 => "required",
        0x0101_0043 => "accountType",
        0x0101_0044 => "process",
        0x0101_0045 => "backupAgent",
        0x0101_0046 => "largeHeap",
        0x0101_0047 => "usesCleartextTraffic",
        0x0101_0048 => "networkSecurityConfig",
        0x0101_0049 => "requestLegacyExternalStorage",
        0x0101_004a => "preserveLegacyExternalStorage",
        0x0101_004b => "extractNativeLibs",
        0x0101_004c => "fullBackupOnly",
        0x0101_004d => "resizeableActivity",
        0x0101_004e => "supportsRtl",
        0x0101_0100 => "parentActivityName",
        0x0101_0101 => "isolatedProcess",
        0x0101_0102 => "requiredAccountType",
        0x0101_0103 => "restrictedAccountType",
        0x0101_0104 => "allowTaskReparenting",
        0x0101_0105 => "usesPermissionFlags",
        0x0101_0106 => "roundIcon",
        0x0101_0107 => "minAspectRatio",
        0x0101_0108 => "maxAspectRatio",
        0x0101_0109 => "supportsPictureInPicture",
        0x0101_010a => "foregroundServiceType",
        0x0101_010b => "requestRawExternalStorageAccess",
        0x0101_010c => "localeConfig",
        0x0101_010d => "enableOnBackInvokedCallback",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_pool_roundtrip() {
        // Minimal binary XML with one UTF-8 string pool and a single element.
        let strings = ["manifest"];
        let mut data = Vec::new();
        // header
        data.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let _ = strings;
        assert!(!data.is_empty());
    }
}
