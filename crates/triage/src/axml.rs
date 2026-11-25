//! 二进制 AndroidManifest.xml（AXML）的尽力解析器。
//!
//! 不依赖 aapt/androguard：分析集群上不想为每个样本拉起 JVM。
//! 解析失败时返回空摘要（配合 `unwrap_or_default`），预筛的其它信号仍然有效。
//!
//! 参考：Android 平台 `frameworks/base/include/androidfw/ResourceTypes.h` 的二进制布局。

use serde::{Deserialize, Serialize};

use crate::ComponentKind;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestSummary {
    pub package: Option<String>,
    pub application_class: Option<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub permissions: Vec<String>,
    pub components: Vec<super::ComponentInfo>,
}

// AXML chunk 类型
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const UTF8_FLAG: u32 = 0x00000100;

// 框架属性资源 ID（属性名未进字符串池时走 resource map 查表）
const ATTR_NAME: u32 = 0x0101_0003;
const ATTR_EXPORTED: u32 = 0x0101_0010;
const ATTR_MIN_SDK: u32 = 0x0101_020c;
const ATTR_TARGET_SDK: u32 = 0x0101_0270;

const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_BOOLEAN: u8 = 0x12;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }
    fn u16(&mut self) -> Option<u16> {
        let v = u16::from_le_bytes([*self.data.get(self.pos)?, *self.data.get(self.pos + 1)?]);
        self.pos += 2;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_le_bytes(self.data.get(self.pos..self.pos + 4)?.try_into().ok()?);
        self.pos += 4;
        Some(v)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        if self.pos > self.data.len() {
            None
        } else {
            Some(())
        }
    }
}

/// 解析字符串池，返回字符串向量（索引即字符串池下标）。
/// 入参为完整 chunk（从 type/header_size 两个 u16 开始）。
fn parse_string_pool(data: &[u8]) -> Option<Vec<Option<String>>> {
    let mut c = Cursor::new(data);
    let _chunk_type = c.u16()?;
    let _header_size = c.u16()?;
    let _chunk_size = c.u32()?;
    let string_count = c.u32()? as usize;
    let _style_count = c.u32()?;
    let flags = c.u32()?;
    let strings_start = c.u32()? as usize;
    let _styles_start = c.u32()?;

    let mut offsets = Vec::with_capacity(string_count);
    for _ in 0..string_count {
        offsets.push(c.u32()? as usize);
    }

    let utf8 = flags & UTF8_FLAG != 0;
    let base = strings_start;
    let mut strings = Vec::with_capacity(string_count);
    for off in offsets {
        let abs = base + off;
        if abs >= data.len() {
            strings.push(None);
            continue;
        }
        let s = if utf8 {
            parse_utf8_string(data, abs)
        } else {
            parse_utf16_string(data, abs)
        };
        strings.push(s);
    }
    Some(strings)
}

fn parse_utf8_string(data: &[u8], start: usize) -> Option<String> {
    // 第一个变长数是 UTF-16 长度（解析时跳过），第二个是 UTF-8 字节数
    let mut p = start;
    // utf16 长度
    let b0 = *data.get(p)?;
    p += 1;
    if b0 & 0x80 != 0 {
        p += 1; // 双字节形式，第二字节
    }
    let b1 = *data.get(p)?;
    let byte_len = if b1 & 0x80 != 0 {
        let b2 = *data.get(p + 1)? as usize;
        (((b1 & 0x7f) as usize) << 8) | b2
    } else {
        b1 as usize
    };
    p += if b1 & 0x80 != 0 { 2 } else { 1 };
    let end = (p + byte_len).min(data.len());
    String::from_utf8(data.get(p..end)?.to_vec()).ok()
}

fn parse_utf16_string(data: &[u8], start: usize) -> Option<String> {
    let mut p = start;
    let first = u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]);
    p += 2;
    let char_len = if first & 0x8000 != 0 {
        let second = u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
        p += 2;
        (((first & 0x7fff) as usize) << 16) | second
    } else {
        first as usize
    };
    let mut units = Vec::with_capacity(char_len);
    for _ in 0..char_len {
        units.push(u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]));
        p += 2;
    }
    String::from_utf16(&units).ok()
}

#[derive(Clone)]
struct Attr {
    name_res_id: Option<u32>,
    name_str: Option<String>,
    raw_str: Option<String>,
    dtype: u8,
    data: u32,
}

pub fn parse_manifest(data: &[u8]) -> Option<ManifestSummary> {
    let mut c = Cursor::new(data);
    // 文件头
    let file_type = c.u16()?;
    if file_type != 0x0003 {
        return None;
    }
    let _header_size = c.u16()?;
    let _file_size = c.u32()?;

    // 第一个 chunk 必须是字符串池
    let pool_type = c.u16()?;
    let _pool_header = c.u16()?;
    if pool_type != RES_STRING_POOL_TYPE {
        return None;
    }
    // 字符串池从 type 字段开始，parse_string_pool 内部重新解析完整头部
    let pool_start = c.pos - 4;
    let strings = parse_string_pool(&data[pool_start..])?;
    let pool_size =
        u32::from_le_bytes(data.get(pool_start + 4..pool_start + 8)?.try_into().ok()?) as usize;
    c.pos = pool_start + pool_size;

    // 可选 resource map chunk：属性资源 ID 表，顺序对应字符串池索引
    let mut resource_ids: Vec<u32> = Vec::new();
    if c.pos + 4 <= data.len() {
        let t = u16::from_le_bytes([data[c.pos], data[c.pos + 1]]);
        if t == 0x0180 {
            let size = u32::from_le_bytes(data[c.pos + 4..c.pos + 8].try_into().ok()?) as usize;
            let count = size.saturating_sub(8) / 4;
            for i in 0..count {
                let off = c.pos + 8 + i * 4;
                resource_ids.push(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?));
            }
            c.pos += size;
        }
    }

    let get_str = |idx: u32| -> Option<String> { strings.get(idx as usize).cloned().flatten() };
    let attr_name = |a: &Attr| -> Option<String> {
        // 真实 AXML 的属性名多走 resource map；测试/简单生成器直接用字符串名。两者都支持。
        a.name_str.clone().or_else(|| match a.name_res_id {
            Some(ATTR_NAME) => Some("name".into()),
            Some(ATTR_EXPORTED) => Some("exported".into()),
            Some(ATTR_MIN_SDK) => Some("minSdkVersion".into()),
            Some(ATTR_TARGET_SDK) => Some("targetSdkVersion".into()),
            _ => None,
        })
    };

    let mut summary = ManifestSummary::default();
    // 组件栈：记录当前所在组件在 summary.components 中的下标，用于挂 intent-filter action
    let mut component_stack: Vec<usize> = Vec::new();

    while c.pos + 8 <= data.len() {
        let chunk_start = c.pos;
        let ctype = c.u16()?;
        let header_size = c.u16()? as usize;
        let chunk_size = c.u32()? as usize;
        if chunk_size < 8 || chunk_start + chunk_size > data.len() {
            break;
        }

        if ctype == RES_XML_START_ELEMENT_TYPE {
            // lineNumber(4) comment(4) ns(4) name(4)
            c.skip(8)?;
            let _ns = c.u32()?;
            let name_idx = c.u32()?;
            let elem_name = get_str(name_idx).unwrap_or_default();

            // attributeStart(2) attributeSize(2) count(2) id(2) class(2) style(2)
            let _attr_start = c.u16()?;
            let _attr_size = c.u16()?;
            let attr_count = c.u16()? as usize;
            let _id_idx = c.u16()?;
            let _class_idx = c.u16()?;
            let _style_idx = c.u16()?;

            let mut attrs = Vec::with_capacity(attr_count);
            for _ in 0..attr_count {
                let _ans = c.u32()?;
                let name_index = c.u32()?;
                let raw_value = c.u32()?;
                let _size = c.u16()?;
                let _res0 = c.data.get(c.pos).copied();
                c.pos += 1;
                let dtype = *data.get(c.pos)?;
                c.pos += 1;
                let dvalue = c.u32()?;

                let name_res_id = resource_ids.get(name_index as usize).copied();
                let name_str = get_str(name_index);
                let raw_str = if raw_value != u32::MAX {
                    get_str(raw_value)
                } else {
                    None
                };
                attrs.push(Attr {
                    name_res_id,
                    name_str,
                    raw_str,
                    dtype,
                    data: dvalue,
                });
            }

            handle_element(
                &elem_name,
                &attrs,
                &attr_name,
                &mut summary,
                &mut component_stack,
            );
        } else if ctype == RES_XML_END_ELEMENT_TYPE {
            // 出栈时机：结束标签的元素名与栈顶组件同名即可
            c.pos = chunk_start + header_size;
            if let Some(name_idx_pos) = chunk_start.checked_add(16) {
                if name_idx_pos + 4 <= data.len() {
                    let name_idx =
                        u32::from_le_bytes(data[name_idx_pos..name_idx_pos + 4].try_into().ok()?);
                    let name = get_str(name_idx).unwrap_or_default();
                    if component_kind(&name).is_some() {
                        component_stack.pop();
                    }
                }
            }
        }

        // 统一跳到下一个 chunk
        c.pos = chunk_start + chunk_size;
    }

    Some(summary)
}

fn component_kind(elem: &str) -> Option<ComponentKind> {
    match elem {
        "activity" | "activity-alias" => Some(ComponentKind::Activity),
        "service" => Some(ComponentKind::Service),
        "receiver" => Some(ComponentKind::Receiver),
        "provider" => Some(ComponentKind::Provider),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_element(
    elem: &str,
    attrs: &[Attr],
    attr_name: &impl Fn(&Attr) -> Option<String>,
    summary: &mut ManifestSummary,
    component_stack: &mut Vec<usize>,
) {
    let value_of = |want: &str| -> Option<&Attr> {
        attrs.iter().find(|a| attr_name(a).as_deref() == Some(want))
    };

    match elem {
        "manifest" => {
            if let Some(a) = value_of("package") {
                summary.package = a.raw_str.clone();
            }
        }
        "uses-sdk" => {
            if let Some(a) = value_of("minSdkVersion") {
                summary.min_sdk = typed_int(a);
            }
            if let Some(a) = value_of("targetSdkVersion") {
                summary.target_sdk = typed_int(a);
            }
        }
        "uses-permission" | "permission" => {
            if let Some(a) = value_of("name") {
                if let Some(s) = &a.raw_str {
                    summary.permissions.push(s.clone());
                }
            }
        }
        "application" => {
            if let Some(a) = value_of("name") {
                summary.application_class = a.raw_str.clone();
            }
        }
        "action" => {
            // intent-filter/action：挂到当前组件
            if let Some(idx) = component_stack.last().copied() {
                if let Some(a) = value_of("name") {
                    if let Some(s) = &a.raw_str {
                        summary.components[idx].actions.push(s.clone());
                    }
                }
            }
        }
        other => {
            if let Some(kind) = component_kind(other) {
                let name = value_of("name")
                    .and_then(|a| a.raw_str.clone())
                    .unwrap_or_default();
                let exported = value_of("exported").and_then(typed_bool);
                summary.components.push(super::ComponentInfo {
                    kind,
                    name,
                    exported,
                    actions: Vec::new(),
                });
                component_stack.push(summary.components.len() - 1);
            }
        }
    }
}

fn typed_int(a: &Attr) -> Option<u32> {
    match a.dtype {
        TYPE_INT_DEC | 0x11 => Some(a.data),
        TYPE_STRING => a.raw_str.as_ref().and_then(|s| s.parse().ok()),
        _ => Some(a.data),
    }
}

fn typed_bool(a: &Attr) -> Option<bool> {
    match a.dtype {
        TYPE_INT_BOOLEAN => Some(a.data != 0),
        TYPE_STRING => a.raw_str.as_deref().map(|s| s == "true"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRINGS: &[&str] = &[
        "manifest",
        "uses-permission",
        "application",
        "receiver",
        "action",
        "name",
        "exported",
        "android.permission.SMS",
        "com.evil.BootRecv",
        "android.intent.action.BOOT_COMPLETED",
        "package",
        "com.evil.app",
    ];

    fn string_pool(utf8: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in STRINGS {
            offsets.push(data.len() as u32);
            if utf8 {
                let b = s.as_bytes();
                data.push(b.len() as u8); // utf16 长度（ASCII 与 utf8 等长）
                data.push(b.len() as u8); // utf8 字节数
                data.extend_from_slice(b);
                data.push(0);
            } else {
                data.extend_from_slice(&(s.len() as u16).to_le_bytes());
                for u in s.encode_utf16() {
                    data.extend_from_slice(&u.to_le_bytes());
                }
                data.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        let header = 28usize + STRINGS.len() * 4;
        let chunk_size = header + data.len();
        let mut out = Vec::new();
        out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        out.extend_from_slice(&28u16.to_le_bytes());
        out.extend_from_slice(&(chunk_size as u32).to_le_bytes());
        out.extend_from_slice(&(STRINGS.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&if utf8 { UTF8_FLAG } else { 0u32 }.to_le_bytes());
        out.extend_from_slice(&(header as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        for o in &offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        out.extend_from_slice(&data);
        out
    }

    fn resource_map() -> Vec<u8> {
        let size = 8 + STRINGS.len() * 4;
        let mut out = Vec::new();
        out.extend_from_slice(&0x0180u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        for _ in 0..STRINGS.len() {
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out
    }

    struct Attr {
        name: u32,
        raw: u32,
        dtype: u8,
        data: u32,
    }

    fn start_element(tag: &str, attrs: Vec<Attr>) -> Vec<u8> {
        let idx = |s: &str| STRINGS.iter().position(|x| *x == s).unwrap() as u32;
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes()); // line
        body.extend_from_slice(&u32::MAX.to_le_bytes()); // comment
        body.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
        body.extend_from_slice(&idx(tag).to_le_bytes()); // name
        body.extend_from_slice(&20u16.to_le_bytes()); // attrStart
        body.extend_from_slice(&20u16.to_le_bytes()); // attrSize
        body.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // id/class/style
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        for a in &attrs {
            body.extend_from_slice(&u32::MAX.to_le_bytes()); // ns
            body.extend_from_slice(&a.name.to_le_bytes());
            body.extend_from_slice(&a.raw.to_le_bytes());
            body.extend_from_slice(&8u16.to_le_bytes());
            body.push(0);
            body.push(a.dtype);
            body.extend_from_slice(&a.data.to_le_bytes());
        }
        let chunk_size = 8 + body.len();
        let mut out = Vec::new();
        out.extend_from_slice(&RES_XML_START_ELEMENT_TYPE.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&(chunk_size as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn str_attr(name: &str, value: &str) -> Attr {
        let idx = |s: &str| STRINGS.iter().position(|x| *x == s).unwrap() as u32;
        let v = idx(value);
        Attr {
            name: idx(name),
            raw: v,
            dtype: TYPE_STRING,
            data: v,
        }
    }

    fn bool_attr(value: bool) -> Attr {
        let idx = |s: &str| STRINGS.iter().position(|x| *x == s).unwrap() as u32;
        Attr {
            name: idx("exported"),
            raw: u32::MAX,
            dtype: TYPE_INT_BOOLEAN,
            data: value as u32,
        }
    }

    fn make_axml(utf8: bool) -> Vec<u8> {
        let idx = |s: &str| STRINGS.iter().position(|x| *x == s).unwrap() as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&3u16.to_le_bytes()); // XML 文件头
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // 文件大小占位
        out.extend_from_slice(&string_pool(utf8));
        out.extend_from_slice(&resource_map());
        out.extend_from_slice(&start_element(
            "manifest",
            vec![str_attr("package", "com.evil.app")],
        ));
        out.extend_from_slice(&start_element(
            "uses-permission",
            vec![str_attr("name", "android.permission.SMS")],
        ));
        out.extend_from_slice(&start_element("application", vec![]));
        out.extend_from_slice(&start_element(
            "receiver",
            vec![str_attr("name", "com.evil.BootRecv"), bool_attr(true)],
        ));
        out.extend_from_slice(&start_element(
            "action",
            vec![str_attr("name", "android.intent.action.BOOT_COMPLETED")],
        ));
        let len = out.len() as u32;
        out[4..8].copy_from_slice(&len.to_le_bytes());
        let _ = idx;
        out
    }

    #[test]
    fn parses_utf8_manifest_components() {
        let s = parse_manifest(&make_axml(true)).expect("解析失败");
        assert_eq!(s.package.as_deref(), Some("com.evil.app"));
        assert!(s.permissions.iter().any(|p| p.contains("SMS")));
        let recv = s
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Receiver)
            .unwrap();
        assert_eq!(recv.name, "com.evil.BootRecv");
        assert_eq!(recv.exported, Some(true));
        assert!(recv.actions.iter().any(|a| a.contains("BOOT_COMPLETED")));
    }

    #[test]
    fn parses_utf16_string_pool() {
        let s = parse_manifest(&make_axml(false)).expect("UTF-16 池解析失败");
        assert_eq!(s.package.as_deref(), Some("com.evil.app"));
        assert!(s.components.iter().any(|c| c.name == "com.evil.BootRecv"));
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_manifest(b"not an axml file at all").is_none());
    }
}
