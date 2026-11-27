//! Resolved in-memory model of a DEX file plus its parser.

use crate::error::{DexError, ErrorKind, Result};
use crate::insn::{self, Insn};
use crate::reader::{mutf8_to_string, Reader};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const NO_INDEX: u32 = 0xffff_ffff;

/// A type descriptor such as `Lcom/example/A;` or `[I`.
pub type Type = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtoRef {
    pub shorty: String,
    pub return_type: Type,
    pub params: Vec<Type>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldRef {
    pub class: Type,
    pub name: String,
    pub ty: Type,
}

impl FieldRef {
    pub fn signature(&self) -> String {
        format!("{}->{}:{}", self.class, self.name, self.ty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodRef {
    pub class: Type,
    pub name: String,
    pub proto: ProtoRef,
}

impl MethodRef {
    /// `Lpkg/Cls;->name(Lp1;I)Ret`
    pub fn signature(&self) -> String {
        let params: String = self.proto.params.iter().map(|p| p.as_str()).collect();
        format!(
            "{}->{}({}){}",
            self.class, self.name, params, self.proto.return_type
        )
    }

    /// Short form used in reports: `pkg.Cls.name(Lp1;I)Ret`
    pub fn display(&self) -> String {
        let params: String = self.proto.params.iter().map(|p| p.as_str()).collect();
        format!(
            "{}.{}({}){}",
            dotted(&self.class),
            self.name,
            params,
            self.proto.return_type
        )
    }
}

/// `Lcom/example/Foo;` -> `com.example.Foo`
pub fn dotted(desc: &str) -> String {
    if let Some(inner) = desc.strip_prefix('L').and_then(|d| d.strip_suffix(';')) {
        inner.replace('/', ".")
    } else if let Some(inner) = desc.strip_prefix('[') {
        format!("{}[]", dotted(inner))
    } else {
        desc.to_string()
    }
}

/// One decoded method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Code {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns_size: u32,
    #[serde(skip)]
    pub units: Vec<u16>,
    pub instructions: Vec<Insn>,
    pub tries: Vec<TryBlock>,
    /// pc -> source line, resolved from the debug info item.
    pub line_table: Vec<(u32, u32)>,
    /// pc -> instruction slot, for O(1) branch lookup.
    #[serde(skip)]
    pub pc_index: HashMap<u32, usize>,
}

impl Code {
    pub fn insn_at(&self, pc: u32) -> Option<&Insn> {
        self.pc_index.get(&pc).map(|&i| &self.instructions[i])
    }

    pub fn insn_index_at(&self, pc: u32) -> Option<usize> {
        self.pc_index.get(&pc).copied()
    }

    pub fn line_for(&self, pc: u32) -> Option<u32> {
        let mut best = None;
        for &(p, l) in &self.line_table {
            if p <= pc {
                best = Some(l);
            } else {
                break;
            }
        }
        best
    }

    /// Ordered list of basic-block entry points.
    pub fn block_starts(&self) -> Vec<u32> {
        let mut starts = vec![0u32];
        for i in &self.instructions {
            if i.kind != insn::InsnKind::Real {
                continue;
            }
            if let Some(t) = i.target {
                starts.push(t);
            }
            if i.is_terminator() && !i.is_return() && !matches!(i.op, 0x27) {
                let next = i.pc + i.width;
                if next < self.insns_size {
                    starts.push(next);
                }
            }
        }
        starts.retain(|&s| self.pc_index.contains_key(&s));
        starts.sort_unstable();
        starts.dedup();
        starts
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TryBlock {
    pub start_pc: u32,
    pub insn_count: u32,
    /// (type descriptor or None for catch-all, handler pc)
    pub handlers: Vec<(Option<Type>, u32)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Method {
    pub index: u32,
    pub class: Type,
    pub name: String,
    pub proto: ProtoRef,
    pub access_flags: u32,
    pub code: Option<Code>,
    pub is_static: bool,
    pub is_native: bool,
    pub is_abstract: bool,
}

impl Method {
    pub fn signature(&self) -> String {
        let params: String = self.proto.params.iter().map(|p| p.as_str()).collect();
        format!(
            "{}->{}({}){}",
            self.class, self.name, params, self.proto.return_type
        )
    }

    pub fn display(&self) -> String {
        let params: String = self.proto.params.iter().map(|p| p.as_str()).collect();
        format!(
            "{}.{}({}){}",
            dotted(&self.class),
            self.name,
            params,
            self.proto.return_type
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub index: u32,
    pub class: Type,
    pub name: String,
    pub ty: Type,
    pub access_flags: u32,
    pub static_value: Option<EncodedValue>,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(String),
    Type(Type),
    Field(FieldRef),
    Method(MethodRef),
    Enum(FieldRef),
    Array(Vec<EncodedValue>),
    Annotation {
        ty: Type,
        elements: Vec<(String, EncodedValue)>,
    },
    Null,
    Boolean(bool),
    MethodHandle(u32),
    MethodType(ProtoRef),
}

impl EncodedValue {
    /// Best-effort `to_string` for tracing and reporting.
    pub fn render(&self) -> String {
        match self {
            EncodedValue::Byte(v) => v.to_string(),
            EncodedValue::Short(v) => v.to_string(),
            EncodedValue::Char(v) => format!("'{}'", char::from_u32(*v as u32).unwrap_or('?')),
            EncodedValue::Int(v) => v.to_string(),
            EncodedValue::Long(v) => format!("{v}L"),
            EncodedValue::Float(v) => format!("{v}f"),
            EncodedValue::Double(v) => format!("{v}d"),
            EncodedValue::String(s) => format!("{s:?}"),
            EncodedValue::Type(t) => t.clone(),
            EncodedValue::Field(f) => f.signature(),
            EncodedValue::Method(m) => m.signature(),
            EncodedValue::Enum(f) => f.signature(),
            EncodedValue::Array(a) => {
                let parts: Vec<String> = a.iter().map(|v| v.render()).collect();
                format!("[{}]", parts.join(", "))
            }
            EncodedValue::Annotation { ty, .. } => format!("@{ty}"),
            EncodedValue::Null => "null".into(),
            EncodedValue::Boolean(b) => b.to_string(),
            EncodedValue::MethodHandle(i) => format!("method-handle@{i}"),
            EncodedValue::MethodType(p) => p.return_type.clone(),
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            EncodedValue::Byte(v) => Some(*v as i64),
            EncodedValue::Short(v) => Some(*v as i64),
            EncodedValue::Char(v) => Some(*v as i64),
            EncodedValue::Int(v) => Some(*v as i64),
            EncodedValue::Long(v) => Some(*v),
            EncodedValue::Boolean(b) => Some(*b as i64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            EncodedValue::String(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassData {
    pub static_fields: Vec<Field>,
    pub instance_fields: Vec<Field>,
    pub direct_methods: Vec<Method>,
    pub virtual_methods: Vec<Method>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Class {
    pub descriptor: Type,
    pub access_flags: u32,
    pub superclass: Option<Type>,
    pub interfaces: Vec<Type>,
    pub source_file: Option<String>,
    pub data: ClassData,
    /// Raw value of the `annotations_off` field (parsed lazily elsewhere).
    pub annotations_off: u32,
}

impl Class {
    pub fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    pub fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    pub fn methods(&self) -> impl Iterator<Item = &Method> {
        self.data
            .direct_methods
            .iter()
            .chain(self.data.virtual_methods.iter())
    }
}

/// A `method_handle_item`: what kind of member it names and which one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodHandleItem {
    pub kind: u16,
    pub member: u16,
}

impl MethodHandleItem {
    pub const STATIC_PUT: u16 = 0x00;
    pub const STATIC_GET: u16 = 0x01;
    pub const INSTANCE_PUT: u16 = 0x02;
    pub const INSTANCE_GET: u16 = 0x03;
    pub const INVOKE_STATIC: u16 = 0x04;
    pub const INVOKE_INSTANCE: u16 = 0x05;
    pub const INVOKE_CONSTRUCTOR: u16 = 0x06;
    pub const INVOKE_DIRECT: u16 = 0x07;
    pub const INVOKE_INTERFACE: u16 = 0x08;

    pub fn is_field(&self) -> bool {
        self.kind <= Self::INSTANCE_GET
    }
}

/// A `call_site_id_item`: the bootstrap method and its static arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub bootstrap: Option<MethodHandleItem>,
    pub args: Vec<EncodedValue>,
}

/// A parsed DEX file. Tables are owned; cross references are indices into them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DexFile {
    pub version: u32,
    pub strings: Vec<String>,
    pub types: Vec<Type>,
    pub protos: Vec<ProtoRef>,
    pub fields: Vec<FieldRef>,
    pub methods: Vec<MethodRef>,
    pub classes: Vec<Class>,
    /// `method_handles` and `call_site_ids`, needed for `invoke-custom` (lambdas)
    /// and `MethodHandle.invoke`. Empty for DEX files that do not use them.
    pub method_handles: Vec<MethodHandleItem>,
    pub call_sites: Vec<CallSite>,
    /// sha1 of the encoded file, used as a stable identity for extracted payloads.
    pub sha1: String,
    pub file_size: u32,
}

/// Flattened per-method view used by the interpreter and call-graph builder.
pub struct InsnTable;

impl DexFile {
    pub fn method(&self, class: &str, name: &str, params: &[&str]) -> Option<&Method> {
        self.classes
            .iter()
            .find(|c| c.descriptor == class)
            .and_then(|c| {
                c.methods().find(|m| {
                    m.name == name
                        && (params.is_empty()
                            || m.proto.params.len() == params.len()
                                && m.proto.params.iter().zip(params).all(|(a, b)| a == b))
                })
            })
    }

    pub fn class(&self, descriptor: &str) -> Option<&Class> {
        self.classes.iter().find(|c| c.descriptor == descriptor)
    }

    /// Every method in the file, with a stable index.
    pub fn all_methods(&self) -> Vec<&Method> {
        let mut out = Vec::new();
        for c in &self.classes {
            out.extend(c.data.direct_methods.iter());
            out.extend(c.data.virtual_methods.iter());
        }
        out
    }

    pub fn string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }

    pub fn type_at(&self, idx: u32) -> Option<&str> {
        self.types.get(idx as usize).map(|s| s.as_str())
    }

    pub fn field_at(&self, idx: u32) -> Option<&FieldRef> {
        self.fields.get(idx as usize)
    }

    pub fn method_at(&self, idx: u32) -> Option<&MethodRef> {
        self.methods.get(idx as usize)
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    raw: &'a [u8],
    strings: Vec<String>,
    types: Vec<Type>,
    protos: Vec<ProtoRef>,
    fields: Vec<FieldRef>,
    methods: Vec<MethodRef>,
}

pub fn parse(data: &[u8]) -> Result<DexFile> {
    let mut r = Reader::new(data);
    let magic = r.bytes(8)?;
    if &magic[..4] != b"dex\n" || magic[7] != 0 {
        return Err(DexError::new(
            ErrorKind::BadMagic,
            format!("not a DEX file (magic {magic:02x?})"),
        ));
    }
    let version = std::str::from_utf8(&magic[4..7])
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| DexError::new(ErrorKind::BadMagic, "bad dex version digits"))?;
    let _checksum = r.u32()?;
    let _signature = r.bytes(20)?;
    let file_size = r.u32()?;
    let header_size = r.u32()?;
    if header_size < 0x70 {
        return Err(DexError::new(
            ErrorKind::Unsupported,
            format!("header_size {header_size:#x} < 0x70"),
        ));
    }
    let endian = r.u32()?;
    if endian != 0x1234_5678 {
        return Err(DexError::new(
            ErrorKind::Unsupported,
            format!("unsupported endian tag {endian:#x}"),
        ));
    }
    let _link_size = r.u32()?;
    let _link_off = r.u32()?;
    let map_off = r.u32()?;
    let string_ids_size = r.u32()?;
    let string_ids_off = r.u32()?;
    let type_ids_size = r.u32()?;
    let type_ids_off = r.u32()?;
    let proto_ids_size = r.u32()?;
    let proto_ids_off = r.u32()?;
    let field_ids_size = r.u32()?;
    let field_ids_off = r.u32()?;
    let method_ids_size = r.u32()?;
    let method_ids_off = r.u32()?;
    let class_defs_size = r.u32()?;
    let class_defs_off = r.u32()?;
    let _data_size = r.u32()?;
    let _data_off = r.u32()?;

    let len = data.len() as u64;
    for (name, off, count, item) in [
        ("string_ids", string_ids_off, string_ids_size, 4u64),
        ("type_ids", type_ids_off, type_ids_size, 4),
        ("proto_ids", proto_ids_off, proto_ids_size, 12),
        ("field_ids", field_ids_off, field_ids_size, 8),
        ("method_ids", method_ids_off, method_ids_size, 8),
        ("class_defs", class_defs_off, class_defs_size, 32),
    ] {
        if count > 0 {
            let need = off as u64 + count as u64 * item;
            if need > len {
                return Err(DexError::new(
                    ErrorKind::Truncated,
                    format!("{name} table ({count} x {item}B at {off:#x}) exceeds file size {len}"),
                ));
            }
        }
    }
    if file_size as u64 > len {
        return Err(DexError::new(
            ErrorKind::Truncated,
            format!("declared file_size {file_size} exceeds buffer {len}"),
        ));
    }

    // string_ids -> string_data_item (uleb length + MUTF-8 + NUL)
    let mut strings = Vec::with_capacity(string_ids_size.min(1 << 20) as usize);
    for i in 0..string_ids_size {
        let off = Reader::at(data, string_ids_off as usize + i as usize * 4)?.u32()?;
        let mut sr = Reader::at(data, off as usize)?;
        let _utf16_len = sr.uleb128()?;
        let start = sr.pos();
        let mut end = start;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        if end >= data.len() {
            return Err(DexError::new(
                ErrorKind::BadString,
                format!("string {i} at {off:#x} is not NUL terminated"),
            ));
        }
        strings.push(mutf8_to_string(&data[start..end])?);
    }

    let mut types = Vec::with_capacity(type_ids_size.min(1 << 20) as usize);
    for i in 0..type_ids_size {
        let idx = Reader::at(data, type_ids_off as usize + i as usize * 4)?.u32()?;
        let s = strings.get(idx as usize).ok_or_else(|| {
            DexError::new(ErrorKind::OutOfRange, format!("type {i} -> string {idx}"))
        })?;
        types.push(s.clone());
    }

    let mut protos = Vec::with_capacity(proto_ids_size.min(1 << 20) as usize);
    for i in 0..proto_ids_size {
        let mut r = Reader::at(data, proto_ids_off as usize + i as usize * 12)?;
        let shorty_idx = r.u32()?;
        let return_idx = r.u32()?;
        let params_off = r.u32()?;
        let shorty = strings
            .get(shorty_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range("proto shorty index"))?;
        let ret = types
            .get(return_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range("proto return type index"))?;
        let params = parse_type_list(data, params_off, &types)?;
        protos.push(ProtoRef {
            shorty,
            return_type: ret,
            params,
        });
    }

    let mut fields = Vec::with_capacity(field_ids_size.min(1 << 20) as usize);
    for i in 0..field_ids_size {
        let mut r = Reader::at(data, field_ids_off as usize + i as usize * 8)?;
        let class_idx = r.u16()?;
        let type_idx = r.u16()?;
        let name_idx = r.u32()?;
        let class = types
            .get(class_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range(format!("field {i} class type {class_idx}")))?;
        let ty = types
            .get(type_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range(format!("field {i} type {type_idx}")))?;
        let name = strings
            .get(name_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range(format!("field {i} name string {name_idx}")))?;
        fields.push(FieldRef { class, name, ty });
    }

    let mut methods = Vec::with_capacity(method_ids_size.min(1 << 20) as usize);
    for i in 0..method_ids_size {
        let mut r = Reader::at(data, method_ids_off as usize + i as usize * 8)?;
        let class_idx = r.u16()?;
        let proto_idx = r.u16()?;
        let name_idx = r.u32()?;
        let class = types
            .get(class_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range(format!("method {i} class type {class_idx}")))?;
        let proto = protos
            .get(proto_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range(format!("method {i} proto {proto_idx}")))?;
        let name = strings
            .get(name_idx as usize)
            .cloned()
            .ok_or_else(|| DexError::out_of_range(format!("method {i} name string {name_idx}")))?;
        methods.push(MethodRef { class, name, proto });
    }

    let mut p = Parser {
        raw: data,
        strings,
        types,
        protos,
        fields,
        methods,
    };

    let mut classes = Vec::with_capacity(class_defs_size.min(1 << 18) as usize);
    for i in 0..class_defs_size {
        let mut r = Reader::at(data, class_defs_off as usize + i as usize * 32)?;
        let class_idx = r.u32()?;
        let access_flags = r.u32()?;
        let superclass_idx = r.u32()?;
        let interfaces_off = r.u32()?;
        let source_file_idx = r.u32()?;
        let annotations_off = r.u32()?;
        let class_data_off = r.u32()?;
        let static_values_off = r.u32()?;

        let descriptor =
            p.types.get(class_idx as usize).cloned().ok_or_else(|| {
                DexError::out_of_range(format!("class_def {i} -> type {class_idx}"))
            })?;
        let superclass = if superclass_idx == NO_INDEX {
            None
        } else {
            Some(
                p.types
                    .get(superclass_idx as usize)
                    .cloned()
                    .ok_or_else(|| DexError::out_of_range("class superclass type"))?,
            )
        };
        let interfaces = parse_type_list_opt(data, interfaces_off, &p.types)?;
        let source_file = if source_file_idx == NO_INDEX {
            None
        } else {
            p.strings.get(source_file_idx as usize).cloned()
        };
        let mut data = p.parse_class_data(class_data_off)?;
        // Attach static values in field order.
        if static_values_off != 0 {
            let values = p.parse_encoded_array(static_values_off)?;
            for (field, value) in data.static_fields.iter_mut().zip(values) {
                field.static_value = Some(value);
            }
        }
        // Fields inherit static-ness from the list they were parsed from.
        for f in &data.static_fields {
            debug_assert!(f.is_static);
        }
        classes.push(Class {
            descriptor,
            access_flags,
            superclass,
            interfaces,
            source_file,
            data,
            annotations_off,
        });
    }

    let (method_handles, call_sites) = p.parse_call_sites(map_off)?;

    let sha1 = sha1_hex(data);
    Ok(DexFile {
        version,
        method_handles,
        call_sites,
        strings: p.strings,
        types: p.types,
        protos: p.protos,
        fields: p.fields,
        methods: p.methods,
        classes,
        sha1,
        file_size,
    })
}

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    hex_lower(&h.finalize())
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

fn parse_type_list(data: &[u8], off: u32, types: &[Type]) -> Result<Vec<Type>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    let mut r = Reader::at(data, off as usize)?;
    let size = r.u32()?;
    if size as u64 * 2 > r.remaining() as u64 {
        return Err(DexError::new(
            ErrorKind::Truncated,
            format!("type_list size {size} at {off:#x} exceeds file"),
        ));
    }
    let mut out = Vec::with_capacity(size.min(4096) as usize);
    for _ in 0..size {
        let idx = r.u16()?;
        out.push(
            types
                .get(idx as usize)
                .cloned()
                .ok_or_else(|| DexError::out_of_range(format!("type_list entry {idx}")))?,
        );
    }
    Ok(out)
}

fn parse_type_list_opt(data: &[u8], off: u32, types: &[Type]) -> Result<Vec<Type>> {
    parse_type_list(data, off, types)
}

impl<'a> Parser<'a> {
    fn parse_class_data(&mut self, off: u32) -> Result<ClassData> {
        if off == 0 {
            return Ok(ClassData::default());
        }
        let mut r = Reader::at(self.raw, off as usize)?;
        let static_fields_size = r.uleb128()?;
        let instance_fields_size = r.uleb128()?;
        let direct_methods_size = r.uleb128()?;
        let virtual_methods_size = r.uleb128()?;
        let total = static_fields_size as u64
            + instance_fields_size as u64
            + direct_methods_size as u64
            + virtual_methods_size as u64;
        if total > 1_000_000 {
            return Err(DexError::new(
                ErrorKind::OutOfRange,
                format!("class_data at {off:#x} declares {total} members"),
            ));
        }

        let mut data = ClassData::default();
        let mut idx = 0u32;
        for _ in 0..static_fields_size {
            idx = idx
                .checked_add(r.uleb128()?)
                .ok_or_else(|| DexError::out_of_range("static field idx diff overflow"))?;
            let flags = r.uleb128()?;
            data.static_fields.push(self.make_field(idx, flags, true)?);
        }
        idx = 0;
        for _ in 0..instance_fields_size {
            idx = idx
                .checked_add(r.uleb128()?)
                .ok_or_else(|| DexError::out_of_range("instance field idx diff overflow"))?;
            let flags = r.uleb128()?;
            data.instance_fields
                .push(self.make_field(idx, flags, false)?);
        }
        idx = 0;
        for _ in 0..direct_methods_size {
            idx = idx
                .checked_add(r.uleb128()?)
                .ok_or_else(|| DexError::out_of_range("direct method idx diff overflow"))?;
            let flags = r.uleb128()?;
            let code_off = r.uleb128()?;
            data.direct_methods
                .push(self.make_method(idx, flags, code_off)?);
        }
        idx = 0;
        for _ in 0..virtual_methods_size {
            idx = idx
                .checked_add(r.uleb128()?)
                .ok_or_else(|| DexError::out_of_range("virtual method idx diff overflow"))?;
            let flags = r.uleb128()?;
            let code_off = r.uleb128()?;
            data.virtual_methods
                .push(self.make_method(idx, flags, code_off)?);
        }
        Ok(data)
    }

    fn make_field(&self, idx: u32, flags: u32, is_static: bool) -> Result<Field> {
        let f = self
            .fields
            .get(idx as usize)
            .ok_or_else(|| DexError::out_of_range(format!("field index {idx}")))?;
        Ok(Field {
            index: idx,
            class: f.class.clone(),
            name: f.name.clone(),
            ty: f.ty.clone(),
            access_flags: flags,
            static_value: None,
            is_static,
        })
    }

    fn make_method(&self, idx: u32, flags: u32, code_off: u32) -> Result<Method> {
        let m = self
            .methods
            .get(idx as usize)
            .ok_or_else(|| DexError::out_of_range(format!("method index {idx}")))?;
        let is_native = flags & 0x0100 != 0;
        let is_abstract = flags & 0x0400 != 0;
        let code = if code_off == 0 || is_native || is_abstract {
            None
        } else {
            Some(self.parse_code(code_off)?)
        };
        Ok(Method {
            index: idx,
            class: m.class.clone(),
            name: m.name.clone(),
            proto: m.proto.clone(),
            access_flags: flags,
            code,
            is_static: flags & 0x0008 != 0,
            is_native,
            is_abstract,
        })
    }

    fn parse_code(&self, off: u32) -> Result<Code> {
        let mut r = Reader::at(self.raw, off as usize)?;
        let registers_size = r.u16()?;
        let ins_size = r.u16()?;
        let outs_size = r.u16()?;
        let tries_size = r.u16()?;
        let debug_info_off = r.u32()?;
        let insns_size = r.u32()?;
        if insns_size as u64 * 2 > r.remaining() as u64 {
            return Err(DexError::new(
                ErrorKind::Truncated,
                format!("code_item at {off:#x} declares {insns_size} insns beyond file"),
            ));
        }
        let mut units = Vec::with_capacity(insns_size.min(1 << 20) as usize);
        for _ in 0..insns_size {
            units.push(r.u16()?);
        }
        let instructions = insn::decode(&units);
        let mut pc_index = HashMap::with_capacity(instructions.len());
        for (i, ins) in instructions.iter().enumerate() {
            pc_index.insert(ins.pc, i);
        }

        let mut tries = Vec::new();
        if tries_size > 0 {
            if insns_size % 2 == 1 {
                let _padding = r.u16()?;
            }
            let mut raw_tries = Vec::with_capacity(tries_size as usize);
            for _ in 0..tries_size {
                let start_pc = r.u32()?;
                let insn_count = r.u16()?;
                let handler_off = r.u16()?;
                raw_tries.push((start_pc, insn_count, handler_off));
            }
            let handlers_base = r.pos();
            for (start_pc, insn_count, handler_off) in raw_tries {
                let mut hr = Reader::at(
                    self.raw,
                    handlers_base
                        .checked_add(handler_off as usize)
                        .ok_or_else(|| DexError::out_of_range("try handler offset"))?,
                )?;
                let size = hr.sleb128()?;
                let mut handlers = Vec::new();
                if size <= 0 {
                    // catch-all only
                    let addr = hr.uleb128()?;
                    handlers.push((None, addr));
                } else {
                    for _ in 0..size {
                        let type_idx = hr.uleb128()?;
                        let addr = hr.uleb128()?;
                        let ty = self
                            .types
                            .get(type_idx as usize)
                            .cloned()
                            .ok_or_else(|| DexError::out_of_range("catch type index"))?;
                        handlers.push((Some(ty), addr));
                    }
                    let catch_all = hr.uleb128()?;
                    if catch_all != 0 {
                        handlers.push((None, catch_all));
                    }
                }
                tries.push(TryBlock {
                    start_pc,
                    insn_count: insn_count as u32,
                    handlers,
                });
            }
        }

        let line_table = if debug_info_off != 0 {
            parse_debug_lines(self.raw, debug_info_off).unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(Code {
            registers_size,
            ins_size,
            outs_size,
            insns_size,
            units,
            instructions,
            tries,
            line_table,
            pc_index,
        })
    }

    /// Parse `method_handles` and `call_site_ids` via the map list.
    fn parse_call_sites(&self, map_off: u32) -> Result<(Vec<MethodHandleItem>, Vec<CallSite>)> {
        if map_off == 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut r = Reader::at(self.raw, map_off as usize)?;
        let count = r.u32()?;
        let mut handles_off = None;
        let mut handles_size = 0u32;
        let mut sites_off = None;
        let mut sites_size = 0u32;
        for _ in 0..count.min(64) {
            let ty = r.u16()?;
            let _unused = r.u16()?;
            let size = r.u32()?;
            let off = r.u32()?;
            match ty {
                0x0008 => {
                    handles_off = Some(off);
                    handles_size = size;
                }
                0x0007 => {
                    sites_off = Some(off);
                    sites_size = size;
                }
                _ => {}
            }
        }
        let mut handles = Vec::new();
        if let Some(off) = handles_off {
            // method_handle_item: kind u16, unused u16, member u16, unused u16
            for i in 0..handles_size.min(1 << 20) {
                let mut hr = Reader::at(self.raw, off as usize + i as usize * 8)?;
                let kind = hr.u16()?;
                let _ = hr.u16()?;
                let member = hr.u16()?;
                handles.push(MethodHandleItem { kind, member });
            }
        }
        let mut sites = Vec::new();
        if let Some(off) = sites_off {
            for i in 0..sites_size.min(1 << 20) {
                let data_off = Reader::at(self.raw, off as usize + i as usize * 4)?.u32()?;
                let values = self.parse_encoded_array(data_off).unwrap_or_default();
                let mut it = values.into_iter();
                let bootstrap = match it.next() {
                    Some(EncodedValue::MethodHandle(idx)) => handles.get(idx as usize).cloned(),
                    _ => None,
                };
                sites.push(CallSite {
                    bootstrap,
                    args: it.collect(),
                });
            }
        }
        Ok((handles, sites))
    }

    fn parse_encoded_array(&self, off: u32) -> Result<Vec<EncodedValue>> {
        let mut r = Reader::at(self.raw, off as usize)?;
        let size = r.uleb128()?;
        if size > 100_000 {
            return Err(DexError::new(
                ErrorKind::OutOfRange,
                "encoded array too large",
            ));
        }
        let mut out = Vec::with_capacity(size as usize);
        for _ in 0..size {
            out.push(self.parse_encoded_value(&mut r)?);
        }
        Ok(out)
    }

    fn parse_encoded_value(&self, r: &mut Reader<'a>) -> Result<EncodedValue> {
        let b = r.u8()?;
        let value_type = b & 0x1f;
        let value_arg = b >> 5;
        if value_arg > 7 && value_type != 0x1c && value_type != 0x1d {
            return Err(DexError::new(
                ErrorKind::OutOfRange,
                "encoded_value arg > 7",
            ));
        }
        let n = value_arg as usize + 1;
        match value_type {
            0x00 => Ok(EncodedValue::Byte(read_signed(r, n)? as i8)),
            0x02 => Ok(EncodedValue::Short(read_signed(r, n)? as i16)),
            0x03 => Ok(EncodedValue::Char(read_unsigned(r, n)? as u16)),
            0x04 => Ok(EncodedValue::Int(read_signed(r, n)? as i32)),
            0x06 => Ok(EncodedValue::Long(read_signed(r, n)?)),
            0x10 => Ok(EncodedValue::Float(f32::from_bits(
                read_unsigned(r, n)? as u32
            ))),
            0x11 => Ok(EncodedValue::Double(f64::from_bits(
                read_unsigned(r, n)?.rotate_left(0) as u64,
            ))),
            0x15 => Ok(EncodedValue::MethodType(
                self.protos
                    .get(read_unsigned(r, n)? as usize)
                    .cloned()
                    .ok_or_else(|| DexError::out_of_range("method type index"))?,
            )),
            0x16 => Ok(EncodedValue::MethodHandle(read_unsigned(r, n)? as u32)),
            0x17 => {
                let idx = read_unsigned(r, n)? as u32;
                Ok(EncodedValue::String(
                    self.strings
                        .get(idx as usize)
                        .cloned()
                        .ok_or_else(|| DexError::out_of_range("encoded string index"))?,
                ))
            }
            0x18 => {
                let idx = read_unsigned(r, n)? as u32;
                Ok(EncodedValue::Type(
                    self.types
                        .get(idx as usize)
                        .cloned()
                        .ok_or_else(|| DexError::out_of_range("encoded type index"))?,
                ))
            }
            0x19 | 0x1b => {
                let idx = read_unsigned(r, n)? as u32;
                let f = self
                    .fields
                    .get(idx as usize)
                    .cloned()
                    .ok_or_else(|| DexError::out_of_range("encoded field index"))?;
                Ok(if value_type == 0x19 {
                    EncodedValue::Field(f)
                } else {
                    EncodedValue::Enum(f)
                })
            }
            0x1a => {
                let idx = read_unsigned(r, n)? as u32;
                Ok(EncodedValue::Method(
                    self.methods
                        .get(idx as usize)
                        .cloned()
                        .ok_or_else(|| DexError::out_of_range("encoded method index"))?,
                ))
            }
            0x1c => {
                // array: value_arg is unused (must be 0), size follows as uleb128
                let size = r.uleb128()?;
                if size > 100_000 {
                    return Err(DexError::new(
                        ErrorKind::OutOfRange,
                        "encoded array too large",
                    ));
                }
                let mut items = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    items.push(self.parse_encoded_value(r)?);
                }
                Ok(EncodedValue::Array(items))
            }
            0x1d => {
                let type_idx = r.uleb128()?;
                let ty = self
                    .types
                    .get(type_idx as usize)
                    .cloned()
                    .ok_or_else(|| DexError::out_of_range("annotation type index"))?;
                let size = r.uleb128()?;
                let mut elements = Vec::with_capacity(size.min(4096) as usize);
                for _ in 0..size {
                    let name_idx = r.uleb128()?;
                    let name = self
                        .strings
                        .get(name_idx as usize)
                        .cloned()
                        .ok_or_else(|| DexError::out_of_range("annotation name index"))?;
                    elements.push((name, self.parse_encoded_value(r)?));
                }
                Ok(EncodedValue::Annotation { ty, elements })
            }
            0x1e => Ok(EncodedValue::Null),
            0x1f => {
                if value_arg > 1 {
                    return Err(DexError::new(
                        ErrorKind::OutOfRange,
                        "bad boolean value_arg",
                    ));
                }
                Ok(EncodedValue::Boolean(value_arg == 1))
            }
            other => Err(DexError::new(
                ErrorKind::Unsupported,
                format!("encoded_value type {other:#x}"),
            )),
        }
    }
}

fn read_unsigned(r: &mut Reader<'_>, n: usize) -> Result<u64> {
    let bytes = r.bytes(n)?;
    let mut v = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    Ok(v)
}

fn read_signed(r: &mut Reader<'_>, n: usize) -> Result<i64> {
    let v = read_unsigned(r, n)?;
    let shift = 64 - 8 * n;
    Ok(((v << shift) as i64) >> shift)
}

/// Parse a debug_info_item into an ordered (pc, line) table.
fn parse_debug_lines(data: &[u8], off: u32) -> Result<Vec<(u32, u32)>> {
    let mut r = Reader::at(data, off as usize)?;
    let line_start = r.uleb128()? as i64;
    let params_size = r.uleb128()?;
    for _ in 0..params_size.min(4096) {
        let _ = r.uleb128()?;
    }
    let mut addr = 0u32;
    let mut line = line_start;
    let mut table: Vec<(u32, u32)> = Vec::new();
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 1_000_000 || r.eof() {
            break;
        }
        let op = r.u8()?;
        match op {
            0x00 => break,
            0x01 => addr = addr.wrapping_add(r.uleb128()?),
            0x02 => line = line.wrapping_add(r.sleb128()? as i64),
            0x03 => {
                let _reg = r.uleb128()?;
                let _name = r.uleb128()?;
                let _ty = r.uleb128()?;
            }
            0x04 => {
                let _reg = r.uleb128()?;
                let _name = r.uleb128()?;
                let _ty = r.uleb128()?;
                let _sig = r.uleb128()?;
            }
            0x05 | 0x06 => {
                let _reg = r.uleb128()?;
            }
            0x07 | 0x08 => {}
            0x09 => {
                let _ = r.uleb128()?;
            }
            special => {
                let adjusted = (special - 0x0a) as u32;
                addr = addr.wrapping_add(adjusted / 15);
                line = line.wrapping_add((adjusted % 15) as i64 - 4).max(0);
                if line >= 0 {
                    let l = line as u32;
                    if table.last().map(|&(_, prev)| prev) != Some(l) {
                        table.push((addr, l));
                    }
                }
            }
        }
    }
    table.sort_by_key(|&(pc, _)| pc);
    Ok(table)
}
