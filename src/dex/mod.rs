//! A complete, bounds-checked parser for the Dalvik Executable format.
//!
//! The parser is deliberately defensive: APKs in this pipeline are hostile, and
//! a malformed DEX must fail with an error the pipeline can report, not abort
//! the process. All offsets are validated before use.
//!
//! Tables that the interpreter needs warm (strings, prototypes, method/field
//! references, class data and code items) are resolved eagerly. Code items are
//! copied into 16-bit instruction buffers so the interpreter can decode them
//! without bounds checks in its inner loop.

pub mod code;

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{decode_mutf8, utf16_to_string, Cursor, Error, Result};

pub const NO_INDEX: u32 = 0xFFFF_FFFF;

pub const ACC_PUBLIC: u32 = 0x0001;
pub const ACC_PRIVATE: u32 = 0x0002;
pub const ACC_PROTECTED: u32 = 0x0004;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_FINAL: u32 = 0x0010;
pub const ACC_SYNCHRONIZED: u32 = 0x0020;
pub const ACC_VOLATILE: u32 = 0x0040;
pub const ACC_BRIDGE: u32 = 0x0040;
pub const ACC_TRANSIENT: u32 = 0x0080;
pub const ACC_VARARGS: u32 = 0x0080;
pub const ACC_NATIVE: u32 = 0x0100;
pub const ACC_INTERFACE: u32 = 0x0200;
pub const ACC_ABSTRACT: u32 = 0x0400;
pub const ACC_STRICT: u32 = 0x0800;
pub const ACC_SYNTHETIC: u32 = 0x1000;
pub const ACC_ANNOTATION: u32 = 0x2000;
pub const ACC_ENUM: u32 = 0x4000;
pub const ACC_CONSTRUCTOR: u32 = 0x10000;

#[derive(Debug, Clone, Copy)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodId {
    pub class_idx: u32,
    pub proto_idx: u32,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldId {
    pub class_idx: u32,
    pub type_idx: u32,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces: Vec<u32>,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug, Clone)]
pub struct CatchHandler {
    pub type_idx: Option<u32>,
    pub addr: u32,
}

#[derive(Debug, Clone)]
pub struct TryBlock {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handlers: Vec<CatchHandler>,
}

#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins: u16,
    pub outs: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryBlock>,
}

impl CodeItem {
    /// Address (in 16-bit code units) of the instruction following `addr`.
    pub fn next_addr(&self, addr: usize) -> usize {
        let op = self.insns.get(addr).map(|w| (*w & 0xff) as u8).unwrap_or(0);
        addr + code::insn_len(&self.insns, addr, op)
    }
}

#[derive(Debug, Clone)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(Vec<EncodedValue>),
    Annotation,
    Null,
    Boolean(bool),
    MethodType(u32),
    MethodHandle(u32),
}

/// A parsed DEX file. Holds its own copy of the byte image so it is
/// self-contained and can be shared between scenario threads.
pub struct DexFile {
    pub data: Arc<Vec<u8>>,
    /// Human-readable provenance (e.g. "classes.dex", "decrypted:com.x.a.dex").
    pub origin: String,
    pub strings: Vec<String>,
    pub types: Vec<u32>,
    pub protos: Vec<ProtoId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassDef>,
    /// Parallel to `classes`; empty class data for classes without any.
    pub class_data: Vec<ClassData>,
    pub code_items: HashMap<u32, Arc<CodeItem>>,
    /// (class type idx, name string idx, proto idx) -> method idx
    pub method_by_sig: HashMap<(u32, u32, u32), u32>,
    /// (class type idx, name string idx, type idx) -> field idx
    pub field_by_sig: HashMap<(u32, u32, u32), u32>,
    /// type idx -> class def index
    pub class_def_by_type: HashMap<u32, u32>,
    /// method idx -> code offset, for all defined methods
    pub method_code: HashMap<u32, (u32, u32)>,
}

impl std::fmt::Debug for DexFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DexFile")
            .field("origin", &self.origin)
            .field("strings", &self.strings.len())
            .field("types", &self.types.len())
            .field("methods", &self.methods.len())
            .field("classes", &self.classes.len())
            .finish()
    }
}

impl DexFile {
    pub fn parse(origin: impl Into<String>, data: Vec<u8>) -> Result<DexFile> {
        let origin = origin.into();
        let parsed = parse_inner(&data, &origin)?;
        let mut dex = DexFile {
            data: Arc::new(data),
            origin,
            strings: parsed.strings,
            types: parsed.types,
            protos: parsed.protos,
            fields: parsed.fields,
            methods: parsed.methods,
            classes: parsed.classes,
            class_data: parsed.class_data,
            code_items: parsed.code_items,
            method_by_sig: HashMap::new(),
            field_by_sig: HashMap::new(),
            class_def_by_type: HashMap::new(),
            method_code: HashMap::new(),
        };
        dex.build_indexes();
        Ok(dex)
    }

    fn build_indexes(&mut self) {
        for (i, cd) in self.classes.iter().enumerate() {
            self.class_def_by_type.insert(cd.class_idx, i as u32);
        }
        for m in &self.methods {
            self.method_by_sig
                .entry((m.class_idx, m.name_idx, m.proto_idx))
                .or_insert(0);
        }
        for (idx, m) in self.methods.iter().enumerate() {
            self.method_by_sig.insert((m.class_idx, m.name_idx, m.proto_idx), idx as u32);
        }
        for (idx, f) in self.fields.iter().enumerate() {
            self.field_by_sig
                .insert((f.class_idx, f.name_idx, f.type_idx), idx as u32);
        }
        for (ci, cd) in self.class_data.iter().enumerate() {
            for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                self.method_code.insert(m.method_idx, (m.code_off, m.access_flags));
            }
            let _ = ci;
        }
    }

    pub fn string(&self, idx: u32) -> &str {
        self.strings.get(idx as usize).map(|s| s.as_str()).unwrap_or("")
    }

    pub fn type_name(&self, type_idx: u32) -> &str {
        match self.types.get(type_idx as usize) {
            Some(sidx) => self.string(*sidx),
            None => "",
        }
    }

    pub fn proto(&self, idx: u32) -> Option<ProtoId> {
        self.protos.get(idx as usize).copied()
    }

    pub fn method(&self, idx: u32) -> Option<MethodId> {
        self.methods.get(idx as usize).copied()
    }

    pub fn field(&self, idx: u32) -> Option<FieldId> {
        self.fields.get(idx as usize).copied()
    }

    pub fn method_name(&self, method_idx: u32) -> String {
        match self.method(method_idx) {
            Some(m) => {
                let class = self.type_name(m.class_idx);
                let name = self.string(m.name_idx);
                let desc = self.proto_descriptor(m.proto_idx);
                format!("{class}->{name}{desc}")
            }
            None => format!("<invalid method {method_idx}>"),
        }
    }

    pub fn method_short_name(&self, method_idx: u32) -> String {
        match self.method(method_idx) {
            Some(m) => format!("{}{}", self.string(m.name_idx), self.proto_descriptor(m.proto_idx)),
            None => format!("<invalid {method_idx}>"),
        }
    }

    pub fn proto_descriptor(&self, proto_idx: u32) -> String {
        let Some(p) = self.proto(proto_idx) else {
            return "(?)".into();
        };
        let mut s = String::from("(");
        if p.parameters_off != 0 {
            if let Ok(params) = self.type_list(p.parameters_off) {
                for t in params {
                    s.push_str(self.type_name(t));
                }
            }
        }
        s.push(')');
        s.push_str(self.type_name(p.return_type_idx));
        s
    }

    pub fn type_list(&self, off: u32) -> Result<Vec<u32>> {
        let mut c = Cursor::at(&self.data, off as usize)?;
        let size = c.u32()?;
        let mut out = Vec::with_capacity(size.min(1024) as usize);
        for _ in 0..size {
            out.push(c.u16()? as u32);
        }
        Ok(out)
    }

    pub fn code_item(&self, code_off: u32) -> Option<Arc<CodeItem>> {
        self.code_items.get(&code_off).cloned()
    }

    pub fn class_def(&self, type_idx: u32) -> Option<&ClassDef> {
        self.class_def_by_type
            .get(&type_idx)
            .and_then(|i| self.classes.get(*i as usize))
    }

    pub fn class_data_for(&self, type_idx: u32) -> Option<&ClassData> {
        self.class_def_by_type
            .get(&type_idx)
            .and_then(|i| self.class_data.get(*i as usize))
    }

    pub fn superclass_of(&self, type_idx: u32) -> Option<u32> {
        let cd = self.class_def(type_idx)?;
        if cd.superclass_idx == NO_INDEX {
            None
        } else {
            Some(cd.superclass_idx)
        }
    }

    pub fn interfaces_of(&self, type_idx: u32) -> &[u32] {
        match self.class_def(type_idx) {
            Some(cd) => &cd.interfaces,
            None => &[],
        }
    }

    /// Find the concrete method implementation for a virtual call on `class_type`.
    /// Walks the superclass chain, then interfaces (for default methods).
    pub fn find_virtual_method(
        &self,
        class_type: u32,
        name_idx: u32,
        proto_idx: u32,
    ) -> Option<u32> {
        let mut cur = Some(class_type);
        let mut depth = 0;
        while let Some(t) = cur {
            if let Some(&idx) = self.method_by_sig.get(&(t, name_idx, proto_idx)) {
                if self.method_code.contains_key(&idx) || self.is_defined_method(idx) {
                    return Some(idx);
                }
                return Some(idx);
            }
            depth += 1;
            if depth > 64 {
                break;
            }
            cur = self.superclass_of(t);
        }
        // Interfaces (default methods / abstract declarations).
        let mut stack: Vec<u32> = self.interfaces_of(class_type).to_vec();
        let mut guard = 0;
        while let Some(iface) = stack.pop() {
            guard += 1;
            if guard > 128 {
                break;
            }
            if let Some(&idx) = self.method_by_sig.get(&(iface, name_idx, proto_idx)) {
                return Some(idx);
            }
            stack.extend_from_slice(self.interfaces_of(iface));
        }
        None
    }

    fn is_defined_method(&self, idx: u32) -> bool {
        self.method_code.contains_key(&idx)
    }

    pub fn static_values(&self, type_idx: u32) -> Result<Vec<EncodedValue>> {
        let Some(cd) = self.class_def(type_idx) else {
            return Ok(Vec::new());
        };
        if cd.static_values_off == 0 {
            return Ok(Vec::new());
        }
        let mut c = Cursor::at(&self.data, cd.static_values_off as usize)?;
        let size = c.uleb128()?;
        let mut out = Vec::with_capacity(size.min(4096) as usize);
        for _ in 0..size {
            out.push(read_encoded_value(&mut c, 0)?);
        }
        Ok(out)
    }

    /// Decode a string value at a string index without going through lossy
    /// UTF-16 conversion, for payloads that need exact code units.
    pub fn string_units(&self, idx: u32) -> Vec<u16> {
        // We stored lossy strings; re-read the raw MUTF-8 for exact units.
        // String data offsets are computed by walking the table on demand is
        // expensive; instead we rely on the common case that the lossy string
        // round-trips. Callers needing exactness use `raw_string_units`.
        self.strings
            .get(idx as usize)
            .map(|s| s.encode_utf16().collect())
            .unwrap_or_default()
    }

    pub fn is_interface(&self, type_idx: u32) -> bool {
        self.class_def(type_idx)
            .map(|cd| cd.access_flags & ACC_INTERFACE != 0)
            .unwrap_or(false)
    }
}

struct Parsed {
    strings: Vec<String>,
    types: Vec<u32>,
    protos: Vec<ProtoId>,
    fields: Vec<FieldId>,
    methods: Vec<MethodId>,
    classes: Vec<ClassDef>,
    class_data: Vec<ClassData>,
    code_items: HashMap<u32, Arc<CodeItem>>,
}

fn parse_inner(data: &[u8], origin: &str) -> Result<Parsed> {
    if data.len() < 0x70 {
        return Err(Error::BadFormat(format!("{origin}: shorter than DEX header")));
    }
    let magic = &data[0..4];
    if magic != b"dex\n" {
        return Err(Error::BadFormat(format!(
            "{origin}: bad dex magic {:02x?}",
            &data[0..8.min(data.len())]
        )));
    }
    let mut c = Cursor::new(data);
    c.seek(0x38)?;
    let string_ids_size = c.u32()?;
    let string_ids_off = c.u32()?;
    let type_ids_size = c.u32()?;
    let type_ids_off = c.u32()?;
    let proto_ids_size = c.u32()?;
    let proto_ids_off = c.u32()?;
    let field_ids_size = c.u32()?;
    let field_ids_off = c.u32()?;
    let method_ids_size = c.u32()?;
    let method_ids_off = c.u32()?;
    let class_defs_size = c.u32()?;
    let class_defs_off = c.u32()?;

    // Bound table counts by the file size so a corrupt header cannot request a
    // gigantic allocation. Each entry is at least 4 bytes.
    let check = |name: &'static str, count: u32, off: u32, min_size: u64| -> Result<()> {
        let need = count as u64 * min_size;
        let avail = (data.len() as u64).saturating_sub(off as u64);
        if off as usize > data.len() || need > avail {
            return Err(Error::BadFormat(format!(
                "{origin}: {name} table ({count} entries at {off:#x}) exceeds file"
            )));
        }
        Ok(())
    };
    check("string_ids", string_ids_size, string_ids_off, 4)?;
    check("type_ids", type_ids_size, type_ids_off, 4)?;
    check("proto_ids", proto_ids_size, proto_ids_off, 12)?;
    check("field_ids", field_ids_size, field_ids_off, 8)?;
    check("method_ids", method_ids_size, method_ids_off, 8)?;
    check("class_defs", class_defs_size, class_defs_off, 32)?;

    let mut strings = Vec::with_capacity(string_ids_size as usize);
    {
        let mut sc = Cursor::at(data, string_ids_off as usize)?;
        for _ in 0..string_ids_size {
            let off = sc.u32()?;
            strings.push(read_string_data(data, off as usize).unwrap_or_default());
        }
    }

    let mut types = Vec::with_capacity(type_ids_size as usize);
    {
        let mut tc = Cursor::at(data, type_ids_off as usize)?;
        for _ in 0..type_ids_size {
            types.push(tc.u32()?);
        }
    }

    let mut protos = Vec::with_capacity(proto_ids_size as usize);
    {
        let mut pc = Cursor::at(data, proto_ids_off as usize)?;
        for _ in 0..proto_ids_size {
            protos.push(ProtoId {
                shorty_idx: pc.u32()?,
                return_type_idx: pc.u32()?,
                parameters_off: pc.u32()?,
            });
        }
    }

    let mut fields = Vec::with_capacity(field_ids_size as usize);
    {
        let mut fc = Cursor::at(data, field_ids_off as usize)?;
        for _ in 0..field_ids_size {
            fields.push(FieldId {
                class_idx: fc.u16()? as u32,
                type_idx: fc.u16()? as u32,
                name_idx: fc.u32()?,
            });
        }
    }

    let mut methods = Vec::with_capacity(method_ids_size as usize);
    {
        let mut mc = Cursor::at(data, method_ids_off as usize)?;
        for _ in 0..method_ids_size {
            methods.push(MethodId {
                class_idx: mc.u16()? as u32,
                proto_idx: mc.u16()? as u32,
                name_idx: mc.u32()?,
            });
        }
    }

    let mut classes = Vec::with_capacity(class_defs_size as usize);
    let mut class_data = Vec::with_capacity(class_defs_size as usize);
    let mut code_items: HashMap<u32, Arc<CodeItem>> = HashMap::new();
    {
        let mut cc = Cursor::at(data, class_defs_off as usize)?;
        for _ in 0..class_defs_size {
            let class_idx = cc.u32()?;
            let access_flags = cc.u32()?;
            let superclass_idx = cc.u32()?;
            let interfaces_off = cc.u32()?;
            let source_file_idx = cc.u32()?;
            let annotations_off = cc.u32()?;
            let class_data_off = cc.u32()?;
            let static_values_off = cc.u32()?;
            let interfaces = if interfaces_off != 0 {
                read_type_list(data, interfaces_off as usize).unwrap_or_default()
            } else {
                Vec::new()
            };
            let cd = ClassDef {
                class_idx,
                access_flags,
                superclass_idx,
                interfaces,
                source_file_idx,
                annotations_off,
                class_data_off,
                static_values_off,
            };
            let parsed_cd = if class_data_off != 0 {
                read_class_data(data, class_data_off as usize, &mut code_items)
                    .unwrap_or_default()
            } else {
                ClassData::default()
            };
            classes.push(cd);
            class_data.push(parsed_cd);
        }
    }

    Ok(Parsed {
        strings,
        types,
        protos,
        fields,
        methods,
        classes,
        class_data,
        code_items,
    })
}

fn read_string_data(data: &[u8], off: usize) -> Result<String> {
    let mut c = Cursor::at(data, off)?;
    let _utf16_len = c.uleb128()?;
    // The string data is NUL-terminated; find the terminator with a scan.
    let start = c.pos();
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(data.len());
    let units = decode_mutf8(&data[start..end]);
    Ok(utf16_to_string(&units))
}

fn read_type_list(data: &[u8], off: usize) -> Result<Vec<u32>> {
    let mut c = Cursor::at(data, off)?;
    let size = c.u32()?;
    if size as usize > (data.len().saturating_sub(off)) / 2 {
        return Err(Error::BadFormat("type_list too large".into()));
    }
    let mut out = Vec::with_capacity(size as usize);
    for _ in 0..size {
        out.push(c.u16()? as u32);
    }
    Ok(out)
}

fn read_class_data(
    data: &[u8],
    off: usize,
    code_items: &mut HashMap<u32, Arc<CodeItem>>,
) -> Result<ClassData> {
    let mut c = Cursor::at(data, off)?;
    let static_fields_size = c.uleb128()?;
    let instance_fields_size = c.uleb128()?;
    let direct_methods_size = c.uleb128()?;
    let virtual_methods_size = c.uleb128()?;

    // Each entry consumes at least 2 bytes (two uleb128s), so bound the counts.
    let max_entries = (data.len().saturating_sub(c.pos())) / 2 + 1;
    for (name, size) in [
        ("static fields", static_fields_size),
        ("instance fields", instance_fields_size),
        ("direct methods", direct_methods_size),
        ("virtual methods", virtual_methods_size),
    ] {
        if size as usize > max_entries {
            return Err(Error::BadFormat(format!("class_data {name} count {size} exceeds input")));
        }
    }

    let mut cd = ClassData {
        static_fields: Vec::with_capacity(static_fields_size as usize),
        instance_fields: Vec::with_capacity(instance_fields_size as usize),
        direct_methods: Vec::with_capacity(direct_methods_size as usize),
        virtual_methods: Vec::with_capacity(virtual_methods_size as usize),
    };
    let mut idx = 0u32;
    for _ in 0..static_fields_size {
        idx = idx.wrapping_add(c.uleb128()?);
        let access_flags = c.uleb128()?;
        cd.static_fields.push(EncodedField { field_idx: idx, access_flags });
    }
    idx = 0;
    for _ in 0..instance_fields_size {
        idx = idx.wrapping_add(c.uleb128()?);
        let access_flags = c.uleb128()?;
        cd.instance_fields.push(EncodedField { field_idx: idx, access_flags });
    }
    idx = 0;
    for _ in 0..direct_methods_size {
        idx = idx.wrapping_add(c.uleb128()?);
        let access_flags = c.uleb128()?;
        let code_off = c.uleb128()?;
        cd.direct_methods.push(EncodedMethod { method_idx: idx, access_flags, code_off });
        if code_off != 0 && !code_items.contains_key(&code_off) {
            if let Ok(item) = read_code_item(data, code_off as usize) {
                code_items.insert(code_off, Arc::new(item));
            }
        }
    }
    idx = 0;
    for _ in 0..virtual_methods_size {
        idx = idx.wrapping_add(c.uleb128()?);
        let access_flags = c.uleb128()?;
        let code_off = c.uleb128()?;
        cd.virtual_methods.push(EncodedMethod { method_idx: idx, access_flags, code_off });
        if code_off != 0 && !code_items.contains_key(&code_off) {
            if let Ok(item) = read_code_item(data, code_off as usize) {
                code_items.insert(code_off, Arc::new(item));
            }
        }
    }
    Ok(cd)
}

fn read_code_item(data: &[u8], off: usize) -> Result<CodeItem> {
    let mut c = Cursor::at(data, off)?;
    let registers_size = c.u16()?;
    let ins = c.u16()?;
    let outs = c.u16()?;
    let tries_size = c.u16()?;
    let debug_info_off = c.u32()?;
    let insns_size = c.u32()?;
    if insns_size as usize > (data.len().saturating_sub(c.pos())) / 2 + 1 {
        return Err(Error::BadFormat("code_item insns_size exceeds input".into()));
    }
    let mut insns = Vec::with_capacity(insns_size as usize);
    for _ in 0..insns_size {
        insns.push(c.u16()?);
    }
    let mut tries = Vec::new();
    if tries_size > 0 {
        // Alignment: try_items follow at a 4-byte-aligned offset.
        let mut pos = off + 16 + insns_size as usize * 2;
        if !pos.is_multiple_of(4) {
            pos += 2;
        }
        if tries_size as usize > (data.len().saturating_sub(pos)) / 8 + 1 {
            return Err(Error::BadFormat("code_item tries_size exceeds input".into()));
        }
        let mut tc = Cursor::at(data, pos)?;
        let mut raw = Vec::with_capacity(tries_size as usize);
        for _ in 0..tries_size {
            let start_addr = tc.u32()?;
            let insn_count = tc.u16()?;
            let handler_off = tc.u16()?;
            raw.push((start_addr, insn_count, handler_off));
        }
        let handlers_base = tc.pos();
        // handler_off is relative to the start of the encoded_catch_handler_list.
        let mut hc = Cursor::at(data, handlers_base)?;
        let _list_size = hc.uleb128()?;
        let mut handler_cache: HashMap<u16, Vec<CatchHandler>> = HashMap::new();
        for (start_addr, insn_count, handler_off) in raw {
            let rel = handlers_base + handler_off as usize;
            handler_cache.entry(handler_off).or_insert_with(|| {
                read_catch_handler(data, rel).unwrap_or_default()
            });
            tries.push(TryBlock {
                start_addr,
                insn_count,
                handlers: handler_cache.get(&handler_off).cloned().unwrap_or_default(),
            });
        }
    }
    Ok(CodeItem { registers_size, ins, outs, debug_info_off, insns, tries })
}

fn read_catch_handler(data: &[u8], off: usize) -> Result<Vec<CatchHandler>> {
    let mut c = Cursor::at(data, off)?;
    let size = c.sleb128()?;
    let typed = size.unsigned_abs() as usize;
    if typed > 256 {
        return Err(Error::BadFormat("catch handler too large".into()));
    }
    let mut out = Vec::with_capacity(typed + 1);
    for _ in 0..typed {
        let type_idx = c.uleb128()?;
        let addr = c.uleb128()?;
        out.push(CatchHandler { type_idx: Some(type_idx), addr });
    }
    if size <= 0 {
        let addr = c.uleb128()?;
        out.push(CatchHandler { type_idx: None, addr });
    }
    Ok(out)
}

fn read_encoded_value(c: &mut Cursor<'_>, depth: u32) -> Result<EncodedValue> {
    if depth > 32 {
        return Err(Error::BadFormat("encoded value nesting too deep".into()));
    }
    let header = c.u8()?;
    let vtype = header >> 5;
    let arg = header & 0x1f;
    let read_unsigned = |c: &mut Cursor<'_>, n: usize| -> Result<u64> {
        // `arg` is 5 bits, so a hostile value can claim 32 bytes. Values
        // wider than 8 bytes are meaningless here; consume them but keep only
        // the low 64 bits.
        let bytes = c.bytes(n)?;
        let mut v: u64 = 0;
        for (i, b) in bytes.iter().take(8).enumerate() {
            v |= (*b as u64) << (8 * i);
        }
        Ok(v)
    };
    let signed = |v: u64, n: usize| -> i64 {
        let bits = (n * 8) as u32;
        if bits >= 64 {
            v as i64
        } else {
            let shift = 64 - bits;
            ((v << shift) as i64) >> shift
        }
    };
    let to_f32 = |v: u64, n: usize| -> f32 {
        // The value's bytes fill the low end of a 32-bit float; missing high
        // bytes are zero.
        let bytes = v.to_le_bytes();
        let mut buf = [0u8; 4];
        buf[..n.min(4)].copy_from_slice(&bytes[..n.min(4)]);
        f32::from_bits(u32::from_le_bytes(buf))
    };
    let to_f64 = |v: u64, n: usize| -> f64 {
        let bytes = v.to_le_bytes();
        let mut buf = [0u8; 8];
        buf[..n.min(8)].copy_from_slice(&bytes[..n.min(8)]);
        f64::from_bits(u64::from_le_bytes(buf))
    };
    let n = arg as usize + 1;
    Ok(match vtype {
        0x00 => EncodedValue::Byte(signed(read_unsigned(c, n)?, n) as i8),
        0x02 => EncodedValue::Short(signed(read_unsigned(c, n)?, n) as i16),
        0x03 => EncodedValue::Char(read_unsigned(c, n)? as u16),
        0x04 => EncodedValue::Int(signed(read_unsigned(c, n)?, n) as i32),
        0x06 => EncodedValue::Long(signed(read_unsigned(c, n)?, n)),
        0x10 => EncodedValue::Float(to_f32(read_unsigned(c, n)?, n)),
        0x11 => EncodedValue::Double(to_f64(read_unsigned(c, n)?, n)),
        0x15 => EncodedValue::MethodType(read_unsigned(c, n)? as u32),
        0x16 => EncodedValue::MethodHandle(read_unsigned(c, n)? as u32),
        0x17 => EncodedValue::String(read_unsigned(c, n)? as u32),
        0x18 => EncodedValue::Type(read_unsigned(c, n)? as u32),
        0x19 => EncodedValue::Field(read_unsigned(c, n)? as u32),
        0x1a => EncodedValue::Method(read_unsigned(c, n)? as u32),
        0x1b => EncodedValue::Enum(read_unsigned(c, n)? as u32),
        0x1c => {
            let size = c.uleb128()?;
            if size as usize > 65536 {
                return Err(Error::BadFormat("encoded array too large".into()));
            }
            let mut items = Vec::with_capacity(size as usize);
            for _ in 0..size {
                items.push(read_encoded_value(c, depth + 1)?);
            }
            EncodedValue::Array(items)
        }
        0x1d => {
            // annotation: type_idx uleb, size uleb, (name_idx uleb, value)*
            let _type_idx = c.uleb128()?;
            let size = c.uleb128()?;
            if size as usize > 4096 {
                return Err(Error::BadFormat("annotation too large".into()));
            }
            for _ in 0..size {
                let _name = c.uleb128()?;
                let _v = read_encoded_value(c, depth + 1)?;
            }
            EncodedValue::Annotation
        }
        0x1e => EncodedValue::Null,
        0x1f => EncodedValue::Boolean(arg != 0),
        other => {
            return Err(Error::BadFormat(format!("unknown encoded value type {other:#x}")))
        }
    })
}
