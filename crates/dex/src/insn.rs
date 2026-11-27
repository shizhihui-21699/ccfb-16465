//! Dalvik instruction decoding.
//!
//! Decoding happens once per method body into a flat table indexed by code unit
//! (`pc`), because Dalvik branch offsets and payload addresses are all expressed
//! in 16-bit code units. Payloads (switch tables, array data) are recorded as
//! data spans rather than instructions.

use serde::{Deserialize, Serialize};

/// Operand layout of an opcode, as defined by the Dalvik bytecode spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Format {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F32x,
    F30t,
    F31t,
    F31i,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
    F20bc,
    F22cs,
    F35mi,
    F35ms,
    F3rmi,
    F3rms,
    /// Unused / reserved opcode byte.
    FUnused,
}

impl Format {
    /// Number of 16-bit code units this instruction occupies.
    pub fn width(self) -> u32 {
        match self {
            Format::F10x | Format::F12x | Format::F11n | Format::F11x | Format::F10t => 1,
            Format::F20t
            | Format::F22x
            | Format::F21t
            | Format::F21s
            | Format::F21h
            | Format::F21c
            | Format::F23x
            | Format::F22b
            | Format::F22t
            | Format::F22s
            | Format::F22c
            | Format::F20bc
            | Format::F22cs => 2,
            Format::F32x
            | Format::F30t
            | Format::F31t
            | Format::F31i
            | Format::F31c
            | Format::F35c
            | Format::F3rc
            | Format::F35mi
            | Format::F35ms
            | Format::F3rmi
            | Format::F3rms => 3,
            Format::F45cc | Format::F4rcc => 4,
            Format::F51l => 5,
            Format::FUnused => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InsnKind {
    /// A normal executable instruction.
    Real,
    /// A `packed-switch` payload table.
    PackedSwitch,
    /// A `sparse-switch` payload table.
    SparseSwitch,
    /// A `fill-array-data` payload block.
    ArrayData,
    /// An opcode byte with no assigned meaning; execution must trap.
    Invalid,
}

/// One decoded instruction or data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insn {
    /// Code-unit address within the method.
    pub pc: u32,
    /// Code-unit width (payloads included).
    pub width: u32,
    pub kind: InsnKind,
    /// Raw opcode byte (0 for payloads).
    pub op: u8,
    pub format: Format,
    /// Register operand A (also the argument count for invoke formats).
    pub a: u16,
    /// Register operand B / string|type|field index depending on format.
    pub b: u16,
    /// Register operand C / secondary index depending on format.
    pub c: u16,
    /// Literal operand, sign-extended.
    pub literal: i64,
    /// Branch target as an absolute code-unit pc (for branch formats).
    pub target: Option<u32>,
    /// Register list for non-range invoke formats (up to 5 registers).
    pub regs: [u8; 5],
    /// For payload instructions: address of the associated branch instruction.
    pub payload_for: Option<u32>,
}

impl Insn {
    fn new(pc: u32, op: u8, format: Format) -> Self {
        Self {
            pc,
            width: format.width(),
            kind: InsnKind::Real,
            op,
            format,
            a: 0,
            b: 0,
            c: 0,
            literal: 0,
            target: None,
            regs: [0; 5],
            payload_for: None,
        }
    }

    pub fn mnemonic(&self) -> &'static str {
        match self.kind {
            InsnKind::PackedSwitch => "packed-switch-payload",
            InsnKind::SparseSwitch => "sparse-switch-payload",
            InsnKind::ArrayData => "array-data-payload",
            InsnKind::Invalid => "invalid",
            InsnKind::Real => op_info(self.op).name,
        }
    }

    /// Branch target as a signed delta from this instruction's pc.
    pub fn branch_delta(&self) -> Option<i32> {
        self.target.map(|t| t as i32 - self.pc as i32)
    }
}

pub struct OpInfo {
    pub name: &'static str,
    pub format: Format,
}

macro_rules! table {
    ($($op:expr => $name:literal, $fmt:ident;)*) => {
        pub static OPCODES: [OpInfo; 256] = {
            const UNUSED: OpInfo = OpInfo { name: "unused", format: Format::FUnused };
            let mut t = [UNUSED; 256];
            $( t[$op] = OpInfo { name: $name, format: Format::$fmt }; )*
            t
        };
    };
}

table! {
    0x00 => "nop", F10x;
    0x01 => "move", F12x;
    0x02 => "move/from16", F22x;
    0x03 => "move/16", F32x;
    0x04 => "move-wide", F12x;
    0x05 => "move-wide/from16", F22x;
    0x06 => "move-wide/16", F32x;
    0x07 => "move-object", F12x;
    0x08 => "move-object/from16", F22x;
    0x09 => "move-object/16", F32x;
    0x0a => "move-result", F11x;
    0x0b => "move-result-wide", F11x;
    0x0c => "move-result-object", F11x;
    0x0d => "move-exception", F11x;
    0x0e => "return-void", F10x;
    0x0f => "return", F11x;
    0x10 => "return-wide", F11x;
    0x11 => "return-object", F11x;
    0x12 => "const/4", F11n;
    0x13 => "const/16", F21s;
    0x14 => "const", F31i;
    0x15 => "const/high16", F21h;
    0x16 => "const-wide/16", F21s;
    0x17 => "const-wide/32", F31i;
    0x18 => "const-wide", F51l;
    0x19 => "const-wide/high16", F21h;
    0x1a => "const-string", F21c;
    0x1b => "const-string/jumbo", F31c;
    0x1c => "const-class", F21c;
    0x1d => "monitor-enter", F11x;
    0x1e => "monitor-exit", F11x;
    0x1f => "check-cast", F21c;
    0x20 => "instance-of", F22c;
    0x21 => "array-length", F12x;
    0x22 => "new-instance", F21c;
    0x23 => "new-array", F22c;
    0x24 => "filled-new-array", F35c;
    0x25 => "filled-new-array/range", F3rc;
    0x26 => "fill-array-data", F31t;
    0x27 => "throw", F11x;
    0x28 => "goto", F10t;
    0x29 => "goto/16", F20t;
    0x2a => "goto/32", F30t;
    0x2b => "packed-switch", F31t;
    0x2c => "sparse-switch", F31t;
    0x2d => "cmpl-float", F23x;
    0x2e => "cmpg-float", F23x;
    0x2f => "cmpl-double", F23x;
    0x30 => "cmpg-double", F23x;
    0x31 => "cmp-long", F23x;
    0x32 => "if-eq", F22t;
    0x33 => "if-ne", F22t;
    0x34 => "if-lt", F22t;
    0x35 => "if-ge", F22t;
    0x36 => "if-gt", F22t;
    0x37 => "if-le", F22t;
    0x38 => "if-eqz", F21t;
    0x39 => "if-nez", F21t;
    0x3a => "if-ltz", F21t;
    0x3b => "if-gez", F21t;
    0x3c => "if-gtz", F21t;
    0x3d => "if-lez", F21t;
    0x44 => "aget", F23x;
    0x45 => "aget-wide", F23x;
    0x46 => "aget-object", F23x;
    0x47 => "aget-boolean", F23x;
    0x48 => "aget-byte", F23x;
    0x49 => "aget-char", F23x;
    0x4a => "aget-short", F23x;
    0x4b => "aput", F23x;
    0x4c => "aput-wide", F23x;
    0x4d => "aput-object", F23x;
    0x4e => "aput-boolean", F23x;
    0x4f => "aput-byte", F23x;
    0x50 => "aput-char", F23x;
    0x51 => "aput-short", F23x;
    0x52 => "iget", F22c;
    0x53 => "iget-wide", F22c;
    0x54 => "iget-object", F22c;
    0x55 => "iget-boolean", F22c;
    0x56 => "iget-byte", F22c;
    0x57 => "iget-char", F22c;
    0x58 => "iget-short", F22c;
    0x59 => "iput", F22c;
    0x5a => "iput-wide", F22c;
    0x5b => "iput-object", F22c;
    0x5c => "iput-boolean", F22c;
    0x5d => "iput-byte", F22c;
    0x5e => "iput-char", F22c;
    0x5f => "iput-short", F22c;
    0x60 => "sget", F21c;
    0x61 => "sget-wide", F21c;
    0x62 => "sget-object", F21c;
    0x63 => "sget-boolean", F21c;
    0x64 => "sget-byte", F21c;
    0x65 => "sget-char", F21c;
    0x66 => "sget-short", F21c;
    0x67 => "sput", F21c;
    0x68 => "sput-wide", F21c;
    0x69 => "sput-object", F21c;
    0x6a => "sput-boolean", F21c;
    0x6b => "sput-byte", F21c;
    0x6c => "sput-char", F21c;
    0x6d => "sput-short", F21c;
    0x6e => "invoke-virtual", F35c;
    0x6f => "invoke-super", F35c;
    0x70 => "invoke-direct", F35c;
    0x71 => "invoke-static", F35c;
    0x72 => "invoke-interface", F35c;
    0x74 => "invoke-virtual/range", F3rc;
    0x75 => "invoke-super/range", F3rc;
    0x76 => "invoke-direct/range", F3rc;
    0x77 => "invoke-static/range", F3rc;
    0x78 => "invoke-interface/range", F3rc;
    0x7b => "neg-int", F12x;
    0x7c => "not-int", F12x;
    0x7d => "neg-long", F12x;
    0x7e => "not-long", F12x;
    0x7f => "neg-float", F12x;
    0x80 => "neg-double", F12x;
    0x81 => "int-to-long", F12x;
    0x82 => "int-to-float", F12x;
    0x83 => "int-to-double", F12x;
    0x84 => "long-to-int", F12x;
    0x85 => "long-to-float", F12x;
    0x86 => "long-to-double", F12x;
    0x87 => "float-to-int", F12x;
    0x88 => "float-to-long", F12x;
    0x89 => "float-to-double", F12x;
    0x8a => "double-to-int", F12x;
    0x8b => "double-to-long", F12x;
    0x8c => "double-to-float", F12x;
    0x8d => "int-to-byte", F12x;
    0x8e => "int-to-char", F12x;
    0x8f => "int-to-short", F12x;
    0x90 => "add-int", F23x;
    0x91 => "sub-int", F23x;
    0x92 => "mul-int", F23x;
    0x93 => "div-int", F23x;
    0x94 => "rem-int", F23x;
    0x95 => "and-int", F23x;
    0x96 => "or-int", F23x;
    0x97 => "xor-int", F23x;
    0x98 => "shl-int", F23x;
    0x99 => "shr-int", F23x;
    0x9a => "ushr-int", F23x;
    0x9b => "add-long", F23x;
    0x9c => "sub-long", F23x;
    0x9d => "mul-long", F23x;
    0x9e => "div-long", F23x;
    0x9f => "rem-long", F23x;
    0xa0 => "and-long", F23x;
    0xa1 => "or-long", F23x;
    0xa2 => "xor-long", F23x;
    0xa3 => "shl-long", F23x;
    0xa4 => "shr-long", F23x;
    0xa5 => "ushr-long", F23x;
    0xa6 => "add-float", F23x;
    0xa7 => "sub-float", F23x;
    0xa8 => "mul-float", F23x;
    0xa9 => "div-float", F23x;
    0xaa => "rem-float", F23x;
    0xab => "add-double", F23x;
    0xac => "sub-double", F23x;
    0xad => "mul-double", F23x;
    0xae => "div-double", F23x;
    0xaf => "rem-double", F23x;
    0xb0 => "add-int/2addr", F12x;
    0xb1 => "sub-int/2addr", F12x;
    0xb2 => "mul-int/2addr", F12x;
    0xb3 => "div-int/2addr", F12x;
    0xb4 => "rem-int/2addr", F12x;
    0xb5 => "and-int/2addr", F12x;
    0xb6 => "or-int/2addr", F12x;
    0xb7 => "xor-int/2addr", F12x;
    0xb8 => "shl-int/2addr", F12x;
    0xb9 => "shr-int/2addr", F12x;
    0xba => "ushr-int/2addr", F12x;
    0xbb => "add-long/2addr", F12x;
    0xbc => "sub-long/2addr", F12x;
    0xbd => "mul-long/2addr", F12x;
    0xbe => "div-long/2addr", F12x;
    0xbf => "rem-long/2addr", F12x;
    0xc0 => "and-long/2addr", F12x;
    0xc1 => "or-long/2addr", F12x;
    0xc2 => "xor-long/2addr", F12x;
    0xc3 => "shl-long/2addr", F12x;
    0xc4 => "shr-long/2addr", F12x;
    0xc5 => "ushr-long/2addr", F12x;
    0xc6 => "add-float/2addr", F12x;
    0xc7 => "sub-float/2addr", F12x;
    0xc8 => "mul-float/2addr", F12x;
    0xc9 => "div-float/2addr", F12x;
    0xca => "rem-float/2addr", F12x;
    0xcb => "add-double/2addr", F12x;
    0xcc => "sub-double/2addr", F12x;
    0xcd => "mul-double/2addr", F12x;
    0xce => "div-double/2addr", F12x;
    0xcf => "rem-double/2addr", F12x;
    0xd0 => "add-int/lit16", F22s;
    0xd1 => "rsub-int", F22s;
    0xd2 => "mul-int/lit16", F22s;
    0xd3 => "div-int/lit16", F22s;
    0xd4 => "rem-int/lit16", F22s;
    0xd5 => "and-int/lit16", F22s;
    0xd6 => "or-int/lit16", F22s;
    0xd7 => "xor-int/lit16", F22s;
    0xd8 => "add-int/lit8", F22b;
    0xd9 => "rsub-int/lit8", F22b;
    0xda => "mul-int/lit8", F22b;
    0xdb => "div-int/lit8", F22b;
    0xdc => "rem-int/lit8", F22b;
    0xdd => "and-int/lit8", F22b;
    0xde => "or-int/lit8", F22b;
    0xdf => "xor-int/lit8", F22b;
    0xe0 => "shl-int/lit8", F22b;
    0xe1 => "shr-int/lit8", F22b;
    0xe2 => "ushr-int/lit8", F22b;
    0xfa => "invoke-polymorphic", F45cc;
    0xfb => "invoke-polymorphic/range", F4rcc;
    0xfc => "invoke-custom", F35c;
    0xfd => "invoke-custom/range", F3rc;
    0xfe => "const-method-handle", F21c;
    0xff => "const-method-type", F21c;
}

#[inline]
pub fn op_info(op: u8) -> &'static OpInfo {
    &OPCODES[op as usize]
}

/// Decoded operand meaning for the reader/interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandKind {
    /// Plain register (numerical).
    Reg,
    /// Object register.
    ObjReg,
    /// Wide (64-bit) register pair.
    WideReg,
    /// String pool index.
    StrIdx,
    /// Type pool index.
    TypeIdx,
    /// Field pool index.
    FieldIdx,
    /// Method pool index.
    MethodIdx,
    /// Proto pool index.
    ProtoIdx,
    /// Call site index.
    CallSiteIdx,
    /// Method handle index.
    MethodHandleIdx,
}

impl Insn {
    /// True if the instruction is a branch of any kind.
    pub fn is_branch(&self) -> bool {
        matches!(self.op, 0x28..=0x2c | 0x32..=0x3d)
    }

    /// True if the instruction ends a basic block.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self.op,
            0x0e..=0x11 | 0x27 | 0x28..=0x2a | 0x32..=0x3d
        ) || self.is_switch()
    }

    pub fn is_switch(&self) -> bool {
        matches!(self.op, 0x2b | 0x2c)
    }

    pub fn is_invoke(&self) -> bool {
        matches!(self.op, 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd)
    }

    pub fn is_return(&self) -> bool {
        matches!(self.op, 0x0e..=0x11)
    }
}

/// Decode a method body (`insns` array, in code units) into instructions.
///
/// Returns the instruction table sorted by pc, with payload pseudo-instructions
/// marked as data so the interpreter skips them.
pub fn decode(insns: &[u16]) -> Vec<Insn> {
    let mut out = Vec::with_capacity(insns.len() / 2 + 4);
    let mut pc = 0usize;
    while pc < insns.len() {
        let unit0 = insns[pc];
        let op_byte = (unit0 & 0xff) as u8;

        // Payload pseudo-instructions are identified by the high byte of the
        // first code unit (0x01/0x02/0x03) with a zero opcode byte.
        if op_byte == 0x00 {
            match (unit0 >> 8) as u8 {
                0x01 => {
                    // packed-switch-payload: ident, size, first_key (2 units), targets
                    if pc + 1 >= insns.len() {
                        break;
                    }
                    // ident(1) + size(1) + first_key(2) + targets(size)
                    let size = insns[pc + 1] as usize;
                    let width = (size + 4) as u32;
                    out.push(Insn {
                        pc: pc as u32,
                        width,
                        kind: InsnKind::PackedSwitch,
                        op: 0,
                        format: Format::FUnused,
                        a: 0,
                        b: 0,
                        c: 0,
                        literal: 0,
                        target: None,
                        regs: [0; 5],
                        payload_for: None,
                    });
                    pc += width as usize;
                    continue;
                }
                0x02 => {
                    // sparse-switch-payload: ident, size, keys[size], targets[size]
                    if pc + 1 >= insns.len() {
                        break;
                    }
                    // ident(1) + size(1) + keys(size) + targets(size)
                    let size = insns[pc + 1] as usize;
                    let width = (size * 2 + 2) as u32;
                    out.push(Insn {
                        pc: pc as u32,
                        width,
                        kind: InsnKind::SparseSwitch,
                        op: 0,
                        format: Format::FUnused,
                        a: 0,
                        b: 0,
                        c: 0,
                        literal: 0,
                        target: None,
                        regs: [0; 5],
                        payload_for: None,
                    });
                    pc += width as usize;
                    continue;
                }
                0x03 => {
                    // fill-array-data-payload: ident, element_width, size(4), data
                    if pc + 3 >= insns.len() {
                        break;
                    }
                    let element_width = insns[pc + 1] as usize;
                    let size = (insns[pc + 2] as usize) | ((insns[pc + 3] as usize) << 16);
                    let bytes = element_width.max(1) * size;
                    let units = bytes.div_ceil(2);
                    let width = (units + 4) as u32;
                    out.push(Insn {
                        pc: pc as u32,
                        width,
                        kind: InsnKind::ArrayData,
                        op: 0,
                        format: Format::FUnused,
                        a: 0,
                        b: 0,
                        c: 0,
                        literal: 0,
                        target: None,
                        regs: [0; 5],
                        payload_for: None,
                    });
                    pc += width as usize;
                    continue;
                }
                _ => {}
            }
        }

        let info = op_info(op_byte);
        if info.format == Format::FUnused && op_byte != 0x00 {
            out.push(Insn {
                pc: pc as u32,
                width: 1,
                kind: InsnKind::Invalid,
                op: op_byte,
                format: Format::FUnused,
                a: 0,
                b: 0,
                c: 0,
                literal: 0,
                target: None,
                regs: [0; 5],
                payload_for: None,
            });
            pc += 1;
            continue;
        }

        let mut insn = Insn::new(pc as u32, op_byte, info.format);
        let w = insn.width as usize;
        if pc + w > insns.len() {
            insn.kind = InsnKind::Invalid;
            out.push(insn);
            break;
        }
        let get = |i: usize| insns[pc + i];
        match info.format {
            Format::F10x => {}
            Format::F12x => {
                insn.a = (get(0) >> 8) & 0x0f;
                insn.b = (get(0) >> 12) & 0x0f;
            }
            Format::F11n => {
                insn.a = (get(0) >> 8) & 0x0f;
                let l = (get(0) >> 12) & 0x0f;
                insn.literal = (((l << 12) as i16) >> 12) as i64; // sign extend 4 bits
            }
            Format::F11x => {
                insn.a = (get(0) >> 8) & 0xff;
            }
            Format::F10t => {
                let off = ((get(0) >> 8) & 0xff) as i8 as i32;
                insn.target = Some((insn.pc as i64 + off as i64) as u32);
            }
            Format::F20t => {
                let off = get(1) as i16 as i32;
                insn.target = Some((insn.pc as i64 + off as i64) as u32);
            }
            Format::F22x => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
            }
            Format::F21t => {
                insn.a = (get(0) >> 8) & 0xff;
                let off = get(1) as i16 as i32;
                insn.target = Some((insn.pc as i64 + off as i64) as u32);
            }
            Format::F21s => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.literal = get(1) as i16 as i64;
                insn.b = get(1);
            }
            Format::F21h => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
                insn.literal = (get(1) as i16 as i64) << 16;
            }
            Format::F21c => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
            }
            Format::F23x => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1) & 0xff;
                insn.c = (get(1) >> 8) & 0xff;
            }
            Format::F22b => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1) & 0xff;
                insn.literal = ((get(1) >> 8) & 0xff) as u8 as i8 as i64;
            }
            Format::F22t => {
                insn.a = (get(0) >> 8) & 0x0f;
                insn.b = (get(0) >> 12) & 0x0f;
                let off = get(1) as i16 as i32;
                insn.target = Some((insn.pc as i64 + off as i64) as u32);
            }
            Format::F22s => {
                insn.a = (get(0) >> 8) & 0x0f;
                insn.b = (get(0) >> 12) & 0x0f;
                insn.literal = get(1) as i16 as i64;
            }
            Format::F22c => {
                insn.a = (get(0) >> 8) & 0x0f;
                insn.b = (get(0) >> 12) & 0x0f;
                insn.c = get(1);
            }
            Format::F32x => {
                // unit1 = A (dest, 16-bit), unit2 = B (src, 16-bit)
                insn.a = get(1);
                insn.b = get(2);
            }
            Format::F30t => {
                let off = (get(1) as i32) | ((get(2) as i32) << 16);
                insn.target = Some((insn.pc as i64 + off as i64) as u32);
            }
            Format::F31t => {
                insn.a = (get(0) >> 8) & 0xff;
                let off = (get(1) as i32) | ((get(2) as i32) << 16);
                insn.target = Some((insn.pc as i64 + off as i64) as u32);
            }
            Format::F31i => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.literal = (get(1) as i32 | ((get(2) as i32) << 16)) as i64;
            }
            Format::F31c => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
                insn.literal = ((get(1) as u32) | ((get(2) as u32) << 16)) as i64;
            }
            Format::F35c | Format::F45cc => {
                insn.a = (get(0) >> 12) & 0x0f;
                let g = (get(0) >> 8) & 0x0f;
                insn.b = get(1);
                let unit2 = get(2);
                let c = (unit2 & 0x0f) as u8;
                let d = ((unit2 >> 4) & 0x0f) as u8;
                let e = ((unit2 >> 8) & 0x0f) as u8;
                let f = ((unit2 >> 12) & 0x0f) as u8;
                insn.regs = [c, d, e, f, g as u8];
                if info.format == Format::F45cc {
                    insn.c = get(3);
                }
            }
            Format::F3rc | Format::F4rcc => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
                insn.c = get(2);
                if info.format == Format::F4rcc {
                    insn.literal = get(3) as i64;
                }
            }
            Format::F51l => {
                insn.a = (get(0) >> 8) & 0xff;
                let lo = (get(1) as u32) | ((get(2) as u32) << 16);
                let hi = (get(3) as u32) | ((get(4) as u32) << 16);
                insn.literal = (((hi as u64) << 32) | lo as u64) as i64;
            }
            Format::F20bc => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
            }
            Format::F22cs => {
                insn.a = (get(0) >> 8) & 0x0f;
                insn.b = (get(0) >> 12) & 0x0f;
                insn.c = get(1);
            }
            Format::F35mi | Format::F35ms => {
                insn.a = (get(0) >> 12) & 0x0f;
                let g = (get(0) >> 8) & 0x0f;
                insn.b = get(1);
                let unit2 = get(2);
                insn.regs = [
                    (unit2 & 0x0f) as u8,
                    ((unit2 >> 4) & 0x0f) as u8,
                    ((unit2 >> 8) & 0x0f) as u8,
                    ((unit2 >> 12) & 0x0f) as u8,
                    g as u8,
                ];
            }
            Format::F3rmi | Format::F3rms => {
                insn.a = (get(0) >> 8) & 0xff;
                insn.b = get(1);
                insn.c = get(2);
            }
            Format::FUnused => {
                insn.kind = InsnKind::Invalid;
            }
        }
        out.push(insn);
        pc += w;
    }
    // Link switch/fill-array targets back to their consuming instruction.
    for i in 0..out.len() {
        if let Some(t) = out[i].target {
            if matches!(out[i].op, 0x26 | 0x2b | 0x2c) {
                if let Some(j) = out.iter().position(|x| x.pc == t) {
                    if out[j].kind != InsnKind::Real {
                        out[j].payload_for = Some(out[i].pc);
                    }
                }
            }
        }
    }
    out
}

/// Render one instruction in a dexdump-like textual form (for reports).
pub fn render(insn: &Insn) -> String {
    let m = insn.mnemonic();
    match insn.format {
        Format::F10x => m.to_string(),
        Format::F12x => format!("{m} v{}, v{}", insn.a, insn.b),
        Format::F11n => format!("{m} v{}, #{}", insn.a, insn.literal),
        Format::F11x => format!("{m} v{}", insn.a),
        Format::F10t | Format::F20t | Format::F30t | Format::F21t | Format::F22t => {
            let t = insn.target.unwrap_or(0);
            let d = insn.branch_delta().unwrap_or(0);
            if matches!(insn.format, Format::F21t) {
                format!("{m} v{}, {t:04x} ({d:+})", insn.a)
            } else if matches!(insn.format, Format::F22t) {
                format!("{m} v{}, v{}, {t:04x} ({d:+})", insn.a, insn.b)
            } else {
                format!("{m} {t:04x} ({d:+})")
            }
        }
        Format::F21s | Format::F21h => format!("{m} v{}, #{}", insn.a, insn.literal),
        Format::F21c => format!("{m} v{}, @{}", insn.a, insn.b),
        Format::F22x => format!("{m} v{}, v{}", insn.a, insn.b),
        Format::F23x => format!("{m} v{}, v{}, v{}", insn.a, insn.b, insn.c),
        Format::F22b => format!("{m} v{}, v{}, #{}", insn.a, insn.b, insn.literal),
        Format::F22s => format!("{m} v{}, v{}, #{}", insn.a, insn.b, insn.literal),
        Format::F22c | Format::F22cs => format!("{m} v{}, v{}, @{}", insn.a, insn.b, insn.c),
        Format::F32x => format!("{m} v{}, v{}", insn.a, insn.b),
        Format::F31t => format!("{m} v{}, {:04x}", insn.a, insn.target.unwrap_or(0)),
        Format::F31i => format!("{m} v{}, #{}", insn.a, insn.literal),
        Format::F31c => format!("{m} v{}, @{}", insn.a, insn.literal),
        Format::F35c | Format::F45cc => {
            let regs: Vec<String> = insn.regs[..insn.a as usize]
                .iter()
                .map(|r| format!("v{r}"))
                .collect();
            format!("{m} {{{}}}, @{}", regs.join(", "), insn.b)
        }
        Format::F3rc | Format::F4rcc => {
            format!(
                "{m} {{v{}..v{}}}, @{}",
                insn.c,
                insn.c + insn.a.saturating_sub(1),
                insn.b
            )
        }
        Format::F51l => format!("{m} v{}, #{}L", insn.a, insn.literal),
        Format::F20bc => format!("{m} v{}, @{}", insn.a, insn.b),
        Format::F35mi | Format::F35ms | Format::F3rmi | Format::F3rms => m.to_string(),
        Format::FUnused => format!("{m} (op 0x{:02x})", insn.op),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_const_and_return() {
        // const/4 v0, #1 ; return v0  (encodings as d8 emits them)
        let insns = [0x1012u16, 0x000f];
        let d = decode(&insns);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].mnemonic(), "const/4");
        assert_eq!(d[0].a, 0);
        assert_eq!(d[0].literal, 1);
        assert_eq!(d[1].mnemonic(), "return");
        assert_eq!(d[1].a, 0);
    }

    #[test]
    fn decodes_invoke_with_regs() {
        // invoke-static {v0, v1}, method@0x10
        // unit2 packs C=v0 in the low nibble and D=v1 in the next one.
        let insns = [0x2071u16, 0x0010, 0x0010];
        let d = decode(&insns);
        assert_eq!(d[0].mnemonic(), "invoke-static");
        assert_eq!(d[0].a, 2);
        assert_eq!(d[0].regs[..2], [0, 1]);
        assert_eq!(d[0].b, 0x10);
    }

    #[test]
    fn skips_packed_switch_payload() {
        // packed-switch-payload: ident 0x0100, size 2, first_key (2 units), 2 targets
        let insns = [0x0100u16, 0x0002, 0x0000, 0x0000, 0x0005, 0x0009, 0x000eu16];
        let d = decode(&insns);
        assert_eq!(d.len(), 2);
        assert!(matches!(d[0].kind, InsnKind::PackedSwitch));
        assert_eq!(d[0].width, 6);
        assert_eq!(d[1].pc, 6);
    }

    #[test]
    fn branch_target_is_absolute() {
        // goto +3 : opcode 0x28 with the 8-bit offset in the high byte.
        let insns = [0x0328u16];
        let d = decode(&insns);
        assert_eq!(d[0].target, Some(3));
        assert_eq!(d[0].branch_delta(), Some(3));
    }

    #[test]
    fn sign_extends_negative_literals() {
        // const/4 v0, #-1  (literal nibble 0xf)
        let insns = [0xf012u16];
        let d = decode(&insns);
        assert_eq!(d[0].literal, -1);
    }
}
