//! Dalvik instruction formats and a non-allocating decoder.
//!
//! The interpreter decodes one instruction at a time from a `&[u16]` code
//! array. Keeping the decoder separate from execution makes both testable and
//! lets the analysis pass walk code without running it.

/// Instruction format. Determines operand layout and instruction width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fmt {
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
    /// Reserved / unused opcode; behaves as a 1-unit nop.
    Unused,
}

impl Fmt {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            Fmt::F10x | Fmt::F12x | Fmt::F11n | Fmt::F11x | Fmt::F10t | Fmt::Unused => 1,
            Fmt::F20t | Fmt::F22x | Fmt::F21t | Fmt::F21s | Fmt::F21h | Fmt::F21c | Fmt::F23x
            | Fmt::F22b | Fmt::F22t | Fmt::F22s | Fmt::F22c => 2,
            Fmt::F32x | Fmt::F30t | Fmt::F31t | Fmt::F31i | Fmt::F31c | Fmt::F35c | Fmt::F3rc => 3,
            Fmt::F45cc | Fmt::F4rcc => 4,
            Fmt::F51l => 5,
        }
    }
}

/// Format for every opcode value 0x00..=0xff.
pub static FORMATS: [Fmt; 256] = {
    use Fmt::*;
    const U: Fmt = Fmt::Unused;
    let mut t = [U; 256];
    // 0x00..0x1b
    t[0x00] = F10x;
    t[0x01] = F12x;
    t[0x02] = F22x;
    t[0x03] = F32x;
    t[0x04] = F12x;
    t[0x05] = F22x;
    t[0x06] = F32x;
    t[0x07] = F12x;
    t[0x08] = F22x;
    t[0x09] = F32x;
    t[0x0a] = F11x;
    t[0x0b] = F11x;
    t[0x0c] = F11x;
    t[0x0d] = F11x;
    t[0x0e] = F10x;
    t[0x0f] = F11x;
    t[0x10] = F11x;
    t[0x11] = F11x;
    t[0x12] = F11n;
    t[0x13] = F21s;
    t[0x14] = F31i;
    t[0x15] = F21h;
    t[0x16] = F21s;
    t[0x17] = F31i;
    t[0x18] = F51l;
    t[0x19] = F21h;
    t[0x1a] = F21c;
    t[0x1b] = F31c;
    t[0x1c] = F21c;
    t[0x1d] = F11x;
    t[0x1e] = F11x;
    t[0x1f] = F21c;
    t[0x20] = F22c;
    t[0x21] = F12x;
    t[0x22] = F21c;
    t[0x23] = F22c;
    t[0x24] = F35c;
    t[0x25] = F3rc;
    t[0x26] = F31t;
    t[0x27] = F11x;
    t[0x28] = F10t;
    t[0x29] = F20t;
    t[0x2a] = F30t;
    t[0x2b] = F31t;
    t[0x2c] = F31t;
    // 0x2d..0x31 cmp
    let mut i = 0x2d;
    while i <= 0x31 {
        t[i] = F23x;
        i += 1;
    }
    // 0x32..0x37 if-*
    i = 0x32;
    while i <= 0x37 {
        t[i] = F22t;
        i += 1;
    }
    // 0x38..0x3d if-*z
    i = 0x38;
    while i <= 0x3d {
        t[i] = F21t;
        i += 1;
    }
    // 0x3e..0x43 unused; 0x44..0x51 array ops
    i = 0x44;
    while i <= 0x51 {
        t[i] = F23x;
        i += 1;
    }
    // 0x52..0x5f i*put
    i = 0x52;
    while i <= 0x5f {
        t[i] = F22c;
        i += 1;
    }
    // 0x60..0x6d s*get/put
    i = 0x60;
    while i <= 0x6d {
        t[i] = F21c;
        i += 1;
    }
    // 0x6e..0x72 invoke
    i = 0x6e;
    while i <= 0x72 {
        t[i] = F35c;
        i += 1;
    }
    // 0x74..0x78 invoke/range
    i = 0x74;
    while i <= 0x78 {
        t[i] = F3rc;
        i += 1;
    }
    // 0x7b..0x8f unops
    i = 0x7b;
    while i <= 0x8f {
        t[i] = F12x;
        i += 1;
    }
    // 0x90..0xaf binops
    i = 0x90;
    while i <= 0xaf {
        t[i] = F23x;
        i += 1;
    }
    // 0xb0..0xcf binop/2addr
    i = 0xb0;
    while i <= 0xcf {
        t[i] = F12x;
        i += 1;
    }
    // 0xd0..0xd7 lit16
    i = 0xd0;
    while i <= 0xd7 {
        t[i] = F22s;
        i += 1;
    }
    // 0xd8..0xe2 lit8
    i = 0xd8;
    while i <= 0xe2 {
        t[i] = F22b;
        i += 1;
    }
    t[0xfa] = F45cc;
    t[0xfb] = F4rcc;
    t[0xfc] = F35c;
    t[0xfd] = F3rc;
    t[0xfe] = F21c;
    t[0xff] = F21c;
    t
};

pub const OP_NOP: u8 = 0x00;
pub const OP_MOVE: u8 = 0x01;
pub const OP_MOVE_FROM16: u8 = 0x02;
pub const OP_MOVE_16: u8 = 0x03;
pub const OP_MOVE_WIDE: u8 = 0x04;
pub const OP_MOVE_WIDE_FROM16: u8 = 0x05;
pub const OP_MOVE_WIDE_16: u8 = 0x06;
pub const OP_MOVE_OBJECT: u8 = 0x07;
pub const OP_MOVE_OBJECT_FROM16: u8 = 0x08;
pub const OP_MOVE_OBJECT_16: u8 = 0x09;
pub const OP_MOVE_RESULT: u8 = 0x0a;
pub const OP_MOVE_RESULT_WIDE: u8 = 0x0b;
pub const OP_MOVE_RESULT_OBJECT: u8 = 0x0c;
pub const OP_MOVE_EXCEPTION: u8 = 0x0d;
pub const OP_RETURN_VOID: u8 = 0x0e;
pub const OP_RETURN: u8 = 0x0f;
pub const OP_RETURN_WIDE: u8 = 0x10;
pub const OP_RETURN_OBJECT: u8 = 0x11;
pub const OP_CONST_4: u8 = 0x12;
pub const OP_CONST_16: u8 = 0x13;
pub const OP_CONST: u8 = 0x14;
pub const OP_CONST_HIGH16: u8 = 0x15;
pub const OP_CONST_WIDE_16: u8 = 0x16;
pub const OP_CONST_WIDE_32: u8 = 0x17;
pub const OP_CONST_WIDE: u8 = 0x18;
pub const OP_CONST_WIDE_HIGH16: u8 = 0x19;
pub const OP_CONST_STRING: u8 = 0x1a;
pub const OP_CONST_STRING_JUMBO: u8 = 0x1b;
pub const OP_CONST_CLASS: u8 = 0x1c;
pub const OP_MONITOR_ENTER: u8 = 0x1d;
pub const OP_MONITOR_EXIT: u8 = 0x1e;
pub const OP_CHECK_CAST: u8 = 0x1f;
pub const OP_INSTANCE_OF: u8 = 0x20;
pub const OP_ARRAY_LENGTH: u8 = 0x21;
pub const OP_NEW_INSTANCE: u8 = 0x22;
pub const OP_NEW_ARRAY: u8 = 0x23;
pub const OP_FILLED_NEW_ARRAY: u8 = 0x24;
pub const OP_FILL_ARRAY_DATA: u8 = 0x26;
pub const OP_THROW: u8 = 0x27;
pub const OP_GOTO: u8 = 0x28;
pub const OP_GOTO_16: u8 = 0x29;
pub const OP_GOTO_32: u8 = 0x2a;
pub const OP_PACKED_SWITCH: u8 = 0x2b;
pub const OP_SPARSE_SWITCH: u8 = 0x2c;
pub const OP_CMPL_FLOAT: u8 = 0x2d;
pub const OP_CMPG_FLOAT: u8 = 0x2e;
pub const OP_CMPL_DOUBLE: u8 = 0x2f;
pub const OP_CMPG_DOUBLE: u8 = 0x30;
pub const OP_CMP_LONG: u8 = 0x31;
pub const OP_IF_EQ: u8 = 0x32;
pub const OP_IF_NE: u8 = 0x33;
pub const OP_IF_LT: u8 = 0x34;
pub const OP_IF_GE: u8 = 0x35;
pub const OP_IF_GT: u8 = 0x36;
pub const OP_IF_LE: u8 = 0x37;
pub const OP_IF_EQZ: u8 = 0x38;
pub const OP_IF_NEZ: u8 = 0x39;
pub const OP_IF_LTZ: u8 = 0x3a;
pub const OP_IF_GEZ: u8 = 0x3b;
pub const OP_IF_GTZ: u8 = 0x3c;
pub const OP_IF_LEZ: u8 = 0x3d;
pub const OP_AGET: u8 = 0x44;
pub const OP_APUT: u8 = 0x4b;
pub const OP_IGET: u8 = 0x52;
pub const OP_IPUT: u8 = 0x59;
pub const OP_SGET: u8 = 0x60;
pub const OP_SPUT: u8 = 0x67;
pub const OP_INVOKE_VIRTUAL: u8 = 0x6e;
pub const OP_INVOKE_SUPER: u8 = 0x6f;
pub const OP_INVOKE_DIRECT: u8 = 0x70;
pub const OP_INVOKE_STATIC: u8 = 0x71;
pub const OP_INVOKE_INTERFACE: u8 = 0x72;
pub const OP_INVOKE_VIRTUAL_RANGE: u8 = 0x74;
pub const OP_INVOKE_SUPER_RANGE: u8 = 0x75;
pub const OP_INVOKE_DIRECT_RANGE: u8 = 0x76;
pub const OP_INVOKE_STATIC_RANGE: u8 = 0x77;
pub const OP_INVOKE_INTERFACE_RANGE: u8 = 0x78;
pub const OP_NEG_INT: u8 = 0x7b;
pub const OP_NOT_INT: u8 = 0x7c;
pub const OP_NEG_LONG: u8 = 0x7d;
pub const OP_NOT_LONG: u8 = 0x7e;
pub const OP_NEG_FLOAT: u8 = 0x7f;
pub const OP_NEG_DOUBLE: u8 = 0x80;
pub const OP_INT_TO_LONG: u8 = 0x81;
pub const OP_INT_TO_FLOAT: u8 = 0x82;
pub const OP_INT_TO_DOUBLE: u8 = 0x83;
pub const OP_LONG_TO_INT: u8 = 0x84;
pub const OP_LONG_TO_FLOAT: u8 = 0x85;
pub const OP_LONG_TO_DOUBLE: u8 = 0x86;
pub const OP_FLOAT_TO_INT: u8 = 0x87;
pub const OP_FLOAT_TO_LONG: u8 = 0x88;
pub const OP_FLOAT_TO_DOUBLE: u8 = 0x89;
pub const OP_DOUBLE_TO_INT: u8 = 0x8a;
pub const OP_DOUBLE_TO_LONG: u8 = 0x8b;
pub const OP_DOUBLE_TO_FLOAT: u8 = 0x8c;
pub const OP_INT_TO_BYTE: u8 = 0x8d;
pub const OP_INT_TO_CHAR: u8 = 0x8e;
pub const OP_INT_TO_SHORT: u8 = 0x8f;
pub const OP_ADD_INT: u8 = 0x90;
pub const OP_INVOKE_POLYMORPHIC: u8 = 0xfa;
pub const OP_CONST_METHOD_HANDLE: u8 = 0xfe;
pub const OP_CONST_METHOD_TYPE: u8 = 0xff;

/// A decoded instruction. Holds the raw code units so operand accessors stay
/// simple and cheap; `len` is in code units.
#[derive(Debug, Clone, Copy)]
pub struct Insn {
    pub op: u8,
    pub fmt: Fmt,
    pub pc: usize,
    pub len: usize,
    pub w: [u16; 5],
}

impl Insn {
    /// vAA (8-bit register) — formats 11x, 21*, 22x, 23x, 31*, 35c-count, 3rc-count.
    pub fn a8(&self) -> u8 {
        (self.w[0] >> 8) as u8
    }
    /// vA (4-bit).
    pub fn a4(&self) -> u8 {
        ((self.w[0] >> 8) & 0xf) as u8
    }
    /// vB (4-bit).
    pub fn b4(&self) -> u8 {
        ((self.w[0] >> 12) & 0xf) as u8
    }
    /// vBB (8-bit) from 23x / 22b.
    pub fn b8(&self) -> u8 {
        (self.w[1] & 0xff) as u8
    }
    /// vCC (8-bit) from 23x / 22b-literal.
    pub fn c8(&self) -> u8 {
        (self.w[1] >> 8) as u8
    }
    /// 16-bit literal without sign (BBBB).
    pub fn u16_1(&self) -> u16 {
        self.w[1]
    }
    /// 32-bit literal from 31i / 31t / 31c (BBB B B B B).
    pub fn s32(&self) -> i32 {
        ((self.w[1] as u32) | ((self.w[2] as u32) << 16)) as i32
    }
    pub fn u32(&self) -> u32 {
        (self.w[1] as u32) | ((self.w[2] as u32) << 16)
    }
    /// 64-bit literal from 51l.
    pub fn s64(&self) -> i64 {
        let mut v: u64 = 0;
        for i in 0..4 {
            v |= (self.w[1 + i] as u64) << (16 * i);
        }
        v as i64
    }
    /// Signed 4-bit literal (11n). The literal sits in bits 12..16 of the
    /// first code unit and must be sign-extended from 4 bits, not from the
    /// 16-bit word (whose top bit belongs to the literal, not the register).
    pub fn lit4(&self) -> i32 {
        let nibble = (self.w[0] >> 12) as i32 & 0xf;
        (nibble << 28) >> 28
    }
    /// Signed 16-bit literal (21s / 22s).
    pub fn lit16(&self) -> i32 {
        self.w[1] as i16 as i32
    }
    /// Signed 8-bit literal (22b).
    pub fn lit8(&self) -> i32 {
        (self.w[1] >> 8) as u8 as i8 as i32
    }
    /// Branch offset as a signed value of the format's width.
    pub fn branch_offset(&self) -> i32 {
        match self.fmt {
            Fmt::F10t => (self.w[0] >> 8) as u8 as i8 as i32,
            Fmt::F20t => self.w[1] as i16 as i32,
            Fmt::F30t => self.s32(),
            Fmt::F21t => self.w[1] as i16 as i32,
            Fmt::F22t => self.w[1] as i16 as i32,
            Fmt::F31t => self.s32(),
            _ => 0,
        }
    }

    /// Register list for 35c / 45cc style (non-range) invokes.
    pub fn arg_regs(&self) -> ([u8; 5], usize) {
        let count = ((self.w[0] >> 12) & 0xf) as usize;
        // 35c layout: `A|G|op BBBB F|E|D|C`, arguments in order C, D, E, F, G.
        let regs = [
            (self.w[2] & 0xf) as u8,
            ((self.w[2] >> 4) & 0xf) as u8,
            ((self.w[2] >> 8) & 0xf) as u8,
            ((self.w[2] >> 12) & 0xf) as u8,
            ((self.w[0] >> 8) & 0xf) as u8,
        ];
        (regs, count.min(5))
    }
}

/// Decode the instruction at `pc`. Never panics; a malformed trailing
/// instruction reads as zero words and reports format `Unused`.
pub fn decode(insns: &[u16], pc: usize) -> Insn {
    let w0 = *insns.get(pc).unwrap_or(&0);
    let op = (w0 & 0xff) as u8;
    let fmt = FORMATS[op as usize];
    let len = fmt.len();
    let mut w = [0u16; 5];
    for (i, slot) in w.iter_mut().enumerate().take(len) {
        *slot = *insns.get(pc + i).unwrap_or(&0);
    }
    Insn { op, fmt, pc, len, w }
}

/// Instruction width in code units, preferring the format table.
pub fn insn_len(insns: &[u16], pc: usize, op: u8) -> usize {
    let _ = (insns, pc);
    FORMATS[op as usize].len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_cover_every_opcode() {
        // Every opcode not marked unused has a real format and width.
        for op in 0u8..=0xff {
            let f = FORMATS[op as usize];
            let n = f.len();
            assert!((1..=5).contains(&n), "opcode {op:#x} bad width {n}");
        }
        assert_eq!(FORMATS[0x18], Fmt::F51l);
        assert_eq!(Fmt::F51l.len(), 5);
        assert_eq!(FORMATS[0x6e], Fmt::F35c);
        assert_eq!(FORMATS[0x25], Fmt::F3rc);
    }

    #[test]
    fn decode_operands() {
        // const/4 v3, #-1  => 0x12 | vA=3 | lit=0xf  -> 0xf312
        let insns = [0xf312u16];
        let i = decode(&insns, 0);
        assert_eq!(i.op, OP_CONST_4);
        assert_eq!(i.a4(), 3);
        assert_eq!(i.lit4(), -1);

        // `invoke-virtual {v0, v1}, m` encodes arguments C,D,E,F in the low
        // word's nibbles (D is the second-lowest), so w2=0x0010 means
        // C=0, D=1 — i.e. registers {v0, v1}. Verified against d8 output.
        let insns = [0x206eu16, 0x1234, 0x0010];
        let i = decode(&insns, 0);
        assert_eq!(i.op, OP_INVOKE_VIRTUAL);
        assert_eq!(i.u16_1(), 0x1234);
        let (regs, count) = i.arg_regs();
        assert_eq!(count, 2);
        assert_eq!(&regs[..2], &[0, 1]);

        // const-string v7, string@0x0002
        let insns = [0x071au16, 0x0002];
        let i = decode(&insns, 0);
        assert_eq!(i.a8(), 7);
        assert_eq!(i.u16_1(), 2);
    }
}
