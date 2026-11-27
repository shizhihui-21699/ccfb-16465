//! A bounded AArch64 interpreter.
//!
//! Only the instructions a compiler emits for byte-manipulation code are
//! implemented. Everything else is an explicit `Unsupported`, which the caller
//! records — silence about an emulated instruction is a lie about coverage, so
//! there is no "best effort" fallback here.

use super::{NativeLimits, NativeOutcome};
use std::collections::HashMap;
use unhusk_dex::reader::Reader;

pub const NUM_REGS: usize = 31;
pub const MEM_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Machine {
    pub regs: [u64; NUM_REGS],
    pub sp: u64,
    pub finished: bool,
    pub return_value: u64,
    pub mem: Vec<u8>,
    pub mem_base: u64,
    pub lr: u64,
    pub steps: u64,
    pub limits: NativeLimits,
    pub last_pc: u64,
    /// Flags from the last flag-setting op: (N, Z, C, V).
    pub flags: (bool, bool, bool, bool),
    pub allocations: Vec<(u64, u64)>,
    /// Byte writes seen, so the caller can extract a decrypted buffer.
    pub writes: HashMap<u64, u8>,
}

impl Machine {
    pub fn new(limits: NativeLimits) -> Self {
        Self {
            regs: [0; NUM_REGS],
            sp: 0x8000_0000,
            finished: false,
            return_value: 0,
            mem: vec![0u8; MEM_SIZE],
            mem_base: 0x1000_0000,
            lr: 0,
            steps: 0,
            limits,
            last_pc: 0,
            flags: (false, false, false, false),
            allocations: Vec::new(),
            writes: HashMap::new(),
        }
    }

    pub fn write_mem(&mut self, addr: u64, data: &[u8]) {
        let off = addr.wrapping_sub(self.mem_base) as usize;
        if off < self.mem.len() {
            let n = data.len().min(self.mem.len() - off);
            self.mem[off..off + n].copy_from_slice(&data[..n]);
        }
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let off = addr.checked_sub(self.mem_base)? as usize;
        if off.checked_add(len)? <= self.mem.len() {
            Some(&self.mem[off..off + len])
        } else {
            None
        }
    }

    fn load32(&self, addr: u64) -> Option<u32> {
        self.read_mem(addr, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Run from `start` until `ret`, an unsupported instruction, or the budget.
    pub fn run(&mut self, start: u64, limits: &NativeLimits) -> NativeOutcome {
        self.limits = limits.clone();
        let mut pc = start;
        self.lr = 0;
        loop {
            self.steps += 1;
            if self.steps > limits.max_steps {
                return NativeOutcome::Budget { steps: self.steps };
            }
            self.last_pc = pc;
            if std::env::var("UNHUSK_NATIVE_TRACE").is_ok() {
                eprintln!("  [0x{pc:x}] x0={:x} x1={:x} x2={:x} x8={:x} x9={:x} x10={:x} x11={:x} flags={:?}",
                    self.regs[0], self.regs[1], self.regs[2], self.regs[8], self.regs[9],
                    self.regs[10], self.regs[11], self.flags);
            }
            let Some(insn) = self.load32(pc) else {
                return NativeOutcome::Unsupported {
                    pc,
                    reason: "fetch outside mapped memory".into(),
                    steps: self.steps,
                };
            };
            match self.step(insn, &mut pc) {
                Ok(true) => {
                    return NativeOutcome::Returned {
                        value: self.return_value,
                        steps: self.steps,
                    }
                }
                Ok(false) => {}
                Err(reason) => {
                    return NativeOutcome::Unsupported {
                        pc: self.last_pc,
                        reason,
                        steps: self.steps,
                    }
                }
            }
        }
    }

    fn x(&self, i: u32) -> u64 {
        match i {
            31 => 0, // XZR
            n if (n as usize) < NUM_REGS => self.regs[n as usize],
            _ => 0,
        }
    }

    fn set_x(&mut self, i: u32, v: u64) {
        if i < 31 {
            self.regs[i as usize] = v;
        }
    }

    fn step(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        if insn & 0xFFFF_FC1F == 0xD65F_0000 {
            self.finished = true;
            return Ok(true);
        }
        if insn == 0xD503_201F {
            *pc += 4;
            return Ok(false);
        }
        let op0 = (insn >> 25) & 0xF;
        match op0 {
            0b1000 | 0b1001 => self.dp_imm(insn, pc),
            0b1010 | 0b1011 => self.branch(insn, pc),
            0b0100 | 0b0110 | 0b1100 | 0b1110 => self.load_store(insn, pc),
            0b0101 | 0b1101 => self.dp_reg(insn, pc),
            _ => Err(format!("opcode 0x{insn:08x} (class {op0:#06b}) not emulated")),
        }
    }

    fn dp_imm(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        let rd = insn & 0x1F;
        let rn = (insn >> 5) & 0x1F;
        let sf = (insn >> 31) & 1 == 1;
        // ADD/SUB (immediate) is bits 28..24 == 0b10001, with bit 30 selecting
        // the operation and bit 29 the flag update. Classifying on bits 25..23
        // alone cannot tell ADD from SUB, which silently turns every loop
        // decrement into an increment.
        let is_addsub_imm = (insn >> 24) & 0x1F == 0b10001;
        if is_addsub_imm {
            {
                let is_sub = (insn >> 30) & 1 == 1;
                let sh = (insn >> 22) & 1;
                let mut imm = ((insn >> 10) & 0xFFF) as u64;
                if sh == 1 {
                    imm <<= 12;
                }
                let a = self.x(rn);
                let r = if is_sub {
                    a.wrapping_sub(imm)
                } else {
                    a.wrapping_add(imm)
                };
                if rd == 31 && rn == 31 {
                    // Stack-pointer adjustment.
                    if is_sub {
                        self.sp = self.sp.wrapping_sub(imm);
                    } else {
                        self.sp = self.sp.wrapping_add(imm);
                    }
                } else if rd == 31 {
                    // CMP (immediate): sets flags.
                    let (n, z, c, v) = if is_sub {
                        flags_sub(a, imm, sf)
                    } else {
                        flags_add(a, imm, sf)
                    };
                    self.flags = (n, z, c, v);
                } else {
                    self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
                }
                *pc += 4;
                return Ok(false);
            }
        }
        let op = (insn >> 23) & 0x7;
        match op {
            0b101 => self.move_wide(insn, pc),
            0b100 => self.logical_imm(insn, pc),
            _ => Err(format!("dp-imm op {op:#05b} not emulated")),
        }
    }

    fn move_wide(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        let rd = insn & 0x1F;
        let sf = (insn >> 31) & 1 == 1;
        let opc = (insn >> 29) & 0x3;
        let hw = ((insn >> 21) & 0x3) * 16;
        let imm = ((insn >> 5) & 0xFFFF) as u64;
        let cur = self.x(rd);
        let v = match opc {
            0b00 => !(imm << hw), // MOVN
            0b10 => imm << hw,    // MOVZ
            0b11 => {
                // MOVK: keep other bits.
                let mask = !(0xFFFFu64 << hw);
                (cur & mask) | (imm << hw)
            }
            _ => return Err("reserved move-wide".into()),
        };
        self.set_x(rd, if sf { v } else { v & 0xFFFF_FFFF });
        *pc += 4;
        Ok(false)
    }

    fn logical_imm(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        let rd = insn & 0x1F;
        let rn = (insn >> 5) & 0x1F;
        let sf = (insn >> 31) & 1 == 1;
        let opc = (insn >> 29) & 0x3;
        let n = (insn >> 22) & 1;
        let immr = (insn >> 16) & 0x3F;
        let imms = (insn >> 10) & 0x3F;
        let imm = decode_bit_masks(n, imms, immr, sf)
            .ok_or_else(|| "invalid logical immediate".to_string())?;
        let a = self.x(rn);
        let r = match opc {
            0b00 => a & imm,
            0b01 => a | imm,
            0b10 => a ^ imm,
            0b11 => a & imm,
            _ => unreachable!(),
        };
        if opc == 0b11 {
            self.flags = (r >> 63 & 1 == 1, r == 0, false, false);
        }
        self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
        *pc += 4;
        Ok(false)
    }

    fn branch(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        let op26 = (insn >> 26) & 0x3F;
        if op26 == 0b000101 || op26 == 0b100101 {
            let link = (insn >> 31) & 1 == 1;
            let off = sign_extend(((insn & 0x03FF_FFFF) as i64) << 2, 28);
            if link {
                return self.call_target(*pc, off, pc);
            }
            // AArch64 branch offsets are relative to the branch itself, not to
            // the following instruction (that is RISC-V and x86).
            *pc = (*pc as i64 + off) as u64;
            return Ok(false);
        }
        if insn & 0xFF00_0010 == 0x5400_0000 {
            let cond = insn & 0xF;
            let off = sign_extend((((insn >> 5) & 0x7FFFF) as i64) << 2, 21);
            if self.cond(cond as u8) {
                *pc = (*pc as i64 + off) as u64;
            } else {
                *pc += 4;
            }
            return Ok(false);
        }
        if insn & 0x7E00_0000 == 0x3400_0000 {
            let sf = (insn >> 31) & 1 == 1;
            let rt = insn & 0x1F;
            let is_nz = (insn >> 24) & 1 == 1;
            let off = sign_extend((((insn >> 5) & 0x7FFFF) as i64) << 2, 21);
            let v = self.x(rt);
            let zero = if sf { v == 0 } else { (v & 0xFFFF_FFFF) == 0 };
            if zero != is_nz {
                *pc = (*pc as i64 + off) as u64;
            } else {
                *pc += 4;
            }
            return Ok(false);
        }
        if insn & 0x7E00_0000 == 0x3600_0000 {
            let rt = insn & 0x1F;
            let bit = ((insn >> 26) & 0x20) | ((insn >> 19) & 0x1F);
            let is_nz = (insn >> 24) & 1 == 1;
            let off = sign_extend((((insn >> 5) & 0x3FFF) as i64) << 2, 16);
            let v = (self.x(rt) >> bit) & 1 == 1;
            if v == is_nz {
                *pc = (*pc as i64 + off) as u64;
            } else {
                *pc += 4;
            }
            return Ok(false);
        }
        Err(format!("branch 0x{insn:08x} not emulated"))
    }

    fn call_target(&mut self, at: u64, off: i64, pc: &mut u64) -> Result<bool, String> {
        let target = (at as i64 + off) as u64;
        if let Some(name) = crate::native::jni::import_at(target) {
            crate::native::jni::dispatch(self, name)?;
            *pc += 4;
            return Ok(false);
        }
        *pc = target;
        Ok(false)
    }

    fn cond(&self, cond: u8) -> bool {
        let (n, z, c, v) = self.flags;
        match cond {
            0b0000 => z,
            0b0001 => !z,
            0b0010 => c,
            0b0011 => !c,
            0b0100 => n,
            0b0101 => !n,
            0b0110 => v,
            0b0111 => !v,
            0b1000 => c && !z,
            0b1001 => !c || z,
            0b1010 => n == v,
            0b1011 => n != v,
            0b1100 => !z && n == v,
            0b1101 => z || n != v,
            0b1110 => true,
            _ => false,
        }
    }

    fn load_store(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        let rt = insn & 0x1F;
        let rn = (insn >> 5) & 0x1F;
        let size = (insn >> 30) & 0x3;
        // `is_load` for the 32/64-bit data class lives in bit 22, but for the
        // byte/halfword class (opc 00/01 in bits 24..23) it lives in bits 23..22.
        // Deriving both from the same bit is what made `ldrb` execute as `strb`.
        let opc = (insn >> 22) & 0x3;
        let is_load = match size {
            3 => opc == 0b01,
            2 => opc == 0b01 || opc == 0b11,
            _ => opc & 1 == 1,
        };
        // Addressing form is selected by bits 25..24 plus bit 21:
        //   01        -> unsigned immediate (imm12)
        //   00, bit21=0 -> imm9 form (unscaled / pre- / post-indexed)
        //   00, bit21=1 -> register offset
        let form = (insn >> 24) & 0x3;
        let reg_offset = (insn >> 21) & 1 == 1;
        let (offset, post_inc) = if form == 0b01 {
            let imm12 = (insn >> 10) & 0xFFF;
            ((imm12 as u64) << size, 0i64)
        } else if form == 0b00 && reg_offset {
            // Register offset, e.g. `ldrb w11, [x0, x8]`.
            let rm = (insn >> 16) & 0x1F;
            let option = (insn >> 13) & 0x7;
            let sh = (insn >> 12) & 1;
            let mut v = self.x(rm);
            // Option codes, per the architecture reference:
            //   010 UXTW, 011 LSL (== UXTX with shift), 110 SXTW, 111 SXTX
            match option {
                0b010 => v = v as u32 as u64,
                0b011 => {}
                0b110 => v = v as i32 as i64 as u64,
                0b111 => {}
                _ => return Err(format!("extend option {option:#05b} not emulated")),
            }
            if sh == 1 {
                v <<= size;
            }
            (v, 0i64)
        } else if form == 0b00 {
            // Unscaled / pre- / post-indexed, imm9.
            let imm9 = sign_extend(((insn >> 12) & 0x1FF) as i64, 9) as u64;
            let mode = (insn >> 10) & 0x3;
            let post = if mode == 1 { imm9 as i64 } else { 0 };
            (imm9, post)
        } else {
            return Err(format!("load/store form 0x{insn:08x} not emulated"));
        };
        let addr = self.x(rn).wrapping_add(offset);
        if !is_load {
            let v = self.x(rt);
            let bytes = match size {
                3 => v.to_le_bytes().to_vec(),
                2 => (v as u32).to_le_bytes().to_vec(),
                1 => (v as u16).to_le_bytes().to_vec(),
                _ => vec![v as u8],
            };
            let off = addr.wrapping_sub(self.mem_base) as usize;
            if off + bytes.len() <= self.mem.len() {
                self.mem[off..off + bytes.len()].copy_from_slice(&bytes);
                for (i, b) in bytes.iter().enumerate() {
                    self.writes.insert(addr + i as u64, *b);
                }
            }
        } else {
            let v = match size {
                3 => self.read_mem(addr, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0),
                2 => self.read_mem(addr, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64).unwrap_or(0),
                1 => self.read_mem(addr, 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()) as u64).unwrap_or(0),
                _ => self.read_mem(addr, 1).map(|b| b[0] as u64).unwrap_or(0),
            };
            self.set_x(rt, v);
        }
        if post_inc != 0 {
            let new = self.x(rn).wrapping_add(post_inc as u64);
            self.set_x(rn, new);
        }
        *pc += 4;
        Ok(false)
    }

    fn dp_reg(&mut self, insn: u32, pc: &mut u64) -> Result<bool, String> {
        let rd = insn & 0x1F;
        let rn = (insn >> 5) & 0x1F;
        let rm = (insn >> 16) & 0x1F;
        let sf = (insn >> 31) & 1 == 1;

        let op24 = (insn >> 24) & 0x1F;
        if op24 == 0b01011 || op24 == 0b11011 {
            let sub = (insn >> 30) & 1 == 1;
            let set_flags = (insn >> 29) & 1 == 1;
            let shift_type = (insn >> 22) & 0x3;
            let shift = (insn >> 10) & 0x3F;
            let a = self.x(rn);
            let b = shift_reg(self.x(rm), shift_type, shift, sf);
            let r = if sub { a.wrapping_sub(b) } else { a.wrapping_add(b) };
            let r = if sf { r } else { r & 0xFFFF_FFFF };
            if set_flags || rd == 31 {
                let (n, z, c, v) = if sub { flags_sub(a, b, sf) } else { flags_add(a, b, sf) };
                self.flags = (n, z, c, v);
            }
            self.set_x(rd, r);
            *pc += 4;
            return Ok(false);
        }

        if op24 == 0b01010 {
            let opc = (insn >> 29) & 0x3;
            let shift_type = (insn >> 22) & 0x3;
            let shift = (insn >> 10) & 0x3F;
            let a = self.x(rn);
            let b = shift_reg(self.x(rm), shift_type, shift, sf);
            let r = match opc {
                0b00 => a & b,
                0b01 => a | b,
                0b10 => a ^ b,
                0b11 => a & b,
                _ => unreachable!(),
            };
            if opc == 0b11 {
                self.flags = (r >> 63 & 1 == 1, r == 0, false, false);
            }
            self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
            *pc += 4;
            return Ok(false);
        }

        // MADD/MSUB (64/32-bit)
        if matches!((insn >> 21) & 0xFF, 0b0011_0110 | 0b1011_0110) {
            let ra = (insn >> 10) & 0x1F;
            let sub = (insn >> 15) & 1 == 1;
            let a = self.x(rn);
            let b = self.x(rm);
            let acc = self.x(ra);
            let prod = a.wrapping_mul(b);
            let r = if sub { acc.wrapping_sub(prod) } else { acc.wrapping_add(prod) };
            self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
            *pc += 4;
            return Ok(false);
        }

        // UDIV/SDIV
        if (insn >> 21) & 0xFFF == 0b0011_0101_1000 || (insn >> 21) & 0xFFF == 0b0011_0101_1001 {
            let signed = (insn >> 10) & 1 == 1;
            let a = self.x(rn);
            let b = self.x(rm);
            let r = if b == 0 {
                0
            } else if signed {
                ((a as i64).wrapping_div(b as i64)) as u64
            } else {
                a / b
            };
            self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
            *pc += 4;
            return Ok(false);
        }

        // UBFM / SBFM (masking and shifts)
        let op23 = (insn >> 23) & 0x3F;
        if op23 == 0b100110 || op23 == 0b100100 {
            let signed = op23 == 0b100100;
            let immr = (insn >> 16) & 0x3F;
            let imms = (insn >> 10) & 0x3F;
            let r = bitfield(self.x(rn), immr, imms, signed, sf);
            self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
            *pc += 4;
            return Ok(false);
        }

        // CSEL family
        if (insn >> 21) & 0x3FF == 0b0011_0100_00 {
            let cond = (insn >> 12) & 0xF;
            let op = (insn >> 10) & 0x3;
            let a = self.x(rn);
            let b = self.x(rm);
            let r = if self.cond(cond as u8) {
                a
            } else {
                match op {
                    0 => b,
                    1 => b.wrapping_add(1),
                    2 => !b,
                    _ => b.wrapping_neg(),
                }
            };
            self.set_x(rd, if sf { r } else { r & 0xFFFF_FFFF });
            *pc += 4;
            return Ok(false);
        }
        Err(format!("dp-reg 0x{insn:08x} not emulated"))
    }
}

fn shift_reg(v: u64, shift_type: u32, amount: u32, sf: bool) -> u64 {
    let amount = if sf { amount & 63 } else { amount & 31 };
    if sf {
        match shift_type {
            0 => v << amount,
            1 => v >> amount,
            2 => ((v as i64) >> amount) as u64,
            _ => {
                if amount == 0 {
                    v
                } else {
                    (v >> amount) | (v << (64 - amount))
                }
            }
        }
    } else {
        let v = v as u32;
        let r = match shift_type {
            0 => v << amount,
            1 => v >> amount,
            2 => ((v as i32) >> amount) as u32,
            _ => v.rotate_right(amount),
        };
        r as u64
    }
}

fn bitfield(src: u64, immr: u32, imms: u32, signed: bool, sf: bool) -> u64 {
    let width = if sf { 64 } else { 32 };
    let immr = immr % width;
    let imms = imms % width;
    let src = if sf { src } else { src & 0xFFFF_FFFF };
    let (field, field_width) = if imms >= immr {
        (
            (src >> immr) & ((1u64 << (imms - immr + 1)) - 1),
            imms - immr + 1,
        )
    } else {
        let low = src >> immr;
        let high = src << (width - immr);
        let mask = (1u64 << (imms + 1)) - 1;
        ((low | high) & mask, imms + 1)
    };
    if signed && field_width < 64 && (field >> (field_width - 1)) & 1 == 1 {
        field | (!0u64 << field_width)
    } else {
        field
    }
}

fn flags_add(a: u64, b: u64, sf: bool) -> (bool, bool, bool, bool) {
    if sf {
        let (sum, carry) = a.overflowing_add(b);
        (sum >> 63 & 1 == 1, sum == 0, carry, false)
    } else {
        let (sum, carry) = (a as u32).overflowing_add(b as u32);
        (sum >> 31 & 1 == 1, sum == 0, carry, false)
    }
}

fn flags_sub(a: u64, b: u64, sf: bool) -> (bool, bool, bool, bool) {
    if sf {
        let (diff, borrow) = a.overflowing_sub(b);
        (diff >> 63 & 1 == 1, diff == 0, !borrow, false)
    } else {
        let (diff, borrow) = (a as u32).overflowing_sub(b as u32);
        (diff >> 31 & 1 == 1, diff == 0, !borrow, false)
    }
}

fn sign_extend(v: i64, bits: u32) -> i64 {
    (v << (64 - bits)) >> (64 - bits)
}

/// ARM's DecodeBitMasks for logical immediates, transcribed from the
/// architecture reference (`len = HighestSetBit(N:~imms<5:0>)`).
fn decode_bit_masks(n: u32, imms: u32, immr: u32, sf: bool) -> Option<u64> {
    let width = if sf { 64 } else { 32 };
    // The 7-bit concatenation N:~imms<5:0>; its highest set bit is `len`.
    let combined = ((n & 1) << 6) | ((!imms) & 0x3F);
    if combined == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros(); // 63 - clz == index of MSB
    if len < 1 {
        return None;
    }
    if (1u32 << len) > width {
        return None;
    }
    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let esize = 1u32 << len;
    let welem = (1u64 << (s + 1)) - 1;
    let wmask = rotate_right(welem, r, esize);
    let mut mask = 0u64;
    let mut i = 0u32;
    while i < width {
        mask |= wmask << i;
        i += esize;
    }
    Some(mask)
}

fn rotate_right(v: u64, r: u32, esize: u32) -> u64 {
    let mask = if esize >= 64 { !0u64 } else { (1u64 << esize) - 1 };
    let v = v & mask;
    let r = r % esize;
    if r == 0 {
        v
    } else {
        ((v >> r) | (v << (esize - r))) & mask
    }
}

/// First `SHF_EXECINSTR` section, for relocatable objects.
fn exec_section(data: &[u8]) -> Option<Code<'_>> {
    if data.len() < 64 {
        return None;
    }
    let shoff = u64::from_le_bytes(data[40..48].try_into().ok()?) as usize;
    let shentsize = u16::from_le_bytes(data[58..60].try_into().ok()?) as usize;
    let shnum = u16::from_le_bytes(data[60..62].try_into().ok()?) as usize;
    if shoff == 0 || shentsize == 0 {
        return None;
    }
    for i in 0..shnum {
        let off = shoff.checked_add(i.checked_mul(shentsize)?)?;
        if off + 40 > data.len() {
            return None;
        }
        let sh_type = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
        let sh_flags = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
        let sh_offset = u64::from_le_bytes(data[off + 24..off + 32].try_into().ok()?) as usize;
        let sh_size = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?) as usize;
        // SHT_PROGBITS with SHF_EXECINSTR (0x4).
        if sh_type == 1 && sh_flags & 0x4 != 0 && sh_size > 0 {
            let end = sh_offset.checked_add(sh_size)?;
            if end <= data.len() {
                // Relocatable sections load at virtual address 0.
                return Some(Code { bytes: &data[sh_offset..end], vaddr: 0 });
            }
        }
    }
    None
}

/// An executable ELF segment of an AArch64 `.so`.
pub struct Code<'a> {
    pub bytes: &'a [u8],
    pub vaddr: u64,
}

impl<'a> Code<'a> {
    /// Locate the executable `PT_LOAD` segment that contains `file_offset`.
    ///
    /// A shared object usually has several executable segments (`.init`,
    /// `.plt`, `.text`); taking the *first* one silently emulates the wrong
    /// code. The caller passes the offset of the function it wants.
    pub fn from_elf_at(data: &'a [u8], file_offset: u64) -> Option<Self> {
        if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
            return None;
        }
        let phoff = u64::from_le_bytes(data[32..40].try_into().ok()?) as usize;
        let phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as usize;
        let phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
        let mut best: Option<(&[u8], u64)> = None;
        for i in 0..phnum {
            let off = phoff.checked_add(i.checked_mul(phentsize)?)?;
            if off + 56 > data.len() {
                break;
            }
            let p_type = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
            let p_flags = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
            let p_offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
            let p_vaddr = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?);
            let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?);
            if p_type != 1 || p_flags & 1 == 0 || p_filesz == 0 {
                continue;
            }
            let start = p_offset as usize;
            let end = start.checked_add(p_filesz as usize)?;
            if end > data.len() {
                continue;
            }
            if file_offset >= p_offset && file_offset < p_offset + p_filesz {
                return Some(Code { bytes: &data[start..end], vaddr: p_vaddr });
            }
            // Remember the largest executable segment as a fallback.
            if best.map(|(b, _)| b.len() < p_filesz as usize).unwrap_or(true) {
                best = Some((&data[start..end], p_vaddr));
            }
        }
        best.map(|(bytes, vaddr)| Code { bytes, vaddr })
    }

    /// Locate the first `PT_LOAD` segment with the execute bit set.
    pub fn from_elf(data: &'a [u8]) -> Option<Self> {
        if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
            return None;
        }
        // e_machine is a 16-bit field at offset 18 (little-endian).
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        if e_machine != 0xB7 {
            return None; // not EM_AARCH64
        }
        let phoff = u64::from_le_bytes(data[32..40].try_into().ok()?) as usize;
        let phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as usize;
        let phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
        for i in 0..phnum {
            let off = phoff.checked_add(i.checked_mul(phentsize)?)?;
            if off + 56 > data.len() {
                break;
            }
            let p_type = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
            let p_flags = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
            let p_offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
            let p_vaddr = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?);
            let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?);
            if p_type == 1 && p_flags & 1 != 0 && p_filesz > 0 {
                let start = p_offset as usize;
                let end = start.checked_add(p_filesz as usize)?;
                if end <= data.len() {
                    return Some(Code { bytes: &data[start..end], vaddr: p_vaddr });
                }
            }
        }
        // Relocatable object (e.g. a `.o` from a unit test): fall back to the
        // section header table and take the first executable section. This is
        // what lets us test the interpreter against a compiler's real output
        // without linking a shared object first.
        exec_section(data)
    }

    pub fn first_word(&self) -> Option<u32> {
        let mut r = Reader::new(self.bytes);
        r.u32().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &[u32]) -> Machine {
        let mut m = Machine::new(NativeLimits { max_steps: 1000 });
        let mut bytes = Vec::new();
        for w in code {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        m.write_mem(m.mem_base, &bytes);
        let base = m.mem_base;
        m.run(base, &NativeLimits { max_steps: 1000 });
        m
    }

    #[test]
    fn movz_then_ret_returns_value() {
        // movz x0, #0x1234 ; ret
        let m = run(&[0xD282_4680, 0xD65F_03C0]);
        assert_eq!(m.regs[0], 0x1234);
    }

    #[test]
    fn add_immediate_accumulates() {
        // movz x1, #5 ; add x0, x1, #10 ; ret
        let m = run(&[0xD280_00A1, 0x9100_2820, 0xD65F_03C0]);
        assert_eq!(m.regs[0], 15);
    }

    #[test]
    fn loop_with_cbnz_runs() {
        // movz x0,#0 ; movz x1,#10 ; add x0,x0,#2 ; sub x1,x1,#1 ; cbnz x1,-4 ; ret
        let code = [
            0xD280_0000, 0xD280_0141, 0x9100_0800, 0xD100_0421, 0xB5FF_FFC1, 0xD65F_03C0,
        ];
        let m = run(&code);
        assert_eq!(m.regs[0], 20);
    }

    #[test]
    fn unsupported_instruction_is_reported_not_guessed() {
        let mut m = Machine::new(NativeLimits { max_steps: 100 });
        m.write_mem(m.mem_base, &0u32.to_le_bytes());
        match m.run(m.mem_base, &NativeLimits { max_steps: 100 }) {
            NativeOutcome::Unsupported { reason, .. } => assert!(reason.contains("not emulated")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn bit_masks_decode_correctly() {
        let mask = decode_bit_masks(1, 7, 0, true).unwrap();
        assert_eq!(mask, 0xFF);
    }
}

/// Find an exported function in an ELF by name, returning its file offset and
/// virtual address. Supports both `.symtab` and `.dynsym`.
pub fn find_export(data: &[u8], name: &str) -> Option<(u64, u64)> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        return None;
    }
    let shoff = u64::from_le_bytes(data[40..48].try_into().ok()?) as usize;
    let shentsize = u16::from_le_bytes(data[58..60].try_into().ok()?) as usize;
    let shnum = u16::from_le_bytes(data[60..62].try_into().ok()?) as usize;
    if shoff == 0 || shentsize == 0 {
        return None;
    }
    let sh = |i: usize| -> Option<(u32, u64, u64, u64, u64)> {
        // (type, offset, size, link, entsize)
        let off = shoff.checked_add(i.checked_mul(shentsize)?)?;
        if off + 64 > data.len() {
            return None;
        }
        let ty = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
        let offset = u64::from_le_bytes(data[off + 24..off + 32].try_into().ok()?);
        let size = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?);
        let link = u32::from_le_bytes(data[off + 40..off + 44].try_into().ok()?) as u64;
        let entsize = u64::from_le_bytes(data[off + 56..off + 64].try_into().ok()?);
        Some((ty, offset, size, link, entsize))
    };
    for i in 0..shnum {
        let Some((ty, offset, size, link, entsize)) = sh(i) else { continue };
        // SHT_SYMTAB (2) or SHT_DYNSYM (11)
        if ty != 2 && ty != 11 {
            continue;
        }
        let entsize = if entsize == 0 { 24 } else { entsize };
        let Some((_, str_off, str_size, _, _)) = sh(link as usize) else { continue };
        let strtab = data
            .get(str_off as usize..(str_off + str_size) as usize)
            .unwrap_or_default();
        let count = size / entsize;
        for k in 0..count {
            let e = offset as usize + k as usize * entsize as usize;
            if e + 24 > data.len() {
                break;
            }
            let st_name = u32::from_le_bytes(data[e..e + 4].try_into().ok()?) as usize;
            let st_info = data[e + 4];
            let st_value = u64::from_le_bytes(data[e + 8..e + 16].try_into().ok()?);
            let st_shndx = u16::from_le_bytes(data[e + 6..e + 8].try_into().ok()?);
            // STB_GLOBAL / STB_WEAK and STT_FUNC, defined in a real section.
            let bind = st_info >> 4;
            let kind = st_info & 0xf;
            if bind != 1 && bind != 2 {
                continue;
            }
            if kind != 2 && kind != 10 {
                continue;
            }
            if st_shndx == 0 {
                continue;
            }
            let Some(sym) = strtab.get(st_name..).and_then(|s| {
                let end = s.iter().position(|&c| c == 0)?;
                std::str::from_utf8(&s[..end]).ok()
            }) else {
                continue;
            };
            if sym != name {
                continue;
            }
            // Translate the virtual address back to a file offset via the
            // program headers.
            let phoff = u64::from_le_bytes(data[32..40].try_into().ok()?) as usize;
            let phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as usize;
            let phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
            for p in 0..phnum {
                let po = phoff + p * phentsize;
                if po + 56 > data.len() {
                    break;
                }
                let p_type = u32::from_le_bytes(data[po..po + 4].try_into().ok()?);
                let p_offset = u64::from_le_bytes(data[po + 8..po + 16].try_into().ok()?);
                let p_vaddr = u64::from_le_bytes(data[po + 16..po + 24].try_into().ok()?);
                let p_filesz = u64::from_le_bytes(data[po + 32..po + 40].try_into().ok()?);
                if p_type == 1 && st_value >= p_vaddr && st_value < p_vaddr + p_filesz {
                    return Some((p_offset + (st_value - p_vaddr), st_value));
                }
            }
            return Some((st_value, st_value));
        }
    }
    None
}
