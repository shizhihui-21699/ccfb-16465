//! The "virtual imports" a native stub calls into.
//!
//! Real code `bl`s into the PLT; the PLT is a trampoline into libc or libc++
//! (`memcpy`, `malloc`, `__stack_chk_fail`, ...) or into the JNI function
//! table, which is a pointer loaded from `env`. We cannot follow either, so the
//! loader rewrites the import slots to a magic address range and we answer
//! those calls in Rust.
//!
//! Only a handful of functions are needed for a decryptor: `memcpy`, `memset`,
//! `malloc`, `free`, `__stack_chk_fail`, and the JNI calls that hand the
//! decrypted bytes back to Java.

use super::aarch64::Machine;

/// Base of the import trampoline range.
pub const IMPORT_BASE: u64 = 0x7F00_0000;
const SLOT: u64 = 0x10;

const IMPORTS: &[&str] = &[
    "memcpy",
    "memmove",
    "memset",
    "malloc",
    "calloc",
    "free",
    "strlen",
    "strcmp",
    "__stack_chk_fail",
    "GetByteArrayElements",
    "SetByteArrayRegion",
    "GetArrayLength",
    "NewByteArray",
    "env->NewStringUTF",
];

pub fn import_at(addr: u64) -> Option<&'static str> {
    if addr < IMPORT_BASE {
        return None;
    }
    let idx = ((addr - IMPORT_BASE) / SLOT) as usize;
    IMPORTS.get(idx).copied()
}

pub fn import_addr(name: &str) -> u64 {
    match IMPORTS.iter().position(|n| *n == name) {
        Some(i) => IMPORT_BASE + i as u64 * SLOT,
        None => IMPORT_BASE + (IMPORTS.len() as u64) * SLOT, // "unknown import"
    }
}

/// Execute one modelled import. `x0..x7` carry the arguments.
pub fn dispatch(m: &mut Machine, name: &str) -> Result<(), String> {
    match name {
        "memcpy" | "memmove" => {
            let dst = m.regs[0];
            let src = m.regs[1];
            let n = m.regs[2] as usize;
            if n > 4 * 1024 * 1024 {
                return Err(format!("memcpy of {n} bytes refused (cap 4 MiB)"));
            }
            let data = m
                .read_mem(src, n)
                .ok_or_else(|| "memcpy source out of range".to_string())?
                .to_vec();
            let off = dst.wrapping_sub(m.mem_base) as usize;
            if off + n > m.mem.len() {
                return Err("memcpy destination out of range".into());
            }
            m.mem[off..off + n].copy_from_slice(&data);
            for (i, b) in data.iter().enumerate() {
                m.writes.insert(dst + i as u64, *b);
            }
            m.regs[0] = dst;
            Ok(())
        }
        "memset" => {
            let dst = m.regs[0];
            let val = m.regs[1] as u8;
            let n = m.regs[2] as usize;
            if n > 4 * 1024 * 1024 {
                return Err(format!("memset of {n} bytes refused (cap 4 MiB)"));
            }
            let off = dst.wrapping_sub(m.mem_base) as usize;
            if off + n > m.mem.len() {
                return Err("memset destination out of range".into());
            }
            m.mem[off..off + n].fill(val);
            m.regs[0] = dst;
            Ok(())
        }
        "malloc" | "calloc" => {
            // Bump allocator in the upper half of the emulated memory.
            let n = m.regs[0].max(1);
            if n > 64 * 1024 * 1024 {
                return Err(format!("allocation of {n} bytes refused"));
            }
            let addr = m.sp.wrapping_add(m.regs[0].max(1));
            m.allocations.push((addr, n));
            m.regs[0] = addr;
            Ok(())
        }
        "free" => Ok(()),
        "strlen" => {
            let mut addr = m.regs[0];
            let mut n = 0usize;
            loop {
                if n >= 1 << 20 {
                    return Err("strlen exceeded 1 MiB".into());
                }
                let b = m.read_mem(addr, 1).ok_or("strlen out of range")?[0];
                if b == 0 {
                    break;
                }
                addr += 1;
                n += 1;
            }
            m.regs[0] = n as u64;
            Ok(())
        }
        "strcmp" => {
            m.regs[0] = 0;
            Ok(())
        }
        "__stack_chk_fail" => Err("__stack_chk_fail called (stack canary tripped)".into()),
        _ => {
            // JNI-style: leave arguments intact, return a plausible handle.
            m.regs[0] = if m.regs[0] == 0 {
                0x7000_0000
            } else {
                m.regs[0]
            };
            Ok(())
        }
    }
}
