//! ELF 内存抓取。
//!
//! 壳通过 JNI `RegisterNatives` 动态注册的 native 函数、以及 mmapped 的可执行
//! 匿名页，是 Java 层 hook 看不到的部分。ELF 头里的 program header 给出各段
//! 虚拟地址与文件偏移，可用于把分散在多个内存页里的段重建成可被 IDA/Ghidra
//! 打开的 so（这里先做定位与尺寸推断，段级重建在后续迭代）。

use sha1::Digest;

use crate::{CarvedCode, CodeKind, MemoryBlob};

const ELF_MAGIC: &[u8] = b"\x7fELF";
const SCAN_STEP: usize = 4;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;

/// ELF header 最小尺寸（32 位 52 字节，64 位 64 字节）。
fn header_min_size(data: &[u8], off: usize) -> Option<usize> {
    let class = *data.get(off + EI_CLASS)?;
    let data_enc = *data.get(off + EI_DATA)?;
    if data_enc != ELFDATA2LSB {
        return None; // 目标平台 Android 均为小端，大端直接放弃
    }
    match class {
        ELFCLASS32 => Some(52),
        ELFCLASS64 => Some(64),
        _ => None,
    }
}

fn carve_at(blob: &MemoryBlob, off: usize) -> Option<CarvedCode> {
    let min = header_min_size(&blob.data, off)?;
    if off + min > blob.data.len() {
        return None;
    }
    let is64 = blob.data[off + EI_CLASS] == ELFCLASS64;

    // e_phoff / e_phentsize / e_phnum 的位置
    // 32: phoff@0x1c(u32), phentsize@0x2a, phnum@0x2c
    // 64: phoff@0x20(u64), phentsize@0x36, phnum@0x38
    let u16at =
        |o: usize| -> u16 { u16::from_le_bytes([blob.data[off + o], blob.data[off + o + 1]]) };
    let u32at = |o: usize| -> u32 {
        u32::from_le_bytes(blob.data[off + o..off + o + 4].try_into().unwrap())
    };
    let u64at = |o: usize| -> u64 {
        u64::from_le_bytes(blob.data[off + o..off + o + 8].try_into().unwrap())
    };

    let (phoff, phentsize, phnum) = if is64 {
        (
            u64at(0x20) as usize,
            u16at(0x36) as usize,
            u16at(0x38) as usize,
        )
    } else {
        (
            u32at(0x1c) as usize,
            u16at(0x2a) as usize,
            u16at(0x2c) as usize,
        )
    };

    let mut repairs = Vec::new();
    // 通过最后一个 PT_LOAD 段推断镜像在快照内的跨度
    let mut span: Option<usize> = None;
    if phoff == 0 || phnum == 0 || phentsize == 0 {
        repairs.push("program header 缺失/异常，无法推断段跨度，按头尺寸截取".into());
    } else {
        for i in 0..phnum {
            let ph = off + phoff + i * phentsize;
            if ph + phentsize > blob.data.len() {
                repairs.push(format!("program header {i} 越界"));
                break;
            }
            // PT_LOAD p_offset/p_filesz：32 位 @0x04/0x10，64 位 @0x08/0x20
            let (p_offset, p_filesz) = if is64 {
                (u64at_ph(blob, off, ph, 0x08), u64at_ph(blob, off, ph, 0x20))
            } else {
                (
                    u32at_ph(blob, off, ph, 0x04) as u64,
                    u32at_ph(blob, off, ph, 0x10) as u64,
                )
            };
            let end = p_offset as usize + p_filesz as usize;
            span = Some(span.map_or(end, |s| s.max(end)));
        }
    }

    let available = blob.data.len() - off;
    let size = span
        .filter(|s| *s >= min && *s <= available)
        .unwrap_or_else(|| {
            if span.is_some() {
                repairs.push("段跨度超出快照，回退可用长度".into());
            }
            available
        });

    let sha1 = {
        let mut hasher = sha1::Sha1::new();
        hasher.update(&blob.data[off..off + size]);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    };

    Some(CarvedCode {
        kind: CodeKind::Elf,
        offset: off,
        addr: blob.base_addr + off as u64,
        size,
        sha1,
        repairs,
        source: blob.tag.clone(),
    })
}

fn u64at_ph(blob: &MemoryBlob, base: usize, ph: usize, field: usize) -> u64 {
    let o = ph + field;
    u64::from_le_bytes(blob.data[base + o..base + o + 8].try_into().unwrap())
}

fn u32at_ph(blob: &MemoryBlob, base: usize, ph: usize, field: usize) -> u32 {
    let o = ph + field;
    u32::from_le_bytes(blob.data[base + o..base + o + 4].try_into().unwrap())
}

pub fn scan(blob: &MemoryBlob) -> Vec<CarvedCode> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= blob.data.len() {
        if blob.data[off..].starts_with(ELF_MAGIC) {
            if let Some(c) = carve_at(blob, off) {
                off += c.size.max(SCAN_STEP);
                out.push(c);
                continue;
            }
        }
        off += SCAN_STEP;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf64_header() -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(ELF_MAGIC);
        d[EI_CLASS] = ELFCLASS64;
        d[EI_DATA] = ELFDATA2LSB;
        // 无 program header：phnum=0，走回退路径
        d
    }

    #[test]
    fn finds_elf64_header() {
        let mut data = vec![0u8; 32];
        data.extend(elf64_header());
        data.resize(200, 0);
        let blob = MemoryBlob::new("anon", 0x9000, data);
        let found = scan(&blob);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, CodeKind::Elf);
        assert!(found[0]
            .repairs
            .iter()
            .any(|r| r.contains("program header")));
    }

    #[test]
    fn big_endian_elf_is_skipped() {
        let mut d = elf64_header();
        d[EI_DATA] = 2;
        let blob = MemoryBlob::new("t", 0, d);
        assert!(scan(&blob).is_empty());
    }
}
