//! DEX 抓取与重构。
//!
//! DEX 头部布局（`dex_header`，小端）：
//! ```text
//! 0x00 magic[8]   "dex\n035\0" ... "dex\n039\0"
//! 0x08 checksum   adler32(从 0x0C 到文件尾)
//! 0x0C signature sha1[20]
//! 0x20 file_size  uint32
//! 0x24 header_size 固定 0x70
//! 0x28 endian_tag 固定 0x12345678
//! ```
//! 壳常见的反抓取手法是把 `file_size` 改 0/改大、抹掉 magic 后在加载前恢复。
//! 这里对头部做容错：magic 在即可尝试重构，尺寸交叉验证并记录修复项。

use sha1::{Digest, Sha1};

use droidunpack_protocol::LoadedDex;

use crate::{CarvedCode, CodeKind, MemoryBlob};

const DEX_MAGIC: &[u8] = b"dex\n";
const ENDIAN_TAG: u32 = 0x1234_5678;
const HEADER_SIZE: usize = 0x70;
/// 魔数扫描的对齐步长。ART 内部对象通常 4/8 字节对齐，4 足够覆盖。
const SCAN_STEP: usize = 4;

#[derive(Debug, Clone)]
struct DexHeader {
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    checksum: u32,
    signature: [u8; 20],
}

fn read_header(data: &[u8], off: usize) -> Option<DexHeader> {
    let get = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(off + o..off + o + 4)?.try_into().ok()?,
        ))
    };
    let mut signature = [0u8; 20];
    signature.copy_from_slice(data.get(off + 0x0c..off + 0x20)?);
    Some(DexHeader {
        file_size: get(0x20)?,
        header_size: get(0x24)?,
        endian_tag: get(0x28)?,
        checksum: get(0x08)?,
        signature,
    })
}

/// 在单个候选位置重构 DEX，返回代码单元与修复记录。
fn carve_at(blob: &MemoryBlob, off: usize) -> Option<CarvedCode> {
    let data = &blob.data;
    if off + HEADER_SIZE > data.len() {
        return None;
    }
    let header = read_header(data, off)?;
    let mut repairs = Vec::new();

    if header.endian_tag != ENDIAN_TAG {
        repairs.push(format!("endian_tag 异常: {:#x}", header.endian_tag));
    }
    if header.header_size != HEADER_SIZE as u32 {
        repairs.push(format!("header_size 非标准: {:#x}", header.header_size));
    }

    // 尺寸决策：头部自报尺寸与快照可用长度交叉验证
    let available = data.len() - off;
    let claimed = header.file_size as usize;
    let size = if claimed >= HEADER_SIZE && claimed <= available {
        claimed
    } else if claimed == 0 {
        repairs.push("file_size 被置 0，回退到快照可用长度".into());
        available
    } else {
        repairs.push(format!(
            "file_size({claimed}) 超出快照可用长度({available})，按可用长度截取"
        ));
        available
    };

    let bytes = &data[off..off + size];

    // checksum 验证（只记录不拦截：壳常把 checksum 也抹掉）
    let actual_checksum = adler::adler32_slice(&bytes[0x0c..]);
    if actual_checksum != header.checksum {
        repairs.push(format!(
            "adler32 校验不符（头 {:#x} / 实算 {:#x}），可能被篡改或截断",
            header.checksum, actual_checksum
        ));
    }

    // signature 验证：DEX 规范规定为 0x20 到文件尾的 SHA-1
    let actual_sig = Sha1::digest(&bytes[0x20..]);
    if actual_sig.as_slice() != header.signature {
        repairs.push("SHA-1 signature 与头部声明不符（内容被壳改写或部分解密）".into());
    }

    // sha1：作为去重 key 与对象存储 key（不用头里的 signature，那个也可能被改）
    let sha1 = hex_encode(&Sha1::digest(bytes));

    Some(CarvedCode {
        kind: CodeKind::Dex,
        offset: off,
        addr: blob.base_addr + off as u64,
        size,
        sha1,
        repairs,
        source: blob.tag.clone(),
    })
}

/// 全快照魔数扫描。
pub fn scan(blob: &MemoryBlob) -> Vec<CarvedCode> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + HEADER_SIZE <= blob.data.len() {
        if blob.data[off..].starts_with(DEX_MAGIC) && is_supported_version(&blob.data[off..]) {
            if let Some(c) = carve_at(blob, off) {
                // 跳过整个已识别区域，避免嵌套命中（壳在 dex 里再包 dex 的情形交给上层递归分析）
                off += c.size.max(SCAN_STEP);
                out.push(c);
                continue;
            }
        }
        off += SCAN_STEP;
    }
    out
}

fn is_supported_version(slice: &[u8]) -> bool {
    // magic: d e x \n v v v \0
    matches!(
        &slice[4..8],
        b"035\0" | b"036\0" | b"037\0" | b"038\0" | b"039\0"
    )
}

/// 按 guest 上报精确定位：先尝试在快照内找匹配 magic，再用上报尺寸约束。
pub fn locate_reported(blob: &MemoryBlob, report: &LoadedDex) -> Option<CarvedCode> {
    let mut off = 0;
    while off + HEADER_SIZE <= blob.data.len() {
        if blob.data[off..].starts_with(DEX_MAGIC) && is_supported_version(&blob.data[off..]) {
            if let Some(c) = carve_at(blob, off) {
                // 上报尺寸与重构尺寸在 25% 内吻合即视为同一 dex
                let lo = report.size.saturating_sub(report.size / 4);
                let hi = report.size.saturating_add(report.size / 4).max(report.size);
                if c.size >= lo && c.size <= hi {
                    return Some(c);
                }
                off += c.size.max(SCAN_STEP);
                continue;
            }
        }
        off += SCAN_STEP;
    }
    None
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dex(size: usize) -> Vec<u8> {
        let mut d = Vec::with_capacity(size);
        d.extend_from_slice(b"dex\n035\0");
        d.extend_from_slice(&0u32.to_le_bytes()); // checksum 占位（0x08）
        d.extend(std::iter::repeat_n(0, 20)); // signature 占位（0x0c..0x20）
        d.extend_from_slice(&(size as u32).to_le_bytes()); // file_size @0x20
        d.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        d.extend_from_slice(&ENDIAN_TAG.to_le_bytes());
        d.resize(size, 0x44);
        // signature = SHA-1(0x20..EOF)
        let sig = Sha1::digest(&d[0x20..]);
        d[0x0c..0x20].copy_from_slice(&sig);
        // checksum = adler32(0x0c..EOF)，须在 signature 写入后计算
        let checksum = adler::adler32_slice(&d[0x0c..]);
        d[0x08..0x0c].copy_from_slice(&checksum.to_le_bytes());
        d
    }

    #[test]
    fn clean_dex_has_no_repairs() {
        let dex = valid_dex(0x100);
        let blob = MemoryBlob::new("t", 0, dex);
        let found = scan(&blob);
        assert_eq!(found.len(), 1);
        assert!(found[0].repairs.is_empty(), "{:?}", found[0].repairs);
        assert_eq!(found[0].size, 0x100);
    }

    #[test]
    fn zero_file_size_is_repaired() {
        let mut dex = valid_dex(0x80);
        dex[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());
        let blob = MemoryBlob::new("t", 0, dex);
        let found = scan(&blob);
        assert!(found[0].repairs.iter().any(|r| r.contains("file_size")));
    }

    #[test]
    fn scan_finds_unaligned_but_4_aligned_dex_in_noise() {
        let mut noise = vec![0xCCu8; 64];
        noise.extend(valid_dex(0x80));
        let blob = MemoryBlob::new("t", 0, noise);
        assert_eq!(scan(&blob).len(), 1);
    }

    #[test]
    fn locate_by_report_size_window() {
        let dex = valid_dex(0x200);
        let blob = MemoryBlob::new("heap", 0x5000, dex);
        let report = LoadedDex {
            origin: "mem".into(),
            magic: "dex\n035".into(),
            size: 0x210, // 与真实 0x200 偏差 < 25%
            sha1: "x".into(),
            object_key: None,
        };
        assert!(locate_reported(&blob, &report).is_some());
        let far = LoadedDex {
            size: 0x9999,
            ..report
        };
        assert!(locate_reported(&blob, &far).is_none());
    }
}
