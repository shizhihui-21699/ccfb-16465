//! 运行时代码抓取与重构。
//!
//! 两条抓取路径互补（见 docs/architecture.md §脱壳）：
//! 1. **hook 引导**：guest agent 在 `DefineCommon`/`DexClassLoader`/`mmap(PROT_EXEC)`
//!    上报候选区域，控制面按地址精确转储，成功率最高；
//! 2. **内存魔数扫描兜底**：对整个内存快照按对齐扫描 `dex\n` / `\x7fELF`，
//!    应对 hook 被壳绕过/篡改的样本。
//!
//! 所有抓取结果按 sha1 去重——同一个 dex 被壳反复释放是常见噪声来源。

pub mod dex;
pub mod elf;

use serde::{Deserialize, Serialize};

use droidunpack_protocol::LoadedDex;

/// 一次内存转储快照。`tag` 标识来源（如 `heap`、`anon:libdex`、`guest-full`）。
#[derive(Debug, Clone)]
pub struct MemoryBlob {
    pub tag: String,
    pub base_addr: u64,
    pub data: Vec<u8>,
}

impl MemoryBlob {
    pub fn new(tag: impl Into<String>, base_addr: u64, data: Vec<u8>) -> Self {
        MemoryBlob {
            tag: tag.into(),
            base_addr,
            data,
        }
    }
}

/// 重构出的单个代码单元。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedCode {
    pub kind: CodeKind,
    /// 快照内偏移
    pub offset: usize,
    /// guest 虚拟地址
    pub addr: u64,
    pub size: usize,
    pub sha1: String,
    /// 头部自报尺寸与实际可截取尺寸不一致等修复记录
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repairs: Vec<String>,
    /// 来源标签链：哪个快照、对应哪个 hook 事件
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeKind {
    Dex,
    Elf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractionOutcome {
    pub carved: Vec<CarvedCode>,
    /// guest hook 上报但快照里没抓到的 dex（壳抹痕迹/已卸载的信号）
    pub missing_reports: Vec<String>,
}

impl ExtractionOutcome {
    pub fn dex_count(&self) -> usize {
        self.carved
            .iter()
            .filter(|c| c.kind == CodeKind::Dex)
            .count()
    }
}

/// 主入口：结合 guest 上报与内存快照做抓取重构。
pub fn extract(blobs: &[MemoryBlob], reported: &[LoadedDex]) -> ExtractionOutcome {
    let mut outcome = ExtractionOutcome::default();
    let mut seen = std::collections::HashSet::new();

    let mut push = |c: CarvedCode, seen: &mut std::collections::HashSet<String>| {
        if seen.insert(c.sha1.clone()) {
            outcome.carved.push(c);
        }
    };

    // 路径 1：hook 上报的 dex，优先在快照里精确定位
    for report in reported {
        let mut located = false;
        for blob in blobs {
            if let Some(found) = dex::locate_reported(blob, report) {
                let mut c = found;
                c.source = format!("{} <- report({})", blob.tag, report.origin);
                located = true;
                push(c, &mut seen);
            }
        }
        if !located {
            outcome.missing_reports.push(report.origin.clone());
        }
    }

    // 路径 2：全快照魔数扫描兜底
    for blob in blobs {
        for c in dex::scan(blob) {
            push(c, &mut seen);
        }
        for c in elf::scan(blob) {
            push(c, &mut seen);
        }
    }

    outcome.carved.sort_by_key(|c| (c.kind as u8, c.addr));
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dex_magic(ver: &[u8; 3]) -> Vec<u8> {
        let mut h = vec![b'd', b'e', b'x', b'\n'];
        h.extend_from_slice(ver);
        h.push(0);
        while h.len() < 0x70 {
            h.push(0);
        }
        h
    }

    #[test]
    fn end_to_end_dedup_and_repair() {
        let mut header = dex_magic(b"035");
        // header_size 固定 0x70
        header[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
        // file_size 故意写大，模拟头部被壳破坏
        header[0x20..0x24].copy_from_slice(&0x1000u32.to_le_bytes());
        // endian tag
        header[0x28..0x2c].copy_from_slice(&0x12345678u32.to_le_bytes());
        // 只给 256 字节实际数据
        header.resize(256, 0xAB);

        let blob = MemoryBlob::new("heap", 0x7000_0000, header.clone());
        let outcome = extract(&[blob], &[]);
        assert_eq!(outcome.dex_count(), 1);
        let c = &outcome.carved[0];
        assert_eq!(c.kind, CodeKind::Dex);
        assert!(c.repairs.iter().any(|r| r.contains("file_size")));
        assert!(!c.sha1.is_empty());
    }

    #[test]
    fn duplicate_dex_across_blobs_collapses() {
        let mut header = dex_magic(b"038");
        header[0x20..0x24].copy_from_slice(&0x70u32.to_le_bytes());
        header[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
        header[0x28..0x2c].copy_from_slice(&0x12345678u32.to_le_bytes());

        let b1 = MemoryBlob::new("heap1", 0x1000, header.clone());
        let b2 = MemoryBlob::new("heap2", 0x2000, header);
        let outcome = extract(&[b1, b2], &[]);
        assert_eq!(outcome.dex_count(), 1, "相同 sha1 必须去重");
    }

    #[test]
    fn reported_but_absent_dex_is_recorded_as_missing() {
        let report = LoadedDex {
            origin: "/data/data/com.x/in-memory".into(),
            magic: "dex\n035".into(),
            size: 1024,
            sha1: "deadbeef".into(),
            object_key: None,
        };
        let blob = MemoryBlob::new("empty", 0, vec![0u8; 64]);
        let outcome = extract(&[blob], &[report]);
        assert_eq!(outcome.missing_reports.len(), 1);
        assert!(outcome.carved.is_empty());
    }

    #[test]
    fn finds_elf_among_noise() {
        let mut data = vec![0u8; 128];
        data.extend_from_slice(b"\x7fELF");
        data.extend_from_slice(&[2, 1, 1, 0]); // 64-bit little-endian
        data.resize(256, 0);
        let blob = MemoryBlob::new("anon", 0x4000, data);
        let outcome = extract(&[blob], &[]);
        assert!(outcome.carved.iter().any(|c| c.kind == CodeKind::Elf));
    }
}
