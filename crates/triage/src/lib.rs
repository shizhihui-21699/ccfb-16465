//! 静态预筛：在不启动样本的前提下识别加固厂商、清单入口与动态分析优先级。
//!
//! 预筛结果决定样本走哪条分析车道（见 [`TriageDecision`]），是吞吐控制的第一道闸：
//! 几万样本/天不可能每个都跑满 4 分钟动态分析。

mod axml;
mod packer;

pub use packer::{PackerConfidence, PackerHit};

use serde::{Deserialize, Serialize};

/// 清单组件类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    Activity,
    Service,
    Receiver,
    Provider,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    pub kind: ComponentKind,
    pub name: String,
    pub exported: Option<bool>,
    /// intent-filter 里的 action，广播接收器的触发条件常藏在这里
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DexInfo {
    pub path: String,
    pub size: usize,
}

/// 分析车道决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageDecision {
    /// 无壳无明显入口：短动态 + 静态即可
    FastLane,
    /// 常规样本：标准动态刺激
    FullDynamic,
    /// 命中加固/强规避特征：完整脱壳流水线 + 自适应反检测
    DeepDynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub package: Option<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<ComponentInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dex_files: Vec<DexInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_libs: Vec<String>,
    pub packer: Option<PackerHit>,
    /// 未命中已知厂商但出现的通用加固迹象
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generic_indicators: Vec<String>,
    pub decision: TriageDecision,
}

impl TriageReport {
    /// 导出组件 + 带 BOOT 等 action 的 receiver，是动态刺激的入口清单。
    pub fn entry_points(&self) -> Vec<&ComponentInfo> {
        self.components
            .iter()
            .filter(|c| {
                c.exported == Some(true)
                    || !c.actions.is_empty()
                    || matches!(c.kind, ComponentKind::Service)
            })
            .collect()
    }
}

/// 对一个 APK 字节流做预筛。
pub fn triage_apk(apk_bytes: &[u8]) -> droidunpack_core::Result<TriageReport> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(apk_bytes))
        .map_err(|e| droidunpack_core::Error::Apk(format!("无法打开 ZIP: {e}")))?;

    let mut manifest_index: Option<usize> = None;
    let mut dex_files = Vec::new();
    let mut native_libs = Vec::new();
    let mut asset_entries = Vec::new();

    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| droidunpack_core::Error::Apk(format!("读取 ZIP 条目失败: {e}")))?;
        let name = entry.name().to_string();
        let size = entry.size() as usize;

        if name == "AndroidManifest.xml" {
            manifest_index = Some(i);
        } else if name.ends_with(".dex") && name.starts_with("classes") {
            dex_files.push(DexInfo { path: name, size });
        } else if name.starts_with("lib/") && name.ends_with(".so") {
            native_libs.push(name);
        } else if name.starts_with("assets/") {
            asset_entries.push(name);
        }
    }

    let manifest_bytes = if let Some(i) = manifest_index {
        let mut buf = Vec::new();
        let mut entry = archive
            .by_index(i)
            .map_err(|e| droidunpack_core::Error::Apk(format!("读取清单失败: {e}")))?;
        std::io::copy(&mut entry, &mut buf).map_err(io_err)?;
        buf
    } else {
        Vec::new()
    };

    let manifest = if manifest_bytes.is_empty() {
        axml::ManifestSummary::default()
    } else {
        axml::parse_manifest(&manifest_bytes).unwrap_or_default()
    };

    let (packer, generic_indicators) =
        packer::detect(&native_libs, &asset_entries, &dex_files, &manifest);

    let decision = if packer
        .as_ref()
        .is_some_and(|p| p.confidence == PackerConfidence::High)
    {
        TriageDecision::DeepDynamic
    } else if packer.is_some()
        || !generic_indicators.is_empty()
        || manifest
            .permissions
            .iter()
            .any(|p| SUSPICIOUS_PERMS.iter().any(|s| p.contains(s)))
        || manifest.components.iter().any(|c| c.exported == Some(true))
    {
        TriageDecision::FullDynamic
    } else {
        TriageDecision::FastLane
    };

    Ok(TriageReport {
        package: manifest.package,
        min_sdk: manifest.min_sdk,
        target_sdk: manifest.target_sdk,
        permissions: manifest.permissions,
        components: manifest.components,
        dex_files,
        native_libs,
        packer,
        generic_indicators,
        decision,
    })
}

fn io_err(e: std::io::Error) -> droidunpack_core::Error {
    droidunpack_core::Error::Io(e)
}

/// 触发 FullDynamic 的高风险权限片段。
const SUSPICIOUS_PERMS: &[&str] = &[
    "SMS",
    "CONTACTS",
    "LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "CALL_PHONE",
    "DEVICE_ADMIN",
    "ACCESSIBILITY",
    "QUERY_ALL_PACKAGES",
    "BIND_NOTIFICATION_LISTENER",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn build_apk(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default();
            for (name, data) in entries {
                zip.start_file(*name, opts).unwrap();
                std::io::Write::write_all(&mut zip, data).unwrap();
            }
            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn detects_360_jiagu_and_routes_deep() {
        let apk = build_apk(&[
            ("AndroidManifest.xml", b"\x03\x00\x08\x00pad"),
            ("classes.dex", b"dex\n035\x00padding"),
            ("lib/arm64-v8a/libjiagu.so", b"\x7fELFdata"),
            ("assets/libjiagu.jar", b"xx"),
        ]);
        let report = triage_apk(&apk).unwrap();
        let hit = report.packer.expect("应识别出 360 加固");
        assert!(hit.vendor.contains("360"));
        assert_eq!(hit.confidence, PackerConfidence::High);
        assert_eq!(report.decision, TriageDecision::DeepDynamic);
    }

    #[test]
    fn plain_apk_without_packer_goes_fast_or_full() {
        let apk = build_apk(&[
            ("classes.dex", b"dex\n035\x00xxxx"),
            ("lib/arm64-v8a/libnative.so", b"\x7fELF"),
        ]);
        let report = triage_apk(&apk).unwrap();
        assert!(report.packer.is_none());
        assert_ne!(report.decision, TriageDecision::DeepDynamic);
    }
}
