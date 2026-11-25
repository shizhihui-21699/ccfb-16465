//! 加固厂商指纹库。
//!
//! 指纹分两类信号：
//! 1. native 库名/路径（壳的 loader 几乎必然带厂商特征 so）
//! 2. assets 中的加密载荷/jar 名称
//!
//! 单信号给 Medium，两类信号同时命中给 High。未知壳走 [`generic_indicators`]
//! 的通用迹象判定，不硬猜厂商——误报厂商会误导分析员。

use serde::{Deserialize, Serialize};

use crate::axml::ManifestSummary;
use crate::DexInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackerConfidence {
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerHit {
    pub vendor: String,
    pub family: String,
    pub confidence: PackerConfidence,
    /// 命中的具体证据，报告里直接展示
    pub evidence: Vec<String>,
}

struct Fingerprint {
    vendor: &'static str,
    family: &'static str,
    /// native 库路径子串（小写匹配）
    native: &'static [&'static str],
    /// assets/其它条路子串
    asset: &'static [&'static str],
}

/// 已知加固方案指纹。新厂商以数据形式追加，不需要改控制面代码。
const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        vendor: "360",
        family: "Jiagu",
        native: &[
            "libjiagu.so",
            "libjiagu_a64.so",
            "libjiagu_x86.so",
            "libprotectclass.so",
        ],
        asset: &["libjiagu.jar", "libjiagu_64.jar", "jiagu"],
    },
    Fingerprint {
        vendor: "Bangcle",
        family: "SecNeo",
        native: &[
            "libsecexe.so",
            "libsecmain.so",
            "libdexhelper.so",
            "libtup.so",
        ],
        asset: &["bangcle", "secdata", "0oo0ooo0"],
    },
    Fingerprint {
        vendor: "Tencent",
        family: "Legu/Bugly",
        native: &[
            "libshell.so",
            "libshella.so",
            "libshellx-super.2019.so",
            "libtup.so",
            "libcom.tencent.StubShell",
        ],
        asset: &["tosversion", "0OO00O00", "tencent_stub"],
    },
    Fingerprint {
        vendor: "Alibaba",
        family: "Bangcle-like/Jiagu360-alibaba",
        native: &["libmobisec.so", "libpreverify.so"],
        asset: &["alimobile", "libmobisec"],
    },
    Fingerprint {
        vendor: "Ijiami",
        family: "ijiami",
        native: &["libexec.so", "libexecmain.so", "ijiami"],
        asset: &["ijiami"],
    },
    Fingerprint {
        vendor: "Qihoo",
        family: "Qihoo-Atlas",
        native: &["libbaiduprotect.so"],
        asset: &["baiduprotect"],
    },
    Fingerprint {
        vendor: "Naga",
        family: "NagaShield",
        native: &["libnaga.so", "libnagae.so"],
        asset: &["naga"],
    },
    Fingerprint {
        vendor: "Google",
        family: "App-Bundle/PlayCore(壳化Dex)",
        native: &[],
        asset: &["split_config"],
    },
    Fingerprint {
        vendor: "Verimatrix",
        family: "Verimatrix/CodePRO",
        native: &["libverimatrix", "libcodepro"],
        asset: &["verimatrix"],
    },
];

/// 通用加固迹象（不指向具体厂商）。
fn generic_indicators(
    native_libs: &[String],
    assets: &[String],
    dex_files: &[DexInfo],
    manifest: &ManifestSummary,
) -> Vec<String> {
    let mut out = Vec::new();

    // 壳通常只留一个极小的 stub dex（真实 dex 在 assets 加密或内存释放）
    let tiny_stub = dex_files.len() == 1 && dex_files[0].size < 40 * 1024;
    if tiny_stub && !assets.is_empty() {
        out.push(format!(
            "仅存在 {} 字节的 stub dex，assets 含 {} 个可疑载荷",
            dex_files[0].size,
            assets.len()
        ));
    }

    // 壳的 Application 类常被替换为厂商 stub
    if let Some(app) = &manifest.application_class {
        let lower = app.to_lowercase();
        if ["stub", "shell", "wrapper", "proxy"]
            .iter()
            .any(|s| lower.contains(s))
        {
            out.push(format!("Application 类疑似壳 stub: {app}"));
        }
    }

    // 存在非标准命名的加密载荷文件（无扩展名的大文件）
    for a in assets {
        let has_ext = a.rsplit('/').next().is_some_and(|base| base.contains('.'));
        if !has_ext && !a.ends_with('/') {
            out.push(format!("assets 中无扩展名载荷: {a}"));
            if out.len() >= 8 {
                break;
            }
        }
    }

    // 同时打包多种 ABI 的 loader 是加固的常见特征（正常业务一般只放 1-2 个 ABI）
    let abis: std::collections::HashSet<&str> = native_libs
        .iter()
        .filter_map(|n| n.split('/').nth(1))
        .collect();
    if abis.len() >= 3 {
        out.push(format!(
            "native 库覆盖 {} 个 ABI，疑似通用壳 loader",
            abis.len()
        ));
    }

    out
}

pub fn detect(
    native_libs: &[String],
    assets: &[String],
    dex_files: &[DexInfo],
    manifest: &ManifestSummary,
) -> (Option<PackerHit>, Vec<String>) {
    let native_lower: Vec<String> = native_libs.iter().map(|s| s.to_lowercase()).collect();
    let asset_lower: Vec<String> = assets.iter().map(|s| s.to_lowercase()).collect();

    let mut best: Option<PackerHit> = None;
    for fp in FINGERPRINTS {
        let native_hits: Vec<String> = fp
            .native
            .iter()
            .filter(|needle| native_lower.iter().any(|n| n.contains(**needle)))
            .map(|s| format!("native:{s}"))
            .collect();
        let asset_hits: Vec<String> = fp
            .asset
            .iter()
            .filter(|needle| asset_lower.iter().any(|a| a.contains(**needle)))
            .map(|s| format!("asset:{s}"))
            .collect();

        if native_hits.is_empty() && asset_hits.is_empty() {
            continue;
        }
        let mut evidence = native_hits;
        evidence.extend(asset_hits);
        let confidence = if !fp.native.is_empty()
            && evidence.iter().any(|e| e.starts_with("native:"))
            && evidence.iter().any(|e| e.starts_with("asset:"))
        {
            PackerConfidence::High
        } else {
            PackerConfidence::Medium
        };
        let hit = PackerHit {
            vendor: fp.vendor.to_string(),
            family: fp.family.to_string(),
            confidence,
            evidence,
        };
        // 取证据最多的指纹作为最终结论
        if best
            .as_ref()
            .is_none_or(|b: &PackerHit| hit.evidence.len() > b.evidence.len())
        {
            best = Some(hit);
        }
    }

    let generic = generic_indicators(native_libs, assets, dex_files, manifest);
    (best, generic)
}
