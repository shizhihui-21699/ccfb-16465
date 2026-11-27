//! Static packer / loader fingerprints.
//!
//! These run before any code executes and drive what the sandbox should focus
//! on: which DEX classes look like a loader, which native libs a packer drops,
//! and which anti-analysis APIs are referenced.

use unhusk_dex::DexFile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackerHit {
    pub family: &'static str,
    pub evidence: String,
    /// Higher means more confident.
    pub score: u32,
}

/// Package prefixes and class names that almost always indicate a runtime
/// loader. These are matched against *class descriptors* only.
const LOADER_CLASSES: &[(&str, &str)] = &[
    ("com/tencent/StubShell", "Tencent Legu stub shell"),
    ("com/tencent/StubApp", "Tencent Legu stub app"),
    ("com/tencent/mobileqq/qfix", "Tencent QFix hotfix"),
    ("com/qihoo/util", "Qihoo 360 shell"),
    ("com/qihoo/StubApplication", "Qihoo 360 stub application"),
    ("com/secneo/apkwrapper", "SecNeo (Bangcle) wrapper"),
    ("com/bangcle", "Bangcle"),
    ("com/naver/protector", "Naver AppProtect"),
    ("com/ali/mobisecenhance", "Alibaba MobiSec"),
    ("com/taobao/wireless/security", "Alibaba SecurityGuard"),
    ("com/alipay/security", "Alipay security"),
    ("com/baidu/protect", "Baidu protect"),
    ("com/ijiami", "ijiami / jiagu"),
    ("com/netease/nis", "NetEase NiS"),
    ("com/jiagu", "Jiagu"),
    ("com/oneclickfix", "OneClickFix"),
    ("com/stub", "generic stub package"),
    ("com/sheild", "shield typo variant"),
    ("com/shield", "shield"),
    ("com/shell", "shell package"),
    ("com/kingsoft", "Kingsoft shell"),
    ("com/tencent/bugly", "Bugly (often bundled by packers)"),
];

const LOADER_CLASS_SUFFIX: &[(&str, &str)] = &[
    ("/StubApp", "StubApp class"),
    ("/StubShell", "StubShell class"),
    ("/ProxyApplication", "ProxyApplication class"),
    ("/StubApplication", "StubApplication class"),
    ("/MyApplication", "generic MyApplication"),
    ("/ShellApplication", "ShellApplication class"),
    ("/WrapperApplication", "WrapperApplication class"),
];

const NATIVE_MARKERS: &[(&str, &str)] = &[
    ("libjiagu", "ijiami jiagu"),
    ("libjiagu_art", "ijiami jiagu (ART)"),
    ("libjiagu_x86", "ijiami jiagu (x86)"),
    ("libshella", "Bangcle shella"),
    ("libshell", "Bangcle/generic shell"),
    ("libSecShell", "SecNeo shell"),
    ("libmobisec", "Alibaba MobiSec"),
    ("libsgmain", "Alibaba SecurityGuard main"),
    ("libsgsecuritybody", "Alibaba SecurityGuard body"),
    ("libDexHelper", "DexHelper"),
    ("libexec.so", "DexHelper exec"),
    ("libexecmain", "DexHelper execmain"),
    ("libprotectClass", "Naver AppProtect class"),
    ("libnesec", "NetEase NiS"),
    ("libbaiduprotect", "Baidu protect"),
    ("libnqshield", "NQ shield"),
    ("libDexLoader", "generic dex loader"),
    ("libdexloader", "generic dex loader"),
    ("libapp.so", "Flutter AOT payload"),
    ("libflutter.so", "Flutter runtime"),
    ("libreactnativejni", "React Native"),
    ("libhermes", "Hermes JS runtime"),
];

/// API names typical of anti-analysis and dynamic loading. Referenced from a
/// method reference table, so we only look at declarations.
const SUSPICIOUS_APIS: &[(&str, &str)] = &[
    ("getRuntime", "runtime hook"),
    ("exec", "process execution"),
    ("loadDex", "explicit DEX loading"),
    ("loadClass", "reflective class loading"),
    ("defineClass", "runtime class definition"),
    ("getDeclaredMethod", "reflection"),
    ("setAccessible", "reflection access bypass"),
    ("getSystemService", "telephony/sensor access"),
    ("getDeviceId", "device fingerprint"),
    ("getSubscriberId", "device fingerprint"),
    ("getSimSerialNumber", "device fingerprint"),
    ("getLine1Number", "device fingerprint"),
    ("getSensorList", "sensor probe"),
    ("registerListener", "sensor probe"),
    ("isEmulator", "emulator check"),
    ("getInstalledPackages", "installed app enumeration"),
    ("getRunningAppProcesses", "process enumeration"),
    ("getRunningServices", "service enumeration"),
    ("sendTextMessage", "SMS send"),
    ("getAccounts", "account enumeration"),
    ("DexClassLoader", "class loader construction"),
    ("PathClassLoader", "class loader construction"),
    ("InMemoryDexClassLoader", "in-memory DEX loader"),
    ("dalvik/system/DexFile", "raw DEX loader"),
];

pub fn scan_dex(dex: &DexFile) -> Vec<PackerHit> {
    let mut hits = Vec::new();
    for class in &dex.classes {
        let desc = class.descriptor.as_str();
        for (prefix, family) in LOADER_CLASSES {
            if desc.starts_with('L') && desc.contains(prefix) {
                hits.push(PackerHit {
                    family,
                    evidence: format!("class {desc}"),
                    score: 60,
                });
            }
        }
        for (suffix, family) in LOADER_CLASS_SUFFIX {
            if desc.starts_with('L') && desc.contains(suffix) {
                hits.push(PackerHit {
                    family,
                    evidence: format!("class {desc}"),
                    score: 25,
                });
            }
        }
    }
    // Multiple DEX files with a tiny stub is a strong shell signal.
    hits.dedup_by(|a, b| a.family == b.family && a.evidence == b.evidence);
    hits
}

pub fn scan_native(names: impl Iterator<Item = String>) -> Vec<PackerHit> {
    let mut hits = Vec::new();
    for name in names {
        let base = name.rsplit('/').next().unwrap_or(&name);
        for (marker, family) in NATIVE_MARKERS {
            if base.starts_with(marker) || base.contains(marker) {
                hits.push(PackerHit {
                    family,
                    evidence: format!("native lib {name}"),
                    score: 55,
                });
            }
        }
    }
    hits.dedup_by(|a, b| a.family == b.family && a.evidence == b.evidence);
    hits
}

/// API names referenced anywhere in the DEX (declaration or resolved reference
/// table), used as an "interest" signal for triage, not a verdict.
pub fn scan_apis(dex: &DexFile) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for m in &dex.methods {
        for (name, why) in SUSPICIOUS_APIS.iter().copied() {
            if m.name == name {
                out.push((m.signature(), why));
            }
        }
    }
    // DEX string constants: class loader type names show up even when the
    // method reference is hidden behind reflection.
    for (needle, why) in [
        ("dalvik/system/DexClassLoader", "DexClassLoader string"),
        (
            "dalvik/system/InMemoryDexClassLoader",
            "InMemoryDexClassLoader string",
        ),
        ("dalvik/system/PathClassLoader", "PathClassLoader string"),
    ] {
        let needle: &str = needle;
        if dex.strings.iter().any(|s| s.contains(needle)) {
            out.push((needle.to_string(), why));
        }
    }
    out
}
