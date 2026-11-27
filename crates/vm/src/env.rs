//! The emulated Android environment: build fingerprint, telephony, sensors,
//! filesystem and network. Two things matter here.
//!
//! 1. It must be *consistent*. Malware cross-checks `Build.MODEL` against
//!    `Build.DEVICE`, `/proc/cpuinfo` against the ABI list, and the SIM
//!    operator against the locale. A profile whose fields disagree is worse
//!    than no profile at all.
//! 2. It must be *observable*. Every access is recorded with the value the
//!    sample saw, so the report can show "this sample reads telephony state
//!    three times before it decrypts anything" — which is often the whole
//!    evasion strategy.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A coherent set of device properties. Values are chosen so that the common
/// emulator tests all answer "real device", including the cross-checks that
/// catch naive sandboxes (`goldfish`, `generic`, `sdk`, empty SIM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub name: String,
    pub manufacturer: String,
    pub brand: String,
    pub model: String,
    pub device: String,
    pub product: String,
    pub board: String,
    pub hardware: String,
    pub fingerprint: String,
    pub bootloader: String,
    pub tags: String,
    pub build_type: String,
    pub build_id: String,
    pub build_display: String,
    pub build_host: String,
    pub build_user: String,
    pub build_time: i64,
    pub incremental: String,
    pub radio: String,
    pub serial: String,
    pub sdk_int: i32,
    pub release: String,
    pub abis: Vec<String>,
    pub supported_abis: Vec<String>,
    pub cpu_abi: String,
    /// e.g. `Android/aosp_oriole/oriole:13/TQ3A...`
    pub cpuinfo: String,
    pub sim_operator: String,
    pub sim_operator_name: String,
    pub sim_country: String,
    pub sim_serial: String,
    pub network_operator: String,
    pub network_operator_name: String,
    pub network_country: String,
    pub network_type: String,
    pub subscriber_id: String,
    pub line1_number: String,
    pub device_id: String,
    pub android_id: String,
    pub locale: String,
    pub time_zone: String,
    pub screen_width: i32,
    pub screen_height: i32,
    pub battery_level: i32,
    pub battery_temp_tenths: i32,
    pub battery_charging: bool,
    pub sensors: Vec<SensorInfo>,
    pub installed_packages: Vec<InstalledPackage>,
    /// Paths that exist in the virtual filesystem (plus anything the app wrote).
    pub existing_paths: Vec<String>,
    pub browser_packages: Vec<String>,
    pub wifi_ssid: String,
    pub wifi_bssid: String,
    pub is_rooted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorInfo {
    pub name: String,
    pub vendor: String,
    pub kind: String,
    pub values: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub label: String,
    pub version: String,
    pub system: bool,
}

/// A realistic mid-range Pixel on Android 13. Chosen because it is old enough
/// that `targetSdk < 31` apps still run with the legacy exported semantics and
/// new enough to have every API the sample might probe.
pub fn pixel_profile() -> DeviceProfile {
    DeviceProfile {
        name: "pixel6-a13".into(),
        manufacturer: "Google".into(),
        brand: "google".into(),
        model: "Pixel 6".into(),
        device: "oriole".into(),
        product: "oriole".into(),
        board: "oriole".into(),
        hardware: "oriole".into(),
        fingerprint: "google/oriole/oriole:13/TQ3A.230805.001/10316531:user/release-keys".into(),
        bootloader: "slider-1.0-9179901".into(),
        tags: "release-keys".into(),
        build_type: "user".into(),
        build_id: "TQ3A.230805.001".into(),
        build_display: "TQ3A.230805.001".into(),
        build_host: "abfarm-release-2".into(),
        build_user: "android-build".into(),
        build_time: 1_691_162_867_000,
        incremental: "10316531".into(),
        radio: "g5123b-116432-230509-B-10065656".into(),
        serial: "2B161FDH2000QJ".into(),
        sdk_int: 33,
        release: "13".into(),
        abis: vec!["arm64-v8a".into(), "armeabi-v7a".into(), "armeabi".into()],
        supported_abis: vec!["arm64-v8a".into(), "armeabi-v7a".into(), "armeabi".into()],
        cpu_abi: "arm64-v8a".into(),
        cpuinfo: "processor\t: 0\nBogoMIPS\t: 78.00\nFeatures\t: fp asimd evtstrm aes \
                  pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop \
                  asimddp\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x0\n\
                  CPU part\t: 0xd44\nCPU revision\t: 2\n\nHardware\t: Oriole\n"
            .into(),
        sim_operator: "310260".into(),
        sim_operator_name: "T-Mobile".into(),
        sim_country: "us".into(),
        sim_serial: "8901260123456789012".into(),
        network_operator: "310260".into(),
        network_operator_name: "T-Mobile".into(),
        network_country: "us".into(),
        network_type: "LTE".into(),
        subscriber_id: "310260123456789".into(),
        line1_number: "+15551234567".into(),
        device_id: "351234567890123".into(),
        android_id: "3f2a8c1d9e4b7f60".into(),
        locale: "en-US".into(),
        time_zone: "America/New_York".into(),
        screen_width: 1080,
        screen_height: 2400,
        battery_level: 73,
        battery_temp_tenths: 281,
        battery_charging: false,
        sensors: vec![
            SensorInfo {
                name: "LSM6DSO Accelerometer".into(),
                vendor: "STMicroelectronics".into(),
                kind: "accelerometer".into(),
                values: vec![0.12, 9.79, 0.31],
            },
            SensorInfo {
                name: "LSM6DSO Gyroscope".into(),
                vendor: "STMicroelectronics".into(),
                kind: "gyroscope".into(),
                values: vec![0.001, -0.002, 0.0005],
            },
            SensorInfo {
                name: "AK09918 Magnetometer".into(),
                vendor: "AKM".into(),
                kind: "magnetometer".into(),
                values: vec![-18.2, 41.7, -33.9],
            },
            SensorInfo {
                name: "Proximity".into(),
                vendor: "Google".into(),
                kind: "proximity".into(),
                values: vec![5.0],
            },
            SensorInfo {
                name: "Light".into(),
                vendor: "Google".into(),
                kind: "light".into(),
                values: vec![212.0],
            },
        ],
        installed_packages: vec![
            InstalledPackage {
                name: "com.android.chrome".into(),
                label: "Chrome".into(),
                version: "117.0.5938.60".into(),
                system: false,
            },
            InstalledPackage {
                name: "com.google.android.gms".into(),
                label: "Google Play services".into(),
                version: "23.34.15".into(),
                system: true,
            },
            InstalledPackage {
                name: "com.android.vending".into(),
                label: "Google Play Store".into(),
                version: "37.0.19".into(),
                system: true,
            },
            InstalledPackage {
                name: "com.whatsapp".into(),
                label: "WhatsApp".into(),
                version: "2.23.18.79".into(),
                system: false,
            },
            InstalledPackage {
                name: "com.android.settings".into(),
                label: "Settings".into(),
                version: "13".into(),
                system: true,
            },
            InstalledPackage {
                name: "com.google.android.apps.maps".into(),
                label: "Maps".into(),
                version: "11.97.1".into(),
                system: false,
            },
            InstalledPackage {
                name: "com.android.systemui".into(),
                label: "System UI".into(),
                version: "13".into(),
                system: true,
            },
            InstalledPackage {
                name: "com.google.android.gm".into(),
                label: "Gmail".into(),
                version: "2023.08.20".into(),
                system: false,
            },
            InstalledPackage {
                name: "com.tencent.mm".into(),
                label: "WeChat".into(),
                version: "8.0.40".into(),
                system: false,
            },
            InstalledPackage {
                name: "com.facebook.katana".into(),
                label: "Facebook".into(),
                version: "425.0.0".into(),
                system: false,
            },
        ],
        existing_paths: vec![
            "/system".into(),
            "/system/bin".into(),
            "/system/lib64".into(),
            "/system/app".into(),
            "/system/priv-app".into(),
            "/data".into(),
            "/data/local".into(),
            "/data/local/tmp".into(),
            "/sdcard".into(),
            "/storage/emulated/0".into(),
            "/proc".into(),
            "/proc/cpuinfo".into(),
            "/proc/meminfo".into(),
            "/proc/version".into(),
            "/proc/self".into(),
            "/proc/self/maps".into(),
            "/sys".into(),
            "/sys/class".into(),
            "/vendor".into(),
            "/vendor/lib64".into(),
        ],
        browser_packages: vec![
            "com.android.chrome".into(),
            "org.mozilla.firefox".into(),
            "com.android.browser".into(),
        ],
        wifi_ssid: "HOME-7F2A".into(),
        wifi_bssid: "3c:5a:b4:1d:9e:02".into(),
        is_rooted: false,
    }
}

/// Paths commonly used by emulator checks. Their *absence* is the point: a
/// hardened profile must not have su or the classic emulator files.
pub const EMULATOR_ARTIFACTS: &[&str] = &[
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/.ext/.su",
    "/dev/socket/qemud",
    "/dev/qemu_pipe",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemu-props",
    "/system/lib/libdvm.so",
];

/// A deliberately naive profile: the kind of emulator a sample is written to
/// detect. Running the same sample under both profiles and diffing the traces
/// shows exactly which checks gate the malicious path.
pub fn naive_emulator_profile() -> DeviceProfile {
    let mut p = pixel_profile();
    p.name = "generic-emulator".into();
    p.manufacturer = "unknown".into();
    p.brand = "generic".into();
    p.model = "sdk".into();
    p.device = "generic".into();
    p.product = "sdk".into();
    p.board = "goldfish".into();
    p.hardware = "goldfish".into();
    p.fingerprint = "generic/sdk/generic:7.1.1/NMF26X/1234567:eng/test-keys".into();
    p.bootloader = "unknown".into();
    p.tags = "test-keys".into();
    p.build_type = "eng".into();
    p.build_id = "NMF26X".into();
    p.build_display = "sdk-eng".into();
    p.build_host = "android-test".into();
    p.radio = "unknown".into();
    p.serial = "unknown".into();
    p.sdk_int = 25;
    p.release = "7.1.1".into();
    p.cpu_abi = "x86".into();
    p.abis = vec!["x86".into()];
    p.supported_abis = vec!["x86".into()];
    p.sim_operator = "".into();
    p.sim_operator_name = "Android".into();
    p.sim_serial = "".into();
    p.subscriber_id = "".into();
    p.line1_number = "".into();
    p.device_id = "000000000000000".into();
    p.android_id = "9774d56d682e549c".into();
    p.sensors = Vec::new();
    p.battery_level = 100;
    p.battery_charging = true;
    p.loaded_packages_clear();
    p
}

impl DeviceProfile {
    fn loaded_packages_clear(&mut self) {
        self.installed_packages
            .retain(|p| p.system && p.name == "com.android.settings");
    }

    /// `/proc/cpuinfo` bytes as the sample would read them.
    pub fn cpuinfo_bytes(&self) -> Vec<u8> {
        self.cpuinfo.as_bytes().to_vec()
    }

    pub fn sensor(&self, kind: &str) -> Option<&SensorInfo> {
        self.sensors
            .iter()
            .find(|s| s.kind.eq_ignore_ascii_case(kind) || s.name.to_lowercase().contains(kind))
    }
}

/// Deterministic pseudo-random source. Seeded per run so two runs of the same
/// sample produce the same trace, which makes regression tests possible.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn next_i32(&mut self) -> i32 {
        self.next_u32() as i32
    }

    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.next_u32() % n
        }
    }
}

/// The virtual filesystem: a small overlay of pre-existing paths plus anything
/// the sample writes during execution.
#[derive(Debug, Default, Clone)]
pub struct VirtualFs {
    pub existing: Vec<String>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub dirs: Vec<String>,
    /// Total bytes written, for budget enforcement.
    pub bytes_written: u64,
}

impl VirtualFs {
    pub fn from_profile(p: &DeviceProfile) -> Self {
        Self {
            existing: p.existing_paths.clone(),
            files: BTreeMap::new(),
            dirs: vec!["/".into()],
            bytes_written: 0,
        }
    }

    pub fn exists(&self, path: &str) -> bool {
        let p = normalize_path(path);
        self.files.contains_key(&p)
            || self.existing.iter().any(|e| normalize_path(e) == p)
            || self.dirs.iter().any(|d| normalize_path(d) == p)
    }

    pub fn is_file(&self, path: &str) -> bool {
        let p = normalize_path(path);
        self.files.contains_key(&p)
    }

    pub fn read(&self, path: &str) -> Option<&[u8]> {
        self.files.get(&normalize_path(path)).map(|v| v.as_slice())
    }

    pub fn write(&mut self, path: &str, data: Vec<u8>) {
        self.bytes_written = self.bytes_written.saturating_add(data.len() as u64);
        self.files.insert(normalize_path(path), data);
    }

    pub fn remove(&mut self, path: &str) -> bool {
        self.files.remove(&normalize_path(path)).is_some()
    }

    pub fn list(&self, dir: &str) -> Vec<String> {
        let d = normalize_path(dir);
        let prefix = if d.ends_with('/') {
            d.clone()
        } else {
            format!("{d}/")
        };
        let mut out: Vec<String> = self
            .files
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn size(&self, path: &str) -> u64 {
        self.read(path).map(|d| d.len() as u64).unwrap_or(0)
    }
}

pub fn normalize_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Network egress model. By default requests are *recorded only* — nothing
/// leaves the machine. Optionally a canned response can be supplied so the
/// sample continues down its post-exfiltration path.
#[derive(Debug, Clone)]
pub struct NetworkModel {
    pub allow_egress: bool,
    pub default_response: Vec<u8>,
    pub default_status: i32,
    /// Requests seen, keyed by method+url; the report cites these.
    pub requests: Vec<RecordedRequest>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecordedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub caller: String,
    pub body_provenance: String,
}

impl Default for NetworkModel {
    fn default() -> Self {
        Self {
            allow_egress: false,
            default_response: b"OK".to_vec(),
            default_status: 200,
            requests: Vec::new(),
        }
    }
}

/// The clock the sample sees. Deterministic and plausible: a bit after the
/// build date of the profile, advancing slowly with execution.
#[derive(Debug, Clone)]
pub struct VirtualClock {
    pub base_ms: i64,
    pub boot_ms: i64,
    pub elapsed_boot_ms: u64,
    pub ticks: u64,
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self {
            // 2024-03-14T09:26:53Z, a plausible "now" for a 2023 build.
            base_ms: 1_710_408_413_000,
            boot_ms: 1_710_400_000_000,
            elapsed_boot_ms: 0,
            ticks: 0,
        }
    }
}

impl VirtualClock {
    pub fn now_ms(&mut self) -> i64 {
        self.ticks += 1;
        self.base_ms + (self.ticks / 1000) as i64
    }

    pub fn uptime_ms(&mut self) -> i64 {
        self.elapsed_boot_ms as i64 + (self.ticks / 100) as i64
    }

    pub fn elapsed_realtime_ms(&mut self) -> i64 {
        self.elapsed_boot_ms as i64 + (self.ticks / 100) as i64
    }
}

/// Everything the "phone" knows. Kept separate from the heap so that profile
/// selection is a parameter of execution, not a mutation of program state.
#[derive(Debug, Clone)]
pub struct Env {
    pub profile: DeviceProfile,
    pub fs: VirtualFs,
    pub net: NetworkModel,
    pub clock: VirtualClock,
    pub rng: Rng,
    pub package_name: String,
    pub app_data_dir: String,
    pub assets: BTreeMap<String, Vec<u8>>,
    pub resources: BTreeMap<String, Vec<u8>>,
    /// Values the app stored in SharedPreferences, per file.
    pub prefs: BTreeMap<String, BTreeMap<String, String>>,
    /// Emulator-check results the sample observed, keyed by check name.
    pub checks: BTreeMap<String, String>,
    pub sdk_int: i32,
    pub pid: i32,
    pub uid: i32,
}

impl Env {
    pub fn new(profile: DeviceProfile, package: impl Into<String>, seed: u64) -> Self {
        let package = package.into();
        let app_data_dir = format!("/data/data/{package}");
        let sdk_int = profile.sdk_int;
        Self {
            fs: VirtualFs::from_profile(&profile),
            profile,
            net: NetworkModel::default(),
            clock: VirtualClock::default(),
            rng: Rng::new(seed),
            package_name: package,
            app_data_dir,
            assets: BTreeMap::new(),
            resources: BTreeMap::new(),
            prefs: BTreeMap::new(),
            checks: BTreeMap::new(),
            sdk_int,
            pid: 12345,
            uid: 10123,
        }
    }

    pub fn files_dir(&self) -> String {
        format!("{}/files", self.app_data_dir)
    }

    pub fn cache_dir(&self) -> String {
        format!("{}/cache", self.app_data_dir)
    }

    pub fn external_dir(&self) -> String {
        "/storage/emulated/0".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_cross_checks_are_consistent() {
        let p = pixel_profile();
        // The classic detection triples must agree.
        assert!(!p.model.eq_ignore_ascii_case("sdk"));
        assert!(!p.fingerprint.contains("generic"));
        assert!(!p.fingerprint.contains("test-keys"));
        assert!(!p.hardware.contains("goldfish"));
        assert!(!p.sim_operator.is_empty());
        assert!(!p.sensors.is_empty());
        assert!(p.fingerprint.contains(&p.device));
    }

    #[test]
    fn naive_profile_trips_the_classic_checks() {
        let p = naive_emulator_profile();
        assert_eq!(p.model, "sdk");
        assert!(p.fingerprint.contains("test-keys"));
        assert_eq!(p.hardware, "goldfish");
        assert!(p.sensors.is_empty());
        assert!(p.sim_operator.is_empty());
    }

    #[test]
    fn fs_normalizes_and_roundtrips() {
        let mut fs = VirtualFs::default();
        fs.write("/data//local/./tmp/x", b"hi".to_vec());
        assert_eq!(fs.read("/data/local/tmp/x").unwrap(), b"hi");
        assert!(fs.exists("/data/local/tmp/x"));
        assert_eq!(fs.list("/data/local/tmp"), vec!["x".to_string()]);
        assert!(fs.remove("/data/local/tmp/x"));
        assert!(!fs.exists("/data/local/tmp/x"));
    }

    #[test]
    fn emulator_artifacts_are_absent_from_hardened_profile() {
        let p = pixel_profile();
        let fs = VirtualFs::from_profile(&p);
        for path in EMULATOR_ARTIFACTS {
            assert!(
                !fs.exists(path),
                "{path} must not exist in the hardened profile"
            );
        }
    }
}
