//! Simulated Android device.
//!
//! Malware decides what to do based on its environment: build fingerprint,
//! IMEI, sensor list, battery, installed packages, wall clock, network
//! reachability, `Settings.Secure` values. The environment is therefore a
//! first-class, *data* object that scenarios vary. Nothing here touches the
//! host: the clock is virtual, the filesystem is an in-memory map, and network
//! operations are answered from a script rather than sent anywhere.
//!
//! Every read of a probe-shaped API is logged as a `Probe` so the report can
//! say which facts the sample used to make decisions.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::report::Probe;

/// Deterministic PRNG (xorshift64*) so a scenario replays identically.
#[derive(Debug, Clone, Copy)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    pub fn range_i32(&mut self, lo: i32, hi: i32) -> i32 {
        if hi <= lo {
            lo
        } else {
            lo + self.below((hi - lo) as u64) as i32
        }
    }
}

/// Hardware/software identity of the simulated device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub manufacturer: String,
    pub brand: String,
    pub model: String,
    pub device: String,
    pub product: String,
    pub hardware: String,
    pub board: String,
    pub fingerprint: String,
    pub tags: String,
    pub bootloader: String,
    pub id: String,
    pub serial: String,
    pub sdk_int: i32,
    pub release: String,
    pub incremental: String,
    pub cpu_abi: String,
    pub radio: String,
}

impl DeviceIdentity {
    /// A mainstream retail phone. Deliberately *not* emulator-shaped: most
    /// real malware refuses to run when it sees `goldfish`/`sdk`/`vbox`.
    pub fn retail_phone() -> Self {
        DeviceIdentity {
            manufacturer: "samsung".into(),
            brand: "samsung".into(),
            model: "SM-G991B".into(),
            device: "o1s".into(),
            product: "o1sxx".into(),
            hardware: "exynos2100".into(),
            board: "exynos2100".into(),
            fingerprint: "samsung/o1sxx/o1s:12/SP1A.210812.016/G991BXXU3BUK8:user/release-keys".into(),
            tags: "release-keys".into(),
            bootloader: "G991BXXU3BUK8".into(),
            id: "SP1A.210812.016".into(),
            serial: "R58M80ABCDE".into(),
            sdk_int: 31,
            release: "12".into(),
            incremental: "G991BXXU3BUK8".into(),
            cpu_abi: "arm64-v8a".into(),
            radio: "G991BXXU3BUK8".into(),
        }
    }

    /// A low-end device: fewer sensors, slower clock, less memory. Some samples
    /// only fire on cheap hardware to blend with botnet populations.
    pub fn cheap_phone() -> Self {
        DeviceIdentity {
            manufacturer: "Xiaomi".into(),
            brand: "Redmi".into(),
            model: "M2007J20CG".into(),
            device: "surrus".into(),
            product: "surrus_global".into(),
            hardware: "surrus".into(),
            board: "surrus".into(),
            fingerprint: "Redmi/surrus_global/surrus:11/RKQ1.200826.002/V12.5.4.0:user/release-keys".into(),
            tags: "release-keys".into(),
            bootloader: "unknown".into(),
            id: "RKQ1.200826.002".into(),
            serial: "b4c1e0d9".into(),
            sdk_int: 30,
            release: "11".into(),
            incremental: "V12.5.4.0".into(),
            cpu_abi: "arm64-v8a".into(),
            radio: "unknown".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Telephony {
    pub imei: String,
    pub imsi: String,
    pub iccid: String,
    pub msisdn: String,
    pub sim_operator: String,
    pub network_operator: String,
    pub network_operator_name: String,
    pub sim_operator_name: String,
    pub sim_state: i32,
    pub phone_type: i32,
    pub network_type: i32,
    /// False makes `getDeviceId` return null, as on a device with no SIM.
    pub sim_present: bool,
}

impl Telephony {
    pub fn with_sim() -> Self {
        Telephony {
            imei: "354918476201935".into(),
            imsi: "310410861243509".into(),
            iccid: "89014103211234567890".into(),
            msisdn: "+12025550143".into(),
            sim_operator: "310410".into(),
            network_operator: "310410".into(),
            network_operator_name: "AT&T".into(),
            sim_operator_name: "AT&T".into(),
            sim_state: 5,  // SIM_STATE_READY
            phone_type: 1, // PHONE_TYPE_GSM
            network_type: 13, // LTE
            sim_present: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationFix {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: f32,
    pub provider: String,
    pub has_altitude: bool,
    pub altitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorInfo {
    pub name: String,
    pub vendor: String,
    pub type_id: i32,
    pub max_range: f32,
    pub resolution: f32,
    pub power: f32,
}

/// Battery state. Samples sometimes wait for charging or a low battery before
/// acting; scenarios sweep these values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Battery {
    pub level: i32,
    pub scale: i32,
    pub status: i32,
    pub plugged: i32,
    pub health: i32,
    pub temperature: i32,
    pub voltage: i32,
    pub present: bool,
}

impl Default for Battery {
    fn default() -> Self {
        Battery {
            level: 76,
            scale: 100,
            status: 3,   // DISCHARGING
            plugged: 0,  // BATTERY_PLUGGED_NONE
            health: 2,   // GOOD
            temperature: 291,
            voltage: 4011,
            present: true,
        }
    }
}

/// One scripted HTTP interaction. The sandbox never dials out; a request is
/// matched to a response and recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRule {
    /// Substring matched against the full URL.
    pub url_contains: String,
    pub status: i32,
    pub body: String,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// Whether sockets/URL connections appear to succeed.
    pub reachable: bool,
    pub rules: Vec<HttpRule>,
    /// Body returned when no rule matches.
    pub default_body: String,
    pub default_status: i32,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            reachable: true,
            rules: Vec::new(),
            default_body: "ok".into(),
            default_status: 200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub label: String,
    pub is_system: bool,
    pub is_debuggable: bool,
}

/// Everything that defines "which device is this, right now".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    pub name: String,
    pub description: String,
    pub identity: DeviceIdentity,
    pub telephony: Telephony,
    pub location: LocationFix,
    pub sensors: Vec<SensorInfo>,
    pub battery: Battery,
    pub network: Network,
    pub packages: Vec<InstalledPackage>,
    /// Wall clock at scenario start, milliseconds since the Unix epoch.
    pub start_time_millis: i64,
    /// Time zone offset in minutes used by `Calendar`/`Date`.
    pub tz_offset_minutes: i32,
    pub locale: String,
    pub android_id: String,
    pub boot_id: String,
    pub rng_seed: u64,
    /// Answers to `Settings.Secure` / `Settings.Global` keys.
    pub settings_secure: BTreeMap<String, String>,
    pub settings_global: BTreeMap<String, String>,
    /// `System.getProperty` answers.
    pub system_properties: BTreeMap<String, String>,
    /// Files that "exist" on the device, with their simulated contents.
    pub files: HashMap<String, Vec<u8>>,
    /// The APK's `assets/` and `res/raw/` entries, keyed without the prefix.
    /// Packers overwhelmingly stash their payload here.
    pub assets: HashMap<String, Vec<u8>>,
}

impl Persona {
    pub fn retail_default() -> Self {
        let mut settings_secure = BTreeMap::new();
        settings_secure.insert("android_id".into(), "3f7c1a90b2d4e8f1".into());
        settings_secure.insert("enabled_accessibility_services".into(), String::new());
        let mut settings_global = BTreeMap::new();
        settings_global.insert("device_name".into(), "Galaxy S21".into());
        settings_global.insert("adb_enabled".into(), "0".into());
        settings_global.insert("development_settings_enabled".into(), "0".into());
        let mut system_properties = BTreeMap::new();
        system_properties.insert("ro.kernel.qemu".into(), "0".into());
        system_properties.insert("ro.debuggable".into(), "0".into());
        system_properties.insert("ro.secure".into(), "1".into());
        system_properties.insert("java.vm.version".into(), "2.1.0".into());
        system_properties.insert("os.arch".into(), "aarch64".into());
        system_properties.insert("user.language".into(), "en".into());
        system_properties.insert("user.region".into(), "US".into());
        system_properties.insert("http.agent".into(), "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)".into());

        let packages = vec![
            pkg("com.android.settings", "Settings", true),
            pkg("com.google.android.gms", "Google Play services", true),
            pkg("com.android.vending", "Google Play Store", true),
            pkg("com.samsung.android.messaging", "Messages", false),
            pkg("com.whatsapp", "WhatsApp", false),
            pkg("com.android.chrome", "Chrome", false),
            pkg("com.instagram.android", "Instagram", false),
            pkg("com.zhiliaoapp.musically", "TikTok", false),
            pkg("com.samsung.android.calendar", "Calendar", false),
            pkg("com.google.android.apps.maps", "Maps", false),
            pkg("com.samsung.android.app.contacts", "Contacts", false),
            pkg("com.netflix.mediaclient", "Netflix", false),
            pkg("com.spotify.music", "Spotify", false),
            pkg("com.android.email", "Email", false),
            pkg("com.samsung.android.forest", "Digital Wellbeing", false),
        ];

        Persona {
            name: "retail".into(),
            description: "Mainstream Samsung retail device, SIM present, 15 apps installed".into(),
            identity: DeviceIdentity::retail_phone(),
            telephony: Telephony::with_sim(),
            location: LocationFix {
                latitude: 37.4219983,
                longitude: -122.084,
                accuracy: 12.0,
                provider: "gps".into(),
                has_altitude: true,
                altitude: 32.0,
            },
            sensors: realistic_sensors(),
            battery: Battery::default(),
            network: Network::default(),
            packages,
            start_time_millis: 1_782_000_000_000, // 2026-06-21T..Z, arbitrary
            tz_offset_minutes: -420,
            locale: "en_US".into(),
            android_id: "3f7c1a90b2d4e8f1".into(),
            boot_id: "5f8a2c1e-7b3d-4f10-9e22-6a1d4c8b9f30".into(),
            rng_seed: 0x5EED_1234_ABCD_0001,
            settings_secure,
            settings_global,
            system_properties,
            files: HashMap::new(),
            assets: HashMap::new(),
        }
    }

    /// A device with no SIM card, few apps and a nearly empty sensor list.
    /// Used to test samples that branch on "is this a real user's phone".
    pub fn sparse_device() -> Self {
        let mut p = Self::retail_default();
        p.name = "sparse".into();
        p.description = "No-SIM device with almost no apps; a common 'farm phone' shape".into();
        p.telephony = Telephony {
            imei: String::new(),
            imsi: String::new(),
            iccid: String::new(),
            msisdn: String::new(),
            sim_operator: String::new(),
            network_operator: "310260".into(),
            network_operator_name: "Android".into(),
            sim_operator_name: "Android".into(),
            sim_state: 1,
            phone_type: 0,
            network_type: 0,
            sim_present: false,
        };
        p.identity = DeviceIdentity::cheap_phone();
        p.packages = p
            .packages
            .into_iter()
            .filter(|x| x.is_system)
            .take(4)
            .collect();
        p.sensors.truncate(3);
        p.battery.level = 14;
        p.android_id = "9774d56d682e549c".into();
        p
    }

    pub fn battery_charging(mut self) -> Self {
        self.name = "charging".into();
        self.battery.status = 2; // CHARGING
        self.battery.plugged = 1;
        self.battery.level = 100;
        self
    }

    /// Start the clock `hours` later. Some droppers wait days before acting.
    pub fn at_offset_hours(mut self, hours: i64) -> Self {
        self.start_time_millis += hours * 3_600_000;
        self.name = format!("{}+{}h", self.name, hours);
        self
    }
}

fn pkg(name: &str, label: &str, system: bool) -> InstalledPackage {
    InstalledPackage {
        name: name.into(),
        label: label.into(),
        is_system: system,
        is_debuggable: false,
    }
}

/// Sensor list shaped like a real phone: accelerometer, gyroscope, magnetometer,
/// proximity, light, pressure, step counter, heart rate.
fn realistic_sensors() -> Vec<SensorInfo> {
    let mk = |name: &str, vendor: &str, t: i32, max: f32, res: f32, power: f32| SensorInfo {
        name: name.into(),
        vendor: vendor.into(),
        type_id: t,
        max_range: max,
        resolution: res,
        power,
    };
    vec![
        mk("LSM6DSO Accelerometer", "STMicroelectronics", 1, 78.4532, 0.0024, 0.16),
        mk("LSM6DSO Gyroscope", "STMicroelectronics", 4, 34.906586, 0.0, 0.35),
        mk("AK09918 Magnetometer", "AKM", 2, 4912.0, 0.15, 0.5),
        mk("STK3338 Proximity", "Samsung", 8, 8.0, 8.0, 0.5),
        mk("STK3338 Light", "Samsung", 5, 90000.0, 1.0, 0.5),
        mk("LPS22HH Pressure", "STMicroelectronics", 6, 1300.0, 0.002, 0.004),
        mk("Step Counter", "Samsung", 19, 100000.0, 1.0, 0.1),
    ]
}

/// Mutable runtime environment for one scenario.
pub struct Environment {
    pub persona: Persona,
    pub clock_millis: i64,
    pub rng: Rng,
    /// Probes recorded so far.
    pub probes: Vec<Probe>,
    pub coverage_gaps: BTreeMap<String, u64>,
    /// Simulated filesystem: path -> contents.
    pub files: HashMap<String, Vec<u8>>,
    /// SharedPreferences: file -> key -> value.
    pub prefs: HashMap<String, HashMap<String, String>>,
    /// SMS messages sent by the sample.
    pub sms_sent: Vec<SmsRecord>,
    /// Shell commands attempted.
    pub commands: Vec<String>,
    /// Network requests made, in order.
    pub requests: Vec<RequestRecord>,
    /// Inbound data the sandbox fabricates for the sample to "receive".
    pub inbox_sms: Vec<SmsRecord>,
    pub contacts: Vec<ContactRecord>,
    pub call_log: Vec<CallRecord>,
    pub clipboard: String,
    /// Files pulled out of the simulated device by the sample (exfil staging).
    pub staged_uploads: Vec<String>,
    /// Number of times each grpc/unmodeled call was seen.
    pub unmodeled_calls: BTreeMap<String, u64>,
    pub scenario_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsRecord {
    pub address: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRecord {
    pub name: String,
    pub number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub number: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRecord {
    pub method: String,
    pub url: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
    /// Seconds since scenario start when the request was made.
    pub at_millis: i64,
}

impl Environment {
    pub fn new(persona: Persona) -> Self {
        let clock_millis = persona.start_time_millis;
        let rng = Rng::new(persona.rng_seed);
        let scenario_name = persona.name.clone();
        let files = persona.files.clone();
        let _assets = persona.assets.clone();
        Environment {
            persona,
            clock_millis,
            rng,
            probes: Vec::new(),
            coverage_gaps: BTreeMap::new(),
            files,
            prefs: HashMap::new(),
            sms_sent: Vec::new(),
            commands: Vec::new(),
            requests: Vec::new(),
            inbox_sms: vec![SmsRecord {
                address: "+12025550143".into(),
                body: "Your verification code is 483920. Do not share it.".into(),
            }],
            contacts: vec![
                ContactRecord { name: "Alex Chen".into(), number: "+14085550117".into() },
                ContactRecord { name: "Maria Lopez".into(), number: "+13105550182".into() },
                ContactRecord { name: "Sam Patel".into(), number: "+16505550139".into() },
            ],
            call_log: vec![
                CallRecord { number: "+14085550117".into(), kind: "OUTGOING".into() },
                CallRecord { number: "+13105550182".into(), kind: "MISSED".into() },
            ],
            clipboard: String::new(),
            staged_uploads: Vec::new(),
            unmodeled_calls: BTreeMap::new(),
            scenario_name,
        }
    }

    pub fn now(&self) -> i64 {
        self.clock_millis
    }

    /// Advance the virtual clock. Used by `Thread.sleep`, `postDelayed` and
    /// explicit scheduler fast-forward. The interpreter counts these as steps,
    /// so a sleep-forever loop still terminates.
    pub fn advance(&mut self, ms: i64) {
        if ms > 0 {
            self.clock_millis = self.clock_millis.saturating_add(ms);
        }
    }

    pub fn probe(&mut self, api: &str, value: impl Into<String>) {
        if self.probes.len() < 4000 {
            self.probes.push(Probe {
                api: api.to_string(),
                value: value.into(),
                scenario: self.scenario_name.clone(),
            });
        }
    }

    pub fn gap(&mut self, what: &str) {
        *self.coverage_gaps.entry(what.to_string()).or_insert(0) += 1;
    }

    /// Look up an APK asset by the name the sample passes to
    /// `AssetManager.open`. Android accepts the name with or without the
    /// `assets/` prefix, and `res/raw` entries are also reachable.
    pub fn asset(&self, name: &str) -> Option<&[u8]> {
        let trimmed = name.trim_start_matches("assets/");
        self.persona.assets
            .get(name)
            .or_else(|| self.persona.assets.get(trimmed))
            .map(|v| v.as_slice())
    }

    pub fn asset_names(&self) -> Vec<String> {
        self.persona.assets.keys().cloned().collect()
    }

    pub fn file_exists(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }

    pub fn read_file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(|v| v.as_slice())
    }

    pub fn write_file(&mut self, path: String, data: Vec<u8>) {
        if self.files.len() < 100_000 {
            self.files.insert(path, data);
        }
    }

    /// Match a URL against the scenario's scripted HTTP rules.
    pub fn http_response(&self, url: &str) -> (i32, String, String) {
        for r in &self.persona.network.rules {
            if url.contains(&r.url_contains) {
                return (r.status, r.body.clone(), r.content_type.clone());
            }
        }
        (
            self.persona.network.default_status,
            self.persona.network.default_body.clone(),
            "text/plain".into(),
        )
    }

    pub fn system_property(&mut self, key: &str) -> String {
        let v = self
            .persona
            .system_properties
            .get(key)
            .cloned()
            .unwrap_or_default();
        self.probe(&format!("System.getProperty({key})"), &v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retail_persona_is_not_emulator_shaped() {
        let p = Persona::retail_default();
        let f = p.identity.fingerprint.to_lowercase();
        for marker in ["generic", "sdk", "emulator", "vbox", "goldfish", "ranchu"] {
            assert!(!f.contains(marker), "fingerprint leaks {marker}");
        }
        assert!(!p.telephony.imei.is_empty());
        assert_ne!(p.sensors.len(), 0);
        assert!(p.packages.len() >= 10);
        assert_eq!(p.system_properties["ro.kernel.qemu"], "0");
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn clock_advances_virtually() {
        let mut env = Environment::new(Persona::retail_default());
        let t0 = env.now();
        env.advance(3_600_000);
        assert_eq!(env.now(), t0 + 3_600_000);
    }
}
