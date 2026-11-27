//! The Android SDK surface: Context, telephony, sensors, package manager,
//! SharedPreferences, SMS, WebView, HTTP clients and the dynamic-loading APIs
//! packers depend on.
//!
//! Two behaviours are deliberate:
//!  * Evasion-relevant reads never "fail". They return plausible values and
//!    are recorded with `Level::Critical`/`evasion`, so a sample that gates its
//!    payload on an emulator check still trips the gate.
//!  * Device-identity reads are tagged `Tag::Device` in provenance. When such a
//!    value later reaches a network sink, the report can say so exactly.

use super::{obs, CallResult, Level, Observation};
use crate::heap::{Object, ObjectValue};
use crate::interp::state::Machine;
use crate::value::{Provenance, Tag, Value};
use unhusk_dex::model::MethodRef;

impl Machine {
    pub(crate) fn call_android(&mut self, mr: &MethodRef, args: &[Value]) -> CallResult {
        let class = mr.class.trim_start_matches('L').trim_end_matches(';');
        let name = mr.name.as_str();
        match class {
            "android/os/Build" | "android/os/Build$VERSION" | "android/os/Build$VERSION_CODES" => self.android_build(class, name, args),
            "android/telephony/TelephonyManager" => self.android_telephony(name, args),
            "android/net/wifi/WifiManager" => self.android_wifi(name, args),
            "android/hardware/SensorManager" | "android/hardware/Sensor" | "android/hardware/SensorEvent" => self.android_sensors(class, name, args),
            "android/content/Context" | "android/content/ContextWrapper" | "android/app/Activity" | "android/app/Application" | "android/app/Service" => self.android_context(class, name, args),
            "android/content/pm/PackageManager" | "android/content/pm/PackageInfo" | "android/content/pm/ApplicationInfo" => self.android_pm(class, name, args),
            "android/content/SharedPreferences" | "android/content/SharedPreferences$Editor" => self.android_prefs(name, args),
            "android/telephony/SmsManager" => self.android_sms(name, args),
            "android/net/Uri" => self.android_uri(name, args),
            "android/os/Environment" => self.android_environment(name, args),
            "android/os/SystemClock" => self.android_clock(name, args),
            "android/os/Looper" | "android/os/Handler" => CallResult::void(),
            "java/net/URL" | "java/net/HttpURLConnection" | "javax/net/ssl/HttpsURLConnection"
            | "org/apache/http/impl/client/DefaultHttpClient" | "org/apache/http/impl/client/DefaultHttpClient$1"
            | "okhttp3/OkHttpClient" | "okhttp3/Request" | "okhttp3/Request$Builder" | "okhttp3/Response" | "okhttp3/Call" => {
                self.net_api(class, name, args)
            }
            "android/webkit/WebView" | "android/webkit/WebSettings" => self.android_webview(class, name, args),
            "android/app/admin/DevicePolicyManager" | "android/app/NotificationManager" | "android/app/ActivityManager" => {
                self.android_misc(class, name, args)
            }
            "android/util/Log" => CallResult::void(),
            "android/view/View" | "android/widget/Toast" | "android/widget/TextView" => CallResult::void(),
            "dalvik/system/DexClassLoader" => self.dalvik_loader(class, name, args),
            _ => CallResult::void(),
        }
    }

    // -- Build -------------------------------------------------------------

    fn android_build(&mut self, class: &str, name: &str, _args: &[Value]) -> CallResult {
        let p = &self.env.profile;
        let v = match (class, name) {
            ("android/os/Build", "MANUFACTURER") => p.manufacturer.clone(),
            ("android/os/Build", "BRAND") => p.brand.clone(),
            ("android/os/Build", "MODEL") => p.model.clone(),
            ("android/os/Build", "DEVICE") => p.device.clone(),
            ("android/os/Build", "PRODUCT") => p.product.clone(),
            ("android/os/Build", "BOARD") => p.board.clone(),
            ("android/os/Build", "HARDWARE") => p.hardware.clone(),
            ("android/os/Build", "FINGERPRINT") => p.fingerprint.clone(),
            ("android/os/Build", "BOOTLOADER") => p.bootloader.clone(),
            ("android/os/Build", "TAGS") => p.tags.clone(),
            ("android/os/Build", "TYPE") => p.build_type.clone(),
            ("android/os/Build", "ID") => p.build_id.clone(),
            ("android/os/Build", "DISPLAY") => p.build_display.clone(),
            ("android/os/Build", "HOST") => p.build_host.clone(),
            ("android/os/Build", "USER") => p.build_user.clone(),
            ("android/os/Build", "RADIO") => p.radio.clone(),
            ("android/os/Build", "SERIAL") => p.serial.clone(),
            ("android/os/Build$VERSION", "SDK_INT") => return CallResult::int(p.sdk_int),
            ("android/os/Build$VERSION", "RELEASE") => p.release.clone(),
            ("android/os/Build$VERSION", "CODENAME") => "REL".to_string(),
            ("android/os/Build$VERSION", "INCREMENTAL") => p.incremental.clone(),
            _ => String::new(),
        };
        // Which fields were read is itself evidence; record the tuple lazily:
        // only the first Build read per run is notable, the rest are routine.
        let o = obs(Level::Routine, "evasion", format!("{class}.{name} = {v:?}"));
        CallResult::new(Some(self.new_string(v, Provenance::of(Tag::Device))), Some(o))
    }

    // -- Telephony ---------------------------------------------------------

    fn android_telephony(&mut self, name: &str, args: &[Value]) -> CallResult {
        let p = &self.env.profile;
        let (val, cat, level) = match name {
            "getDeviceId" | "getImei" | "getMeid" => (p.device_id.clone(), "telephony", Level::Critical),
            "getSubscriberId" => (p.subscriber_id.clone(), "telephony", Level::Critical),
            "getSimSerialNumber" => (p.sim_serial.clone(), "telephony", Level::Critical),
            "getLine1Number" => (p.line1_number.clone(), "telephony", Level::Critical),
            "getSimOperator" => (p.sim_operator.clone(), "telephony", Level::Notable),
            "getSimOperatorName" => (p.sim_operator_name.clone(), "telephony", Level::Notable),
            "getSimCountryIso" => (p.sim_country.clone(), "telephony", Level::Notable),
            "getNetworkOperator" => (p.network_operator.clone(), "telephony", Level::Notable),
            "getNetworkOperatorName" => (p.network_operator_name.clone(), "telephony", Level::Notable),
            "getNetworkCountryIso" => (p.network_country.clone(), "telephony", Level::Notable),
            "getNetworkType" | "getDataNetworkType" => ("13".to_string(), "telephony", Level::Notable),
            "getPhoneType" => ("1".to_string(), "telephony", Level::Routine),
            "getSimState" => ("5".to_string(), "telephony", Level::Notable),
            "getCallState" => ("0".to_string(), "telephony", Level::Routine),
            "getNetworkTypeName" => (p.network_type.clone(), "telephony", Level::Routine),
            "isNetworkRoaming" => ("false".to_string(), "telephony", Level::Routine),
            "getAllCellInfo" | "getCellLocation" | "getNeighboringCellInfo" => {
                let o = obs(Level::Notable, "telephony", format!("{name} -> empty (no cell data)"));
                return CallResult::new(Some(Value::NULL), Some(o));
            }
            "getImsi" => (p.subscriber_id.clone(), "telephony", Level::Critical),
            "listen" => {
                let o = obs(Level::Notable, "telephony", "TelephonyManager.listen (SMS/call interception)");
                return CallResult::new(Some(Value::NULL), Some(o));
            }
            _ => ("".to_string(), "telephony", Level::Routine),
        };
        let _ = self.arg_i32(args, 0);
        let o = obs(level, cat, format!("{name} = {val:?}"));
        CallResult::new(Some(self.new_string(val, Provenance::of(Tag::Device))), Some(o))
    }

    fn android_wifi(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getConnectionInfo" => {
                let v = match self.new_model("Landroid/net/wifi/WifiInfo;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "ssid", ObjectValue::Str(self.env.profile.wifi_ssid.clone()));
                        self.set_model_field(id, "bssid", ObjectValue::Str(self.env.profile.wifi_bssid.clone()));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::new(Some(v), Some(obs(Level::Notable, "device", "WifiManager.getConnectionInfo")))
            }
            "getScanResults" => CallResult::obj(match self.heap.new_obj_array("[Ljava/lang/Object;", vec![], Provenance::default()) {
                Some(id) => Value::obj(id),
                None => Value::NULL,
            }),
            "getMacAddress" => {
                let o = obs(Level::Notable, "device", "WifiInfo.getMacAddress");
                CallResult::new(Some(self.new_string("02:00:00:00:00:00", Provenance::of(Tag::Device))), Some(o))
            }
            "getSSID" => CallResult::obj(self.new_string(self.env.profile.wifi_ssid.clone(), Provenance::of(Tag::Device))),
            "getBSSID" => CallResult::obj(self.new_string(self.env.profile.wifi_bssid.clone(), Provenance::of(Tag::Device))),
            _ => {
                let _ = args;
                CallResult::void()
            }
        }
    }

    // -- Sensors -----------------------------------------------------------

    fn android_sensors(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match (class, name) {
            ("android/hardware/SensorManager", "getSensorList") => {
                let sensors = self.env.profile.sensors.clone();
                let items: Vec<Value> = sensors
                    .iter()
                    .map(|s| {
                        match self.new_model_default("Landroid/hardware/Sensor;") {
                            Value::Obj(id) => {
                                self.set_model_field(id, "name", ObjectValue::Str(s.name.clone()));
                                self.set_model_field(id, "kind", ObjectValue::Str(s.kind.clone()));
                                Value::obj(id)
                            }
                            v => v,
                        }
                    })
                    .collect();
                let n = items.len();
                let v = match self.heap.new_obj_array("[Landroid/hardware/Sensor;", items, Provenance::default()) {
                    Some(id) => Value::obj(id),
                    None => Value::NULL,
                };
                CallResult::new(Some(v), Some(obs(Level::Notable, "evasion", format!("getSensorList -> {n} sensors"))))
            }
            ("android/hardware/SensorManager", "getDefaultSensor") => {
                let kind = self.arg_i32(args, 1);
                let s = match kind {
                    1 => set_values(&self.env.profile.sensors, "accelerometer"),
                    4 => set_values(&self.env.profile.sensors, "gyroscope"),
                    2 => set_values(&self.env.profile.sensors, "magnetometer"),
                    5 => set_values(&self.env.profile.sensors, "light"),
                    8 => set_values(&self.env.profile.sensors, "proximity"),
                    _ => None,
                };
                match s {
                    Some((n, v)) => {
                        let vv = match self.new_model_default("Landroid/hardware/Sensor;") {
                            Value::Obj(id) => {
                                self.set_model_field(id, "name", ObjectValue::Str(n));
                                self.set_model_field(id, "values", ObjectValue::Bytes(v.iter().flat_map(|x| x.to_le_bytes()).collect()));
                                Value::obj(id)
                            }
                            v => v,
                        };
                        CallResult::new(Some(vv), Some(obs(Level::Notable, "evasion", "getDefaultSensor")))
                    }
                    None => CallResult::new(Some(Value::NULL), Some(obs(Level::Notable, "evasion", "getDefaultSensor -> null (no sensors)"))),
                }
            }
            ("android/hardware/SensorManager", "registerListener") => {
                CallResult::new(Some(Value::I(1)), Some(obs(Level::Notable, "evasion", "registerListener (sensor gating)")))
            }
            ("android/hardware/SensorManager", "unregisterListener") => CallResult::void(),
            ("android/hardware/Sensor", "getType") => {
                let kind = self.arg_obj(args, 0).and_then(|id| self.model_string(id, "kind")).unwrap_or_default();
                let t = match kind.as_str() {
                    "accelerometer" => 1,
                    "magnetometer" => 2,
                    "gyroscope" => 4,
                    "light" => 5,
                    "proximity" => 8,
                    _ => 0,
                };
                CallResult::int(t)
            }
            ("android/hardware/Sensor", "getName") => {
                let n = self.arg_obj(args, 0).and_then(|id| self.model_string(id, "name")).unwrap_or_default();
                CallResult::obj(self.new_string(n, Provenance::of(Tag::Device)))
            }
            ("android/hardware/Sensor", "getVendor") => {
                let n = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "kind"))
                    .and_then(|k| self.env.profile.sensor(&k).map(|s| s.vendor.clone()))
                    .unwrap_or_default();
                CallResult::obj(self.new_string(n, Provenance::of(Tag::Device)))
            }
            ("android/hardware/SensorEvent", "values") => {
                let v = self.arg_obj(args, 0).and_then(|id| match self.model_field(id, "values") {
                    Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                    _ => None,
                }).unwrap_or_default();
                CallResult::obj(self.new_bytes(v, Provenance::of(Tag::Device)))
            }
            _ => CallResult::void(),
        }
    }

    // -- Context -----------------------------------------------------------

    fn android_context(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getSystemService" => {
                let svc = self.arg_str_or_named(args, "android.content.Context", "getSystemService");
                let v = match svc.as_str() {
                    "phone" => self.new_model_default("Landroid/telephony/TelephonyManager;"),
                    "sensor" => self.new_model("Landroid/hardware/SensorManager;"),
                    "wifi" => self.new_model("Landroid/net/wifi/WifiManager;"),
                    "package" => self.new_model("Landroid/content/pm/PackageManager;"),
                    "activity" => self.new_model_default("Landroid/app/ActivityManager;"),
                    "device_policy" => self.new_model_default("Landroid/app/admin/DevicePolicyManager;"),
                    "notification" => self.new_model_default("Landroid/app/NotificationManager;"),
                    "window" => self.new_model_default("Landroid/view/WindowManager;"),
                    "connectivity" => self.new_model_default("Landroid/net/ConnectivityManager;"),
                    "clipboard" => self.new_model_default("Landroid/content/ClipboardManager;"),
                    _ => self.new_model_default("Ljava/lang/Object;"),
                };
                let mut o = obs(Level::Notable, "permission", format!("getSystemService({svc:?})"));
                o.prov = Some(Provenance::of(Tag::Device));
                CallResult::new(Some(v), Some(o))
            }
            "getPackageName" | "getOpPackageName" => {
                let pkg = self.env.package_name.clone();
                CallResult::obj(self.new_string(pkg, Provenance::constant()))
            }
            "getApplicationContext" | "getBaseContext" | "getApplication" => {
                // Create a fresh Application instance if the app declares one, so
                // that `((MyApp) getApplication()).init()` style seeding works.
                let app = self.env.profile.clone();
                let _ = app;
                let cls = self.app_class.clone();
                match cls {
                    Some(c) if self.program.class_exists(&c) => self.instantiate_and_init(&c, &[]),
                    _ => CallResult::obj(self.new_model("Landroid/content/Context;")),
                }
            }
            "getFilesDir" => {
                let dir = self.env.files_dir();
                CallResult::obj(self.new_model_with_path("Ljava/io/File;", dir))
            }
            "getCacheDir" => {
                let dir = self.env.cache_dir();
                CallResult::obj(self.new_model_with_path("Ljava/io/File;", dir))
            }
            "getExternalFilesDir" | "getExternalCacheDir" => {
                let dir = self.env.external_dir();
                CallResult::obj(self.new_model_with_path("Ljava/io/File;", dir))
            }
            "getDir" => {
                let n = self.arg_str_or_named(args, "android.content.Context", "getDir");
                let dir = format!("{}/app_{n}", self.env.app_data_dir);
                CallResult::obj(self.new_model_with_path("Ljava/io/File;", dir))
            }
            "getSharedPreferences" => {
                let n = self.arg_str_or_named(args, "android.content.Context", "getSharedPreferences");
                CallResult::new(Some(self.new_model_named(format!("Landroid/content/SharedPreferences;#{n}"))),
                    Some(obs(Level::Routine, "file", format!("getSharedPreferences({n})"))))
            }
            "openFileInput" | "openFileOutput" => {
                let n = self.arg_str_or_named(args, "android.content.Context", "openFile");
                let dir = self.env.files_dir();
                let path = format!("{dir}/{n}");
                let v = match self.new_model("Ljava/io/FileInputStream;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "path", ObjectValue::Str(path.clone()));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::new(Some(v), Some(obs(Level::Routine, "file", format!("openFile({path})"))))
            }
            "getAssets" => CallResult::obj(self.new_model("Landroid/content/res/AssetManager;")),
            "getResources" => CallResult::obj(self.new_model("Landroid/content/res/Resources;")),
            "startActivity" | "startService" | "sendBroadcast" => {
                let mut o = obs(Level::Notable, "permission", format!("{class}.{name}"));
                o.result = format!("{class}.{name} (intent dispatched inside sandbox)");
                CallResult::void_with(Some(o))
            }
            "getContentResolver" => CallResult::obj(self.new_model("Landroid/content/ContentResolver;")),
            "getClassLoader" => CallResult::obj(self.new_model("Ldalvik/system/PathClassLoader;")),
            _ => {
                let _ = args;
                CallResult::void()
            }
        }
    }

    // -- Package manager ---------------------------------------------------

    fn android_pm(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match (class, name) {
            ("android/content/pm/PackageManager", "getInstalledPackages")
            | ("android/content/pm/PackageManager", "getInstalledApplications") => {
                let pkgs = self.env.profile.installed_packages.clone();
                let items: Vec<Value> = pkgs
                    .iter()
                    .map(|p| match self.new_model_default("Landroid/content/pm/PackageInfo;") {
                        Value::Obj(id) => {
                            self.set_model_field(id, "packageName", ObjectValue::Str(p.name.clone()));
                            self.set_model_field(id, "versionName", ObjectValue::Str(p.version.clone()));
                            Value::obj(id)
                        }
                        v => v,
                    })
                    .collect();
                let n = items.len();
                let v = match self.heap.new_obj_array("[Ljava/lang/Object;", items, Provenance::default()) {
                    Some(id) => Value::obj(id),
                    None => Value::NULL,
                };
                CallResult::new(Some(v), Some(obs(Level::Notable, "device", format!("getInstalledPackages -> {n} packages"))))
            }
            ("android/content/pm/PackageManager", "getPackageInfo") => {
                let pkg = self.arg_str_or_named(args, "android.content/pm/PackageManager", "getPackageInfo");
                let known = self.env.profile.installed_packages.iter().any(|p| p.name == pkg);
                if !known && pkg != self.env.package_name {
                    return CallResult::new(Some(Value::NULL), None);
                }
                let v = match self.new_model_default("Landroid/content/pm/PackageInfo;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "packageName", ObjectValue::Str(pkg.clone()));
                        self.set_model_field(id, "versionName", ObjectValue::Str("1.0".into()));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::new(Some(v), Some(obs(Level::Notable, "device", format!("getPackageInfo({pkg})"))))
            }
            ("android/content/pm/PackageManager", "getApplicationInfo") => CallResult::obj(self.new_model_default("Landroid/content/pm/ApplicationInfo;")),
            ("android/content/pm/PackageManager", "getLaunchIntentForPackage") => {
                let pkg = self.arg_str_or_named(args, "android.content/pm/PackageManager", "getLaunchIntentForPackage");
                let known = self.env.profile.browser_packages.contains(&pkg);
                if known {
                    CallResult::new(Some(self.new_model("Landroid/content/Intent;")), Some(obs(Level::Notable, "device", format!("launch intent for {pkg}"))))
                } else {
                    CallResult::new(Some(Value::NULL), None)
                }
            }
            ("android/content/pm/PackageManager", "queryIntentActivities") => {
                CallResult::obj(match self.heap.new_obj_array("[Ljava/lang/Object;", vec![], Provenance::default()) {
                    Some(id) => Value::obj(id),
                    None => Value::NULL,
                })
            }
            ("android/content/pm/PackageManager", "checkPermission") | ("android/content/pm/PackageManager", "checkCallingOrSelfPermission") => {
                // The sample's manifest permissions decide; the sandbox grants
                // exactly what the APK declared, which mirrors a real install
                // and keeps permission-gated branches reachable.
                let perm = self.arg_str(args, 1).or_else(|| self.arg_str(args, 0)).unwrap_or_default();
                let granted = self.granted_permissions.iter().any(|p| *p == perm);
                let mut o = obs(
                    Level::Notable,
                    "permission",
                    format!("checkPermission({perm}) = {}", if granted { "GRANTED" } else { "DENIED" }),
                );
                if !granted {
                    o.level = Level::Critical;
                    o.category = "evasion";
                }
                CallResult::new(Some(Value::I(if granted { 0 } else { -1 })), Some(o))
            }
            ("android/content/pm/PackageManager", "getNameForUid") => CallResult::obj(self.new_string(self.env.package_name.clone(), Provenance::constant())),
            ("android/content/pm/PackageInfo", "…") => CallResult::void(),
            ("android/content/pm/ApplicationInfo", "…") => CallResult::void(),
            _ => {
                let _ = args;
                CallResult::void()
            }
        }
    }

    // -- SharedPreferences -------------------------------------------------

    fn android_prefs(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getString" => {
                let (file, key) = (
                    self.arg_obj(args, 0).and_then(|id| self.model_string(id, "file")),
                    self.arg_str_or_named(args, "x", "getString"),
                );
                let _ = (file, key);
                let def = self.arg_str(args, 2).unwrap_or_default();
                CallResult::obj(self.new_string(def, Provenance::of(Tag::PackedData)))
            }
            "getInt" | "getLong" | "getBoolean" | "getFloat" => CallResult::new(Some(Value::I(self.arg_i32(args, 2))), None),
            "edit" => CallResult::obj(self.new_model("Landroid/content/SharedPreferences$Editor;")),
            "putString" | "putInt" | "putLong" | "putBoolean" | "remove" | "clear" => {
                CallResult::new(Some(args.first().copied().unwrap_or(Value::NULL)), None)
            }
            "commit" | "apply" => CallResult::new(Some(Value::I(1)), Some(obs(Level::Routine, "file", "SharedPreferences commit"))),
            "contains" => CallResult::int(0),
            _ => CallResult::void(),
        }
    }

    // -- SMS ---------------------------------------------------------------

    fn android_sms(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "sendTextMessage" | "sendMultipartTextMessage" | "sendDataMessage" => {
                let dest = self.arg_str(args, 1).unwrap_or_default();
                let body = self.arg_str(args, 4).unwrap_or_default();
                let prov = self.arg_prov(args, 4);
                let mut o = obs(
                    Level::Critical,
                    "sms",
                    format!("SmsManager.{name} -> {dest} body={:?}", truncate(&body, 80)),
                );
                o.prov = Some(prov);
                o.target = Some(dest);
                CallResult::new(Some(self.new_model("Landroid/app/PendingIntent;")), Some(o))
            }
            "getDefault" | "getSmsManagerForSubscriptionId" => CallResult::obj(self.new_model("Landroid/telephony/SmsManager;")),
            "divideMessage" => CallResult::new(None, None),
            _ => CallResult::void(),
        }
    }

    fn android_uri(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "parse" => {
                let s = self.arg_str_or_named(args, "android.net.Uri", "parse");
                let v = match self.new_model("Landroid/net/Uri;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "uri", ObjectValue::Str(s));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            "toString" => {
                let s = self.arg_obj(args, 0).and_then(|id| self.model_string(id, "uri")).unwrap_or_default();
                CallResult::obj(self.new_string(s, Provenance::constant()))
            }
            _ => CallResult::void(),
        }
    }

    fn android_environment(&mut self, name: &str, _args: &[Value]) -> CallResult {
        match name {
            "getExternalStorageDirectory" => {
                let dir = self.env.external_dir();
                CallResult::obj(self.new_model_with_path("Ljava/io/File;", dir))
            }
            "getDataDirectory" => CallResult::obj(self.new_model_with_path("Ljava/io/File;", "/data".into())),
            "getRootDirectory" => CallResult::obj(self.new_model_with_path("Ljava/io/File;", "/system".into())),
            "getExternalStorageState" => CallResult::obj(self.new_string("mounted", Provenance::constant())),
            "getExternalStoragePublicDirectory" => {
                CallResult::obj(self.new_model_with_path("Ljava/io/File;", format!("{}/{}", self.env.external_dir(), "Download")))
            }
            _ => CallResult::void(),
        }
    }

    fn android_clock(&mut self, name: &str, _args: &[Value]) -> CallResult {
        match name {
            "elapsedRealtime" | "uptimeMillis" | "currentThreadTimeMillis" => {
                CallResult::new(Some(Value::J(self.env.clock.elapsed_realtime_ms())), None)
            }
            "setCurrentTimeMillis" => CallResult::new(Some(Value::I(1)), None),
            _ => CallResult::void(),
        }
    }

    fn android_webview(&mut self, _class: &str, name: &str, args: &[Value]) -> CallResult {
        match name {
            "loadUrl" | "loadData" | "loadDataWithBaseURL" | "evaluateJavascript" | "addJavascriptInterface" => {
                let url = self.arg_str(args, 1).unwrap_or_default();
                let mut o = obs(Level::Critical, "egress", format!("WebView.{name}({url})"));
                o.target = Some(url);
                CallResult::void_with(Some(o))
            }
            _ => CallResult::void(),
        }
    }

    fn android_misc(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match (class, name) {
            ("android/app/ActivityManager", "getRunningAppProcesses") | ("android/app/ActivityManager", "getRunningServices") => {
                CallResult::new(
                    Some(Value::NULL),
                    Some(obs(Level::Notable, "device", format!("{class}.{name} (process enumeration)"))),
                )
            }
            ("android/app/ActivityManager", "getDeviceConfigurationInfo") => CallResult::obj(self.new_model("Landroid/content/pm/FeatureInfo;")),
            ("android/app/admin/DevicePolicyManager", n) if n.starts_with("is") || n.starts_with("get") => {
                CallResult::new(Some(Value::I(0)), Some(obs(Level::Notable, "permission", format!("DevicePolicyManager.{n}"))))
            }
            ("android/app/NotificationManager", "notify") => CallResult::new(None, Some(obs(Level::Notable, "permission", "NotificationManager.notify"))),
            _ => {
                let _ = args;
                CallResult::void()
            }
        }
    }

    fn arg_str_or_named(&self, args: &[Value], _class: &str, _name: &str) -> String {
        // Most Android calls carry the interesting string at index 1 (after
        // `this`), falling back to index 0 for static helpers.
        self.arg_str(args, 1)
            .or_else(|| self.arg_str(args, 0))
            .unwrap_or_default()
    }

    pub(crate) fn new_model_with_path(&mut self, class: &str, path: String) -> Value {
        match self.heap.alloc(Object::Model {
            class: class.to_string(),
            fields: [("path".to_string(), ObjectValue::Str(path))].into_iter().collect(),
            prov: Provenance::default(),
        }) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }

    pub(crate) fn new_model_named(&mut self, class: String) -> Value {
        match self.heap.alloc(Object::Model {
            class: class,
            fields: Default::default(),
            prov: Provenance::default(),
        }) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }
}

impl CallResult {
    pub fn void_with(o: Option<Observation>) -> Self {
        CallResult::new(None, o)
    }
}

fn set_values(sensors: &[crate::env::SensorInfo], kind: &str) -> Option<(String, Vec<f32>)> {
    sensors
        .iter()
        .find(|s| s.kind == kind)
        .map(|s| (s.name.clone(), s.values.clone()))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}
