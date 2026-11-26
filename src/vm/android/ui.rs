//! `android.*` framework model: context, build/telephony/sensors, intents,
//! handlers, services, packages, SMS, storage and the evasion probes malware
//! uses to decide whether it is being analysed.
//!
//! Every probe is recorded. That matters twice over: a sample that asks
//! `Build.FINGERPRINT` and then refuses to run has told us its detection
//! predicate, and the analyst gets that predicate in the report even though no
//! malicious payload executed.

use crate::report::SinkKind;
use crate::vm::android::state::TaintSource;
use crate::vm::android::{
    arg_int, arg_long, arg_ref, arg_str, arg_taint, ret_bool, ret_int, ret_long, ret_obj, ret_void,
    set_state_int, set_state_ref, state_int, state_ref, state_str, union_taint,
};
use crate::vm::heap::ObjKind;
use crate::vm::interp::{CallOutcome, Vm};
use crate::vm::value::{ObjRef, Slot, Taint, Value};

use super::AndroidHost;

/// The application context. There is one per scenario; the runner creates it.
pub const CONTEXT_CLASS: &str = "Landroid/content/Context;";

pub fn dispatch(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    key: &crate::vm::intern::MethodKey,
    args: &[Slot],
) -> CallOutcome {
    let _ = key;
    // Prefix routing by package.
    if class.starts_with("Landroid/os/Build") {
        return build_fields(vm, class, name, args);
    }
    if class.starts_with("Landroid/telephony/") || class.starts_with("Landroid/telecom/") {
        return telephony(vm, class, name, args);
    }
    if class.starts_with("Landroid/hardware/") {
        return hardware(vm, class, name, args);
    }
    if class.starts_with("Landroid/location/") {
        return location(vm, class, name, args);
    }
    if class.starts_with("Landroid/content/") {
        return content(vm, host, class, name, args);
    }
    if class.starts_with("Landroid/os/") {
        return os(vm, host, class, name, args);
    }
    if class.starts_with("Landroid/provider/") {
        return provider(vm, class, name, args);
    }
    if class.starts_with("Landroid/util/") {
        return util(vm, class, name, args);
    }
    if class.starts_with("Landroid/net/") || class.starts_with("Landroid/accounts/") {
        return net(vm, class, name, args);
    }
    if class.starts_with("Landroid/webkit/") {
        return webkit(vm, class, name, args);
    }
    if class.starts_with("Landroid/text/") {
        return text(vm, class, name, args);
    }
    if class.starts_with("Landroid/graphics/") || class.starts_with("Landroid/view/")
        || class.starts_with("Landroid/widget/")
    {
        return ui(vm, class, name, args);
    }
    if class.starts_with("Landroid/database/") {
        return database(vm, class, name, args);
    }
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

fn build_fields(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    // Static getters such as Build.getSerial(), Build.MODEL via <clinit> sget.
    let id = &vm.env.persona.identity;
    let val = match name {
        "getSerial" => Some(id.serial.clone()),
        "getRadioVersion" => Some(id.radio.clone()),
        "getFingerprint" => Some(id.fingerprint.clone()),
        _ => None,
    };
    if let Some(v) = val {
        vm.probe(&format!("{class}->{name}"), &v);
        let t = if name == "getSerial" {
            vm.mint_taint(TaintSource::Serial.label())
        } else {
            Taint::CLEAN
        };
        return match vm.new_string_t(v, t) {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        };
    }
    let _ = args;
    CallOutcome::Decline
}

/// Static fields of `android.os.Build`. Called from the `static_field` hook.
pub fn build_static_field(vm: &mut Vm, class: &str, name: &str) -> Option<Slot> {
    let id = &vm.env.persona.identity;
    let val = match name {
        "MODEL" => id.model.clone(),
        "MANUFACTURER" => id.manufacturer.clone(),
        "BRAND" => id.brand.clone(),
        "DEVICE" => id.device.clone(),
        "PRODUCT" => id.product.clone(),
        "HARDWARE" => id.hardware.clone(),
        "BOARD" => id.board.clone(),
        "FINGERPRINT" => id.fingerprint.clone(),
        "TAGS" => id.tags.clone(),
        "BOOTLOADER" => id.bootloader.clone(),
        "ID" => id.id.clone(),
        "SERIAL" => id.serial.clone(),
        "DISPLAY" => id.incremental.clone(),
        "TYPE" => "user".into(),
        "HOST" => "buildhost".into(),
        "USER" => "build".into(),
        "RADIO" => id.radio.clone(),
        _ => return None,
    };
    vm.probe(&format!("{class}->{name}"), &val);
    // A fingerprint read is itself a probe worth reporting when the value
    // changes the branch; record the value for the analyst.
    vm.new_string(val).ok().map(Slot::reference)
}

pub fn build_version_static(vm: &mut Vm, class: &str, name: &str) -> Option<Slot> {
    let id = &vm.env.persona.identity;
    let v = match name {
        "SDK_INT" => return Some(Slot::int(id.sdk_int)),
        "RELEASE" => id.release.clone(),
        "INCREMENTAL" => id.incremental.clone(),
        "CODENAME" => "REL".into(),
        "SECURITY_PATCH" => format!("2022-{}-01", 1 + (id.sdk_int % 9)),
        _ => {
            let _ = class;
            return None;
        }
    };
    vm.probe(&format!("{class}->{name}"), &v);
    vm.new_string(v).ok().map(Slot::reference)
}

// ---------------------------------------------------------------------------
// Telephony
// ---------------------------------------------------------------------------

fn telephony(vm: &mut Vm, class: &str, name: &str, _args: &[Slot]) -> CallOutcome {
    let tel = vm.env.persona.telephony.clone();
    match name {
        "getDeviceId" | "getImei" | "getMeid" | "getDeviceIdForSubscriber" => {
            if !tel.sim_present || tel.imei.is_empty() {
                vm.probe(&format!("{class}->{name}"), "null");
                return ret_obj(ObjRef::NULL);
            }
            vm.probe(&format!("{class}->{name}"), &tel.imei);
            let t = vm.mint_taint(TaintSource::Imei.label());
            match vm.new_string_t(tel.imei.clone(), t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getSubscriberId" | "getImsi" => {
            if !tel.sim_present {
                return ret_obj(ObjRef::NULL);
            }
            vm.probe(&format!("{class}->{name}"), &tel.imsi);
            let t = vm.mint_taint(TaintSource::Imsi.label());
            match vm.new_string_t(tel.imsi.clone(), t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getSimSerialNumber" | "getIccId" => {
            if !tel.sim_present {
                return ret_obj(ObjRef::NULL);
            }
            vm.probe(&format!("{class}->{name}"), &tel.iccid);
            let t = vm.mint_taint(TaintSource::Iccid.label());
            match vm.new_string_t(tel.iccid.clone(), t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getLine1Number" => {
            if tel.msisdn.is_empty() {
                return ret_obj(ObjRef::NULL);
            }
            vm.probe(&format!("{class}->{name}"), &tel.msisdn);
            let t = vm.mint_taint(TaintSource::PhoneNumber.label());
            match vm.new_string_t(tel.msisdn.clone(), t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getSimOperator" => string_or_empty(vm, &tel.sim_operator),
        "getSimOperatorName" => string_or_empty(vm, &tel.sim_operator_name),
        "getNetworkOperator" => string_or_empty(vm, &tel.network_operator),
        "getNetworkOperatorName" => string_or_empty(vm, &tel.network_operator_name),
        "getSimState" => ret_int(tel.sim_state),
        "getPhoneType" => ret_int(tel.phone_type),
        "getNetworkType" | "getDataNetworkType" => ret_int(tel.network_type),
        "isNetworkRoaming" => ret_bool(false),
        "getSimCountryIso" | "getNetworkCountryIso" => str_to_obj(vm, "us"),
        "getSubscriberIdForSubscriber" => ret_obj(ObjRef::NULL),
        "getAllCellInfo" => empty_array(vm, "Landroid/telephony/CellInfo;"),
        "getCellLocation" => match vm.new_instance_of("Landroid/telephony/CellLocation;") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_obj(ObjRef::NULL),
        },
        "getNeighboringCellInfo" => empty_array(vm, "Landroid/telephony/NeighboringCellInfo;"),
        "getSubscriptionId" | "getDefaultSubscriptionId" => ret_int(1),
        "listen" | "registerTelephonyCallback" => ret_void(),
        "getServiceState" => match vm.new_instance_of("Landroid/telephony/ServiceState;") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        _ => CallOutcome::Decline,
    }
}

fn string_or_empty(vm: &mut Vm, s: &str) -> CallOutcome {
    match vm.new_string(s) {
        Ok(r) => ret_obj(r),
        Err(_) => ret_void(),
    }
}

fn str_to_obj(vm: &mut Vm, s: &str) -> CallOutcome {
    string_or_empty(vm, s)
}

fn empty_array(vm: &mut Vm, elem: &str) -> CallOutcome {
    let sym = vm.sym(elem);
    match vm.heap.new_array(sym, elem, 0, Taint::CLEAN) {
        Ok(r) => ret_obj(r),
        Err(_) => ret_obj(ObjRef::NULL),
    }
}

// ---------------------------------------------------------------------------
// Sensors & hardware
// ---------------------------------------------------------------------------

fn hardware(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    if class.starts_with("Landroid/hardware/SensorManager;") {
        match name {
            "getSensorList" => {
                let type_id = arg_int(args, 1);
                // -1 = TYPE_ALL
                let sensors: Vec<_> = vm
                    .env
                    .persona
                    .sensors
                    .iter()
                    .filter(|s| type_id == -1 || s.type_id == type_id)
                    .cloned()
                    .collect();
                let elem = vm.sym("Landroid/hardware/Sensor;");
                let arr = match vm.heap.new_array(elem, "Landroid/hardware/Sensor;", sensors.len(), Taint::CLEAN) {
                    Ok(a) => a,
                    Err(_) => return ret_obj(ObjRef::NULL),
                };
                for (i, sensor) in sensors.iter().enumerate() {
                    let obj = match vm.new_instance_of("Landroid/hardware/Sensor;") {
                        Ok(o) => o,
                        Err(_) => continue,
                    };
                    super::put_state_str(vm, obj, "name", sensor.name.clone());
                    super::put_state_int(vm, obj, "type", sensor.type_id);
                    super::put_state_str(vm, obj, "vendor", sensor.vendor.clone());
                    super::put_state_float(vm, obj, "maxRange", sensor.max_range);
                    super::put_state_float(vm, obj, "resolution", sensor.resolution);
                    super::put_state_float(vm, obj, "power", sensor.power);
                    vm.heap.array_set(arr, i, Slot::reference(obj));
                }
                vm.probe(&format!("SensorManager.getSensorList({type_id})"), sensors.len().to_string());
                ret_obj(arr)
            }
            "getDefaultSensor" => {
                let type_id = arg_int(args, 1);
                let found = vm
                    .env
                    .persona
                    .sensors
                    .iter()
                    .find(|s| s.type_id == type_id)
                    .cloned();
                match found {
                    Some(sensor) => {
                        vm.probe(&format!("SensorManager.getDefaultSensor({type_id})"), &sensor.name);
                        let obj = match vm.new_instance_of("Landroid/hardware/Sensor;") {
                            Ok(o) => o,
                            Err(_) => return ret_obj(ObjRef::NULL),
                        };
                        super::put_state_str(vm, obj, "name", sensor.name.clone());
                        super::put_state_int(vm, obj, "type", sensor.type_id);
                        ret_obj(obj)
                    }
                    None => {
                        vm.probe(&format!("SensorManager.getDefaultSensor({type_id})"), "null");
                        ret_obj(ObjRef::NULL)
                    }
                }
            }
            "registerListener" => ret_bool(true),
            "unregisterListener" => ret_void(),
            _ => CallOutcome::Decline,
        }
    } else if class.starts_with("Landroid/hardware/Sensor;") {
        let this = arg_ref(args, 0);
        match name {
            "getName" => ret_obj(state_ref(vm, this, "name")),
            "getType" => ret_int(state_int(vm, this, "type")),
            "getVendor" => {
                let v = vm.heap.instance(this).and_then(|i| i.state.get("vendor")).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL);
                ret_obj(v)
            }
            "getMaxRange" => {
                let v = vm.heap.instance(this).and_then(|i| i.state.get("maxRange")).map(|s| s.v.as_float()).unwrap_or(0.0);
                CallOutcome::Value(Slot::float(v))
            }
            "getResolution" => {
                let v = vm.heap.instance(this).and_then(|i| i.state.get("resolution")).map(|s| s.v.as_float()).unwrap_or(0.0);
                CallOutcome::Value(Slot::float(v))
            }
            "getPower" => {
                let v = vm.heap.instance(this).and_then(|i| i.state.get("power")).map(|s| s.v.as_float()).unwrap_or(0.0);
                CallOutcome::Value(Slot::float(v))
            }
            _ => CallOutcome::Decline,
        }
    } else if class.starts_with("Landroid/hardware/camera2/") || class.starts_with("Landroid/hardware/Camera") {
        match name {
            "getNumberOfCameras" => ret_int(2),
            "open" => match vm.new_instance_of("Landroid/hardware/Camera;") {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            },
            _ => CallOutcome::Decline,
        }
    } else {
        CallOutcome::Decline
    }
}

// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

fn location(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let fix = vm.env.persona.location.clone();
    if class.starts_with("Landroid/location/LocationManager;") {
        match name {
            "getLastKnownLocation" => {
                vm.probe("LocationManager.getLastKnownLocation", format!("{},{}", fix.latitude, fix.longitude));
                let obj = match vm.new_instance_of("Landroid/location/Location;") {
                    Ok(o) => o,
                    Err(_) => return ret_obj(ObjRef::NULL),
                };
                super::put_state_double(vm, obj, "lat", fix.latitude);
                super::put_state_double(vm, obj, "lon", fix.longitude);
                super::put_state_float(vm, obj, "acc", fix.accuracy);
                super::put_state_str(vm, obj, "provider", fix.provider.clone());
                let lt = vm.mint_taint(TaintSource::Location.label());
                vm.heap.add_taint(obj, lt);
                ret_obj(obj)
            }
            "requestLocationUpdates" | "isProviderEnabled" => ret_bool(true),
            "getAllProviders" | "getProviders" => empty_array(vm, "Ljava/lang/String;"),
            "isLocationEnabled" => ret_bool(true),
            _ => CallOutcome::Decline,
        }
    } else if class.starts_with("Landroid/location/Location;") {
        let this = arg_ref(args, 0);
        match name {
            "getLatitude" => {
                let v = vm.heap.instance(this).and_then(|i| i.state.get("lat")).map(|s| s.v.as_double()).unwrap_or(0.0);
                CallOutcome::Value(Slot::double(v))
            }
            "getLongitude" => {
                let v = vm.heap.instance(this).and_then(|i| i.state.get("lon")).map(|s| s.v.as_double()).unwrap_or(0.0);
                CallOutcome::Value(Slot::double(v))
            }
            "getAccuracy" => CallOutcome::Value(Slot::float(12.0)),
            "getProvider" => ret_obj(state_ref(vm, this, "provider")),
            "getTime" | "getElapsedRealtimeNanos" => ret_long(vm.env.now()),
            "getSpeed" | "getBearing" | "getAltitude" => CallOutcome::Value(Slot::double(0.0)),
            "setLatitude" | "setLongitude" => ret_void(),
            _ => CallOutcome::Decline,
        }
    } else {
        CallOutcome::Decline
    }
}

// ---------------------------------------------------------------------------
// Content, Context, Intents, Resources
// ---------------------------------------------------------------------------

fn content(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    args: &[Slot],
) -> CallOutcome {
    match class {
        "Landroid/content/Context;" | "Landroid/content/ContextWrapper;" | "Landroid/content/MutableContextWrapper;" => {
            context_ops(vm, host, name, args)
        }
        "Landroid/content/Intent;" => intent_ops(vm, name, args),
        "Landroid/content/ComponentName;" => component_ops(vm, name, args),
        "Landroid/content/pm/PackageManager;" | "Landroid/content/pm/PackageInfo;"
        | "Landroid/content/pm/PackageInstaller;" | "Landroid/content/pm/ApplicationInfo;"
        | "Landroid/content/pm/ResolveInfo;" => pm_ops(vm, class, name, args),
        "Landroid/content/pm/Signature;" => ret_obj(ObjRef::NULL),
        "Landroid/content/ClipboardManager;" | "Landroid/content/ClipboardManager$1;"
        | "Landroid/content/ClipData;" | "Landroid/content/ClipData$Item;" => {
            clipboard(vm, class, name, args)
        }
        "Landroid/content/SharedPreferences;" | "Landroid/content/SharedPreferences$Editor;" => {
            prefs(vm, class, name, args)
        }
        "Landroid/content/BroadcastReceiver;" | "Landroid/content/ServiceConnection;" => ret_void(),
        "Landroid/content/IntentFilter;" => intent_filter(vm, name, args),
        "Landroid/content/ContentValues;" => content_values(vm, name, args),
        "Landroid/content/ContentResolver;" => resolver(vm, host, name, args),
        "Landroid/content/DialogInterface$OnClickListener;" => ret_void(),
        "Landroid/content/res/Resources;" => resources(vm, name, args),
        "Landroid/content/res/AssetManager;" => asset_manager(vm, name, args),
        "Landroid/content/res/Configuration;" => ret_int(0),
        "Landroid/content/pm/ActivityInfo;" | "Landroid/content/pm/ServiceInfo;" => ret_int(0),
        _ => {
            if class.starts_with("Landroid/content/pm/") {
                return pm_ops(vm, class, name, args);
            }
            if class.starts_with("Landroid/content/") {
                return ret_void();
            }
            CallOutcome::Decline
        }
    }
}

fn context_ops(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getApplicationContext" | "getApplication" | "getBaseContext" | "getContext" => ret_obj(this),
        "getPackageName" => {
            let pkg = vm.env.persona.system_properties.get("app.package").cloned().unwrap_or_else(|| "com.example.app".into());
            string_or_empty(vm, &pkg)
        }
        "getSystemService" | "getSystemServiceName" => ret_obj(this),
        "getSharedPreferences" => {
            // Returns a persistent prefs object keyed by file name.
            let file = arg_str(vm, args, 1).unwrap_or_else(|| "prefs".into());
            let o = match vm.new_instance_of("Landroid/content/SharedPreferences;") {
                Ok(o) => o,
                Err(_) => return ret_obj(ObjRef::NULL),
            };
            if let Ok(n) = vm.new_string(file) {
                set_state_ref(vm, o, "file", n);
            }
            ret_obj(o)
        }
        "getContentResolver" => match vm.new_instance_of("Landroid/content/ContentResolver;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getResources" => match vm.new_instance_of("Landroid/content/res/Resources;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getAssets" => match vm.new_instance_of("Landroid/content/res/AssetManager;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getFilesDir" | "getCacheDir" | "getDir" | "getCodeCacheDir" => {
            // These return a `File`, not a String. Samples routinely call
            // `.getAbsolutePath()` on the result and build a write path from
            // it, so the model must fabricate a File carrying the path.
            let pkg = app_package(vm);
            let sub = if name == "getCacheDir" { "cache" } else { "files" };
            file_at(vm, &format!("/data/user/0/{pkg}/{sub}"))
        }
        "getExternalFilesDir" | "getExternalCacheDir" => {
            let pkg = app_package(vm);
            let sub = if name == "getExternalCacheDir" { "cache" } else { "files" };
            file_at(vm, &format!("/sdcard/Android/data/{pkg}/{sub}"))
        }
        "getExternalStorageDirectory" | "getExternal" => {
            file_at(vm, "/storage/emulated/0")
        }
        "getPackageCodePath" | "getPackageResourcePath" => {
            string_or_empty(vm, "/data/app/~~hash==/com.example.app/base.apk")
        }
        "getClassLoader" => match vm.new_instance_of("Ljava/lang/ClassLoader;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getMainLooper" => match vm.new_instance_of("Landroid/os/Looper;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getApplicationInfo" => match vm.new_instance_of("Landroid/content/pm/ApplicationInfo;") {
            Ok(o) => {
                let pkg = vm.env.persona.system_properties.get("app.package").cloned().unwrap_or_else(|| "com.example.app".into());
                if let Ok(p) = vm.new_string(pkg) {
                    set_state_ref(vm, o, "packageName", p);
                }
                ret_obj(o)
            }
            Err(_) => ret_void(),
        },
        "getPackageManager" => match vm.new_instance_of("Landroid/content/pm/PackageManager;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "startService" | "bindService" | "unbindService" | "stopService" | "stopSelf" => {
            let intent = arg_ref(args, 1);
            let desc = intent_describe(vm, intent);
            vm.report_sink(
                SinkKind::Persistence,
                format!("Context->{name}"),
                format!("service intent: {desc}"),
                vm.heap.taint_of(intent),
                vec![desc],
            );
            ret_void()
        }
        "startActivity" | "startActivityForResult" | "startActivities" => {
            let intent = arg_ref(args, 1);
            let desc = intent_describe(vm, intent);
            vm.report_sink(
                SinkKind::Persistence,
                format!("Context->{name}"),
                format!("activity intent: {desc}"),
                vm.heap.taint_of(intent),
                vec![desc],
            );
            // Deliver to our own launcher activity if the intent targets us.
            let _ = host;
            ret_void()
        }
        "sendBroadcast" | "sendOrderedBroadcast" | "sendBroadcastAsUser" => {
            let intent = arg_ref(args, 1);
            let desc = intent_describe(vm, intent);
            vm.report_sink(
                SinkKind::Persistence,
                format!("Context->{name}"),
                format!("broadcast: {desc}"),
                vm.heap.taint_of(intent),
                vec![desc],
            );
            ret_void()
        }
        "registerReceiver" => {
            let receiver = arg_ref(args, 1);
            let filter = arg_ref(args, 2);
            let action = state_str(vm, filter, "action").unwrap_or_default();
            vm.report_sink(
                SinkKind::Persistence,
                "Context->registerReceiver",
                format!("dynamic receiver for {action}"),
                Taint::CLEAN,
                vec![format!("receiver={}", vm.object_describe(receiver))],
            );
            ret_obj(receiver)
        }
        "enforceCallingPermission" | "checkSelfPermission" | "checkCallingOrSelfPermission"
        | "checkPermission" => {
            let perm = arg_str(vm, args, 1).unwrap_or_default();
            vm.probe(&format!("Context.{name}({perm})"), "GRANTED");
            ret_int(0) // PackageManager.PERMISSION_GRANTED
        }
        "openFileInput" | "openFileOutput" | "deleteFile" | "getFileStreamPath" => {
            io_file_op(vm, name, args)
        }
        "getDatabasePath" | "openOrCreateDatabase" => match vm.new_instance_of("Landroid/database/sqlite/SQLiteDatabase;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "createPackageContext" => ret_obj(this),
        "grantUriPermission" | "revokeUriPermission" => ret_void(),
        "isRestricted" => ret_bool(false),
        "getObbDir" => string_or_empty(vm, "/storage/emulated/0/Android/obb"),
        "getNoBackupFilesDir" => {
            let pkg = vm.env.persona.system_properties.get("app.package").cloned().unwrap_or_else(|| "com.example.app".into());
            string_or_empty(vm, &format!("/data/user/0/{pkg}/no_backup"))
        }
        "getString" | "getText" => string_or_empty(vm, ""),
        _ => CallOutcome::Decline,
    }
}

/// The package name the simulated app sees itself as.
fn app_package(vm: &Vm) -> String {
    vm.env
        .persona
        .system_properties
        .get("app.package")
        .cloned()
        .unwrap_or_else(|| "com.example.app".into())
}

/// Build a `java.io.File` whose path is `path`.
fn file_at(vm: &mut Vm, path: &str) -> CallOutcome {
    match vm.new_instance_of("Ljava/io/File;") {
        Ok(f) => {
            if let Ok(p) = vm.new_string(path) {
                super::set_state_ref(vm, f, "path", p);
            }
            ret_obj(f)
        }
        Err(_) => ret_void(),
    }
}

fn io_file_op(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    // File IO: return a stream backed by the environment's in-memory files.
    let fname = arg_str(vm, args, 1).unwrap_or_default();
    match name {
        "openFileOutput" => {
            let pkg_dir = "/data/user/0/com.example.app/files";
            let path = format!("{pkg_dir}/{fname}");
            let obj = match vm.new_instance_of("Ljava/io/FileOutputStream;") {
                Ok(o) => o,
                Err(_) => return ret_void(),
            };
            if let Ok(p) = vm.new_string(path.clone()) {
                set_state_ref(vm, obj, "path", p);
            }
            if let Ok(buf) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                set_state_ref(vm, obj, "buf", buf);
            }
            vm.env.write_file(path, Vec::new());
            ret_obj(obj)
        }
        "openFileInput" => {
            let pkg_dir = "/data/user/0/com.example.app/files";
            let path = format!("{pkg_dir}/{fname}");
            let data = vm.env.read_file(&path).map(|b| b.to_vec()).unwrap_or_default();
            let t = if data.is_empty() {
                Taint::CLEAN
            } else {
                vm.mint_taint(TaintSource::FileContents.label())
            };
            match vm.heap.new_bytes(data, t) {
                Ok(b) => {
                    let obj = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                        Ok(o) => o,
                        Err(_) => return ret_void(),
                    };
                    set_state_ref(vm, obj, "buf", b);
                    set_state_int(vm, obj, "pos", 0);
                    ret_obj(obj)
                }
                Err(_) => ret_void(),
            }
        }
        "deleteFile" => {
            let pkg_dir = "/data/user/0/com.example.app/files";
            vm.env.files.remove(&format!("{pkg_dir}/{fname}"));
            ret_bool(true)
        }
        "getFileStreamPath" => string_or_empty(vm, &format!("/data/user/0/com.example.app/files/{fname}")),
        _ => CallOutcome::Decline,
    }
}

fn intent_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // Intent() / Intent(String action) / Intent(Context, Class)
            for a in args.iter().skip(1) {
                if let Value::Ref(r) = a.v {
                    if vm.heap.is_string(r) {
                        let s = vm.string_of(r);
                        if let Some(inst) = vm.heap.instance_mut(this) {
                            inst.state.insert("action".into(), Slot::reference(r));
                        }
                        let _ = s;
                        break;
                    }
                }
            }
            // (Context, Class): stash target class.
            if let Some(v) = args.get(2) {
                if let Value::Ref(r) = v.v {
                    if let Ok(n) = vm.new_string(vm.object_describe(r)) {
                        set_state_ref(vm, this, "target", n);
                    }
                }
            }
            ret_void()
        }
        "setAction" | "setData" | "setDataAndType" | "setType" | "setPackage" | "setClass"
        | "setClassName" | "putExtra" | "putExtras" | "putParcelableArrayListExtra"
        | "setFlags" | "addFlags" | "setComponent" => {
            if name == "putExtra" {
                let key = arg_str(vm, args, 1).unwrap_or_default();
                if let Some(v) = args.get(2) {
                    if let Some(inst) = vm.heap.instance_mut(this) {
                        inst.state.insert(format!("extra:{key}"), *v);
                    }
                }
            } else if name == "setAction" {
                if let Some(a) = args.get(1) {
                    if let Some(inst) = vm.heap.instance_mut(this) {
                        inst.state.insert("action".into(), *a);
                    }
                }
            } else if name == "setClassName" || name == "setClass" {
                let target = arg_str(vm, args, 3).or_else(|| arg_str(vm, args, 1)).unwrap_or_default();
                set_state_str_into(vm, this, "target", target);
            } else if name == "setPackage" {
                let pkg = arg_str(vm, args, 1).unwrap_or_default();
                set_state_str_into(vm, this, "package", pkg);
            }
            ret_obj(this)
        }
        "getAction" => ret_obj(state_ref(vm, this, "action")),
        "getStringExtra" | "getCharSequenceExtra" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL);
            ret_obj(v)
        }
        "getIntExtra" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_int()).unwrap_or(0);
            ret_int(v)
        }
        "getBooleanExtra" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_int() != 0).unwrap_or(false);
            ret_bool(v)
        }
        "hasExtra" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            ret_bool(vm.heap.instance(this).map(|i| i.state.contains_key(&format!("extra:{key}"))).unwrap_or(false))
        }
        "getExtras" => match vm.new_instance_of("Landroid/os/Bundle;") {
            Ok(b) => {
                // Copy extras across.
                let pairs: Vec<(String, Slot)> = vm
                    .heap
                    .instance(this)
                    .map(|i| {
                        i.state
                            .iter()
                            .filter(|(k, _)| k.starts_with("extra:"))
                            .map(|(k, v)| (k[6..].to_string(), *v))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(inst) = vm.heap.instance_mut(b) {
                    for (k, v) in pairs {
                        inst.state.insert(format!("extra:{k}"), v);
                    }
                }
                ret_obj(b)
            }
            Err(_) => ret_void(),
        },
        "getComponent" | "getComponentName" | "getData" | "getDataString" => ret_obj(state_ref(vm, this, "data")),
        "toString" => {
            let d = intent_describe(vm, this);
            string_or_empty(vm, &d)
        }
        "getFlags" => ret_int(0),
        _ => CallOutcome::Decline,
    }
}

fn set_state_str_into(vm: &mut Vm, obj: ObjRef, key: &str, value: String) {
    if let Ok(r) = vm.new_string(value) {
        set_state_ref(vm, obj, key, r);
    }
}

pub fn intent_describe(vm: &Vm, intent: ObjRef) -> String {
    if intent.is_null() {
        return "null".into();
    }
    let action = state_str(vm, intent, "action").unwrap_or_else(|| "(none)".into());
    let target = state_str(vm, intent, "target").unwrap_or_default();
    let package = state_str(vm, intent, "package").unwrap_or_default();
    let data = state_str(vm, intent, "data").unwrap_or_default();
    let mut parts = vec![format!("action={action}")];
    if !target.is_empty() {
        parts.push(format!("target={target}"));
    }
    if !package.is_empty() {
        parts.push(format!("pkg={package}"));
    }
    if !data.is_empty() {
        parts.push(format!("data={data}"));
    }
    // Extras, which often carry the exfiltrated data.
    if let Some(inst) = vm.heap.instance(intent) {
        let extras: Vec<String> = inst
            .state
            .iter()
            .filter(|(k, _)| k.starts_with("extra:"))
            .map(|(k, v)| format!("{}={}", &k[6..], vm.object_describe(v.v.as_ref())))
            .collect();
        if !extras.is_empty() {
            parts.push(format!("extras[{}]", extras.join(",")));
        }
    }
    parts.join(" ")
}

fn intent_filter(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if let Some(a) = arg_str(vm, args, 1) {
                set_state_str_into(vm, this, "action", a);
            }
            ret_void()
        }
        "addAction" => {
            let a = arg_str(vm, args, 1).unwrap_or_default();
            set_state_str_into(vm, this, "action", a);
            ret_obj(this)
        }
        _ => ret_void(),
    }
}

fn component_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            let (pkg, cls) = (arg_str(vm, args, 1).unwrap_or_default(), arg_str(vm, args, 2).unwrap_or_default());
            set_state_str_into(vm, this, "package", pkg);
            set_state_str_into(vm, this, "class", cls);
            ret_void()
        }
        "getPackageName" => ret_obj(state_ref(vm, this, "package")),
        "getClassName" => ret_obj(state_ref(vm, this, "class")),
        "getShortClassName" => ret_obj(state_ref(vm, this, "class")),
        "flattenToString" | "flattenToShortString" => {
            let p = state_str(vm, this, "package").unwrap_or_default();
            let c = state_str(vm, this, "class").unwrap_or_default();
            string_or_empty(vm, &format!("{p}/{c}"))
        }
        _ => CallOutcome::Decline,
    }
}

fn pm_ops(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "getInstalledPackages" | "getInstalledApplications" => {
            let pkgs = vm.env.persona.packages.clone();
            let elem_desc = if name.contains("Applications") {
                "Landroid/content/pm/ApplicationInfo;"
            } else {
                "Landroid/content/pm/PackageInfo;"
            };
            let elem = vm.sym(elem_desc);
            let arr = match vm.heap.new_array(elem, elem_desc, pkgs.len(), Taint::CLEAN) {
                Ok(a) => a,
                Err(_) => return ret_void(),
            };
            for (i, p) in pkgs.iter().enumerate() {
                let obj = match vm.new_instance_of(elem_desc) {
                    Ok(o) => o,
                    Err(_) => continue,
                };
                super::put_state_str(vm, obj, "packageName", p.name.clone());
                super::put_state_int(vm, obj, "flags", if p.is_system { 1 } else { 0 });
                super::put_state_str(vm, obj, "label", p.label.clone());
                super::put_state_int(vm, obj, "debuggable", if p.is_debuggable { 1 } else { 0 });
                vm.heap.array_set(arr, i, Slot::reference(obj));
            }
            vm.probe("PackageManager.getInstalledPackages", pkgs.len().to_string());
            let t = vm.mint_taint(TaintSource::InstalledApps.label());
            vm.heap.add_taint(arr, t);
            ret_obj(arr)
        }
        "getPackageInfo" | "getApplicationInfo" => {
            let pkg = arg_str(vm, args, 1).unwrap_or_default();
            let known = vm.env.persona.packages.iter().find(|p| p.name == pkg).cloned();
            vm.probe(&format!("PackageManager.{name}({pkg})"), known.is_some().to_string());
            match known {
                Some(p) => {
                    let desc = if name == "getApplicationInfo" {
                        "Landroid/content/pm/ApplicationInfo;"
                    } else {
                        "Landroid/content/pm/PackageInfo;"
                    };
                    match vm.new_instance_of(desc) {
                        Ok(o) => {
                            if let Ok(n) = vm.new_string(p.name.clone()) {
                                set_state_ref(vm, o, "packageName", n);
                            }
                            ret_obj(o)
                        }
                        Err(_) => ret_void(),
                    }
                }
                None => CallOutcome::Throw(
                    vm.exc_generic,
                    format!("NameNotFoundException: {pkg}"),
                ),
            }
        }
        "getPackageNameForUid" => ret_obj(ObjRef::NULL),
        "hasSystemFeature" => {
            let f = arg_str(vm, args, 1).unwrap_or_default();
            ret_bool(f.contains("telephony") || f.contains("camera") || f.contains("touchscreen"))
        }
        "queryIntentServices" | "queryBroadcastReceivers" | "queryIntentActivities" => {
            empty_array(vm, "Landroid/content/pm/ResolveInfo;")
        }
        "getApplicationLabel" => {
            let ai = arg_ref(args, 1);
            ret_obj(state_ref(vm, ai, "label"))
        }
        "getLaunchIntentForPackage" => match vm.new_instance_of("Landroid/content/Intent;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getInstallerPackageName" => string_or_empty(vm, "com.android.vending"),
        "isSafeMode" => ret_bool(false),
        "getPermissionInfo" | "checkPermission" => ret_int(0),
        _ if class.starts_with("Landroid/content/pm/PackageInfo;") || class.starts_with("Landroid/content/pm/ApplicationInfo;") => {
            let this = arg_ref(args, 0);
            match name {
                "getPackageName" | "getPackage" => ret_obj(state_ref(vm, this, "packageName")),
                "getClass" => ret_void(),
                _ => {
                    let v = vm.heap.instance(this).and_then(|i| i.state.get(match name {
                        "getFlags" => "flags",
                        "isDebuggable" => "debuggable",
                        _ => "",
                    })).map(|s| s.v.as_int()).unwrap_or(0);
                    if name == "isDebuggable" {
                        ret_bool(v != 0)
                    } else {
                        ret_int(v)
                    }
                }
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn clipboard(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getPrimaryClip" => {
            if vm.env.clipboard.is_empty() {
                return ret_obj(ObjRef::NULL);
            }
            match vm.new_instance_of("Landroid/content/ClipData;") {
                Ok(o) => {
                    let t = vm.mint_taint(TaintSource::Clipboard.label());
                    if let Ok(s) = vm.new_string(vm.env.clipboard.clone()) {
                        set_state_ref(vm, o, "text", s);
                        vm.heap.add_taint(o, t);
                    }
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            }
        }
        "getText" | "getItemAt" | "coerceToText" => ret_obj(state_ref(vm, this, "text")),
        "setPrimaryClip" | "setText" => {
            let item = args.iter().rev().find(|s| !matches!(s.v, Value::Int(_))).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL);
            let text = vm.string_of(item);
            vm.env.clipboard = text;
            ret_void()
        }
        "newPlainText" | "newHtmlText" => match vm.new_instance_of("Landroid/content/ClipData;") {
            Ok(o) => {
                if let Some(t) = args.iter().rev().find_map(|s| {
                    let r = s.v.as_ref();
                    vm.heap.string_of(r).map(|x| x.to_string())
                }) {
                    if let Ok(rs) = vm.new_string(t) {
                        set_state_ref(vm, o, "text", rs);
                    }
                }
                ret_obj(o)
            }
            Err(_) => ret_void(),
        },
        "getItemCount" => ret_int(1),
        _ => {
            let _ = class;
            CallOutcome::Decline
        }
    }
}

fn prefs(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    if class.ends_with("$Editor;") {
        return match name {
            "putString" | "putInt" | "putLong" | "putBoolean" | "putFloat" | "putStringSet" => {
                let file = state_str(vm, this, "file").unwrap_or_default();
                let key = arg_str(vm, args, 1).unwrap_or_default();
                let val = super::java_to_string(vm, args.get(2).copied().unwrap_or_default());
                vm.env.prefs.entry(file).or_default().insert(key, val);
                ret_obj(this)
            }
            "remove" | "clear" => {
                let file = state_str(vm, this, "file").unwrap_or_default();
                vm.env.prefs.entry(file).or_default().clear();
                ret_obj(this)
            }
            "commit" => ret_bool(true),
            "apply" => ret_void(),
            _ => CallOutcome::Decline,
        };
    }
    match name {
        "getString" => {
            let file = state_str(vm, this, "file").unwrap_or_default();
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm
                .env
                .prefs
                .get(&file)
                .and_then(|m| m.get(&key))
                .cloned()
                .or_else(|| arg_str(vm, args, 2));
            match v {
                Some(s) => string_or_empty(vm, &s),
                None => ret_obj(ObjRef::NULL),
            }
        }
        "getInt" => {
            let file = state_str(vm, this, "file").unwrap_or_default();
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.env.prefs.get(&file).and_then(|m| m.get(&key)).and_then(|x| x.parse().ok()).unwrap_or_else(|| arg_int(args, 2));
            ret_int(v)
        }
        "getBoolean" => {
            let file = state_str(vm, this, "file").unwrap_or_default();
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.env.prefs.get(&file).and_then(|m| m.get(&key)).map(|x| x == "true").unwrap_or(arg_int(args, 2) != 0);
            ret_bool(v)
        }
        "getLong" => {
            let file = state_str(vm, this, "file").unwrap_or_default();
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.env.prefs.get(&file).and_then(|m| m.get(&key)).and_then(|x| x.parse().ok()).unwrap_or_else(|| arg_long(args, 2));
            ret_long(v)
        }
        "edit" => {
            let file = state_str(vm, this, "file").unwrap_or_default();
            match vm.new_instance_of("Landroid/content/SharedPreferences$Editor;") {
                Ok(o) => {
                    set_state_str_into(vm, o, "file", file);
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            }
        }
        "contains" => {
            let file = state_str(vm, this, "file").unwrap_or_default();
            let key = arg_str(vm, args, 1).unwrap_or_default();
            ret_bool(vm.env.prefs.get(&file).map(|m| m.contains_key(&key)).unwrap_or(false))
        }
        "getAll" => match vm.new_instance_of("Ljava/util/HashMap;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        _ => CallOutcome::Decline,
    }
}

fn content_values(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => ret_void(),
        "put" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            if let Some(v) = args.get(2) {
                if let Some(inst) = vm.heap.instance_mut(this) {
                    inst.state.insert(format!("v:{key}"), *v);
                }
            }
            ret_void()
        }
        _ => CallOutcome::Decline,
    }
}

fn resolver(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "query" => {
            let uri = arg_str(vm, args, 1).unwrap_or_default();
            // Serve contacts/SMS/call-log from the scenario's fabricated data.
            let t = if uri.contains("contact") {
                vm.mint_taint(TaintSource::Contacts.label())
            } else if uri.contains("sms") {
                vm.mint_taint(TaintSource::SmsInbox.label())
            } else if uri.contains("call_log") || uri.contains("calls") {
                vm.mint_taint(TaintSource::CallLog.label())
            } else {
                Taint::CLEAN
            };
            let rows: Vec<(String, String)> = if uri.contains("contact") {
                vm.env.contacts.iter().map(|c| (c.name.clone(), c.number.clone())).collect()
            } else if uri.contains("sms") {
                vm.env.inbox_sms.iter().map(|m| (m.address.clone(), m.body.clone())).collect()
            } else if uri.contains("call_log") || uri.contains("calls") {
                vm.env.call_log.iter().map(|c| (c.number.clone(), c.kind.clone())).collect()
            } else {
                Vec::new()
            };
            vm.report_sink(
                SinkKind::SensitiveFlow,
                "ContentResolver->query",
                format!("queried {uri}: {} rows", rows.len()),
                t,
                rows.iter().map(|(a, b)| format!("{a} | {b}")).take(20).collect(),
            );
            // Return a Cursor object carrying the rows.
            match vm.new_instance_of("Landroid/database/Cursor;") {
                Ok(c) => {
                    super::put_state_int(vm, c, "count", rows.len() as i32);
                    let elem = vm.sym("Ljava/lang/Object;");
                    if let Ok(arr) = vm.heap.new_array(elem, "Ljava/lang/Object;", rows.len() * 2, t) {
                        for (i, (a, b)) in rows.iter().enumerate() {
                            if let Ok(ra) = vm.new_string_t(a.clone(), t) {
                                vm.heap.array_set(arr, i * 2, Slot::reference(ra));
                            }
                            if let Ok(rb) = vm.new_string_t(b.clone(), t) {
                                vm.heap.array_set(arr, i * 2 + 1, Slot::reference(rb));
                            }
                        }
                        super::put_state_slot(vm, c, "rows", Slot::reference(arr));
                    }
                    ret_obj(c)
                }
                Err(_) => ret_void(),
            }
        }
        "openInputStream" => {
            let uri = arg_str(vm, args, 1).unwrap_or_default();
            let data = vm.env.read_file(&uri).map(|b| b.to_vec()).unwrap_or_default();
            let t = vm.mint_taint(TaintSource::FileContents.label());
            match vm.heap.new_bytes(data, t) {
                Ok(b) => {
                    let obj = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                        Ok(o) => o,
                        Err(_) => return ret_void(),
                    };
                    set_state_ref(vm, obj, "buf", b);
                    set_state_int(vm, obj, "pos", 0);
                    ret_obj(obj)
                }
                Err(_) => ret_void(),
            }
        }
        "openOutputStream" => match vm.new_instance_of("Ljava/io/ByteArrayOutputStream;") {
            Ok(o) => {
                if let Ok(b) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                    set_state_ref(vm, o, "buf", b);
                }
                ret_obj(o)
            }
            Err(_) => ret_void(),
        },
        "registerContentObserver" => ret_void(),
        "getType" => string_or_empty(vm, "*/*"),
        "delete" | "update" => ret_int(1),
        "insert" => {
            let uri = arg_str(vm, args, 1).unwrap_or_default();
            let values = arg_ref(args, 2);
            vm.report_sink(
                SinkKind::SensitiveFlow,
                "ContentResolver->insert",
                format!("insert into {uri}"),
                vm.heap.taint_of(values),
                vec![],
            );
            match vm.new_instance_of("Landroid/net/Uri;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            }
        }
        _ => {
            let _ = host;
            CallOutcome::Decline
        }
    }
}

fn resources(vm: &mut Vm, name: &str, _args: &[Slot]) -> CallOutcome {
    match name {
        "getIdentifier" | "getInteger" => ret_int(0),
        "getString" | "getStringArray" | "getAssets" => match vm.new_string("") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "openRawResource" => match vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "getDisplayMetrics" => match vm.new_instance_of("Landroid/util/DisplayMetrics;") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "getConfiguration" => match vm.new_instance_of("Landroid/content/res/Configuration;") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "getLayout" | "getColor" => ret_int(0),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// android.os: Build, SystemClock, Handler, Looper, Bundle, PowerManager, ...
// ---------------------------------------------------------------------------

fn os(vm: &mut Vm, host: &mut AndroidHost, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    match class {
        "Landroid/os/Build;" => CallOutcome::Decline,
        "Landroid/os/SystemClock;" => match name {
            "uptimeMillis" | "elapsedRealtime" | "currentThreadTimeMillis" => ret_long(vm.env.now()),
            "sleep" => {
                vm.env.advance(arg_long(args, 0));
                ret_void()
            }
            _ => CallOutcome::Decline,
        },
        "Landroid/os/Handler;" => handler(vm, host, name, args),
        "Landroid/os/Looper;" => match name {
            "getMainLooper" | "myLooper" | "getCurrentLooper" => {
                match vm.new_instance_of("Landroid/os/Looper;") {
                    Ok(o) => ret_obj(o),
                    Err(_) => ret_void(),
                }
            }
            "prepare" | "loop" | "quit" | "quitSafely" => ret_void(),
            _ => CallOutcome::Decline,
        },
        "Landroid/os/Bundle;" => bundle(vm, name, args),
        "Landroid/os/PowerManager;" | "Landroid/os/PowerManager$WakeLock;" => power(vm, class, name, args),
        "Landroid/os/Environment;" => match name {
            "getExternalStorageDirectory" => string_or_empty(vm, "/storage/emulated/0"),
            "getExternalStorageState" => string_or_empty(vm, "mounted"),
            "getDataDirectory" => string_or_empty(vm, "/data"),
            "getRootDirectory" => string_or_empty(vm, "/system"),
            "isExternalStorageEmulated" => ret_bool(true),
            "isExternalStorageRemovable" => ret_bool(false),
            _ => CallOutcome::Decline,
        },
        "Landroid/os/Process;" => {
            if name == "killProcess" {
                let pid = arg_int(args, 0);
                vm.report_sink(
                    SinkKind::PrivilegedAction,
                    "android/os/Process->killProcess",
                    format!("killProcess({pid})"),
                    Taint::CLEAN,
                    vec![],
                );
            }
            if name == "myPid" {
                return ret_int(4242);
            }
            if name == "myUid" {
                return ret_int(10123);
            }
            ret_void()
        }
        "Landroid/os/Message;" => match name {
            "<init>" | "obtain" => match vm.new_instance_of("Landroid/os/Message;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            },
            "sendToTarget" => {
                // Deliver to the handler this message was built for.
                let handler = state_ref(vm, arg_ref(args, 0), "handler");
                if !handler.is_null() {
                    let _ = invoke_handler_message(vm, host, handler, arg_ref(args, 0));
                }
                ret_void()
            }
            "getData" => match vm.new_instance_of("Landroid/os/Bundle;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            },
            "getTarget" => ret_obj(state_ref(vm, arg_ref(args, 0), "handler")),
            "setTarget" => {
                let this = arg_ref(args, 0);
                let target = arg_ref(args, 1);
                set_state_ref(vm, this, "handler", target);
                ret_void()
            }
            _ => CallOutcome::Decline,
        },
        "Landroid/os/MessageQueue;" | "Landroid/os/IBinder;" | "Landroid/os/IInterface;"
        | "Landroid/os/Binder;" | "Landroid/os/Parcel;" | "Landroid/os/Parcelable;"
        | "Landroid/os/Parcelable$Creator;" => match name {
            "obtain" | "asInterface" => ret_obj(ObjRef::NULL),
            "writeString" | "writeInt" | "recycle" => ret_void(),
            "readString" => match vm.new_string("") {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            },
            "readInt" => ret_int(0),
            _ => ret_void(),
        },
        "Landroid/os/Debug;" => match name {
            "isDebuggerConnected" | "waitingForDebugger" => {
                vm.probe(&format!("Debug.{name}"), "false");
                ret_bool(false)
            }
            "getNativeHeapAllocatedSize" => ret_long(1_000_000),
            _ => ret_void(),
        },
        "Landroid/os/Vibrator;" => {
            if name == "vibrate" {
                vm.report_sink(
                    SinkKind::PrivilegedAction,
                    "android/os/Vibrator->vibrate",
                    "device vibration (often a payload-arrival signal)",
                    Taint::CLEAN,
                    vec![],
                );
            }
            ret_void()
        }
        "Landroid/os/StatFs;" | "Landroid/os/Stat;" => match name {
            "getAvailableBlocks" => ret_long(1_000_000),
            "getBlockSize" => ret_long(4096),
            "getAvailableBytes" => ret_long(4_000_000_000),
            "stat" => ret_void(),
            _ => CallOutcome::Decline,
        },
        "Landroid/os/AsyncTask;" => async_task(vm, host, name, args),
        "Landroid/os/PatternMatcher;" | "Landroid/os/FileObserver;" => ret_void(),
        _ => {
            if class.starts_with("Landroid/os/StrictMode") {
                return ret_void();
            }
            CallOutcome::Decline
        }
    }
}

fn handler(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => ret_void(),
        "post" | "postDelayed" | "sendEmptyMessage" | "sendEmptyMessageDelayed"
        | "sendMessage" | "sendMessageDelayed" | "sendMessageAtTime" | "postAtTime" => {
            let delay = match name {
                "postDelayed" | "sendEmptyMessageDelayed" | "sendMessageDelayed" => arg_long(args, 2),
                _ => 0,
            };
            // Runnable or Message payload.
            let payload = args.get(1).copied().unwrap_or_default();
            let what = arg_int(args, 1);
            let mut callback = None;
            if let Value::Ref(r) = payload.v {
                if !r.is_null() {
                    if vm.heap.is_string(r) {
                        // not a runnable
                    } else if matches!(vm.heap.get(r).map(|o| &o.kind), Some(ObjKind::Instance(_))) {
                        callback = Some(r);
                    }
                }
            }
            let cb = if let Some(r) = callback {
                super::reflect::CallbackTarget::Runnable(r)
            } else {
                super::reflect::CallbackTarget::Message { handler: this, what }
            };
            let label = format!("handler {name} what={what} delay={delay}");
            super::reflect::schedule(vm, delay, label, cb);
            let _ = host;
            ret_bool(true)
        }
        "removeCallbacks" | "removeMessages" | "removeCallbacksAndMessages" => ret_void(),
        "handleMessage" => CallOutcome::Decline,
        "obtainMessage" => match vm.new_instance_of("Landroid/os/Message;") {
            Ok(o) => {
                let what = arg_int(args, 1);
                set_state_int(vm, o, "what", what);
                set_state_ref(vm, o, "handler", this);
                ret_obj(o)
            }
            Err(_) => ret_void(),
        },
        "getLooper" => match vm.new_instance_of("Landroid/os/Looper;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        _ => CallOutcome::Decline,
    }
}

pub fn invoke_handler_message(vm: &mut Vm, host: &mut AndroidHost, handler: ObjRef, message: ObjRef) -> bool {
    // Find an app-defined Handler subclass and call handleMessage(Message).
    let Some(class) = vm.heap.class_of(handler) else { return false };
    let hm = vm.sym("handleMessage");
    let proto = vm.sym("(Landroid/os/Message;)V");
    let entry = vm.registry.resolve_virtual(class, hm, proto);
    if let Some(entry) = entry {
        if entry.code_off != 0 {
            let _ = vm.execute(host, entry, vec![Slot::reference(handler), Slot::reference(message)]);
            return true;
        }
    }
    false
}

fn bundle(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => ret_void(),
        "putString" | "putInt" | "putLong" | "putBoolean" | "putParcelable" | "putSerializable"
        | "putStringArrayList" | "putByteArray" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            if let Some(v) = args.get(2) {
                if let Some(inst) = vm.heap.instance_mut(this) {
                    inst.state.insert(format!("extra:{key}"), *v);
                }
            }
            ret_void()
        }
        "getString" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL);
            ret_obj(v)
        }
        "getInt" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_int()).unwrap_or(0);
            ret_int(v)
        }
        "getLong" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_long()).unwrap_or(0);
            ret_long(v)
        }
        "getBoolean" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_int() != 0).unwrap_or(false);
            ret_bool(v)
        }
        "getByteArray" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            let v = vm.heap.instance(this).and_then(|i| i.state.get(&format!("extra:{key}"))).map(|s| s.v.as_ref()).unwrap_or(ObjRef::NULL);
            ret_obj(v)
        }
        "containsKey" => {
            let key = arg_str(vm, args, 1).unwrap_or_default();
            ret_bool(vm.heap.instance(this).map(|i| i.state.contains_key(&format!("extra:{key}"))).unwrap_or(false))
        }
        "keySet" | "size" | "isEmpty" => ret_int(0),
        _ => CallOutcome::Decline,
    }
}

fn power(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    let battery = vm.env.persona.battery.clone();
    if class.ends_with("$WakeLock;") {
        return match name {
            "acquire" | "release" => ret_void(),
            "isHeld" => ret_bool(true),
            _ => CallOutcome::Decline,
        };
    }
    match name {
        "isScreenOn" | "isInteractive" => ret_bool(true),
        "isPowerSaveMode" => ret_bool(false),
        "newWakeLock" => match vm.new_instance_of("Landroid/os/PowerManager$WakeLock;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getBatteryLevel" => ret_int(battery.level),
        "isIgnoringBatteryOptimizations" => ret_bool(true),
        _ => {
            let _ = this;
            CallOutcome::Decline
        }
    }
}

fn async_task(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "execute" => {
            // Run doInBackground on the app's subclass.
            if let Some(class) = vm.heap.class_of(this) {
                let dn = vm.sym("doInBackground");
                let dproto = vm.sym("([Ljava/lang/Object;)Ljava/lang/Object;");
                if let Some(entry) = vm.registry.resolve_virtual(class, dn, dproto) {
                    if entry.code_off != 0 {
                        let empty = vm.new_array_of("Ljava/lang/Object;", 0).unwrap_or(ObjRef::NULL);
                        let _ = vm.execute(host, entry, vec![Slot::reference(this), Slot::reference(empty)]);
                    }
                }
            }
            ret_obj(this)
        }
        "onPreExecute" | "onPostExecute" | "onProgressUpdate" | "publishProgress" => ret_void(),
        "cancel" => ret_bool(false),
        "isCancelled" => ret_bool(false),
        "<init>" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// Providers (Settings, Telephony.Sms, Contacts)
// ---------------------------------------------------------------------------

fn provider(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let _ = args;
    let up = class.to_string();
    if up.starts_with("Landroid/provider/Settings$Secure;") {
        return match name {
            "getString" => {
                // (ContentResolver, String)
                let key = arg_str(vm, args, 1).unwrap_or_default();
                let v = vm.env.persona.settings_secure.get(&key).cloned().unwrap_or_default();
                vm.probe(&format!("Settings.Secure.getString({key})"), &v);
                let t = if key == "android_id" {
                    vm.mint_taint(TaintSource::AndroidId.label())
                } else {
                    Taint::CLEAN
                };
                match vm.new_string_t(v, t) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                }
            }
            "getInt" => ret_int(0),
            "putString" => ret_bool(true),
            _ => CallOutcome::Decline,
        };
    }
    if up.starts_with("Landroid/provider/Settings$Global;") {
        return match name {
            "getString" => {
                let key = arg_str(vm, args, 1).unwrap_or_default();
                let v = vm.env.persona.settings_global.get(&key).cloned().unwrap_or_default();
                vm.probe(&format!("Settings.Global.getString({key})"), &v);
                match vm.new_string(v) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                }
            }
            "getInt" => ret_int(0),
            _ => CallOutcome::Decline,
        };
    }
    if up.starts_with("Landroid/provider/Settings$System;") {
        return match name {
            "getString" => {
                let key = arg_str(vm, args, 1).unwrap_or_default();
                match vm.new_string("") {
                    Ok(r) => {
                        vm.probe(&format!("Settings.System.getString({key})"), "");
                        ret_obj(r)
                    }
                    Err(_) => ret_void(),
                }
            }
            _ => CallOutcome::Decline,
        };
    }
    if up.starts_with("Landroid/provider/Telephony$Sms;") || up.starts_with("Landroid/provider/Telephony;") {
        return match name {
            "getDefaultSmsPackage" => string_or_empty(vm, "com.samsung.android.messaging"),
            "getDefault" => match vm.new_instance_of("Landroid/net/Uri;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            },
            _ => CallOutcome::Decline,
        };
    }
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// Utilities: Log, Base64, StringBuilder-ish, AtomicInteger, etc.
// ---------------------------------------------------------------------------

fn util(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    match class {
        "Landroid/util/Log;" => {
            // Log lines are useful evidence: strip the tag and message.
            let tag = arg_str(vm, args, 0).unwrap_or_default();
            let msg = arg_str(vm, args, 1).unwrap_or_default();
            if !tag.is_empty() || !msg.is_empty() {
                vm.note_decrypted(format!("[log/{tag}] {msg}"));
            }
            ret_int(msg.len() as i32)
        }
        "Landroid/util/Base64;" => base64_ops(vm, name, args),
        "Landroid/util/AtomicFile;" => ret_void(),
        "Landroid/util/SparseArray;" => match name {
            "get" => ret_obj(ObjRef::NULL),
            "put" | "remove" | "clear" => ret_void(),
            "size" => ret_int(0),
            _ => CallOutcome::Decline,
        },
        "Landroid/util/DisplayMetrics;" => match name {
            "getWidthPixels" | "getHeightPixels" => ret_int(1080),
            _ => {
                let this = arg_ref(args, 0);
                let v = vm.heap.instance(this).and_then(|i| i.state.get("density")).map(|s| s.v.as_float()).unwrap_or(2.75);
                match name {
                    "getDensity" => CallOutcome::Value(Slot::float(v)),
                    "getDensityDpi" => ret_int(440),
                    "getScaledDensity" => CallOutcome::Value(Slot::float(v)),
                    _ => CallOutcome::Decline,
                }
            }
        },
        _ => CallOutcome::Decline,
    }
}

fn base64_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    use base64::Engine as _;
    // android.util.Base64.encodeToString(byte[] input, int flags)
    // android.util.Base64.decode(String str, int flags) / decode(byte[], int)
    let flags = arg_int(args, args.len().saturating_sub(1));
    let url_safe = flags & 8 != 0; // URL_SAFE
    let no_wrap = flags & 2 != 0; // NO_WRAP
    match name {
        "encodeToString" => {
            let data = crate::vm::android::arg_bytes(vm, args, 0).unwrap_or_default();
            let t = vm.heap.taint_of(arg_ref(args, 0));
            let enc = if url_safe {
                base64::engine::general_purpose::URL_SAFE.encode(&data)
            } else {
                base64::engine::general_purpose::STANDARD.encode(&data)
            };
            let _ = no_wrap; // line-wrapping is not modelled; NO_WRAP is the norm
            vm.note_decrypted(format!("b64({})", &enc[..enc.len().min(48)]));
            match vm.new_string_t(enc, t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "decode" => {
            // String or byte[] input.
            let input = if let Some(s) = arg_str(vm, args, 0) {
                s.into_bytes()
            } else {
                crate::vm::android::arg_bytes(vm, args, 0).unwrap_or_default()
            };
            let t = arg_taint(args, 0);
            let cleaned: Vec<u8> = input.into_iter().filter(|b| !b.is_ascii_whitespace()).collect();
            let decoded = if url_safe {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cleaned)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&cleaned))
            } else {
                base64::engine::general_purpose::STANDARD.decode(&cleaned)
            }
            .unwrap_or_default();
            if !decoded.is_empty() {
                let preview = String::from_utf8_lossy(&decoded[..decoded.len().min(64)]).to_string();
                vm.note_decrypted(preview);
            }
            match vm.heap.new_bytes(decoded, t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "encode" => {
            let data = crate::vm::android::arg_bytes(vm, args, 0).unwrap_or_default();
            let t = vm.heap.taint_of(arg_ref(args, 0));
            let enc = if url_safe {
                base64::engine::general_purpose::URL_SAFE.encode(&data)
            } else {
                base64::engine::general_purpose::STANDARD.encode(&data)
            };
            match vm.heap.new_bytes(enc.into_bytes(), t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// android.net: Uri, ConnectivityManager, WifiManager, TelephonyManager extras
// ---------------------------------------------------------------------------

fn net(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    match class {
        "Landroid/net/Uri;" => match name {
            "parse" => {
                let s = arg_str(vm, args, 0).unwrap_or_default();
                match vm.new_instance_of("Landroid/net/Uri;") {
                    Ok(o) => {
                        set_state_str_into(vm, o, "uri", s);
                        ret_obj(o)
                    }
                    Err(_) => ret_void(),
                }
            }
            "toString" => ret_obj(state_ref(vm, arg_ref(args, 0), "uri")),
            "getLastPathSegment" | "getPath" | "getHost" | "getScheme" | "getQueryParameter" => {
                let this = arg_ref(args, 0);
                let u = state_str(vm, this, "uri").unwrap_or_default();
                let part = match name {
                    "getHost" => url_part(&u, Part::Host),
                    "getScheme" => url_part(&u, Part::Scheme),
                    "getPath" => url_part(&u, Part::Path),
                    _ => url_part(&u, Part::LastSegment),
                };
                string_or_empty(vm, &part)
            }
            _ => ret_obj(ObjRef::NULL),
        },
        "Landroid/net/ConnectivityManager;" => match name {
            "getActiveNetworkInfo" => match vm.new_instance_of("Landroid/net/NetworkInfo;") {
                Ok(o) => {
                    let reachable = vm.env.persona.network.reachable;
                    set_state_int(vm, o, "connected", if reachable { 1 } else { 0 });
                    set_state_int(vm, o, "type", 1); // WIFI
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            },
            "isActiveNetworkMetered" => ret_bool(false),
            "getNetworkCapabilities" | "getLinkProperties" => ret_obj(ObjRef::NULL),
            "registerNetworkCallback" => ret_void(),
            _ => CallOutcome::Decline,
        },
        "Landroid/net/NetworkInfo;" => {
            let this = arg_ref(args, 0);
            match name {
                "isConnected" | "isAvailable" => {
                    let v = state_int(vm, this, "connected");
                    ret_bool(v != 0)
                }
                "getType" => ret_int(state_int(vm, this, "type")),
                "getTypeName" => string_or_empty(vm, "WIFI"),
                "getSubtype" => ret_int(0),
                "getExtraInfo" => ret_obj(ObjRef::NULL),
                _ => CallOutcome::Decline,
            }
        }
        "Landroid/net/wifi/WifiManager;" => match name {
            "getConnectionInfo" => match vm.new_instance_of("Landroid/net/wifi/WifiInfo;") {
                Ok(o) => {
                    if let Ok(m) = vm.new_string("a4:50:46:1b:2c:3d") {
                        set_state_ref(vm, o, "mac", m);
                    }
                    vm.probe("WifiManager.getConnectionInfo", "a4:50:46:1b:2c:3d");
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            },
            "getScanResults" => empty_array(vm, "Landroid/net/wifi/ScanResult;"),
            "isWifiEnabled" => ret_bool(true),
            "setWifiEnabled" => ret_bool(true),
            _ => CallOutcome::Decline,
        },
        "Landroid/net/wifi/WifiInfo;" => match name {
            "getMacAddress" => ret_obj(state_ref(vm, arg_ref(args, 0), "mac")),
            "getSSID" => string_or_empty(vm, "\"HomeNetwork\""),
            "getBSSID" => string_or_empty(vm, "a4:50:46:1b:2c:3d"),
            "getIpAddress" => ret_int(0),
            _ => CallOutcome::Decline,
        },
        "Landroid/net/NetworkInfo$State;" | "Landroid/net/Uri$Builder;" => CallOutcome::Decline,
        "Landroid/accounts/AccountManager;" => match name {
            "getAccounts" | "getAccountsByType" => {
                let elem = vm.sym("Landroid/accounts/Account;");
                match vm.heap.new_array(elem, "Landroid/accounts/Account;", 1, Taint::CLEAN) {
                    Ok(arr) => {
                        if let Ok(a) = vm.new_instance_of("Landroid/accounts/Account;") {
                            if let Ok(n) = vm.new_string("user@gmail.com") {
                                set_state_ref(vm, a, "name", n);
                            }
                            set_state_int(vm, a, "type", 0);
                            vm.heap.array_set(arr, 0, Slot::reference(a));
                        }
                        let t = vm.mint_taint(TaintSource::Accounts.label());
                        vm.heap.add_taint(arr, t);
                        ret_obj(arr)
                    }
                    Err(_) => ret_void(),
                }
            }
            _ => CallOutcome::Decline,
        },
        _ => {
            if class.starts_with("Landroid/net/Uri$Builder") {
                return match name {
                    "build" => match vm.new_instance_of("Landroid/net/Uri;") {
                        Ok(o) => ret_obj(o),
                        Err(_) => ret_void(),
                    },
                    _ => ret_obj(arg_ref(args, 0)),
                };
            }
            CallOutcome::Decline
        }
    }
}

enum Part {
    Host,
    Scheme,
    Path,
    LastSegment,
}

fn url_part(u: &str, part: Part) -> String {
    let (scheme, rest) = match u.find("://") {
        Some(p) => (&u[..p], &u[p + 3..]),
        None => ("", u),
    };
    match part {
        Part::Scheme => scheme.to_string(),
        Part::Host => rest.split('/').next().unwrap_or("").to_string(),
        Part::Path => {
            let p = rest.find('/').map(|i| &rest[i..]).unwrap_or("");
            p.to_string()
        }
        Part::LastSegment => rest.rsplit('/').next().unwrap_or("").to_string(),
    }
}

// ---------------------------------------------------------------------------
// WebView, Text, UI, Database
// ---------------------------------------------------------------------------

fn webkit(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    if class.starts_with("Landroid/webkit/WebView;") {
        match name {
            "loadUrl" => {
                let url = arg_str(vm, args, 1).unwrap_or_default();
                let t = arg_taint(args, 1);
                vm.report_sink(
                    SinkKind::Network,
                    "android/webkit/WebView->loadUrl",
                    format!("loads {url}"),
                    t,
                    vec![url.clone()],
                );
                vm.env.requests.push(crate::vm::env::RequestRecord {
                    method: "GET".into(),
                    url,
                    body: String::new(),
                    headers: vec![],
                    at_millis: vm.env.now(),
                });
                ret_void()
            }
            "loadData" | "loadDataWithBaseURL" => {
                let data = arg_str(vm, args, 1).unwrap_or_default();
                vm.report_sink(
                    SinkKind::Reflection,
                    "android/webkit/WebView->loadData",
                    format!("loads inline html/JS ({} bytes)", data.len()),
                    arg_taint(args, 1),
                    vec![data.chars().take(200).collect()],
                );
                ret_void()
            }
            "addJavascriptInterface" => {
                let iface = arg_str(vm, args, 2).unwrap_or_default();
                vm.report_sink(
                    SinkKind::Reflection,
                    "android/webkit/WebView->addJavascriptInterface",
                    format!("exposes JS bridge '{iface}'"),
                    Taint::CLEAN,
                    vec![],
                );
                ret_void()
            }
            "evaluateJavascript" => ret_void(),
            "setWebViewClient" | "setWebChromeClient" | "getSettings" => ret_void(),
            _ => CallOutcome::Decline,
        }
    } else if class.starts_with("Landroid/webkit/WebViewClient;") {
        // WebViewClient callbacks are app-defined; host calls arrive here only
        // for the framework's own methods.
        CallOutcome::Decline
    } else {
        CallOutcome::Decline
    }
}

fn text(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    if class.starts_with("Landroid/text/TextUtils;") {
        return match name {
            "isEmpty" | "equals" => {
                if name == "isEmpty" {
                    let s = arg_str(vm, args, 0);
                    ret_bool(s.map(|x| x.is_empty()).unwrap_or(true))
                } else {
                    let a = arg_str(vm, args, 0);
                    let b = arg_str(vm, args, 1);
                    ret_bool(a == b)
                }
            }
            "join" => {
                // (CharSequence delimiter, Iterable tokens)
                let sep = arg_str(vm, args, 0).unwrap_or_default();
                let it = arg_ref(args, 1);
                let list = state_ref(vm, it, "list");
                let n = state_int(vm, list, "size");
                let elems = state_ref(vm, list, "elems");
                let mut parts = Vec::new();
                for i in 0..n.max(0) as usize {
                    if let Some(s) = vm.heap.array_get(elems, i) {
                        parts.push(super::java_to_string(vm, s));
                    }
                }
                string_or_empty(vm, &parts.join(&sep))
            }
            "htmlEncode" => {
                let s = arg_str(vm, args, 0).unwrap_or_default();
                string_or_empty(vm, &s)
            }
            _ => CallOutcome::Decline,
        };
    }
    if class.starts_with("Landroid/text/Editable;") || class.starts_with("Landroid/text/SpannableString") {
        match name {
            "toString" => string_or_empty(vm, ""),
            _ => ret_void(),
        }
    } else {
        CallOutcome::Decline
    }
}

fn ui(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    // Common accessors on View/TextView/etc.
    match name {
        "getText" => ret_obj(state_ref(vm, this, "text")),
        "setText" | "setVisibility" | "setEnabled" | "setClickable" | "invalidate"
        | "setContentView" | "setTitle" | "findViewById" => {
            if name == "setText" {
                if let Some(t) = args.get(1) {
                    set_state_ref(vm, this, "text", t.v.as_ref());
                }
            }
            if name == "findViewById" {
                return ret_obj(this);
            }
            ret_void()
        }
        "getVisibility" => ret_int(0),
        "getContext" => ret_obj(this),
        "runOnUiThread" => {
            // Run the Runnable inline; ordering is what matters.
            if let Some(v) = args.get(1) {
                let r = v.v.as_ref();
                if !r.is_null() {
                    let mut h = super::AndroidHost::new(); let _ = vm.invoke_runnable(&mut h, r);
                }
            }
            let _ = class;
            ret_void()
        }
        _ => {
            if class.starts_with("Landroid/view/View;") || class.starts_with("Landroid/view/ViewGroup;")
                || class.starts_with("Landroid/widget/") || class.starts_with("Landroid/graphics/")
            {
                return ret_void();
            }
            CallOutcome::Decline
        }
    }
}

fn database(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    if class.starts_with("Landroid/database/Cursor;") {
        let this = arg_ref(args, 0);
        return match name {
            "getCount" => ret_int(state_int(vm, this, "count")),
            "moveToNext" | "moveToFirst" | "move" => {
                let pos = state_int(vm, this, "pos");
                let count = state_int(vm, this, "count");
                let next = match name {
                    "moveToFirst" => 0,
                    "moveToNext" => pos + 1,
                    _ => arg_int(args, 1),
                };
                set_state_int(vm, this, "pos", next);
                ret_bool(next < count)
            }
            "getString" | "getInt" | "getLong" => {
                let col = arg_int(args, 1).max(0) as usize;
                let pos = state_int(vm, this, "pos").max(0) as usize;
                let rows = state_ref(vm, this, "rows");
                let idx = pos * 2 + col.min(1);
                match vm.heap.array_get(rows, idx) {
                    Some(s) => {
                        if name == "getString" {
                            CallOutcome::Value(s)
                        } else {
                            ret_int(s.v.as_int())
                        }
                    }
                    None => match name {
                        "getString" => ret_obj(ObjRef::NULL),
                        _ => ret_int(0),
                    },
                }
            }
            "getColumnIndex" | "getColumnIndexOrThrow" => {
                let col = arg_str(vm, args, 1).unwrap_or_default();
                ret_int(if col == "_id" { 0 } else { 1 })
            }
            "close" | "moveToPrevious" => ret_void(),
            "getPosition" => ret_int(state_int(vm, this, "pos")),
            _ => CallOutcome::Decline,
        };
    }
    if class.starts_with("Landroid/database/sqlite/SQLiteDatabase;") {
        return match name {
            "execSQL" => {
                let sql = arg_str(vm, args, 1).unwrap_or_default();
                let t = union_taint(args);
                vm.report_sink(
                    SinkKind::SensitiveFlow,
                    "SQLiteDatabase->execSQL",
                    format!("sql: {}", sql.chars().take(120).collect::<String>()),
                    t,
                    vec![sql],
                );
                ret_void()
            }
            "rawQuery" | "query" => match vm.new_instance_of("Landroid/database/Cursor;") {
                Ok(c) => {
                    set_state_int(vm, c, "count", 0);
                    ret_obj(c)
                }
                Err(_) => ret_void(),
            },
            "insert" | "insertOrThrow" | "update" | "delete" => ret_long(1),
            "openOrCreateDatabase" => ret_obj(arg_ref(args, 0)),
            "close" => ret_void(),
            _ => CallOutcome::Decline,
        };
    }
    if class.starts_with("Landroid/database/sqlite/SQLiteOpenHelper;") {
        return match name {
            "getWritableDatabase" | "getReadableDatabase" => {
                match vm.new_instance_of("Landroid/database/sqlite/SQLiteDatabase;") {
                    Ok(o) => ret_obj(o),
                    Err(_) => ret_void(),
                }
            }
            "close" => ret_void(),
            _ => CallOutcome::Decline,
        };
    }
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// Static field answers
// ---------------------------------------------------------------------------

/// `AssetManager`: serves the APK's `assets/` (and `res/raw/`) entries as
/// byte streams. Packers overwhelmingly hide their payload here, so this is a
/// load-bearing part of the model.
fn asset_manager(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "open" | "openFd" => {
            let asset_name = arg_str(vm, args, 1).unwrap_or_default();
            let Some(data) = vm.env.asset(&asset_name).map(|b| b.to_vec()) else {
                return CallOutcome::Throw(vm.exc_io, format!("FileNotFoundException: {asset_name}"));
            };
            // Reading a bundled asset is not itself malicious, but it is where
            // packed payloads live, so it is recorded as low-severity evidence.
            vm.report_sink(
                SinkKind::AssetRead,
                "AssetManager->open",
                format!("reads APK asset {asset_name} ({} bytes)", data.len()),
                Taint::CLEAN,
                vec![format!("asset={asset_name} head={}", preview_bytes(&data))],
            );
            let obj = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                Ok(o) => o,
                Err(_) => return ret_void(),
            };
            if let Ok(b) = vm.heap.new_bytes(data, Taint::CLEAN) {
                super::set_state_ref(vm, obj, "buf", b);
                super::set_state_int(vm, obj, "pos", 0);
            }
            ret_obj(obj)
        }
        "list" => {
            let names = vm.env.asset_names();
            let elem = vm.sym("Ljava/lang/String;");
            match vm.heap.new_array(elem, "Ljava/lang/String;", names.len(), Taint::CLEAN) {
                Ok(arr) => {
                    for (i, n) in names.into_iter().enumerate() {
                        if let Ok(r) = vm.new_string(n) {
                            vm.heap.array_set(arr, i, Slot::reference(r));
                        }
                    }
                    ret_obj(arr)
                }
                Err(_) => ret_void(),
            }
        }
        "close" => {
            let _ = this;
            ret_void()
        }
        _ => CallOutcome::Decline,
    }
}

fn preview_bytes(data: &[u8]) -> String {
    let head: String = data
        .iter()
        .take(32)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    format!("{head} ({}B)", data.len())
}

pub fn static_field_value(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
) -> Option<Slot> {
    let _ = host;
    if class.starts_with("Landroid/os/Build$VERSION") {
        return build_version_static(vm, class, name);
    }
    if class.starts_with("Landroid/os/Build") {
        return build_static_field(vm, class, name);
    }
    // Permission constants, Intent flags, and similar ints that samples compare.
    let int = match name {
        "PERMISSION_GRANTED" => Some(0),
        "PERMISSION_DENIED" => Some(-1),
        "START_REDELIVER_INTENT" | "START_STICKY" => Some(1),
        "FLAG_ACTIVITY_NEW_TASK" => Some(0x1000_0000),
        "TYPE_WIFI" => Some(1),
        "TYPE_MOBILE" => Some(0),
        "TYPE_ALL" => Some(-1),
        "SCREEN_STATE_ON" => Some(2),
        _ => None,
    };
    if let Some(v) = int {
        return Some(Slot::int(v));
    }
    // Sensor type constants.
    let sensor = match name {
        "TYPE_ACCELEROMETER" => Some(1),
        "TYPE_MAGNETIC_FIELD" => Some(2),
        "TYPE_ORIENTATION" => Some(3),
        "TYPE_GYROSCOPE" => Some(4),
        "TYPE_LIGHT" => Some(5),
        "TYPE_PRESSURE" => Some(6),
        "TYPE_TEMPERATURE" => Some(7),
        "TYPE_PROXIMITY" => Some(8),
        "TYPE_GRAVITY" => Some(9),
        "TYPE_LINEAR_ACCELERATION" => Some(10),
        "TYPE_ROTATION_VECTOR" => Some(11),
        "TYPE_STEP_COUNTER" => Some(19),
        "TYPE_STEP_DETECTOR" => Some(18),
        "TYPE_HEART_RATE" => Some(21),
        _ => None,
    };
    if class.starts_with("Landroid/hardware/Sensor;") {
        if let Some(v) = sensor {
            return Some(Slot::int(v));
        }
    }
    // Environment / Settings key strings used as sget.
    if class.starts_with("Landroid/provider/Settings") && name.ends_with("_ID") {
        let key = name.to_lowercase();
        if let Ok(r) = vm.new_string(key) {
            return Some(Slot::reference(r));
        }
    }
    let _ = class;
    None
}
