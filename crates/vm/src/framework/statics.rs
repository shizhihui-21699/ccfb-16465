//! Framework static fields.
//!
//! A great deal of anti-analysis logic reads `android.os.Build.FINGERPRINT`,
//! `Build.MODEL`, `Build$VERSION.SDK_INT` and friends through `sget`/`sput`,
//! not through methods. If those reads return null the sample's own check
//! takes a branch we never see, so the model has to answer them.

use crate::interp::state::Machine;
use crate::value::{Provenance, Tag, Value};

impl Machine {
    /// Value of a framework static field. Returns `None` for fields we do not
    /// model, so the caller can fall back to the sample's own statics.
    pub(crate) fn framework_static(&mut self, class: &str, name: &str) -> Option<Value> {
        let c = class.trim_start_matches('L').trim_end_matches(';');
        let p = &self.env.profile;
        let s = match (c, name) {
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
            ("android/os/Build", "TIME") => return Some(Value::J(p.build_time)),
            ("android/os/Build$VERSION", "SDK_INT") => return Some(Value::I(p.sdk_int)),
            ("android/os/Build$VERSION", "RELEASE") => p.release.clone(),
            ("android/os/Build$VERSION", "CODENAME") => "REL".to_string(),
            ("android/os/Build$VERSION", "INCREMENTAL") => p.incremental.clone(),
            ("android/os/Build$VERSION", "PREVIEW_SDK_INT") => return Some(Value::I(0)),
            ("android/os/Build$VERSION_CODES", f) => return Some(Value::I(api_level(f))),
            ("java/lang/Boolean", "TRUE") | ("java/lang/Boolean", "FALSE") => {
                return Some(Value::I((name == "TRUE") as i32))
            }
            ("java/lang/Integer", "MAX_VALUE") => return Some(Value::I(i32::MAX)),
            ("java/lang/Integer", "MIN_VALUE") => return Some(Value::I(i32::MIN)),
            ("java/lang/Long", "MAX_VALUE") => return Some(Value::J(i64::MAX)),
            ("java/lang/Byte", "MAX_VALUE") => return Some(Value::I(i8::MAX as i32)),
            ("java/lang/Short", "MAX_VALUE") => return Some(Value::I(i16::MAX as i32)),
            ("java/lang/System", "out") | ("java/lang/System", "err") => {
                return Some(self.new_model_default("Ljava/io/PrintStream;"))
            }
            ("android/os/Build", _) | ("android/os/Build$VERSION", _) => String::new(),
            _ => return None,
        };
        if std::env::var("UNHUSK_DEBUG").is_ok() {
            eprintln!("    framework_static {c}.{name} = {s:?}");
        }
        let v = self.new_string(s, Provenance::of(Tag::Device));
        if std::env::var("UNHUSK_DEBUG").is_ok() {
            eprintln!("      new_string => {v:?}");
        }
        Some(v)
    }

    /// Set a framework static field. Almost always an app overwriting a system
    /// property (hook); we record the intent and keep the modelled value.
    pub(crate) fn set_framework_static(&mut self, class: &str, name: &str, value: Value) -> bool {
        let c = class.trim_start_matches('L').trim_end_matches(';');
        if c == "android/os/Build" || c.starts_with("android/os/Build$") {
            self.env
                .checks
                .insert(format!("{c}.{name}"), self.render_value(value));
            return true;
        }
        false
    }
}

/// API level constants from `Build.VERSION_CODES`.
fn api_level(field: &str) -> i32 {
    // A subset is enough: the constants that appear in version gates.
    match field {
        "BASE" => 1,
        "CUPCAKE" => 3,
        "DONUT" => 4,
        "ECLAIR" => 5,
        "FROYO" => 8,
        "GINGERBREAD" => 9,
        "HONEYCOMB" => 11,
        "ICE_CREAM_SANDWICH" => 14,
        "JELLY_BEAN" => 16,
        "JELLY_BEAN_MR2" => 18,
        "KITKAT" => 19,
        "LOLLIPOP" => 21,
        "LOLLIPOP_MR1" => 22,
        "M" => 23,
        "N" => 24,
        "N_MR1" => 25,
        "O" => 26,
        "O_MR1" => 27,
        "P" => 28,
        "Q" => 29,
        "R" => 30,
        "S" => 31,
        "S_V2" => 32,
        "TIRAMISU" => 33,
        "UPSIDE_DOWN_CAKE" => 34,
        _ => 0,
    }
}

/// Materialise a DEX `static_values` entry into a runtime `Value`.
///
/// This is how constants like `static final byte[] KEY = {...}` become real
/// arrays at runtime: the values live in the class's `static_values` table,
/// not in any method body, so nothing would ever execute code to build them.
impl Machine {
    pub(crate) fn materialise_encoded(&mut self, v: &unhusk_dex::EncodedValue) -> Value {
        use unhusk_dex::EncodedValue as E;
        match v {
            E::Byte(b) => Value::I(*b as i32),
            E::Short(s) => Value::I(*s as i32),
            E::Char(c) => Value::I(*c as i32),
            E::Int(i) => Value::I(*i),
            E::Long(l) => Value::J(*l),
            E::Float(f) => Value::f32(*f),
            E::Double(d) => Value::f64(*d),
            E::Boolean(b) => Value::I(*b as i32),
            E::Null => Value::NULL,
            E::String(s) => self.new_string(s.clone(), Provenance::constant()),
            E::Type(t) => match self.heap.alloc(crate::heap::Object::Class { descriptor: t.clone() }) {
                Some(id) => Value::obj(id),
                None => Value::NULL,
            },
            E::Array(items) => {
                // Byte arrays are the common case and the one packers use for
                // payloads; other element types are stored as a byte array too,
                // since the interpreter only reads raw bytes from them.
                let all_bytes = items.iter().all(|i| matches!(i, E::Byte(_)));
                if all_bytes {
                    let bytes: Vec<u8> = items
                        .iter()
                        .map(|i| match i {
                            E::Byte(b) => *b as u8,
                            _ => 0,
                        })
                        .collect();
                    self.new_bytes(bytes, Provenance::of(Tag::PackedData))
                } else {
                    let values: Vec<Value> = items.iter().map(|i| self.materialise_encoded(i)).collect();
                    match self.heap.new_obj_array("[Ljava/lang/Object;", values, Provenance::constant()) {
                        Some(id) => Value::obj(id),
                        None => Value::NULL,
                    }
                }
            }
            _ => Value::NULL,
        }
    }

    /// Interned field id -> its declared static value, if any. Searches the
    /// program once per (dex, class) and caches nothing: this is only called
    /// on the first `sget` of an unset field, which is rare.
    pub(crate) fn declared_static(&mut self, field: u32) -> Option<Value> {
        let sig = self.program.field_name(field).to_string();
        let (class, _rest) = sig.split_once("->")?;
        let (dex, ci) = self.program.find_class(class)?;
        // Fields in `static_fields` carry their encoded value.
        let value = {
            let data = self.program.class_data(dex, ci);
            data.static_fields.iter().find_map(|f| {
                let fsig = format!("{}->{}:{}", f.class, f.name, f.ty);
                if fsig == sig {
                    f.static_value.clone()
                } else {
                    None
                }
            })
        }?;
        Some(self.materialise_encoded(&value))
    }
}
