//! The JDK surface: strings, boxed types, collections, reflection, class
//! loading, crypto, I/O and runtime exec. This is where most of a packer's
//! unpacking loop actually lives, because the DEX decryptor typically calls
//! `MessageDigest`, `Cipher`, `String.getBytes` and `ClassLoader.loadClass`.

use super::{obs, CallResult, Level, Observation};
use crate::crypto as k;
use crate::heap::{Object, ObjectValue};
use crate::interp::state::Machine;
use crate::value::{Provenance, Tag, Value};
use unhusk_dex::model::MethodRef;

impl Machine {
    pub(crate) fn call_java(&mut self, mr: &MethodRef, args: &[Value]) -> CallResult {
        let class = mr.class.trim_start_matches('L').trim_end_matches(';');
        let name = mr.name.as_str();
        match class {
            "java/lang/String" => self.java_string(name, args),
            "java/lang/StringBuilder" => self.java_string_builder(name, args),
            "java/lang/StringBuffer" => self.java_string_builder(name, args),
            "java/lang/Object" => self.java_object(name, args),
            "java/lang/Class" => self.java_class(name, args),
            "java/lang/ClassLoader" => self.java_class_loader(name, args),
            "dalvik/system/DexClassLoader"
            | "dalvik/system/PathClassLoader"
            | "dalvik/system/InMemoryDexClassLoader"
            | "dalvik/system/BaseDexClassLoader" => self.dalvik_loader(class, name, args),
            "dalvik/system/DexFile" => self.dalvik_dex_file(name, args),
            "java/lang/reflect/Method" => self.java_reflect_method(name, args),
            "java/lang/reflect/Field" => CallResult::void(),
            "java/lang/System" => self.java_system(name, args),
            "java/lang/Runtime" => self.java_runtime(name, args),
            "java/lang/ProcessBuilder" => self.java_process_builder(name, args),
            "java/io/File"
            | "java/io/FileInputStream"
            | "java/io/FileOutputStream"
            | "java/io/FileReader"
            | "java/io/FileWriter"
            | "java/io/RandomAccessFile"
            | "java/io/OutputStream"
            | "java/io/InputStream"
            | "java/io/PrintStream"
            | "java/io/DataInputStream"
            | "java/io/DataOutputStream" => self.java_io(class, name, args),
            "java/io/ByteArrayOutputStream" | "java/io/ByteArrayInputStream" => {
                self.java_byte_stream(class, name, args)
            }
            "java/io/BufferedInputStream" | "java/io/BufferedOutputStream" => CallResult::void(),
            "java/lang/Integer"
            | "java/lang/Long"
            | "java/lang/Short"
            | "java/lang/Byte"
            | "java/lang/Character"
            | "java/lang/Boolean"
            | "java/lang/Float"
            | "java/lang/Double" => self.java_boxed(class, name, args),
            "java/lang/Math" => self.java_math(name, args),
            "java/util/Arrays" => self.java_arrays(name, args),
            "java/util/Base64" | "android/util/Base64" => self.java_base64(name, args),
            "java/lang/Thread" => self.java_thread(name, args),
            "java/lang/Throwable" | "java/lang/Exception" | "java/lang/RuntimeException" => {
                CallResult::void()
            }
            "java/security/MessageDigest" => self.java_message_digest(name, args),
            "javax/crypto/Cipher" => self.javax_cipher(name, args),
            "javax/crypto/spec/SecretKeySpec"
            | "javax/crypto/spec/IvParameterSpec"
            | "javax/crypto/spec/PBEKeySpec" => self.javax_key_spec(class, name, args),
            "java/nio/charset/Charset"
            | "java/nio/charset/CharsetEncoder"
            | "java/nio/ByteBuffer" => self.java_nio(class, name, args),
            "java/util/Random" | "java/security/SecureRandom" => {
                self.java_random(class, name, args)
            }
            "java/lang/ThreadLocal" | "java/lang/Iterable" | "java/util/Iterator" => {
                CallResult::void()
            }
            "java/lang/Enum" => CallResult::void(),
            "java/util/HashMap"
            | "java/util/HashSet"
            | "java/util/ArrayList"
            | "java/util/Map"
            | "java/util/List"
            | "java/util/LinkedList"
            | "java/util/TreeMap" => self.java_collections(class, name, args),
            "org/json/JSONObject" => self.java_json(class, name, args),
            // HTTP clients live with the network model, not the JDK table.
            "java/net/URL"
            | "java/net/URLConnection"
            | "java/net/HttpURLConnection"
            | "javax/net/ssl/HttpsURLConnection" => self.net_api(class, name, args),
            _ => CallResult::void(),
        }
    }

    fn arg_str_or(&self, args: &[Value], i: usize) -> String {
        self.arg_str(args, i).unwrap_or_default()
    }

    // -- String ------------------------------------------------------------

    fn java_string(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "<init>" => {
                // Constructors: String(byte[]), String(byte[], charset), String(byte[], off, len)
                if let Some(bytes) = self.arg_bytes(args, 1) {
                    let s = String::from_utf8_lossy(&bytes).into_owned();
                    let prov = self.arg_prov(args, 1);
                    let this = self.arg_obj(args, 0);
                    if let Some(this) = this {
                        if let Some(Object::Instance { .. }) = self.heap.get(this) {
                            // Represent the constructed string by replacing the
                            // instance with an immutable Str, which the model
                            // then treats as the receiver.
                            let _ = self.heap.get_mut(this);
                        }
                    }
                    let _ = (s, prov);
                }
                CallResult::void()
            }
            "getBytes" => {
                let s = self.arg_str_or(args, 0);
                let prov = self.arg_prov(args, 0);
                CallResult::obj(self.new_bytes(s.into_bytes(), {
                    let mut p = prov;
                    p.add(Tag::Built);
                    p
                }))
            }
            "length" => {
                let s = self.arg_str_or(args, 0);
                CallResult::int(s.chars().count() as i32)
            }
            "isEmpty" => CallResult::int((self.arg_str_or(args, 0).is_empty()) as i32),
            "equals" | "equalsIgnoreCase" | "contentEquals" => {
                let a = self.arg_str_or(args, 0);
                let b = self.arg_str_or(args, 1);
                let eq = if name == "equalsIgnoreCase" {
                    a.eq_ignore_ascii_case(&b)
                } else {
                    a == b
                };
                CallResult::int(eq as i32)
            }
            "hashCode" => {
                // Java's String.hashCode, which samples use for key derivation.
                let s = self.arg_str_or(args, 0);
                let h = s
                    .encode_utf16()
                    .fold(0i32, |acc, u| acc.wrapping_mul(31).wrapping_add(u as i32));
                CallResult::int(h)
            }
            "toString" => CallResult::new(args.first().copied(), None),
            "substring" => {
                let s = self.arg_str_or(args, 0);
                let start = self.arg_i32(args, 1).max(0) as usize;
                let end = if args.len() > 2 {
                    self.arg_i32(args, 2).max(0) as usize
                } else {
                    s.chars().count()
                };
                let chars: Vec<char> = s.chars().collect();
                let end = end.min(chars.len());
                let start = start.min(end);
                let out: String = chars[start..end].iter().collect();
                CallResult::obj(self.new_string(out, self.arg_prov(args, 0)))
            }
            "charAt" => {
                let s = self.arg_str_or(args, 0);
                let i = self.arg_i32(args, 1).max(0) as usize;
                let c = s.chars().nth(i).unwrap_or('\0');
                CallResult::int(c as i32)
            }
            "toCharArray" => {
                let s = self.arg_str_or(args, 0);
                let prov = self.arg_prov(args, 0);
                let mut bytes = Vec::with_capacity(s.len() * 2);
                for c in s.encode_utf16() {
                    bytes.extend_from_slice(&c.to_le_bytes());
                }
                CallResult::obj(self.new_bytes(bytes, prov))
            }
            "valueOf" | "copyValueOf" => CallResult::new(args.last().copied(), None),
            "trim" => {
                let s = self.arg_str_or(args, 0);
                CallResult::obj(self.new_string(s.trim().to_string(), self.arg_prov(args, 0)))
            }
            "toLowerCase" => {
                let s = self.arg_str_or(args, 0);
                CallResult::obj(self.new_string(s.to_lowercase(), self.arg_prov(args, 0)))
            }
            "toUpperCase" => {
                let s = self.arg_str_or(args, 0);
                CallResult::obj(self.new_string(s.to_uppercase(), self.arg_prov(args, 0)))
            }
            "replace" | "replaceAll" => {
                // String.replace(CharSequence, CharSequence) or (char, char).
                let s = self.arg_str_or(args, 0);
                let from = self.arg_str(args, 1);
                let to = self.arg_str(args, 2);
                let out = match (from, to) {
                    (Some(f), Some(t)) => s.replace(&f, &t),
                    _ => {
                        let f = self.arg_i32(args, 1);
                        let t = self.arg_i32(args, 2);
                        s.chars()
                            .map(|c| {
                                if c as i32 == f {
                                    char::from_u32(t as u32).unwrap_or(c)
                                } else {
                                    c
                                }
                            })
                            .collect()
                    }
                };
                let mut prov = self.arg_prov(args, 0);
                prov.add(Tag::Built);
                CallResult::obj(self.new_string(out, prov))
            }
            "startsWith" => {
                let s = self.arg_str_or(args, 0);
                let p = self.arg_str_or(args, 1);
                let off = if args.len() > 2 {
                    self.arg_i32(args, 2).max(0) as usize
                } else {
                    0
                };
                let tail: String = s.chars().skip(off).collect();
                CallResult::int(tail.starts_with(&p) as i32)
            }
            "endsWith" => {
                let s = self.arg_str_or(args, 0);
                let p = self.arg_str_or(args, 1);
                CallResult::int(s.ends_with(&p) as i32)
            }
            "contains" => {
                let s = self.arg_str_or(args, 0);
                let p = self.arg_str_or(args, 1);
                CallResult::int(s.contains(&p) as i32)
            }
            "indexOf" => {
                let s = self.arg_str_or(args, 0);
                match self.arg_str(args, 1) {
                    Some(p) => {
                        let from = if args.len() > 2 {
                            self.arg_i32(args, 2).max(0) as usize
                        } else {
                            0
                        };
                        let tail: String = s.chars().skip(from).collect();
                        let byte_off: usize = s.chars().take(from).map(|c| c.len_utf8()).sum();
                        CallResult::int(tail.find(&p).map(|i| (i + byte_off) as i32).unwrap_or(-1))
                    }
                    None => {
                        let c = self.arg_i32(args, 1) as u32;
                        let pos = s.chars().position(|x| x as u32 == c);
                        CallResult::int(pos.map(|p| p as i32).unwrap_or(-1))
                    }
                }
            }
            "split" => {
                let s = self.arg_str_or(args, 0);
                let sep = self.arg_str_or(args, 1);
                let parts: Vec<Value> = if sep.is_empty() {
                    s.chars()
                        .map(|c| self.new_string(c.to_string(), Provenance::constant()))
                        .collect()
                } else {
                    s.split(&sep[..])
                        .map(|p| self.new_string(p.to_string(), Provenance::constant()))
                        .collect()
                };
                CallResult::obj(
                    match self.heap.new_obj_array(
                        "[Ljava/lang/String;",
                        parts,
                        Provenance::constant(),
                    ) {
                        Some(id) => Value::obj(id),
                        None => Value::NULL,
                    },
                )
            }
            "concat" => {
                let mut out = self.arg_str_or(args, 0);
                out.push_str(&self.arg_str_or(args, 1));
                let mut prov = self.arg_prov(args, 0);
                prov.merge(&self.arg_prov(args, 1));
                prov.add(Tag::Built);
                CallResult::obj(self.new_string(out, prov))
            }
            "intern" => CallResult::new(args.first().copied(), None),
            "format" => {
                let fmt = self.arg_str_or(args, 0);
                CallResult::obj(self.new_string(fmt, Provenance::constant()))
            }
            _ => CallResult::void(),
        }
    }

    fn java_string_builder(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "<init>" => {
                let this = match self.arg_obj(args, 0) {
                    Some(t) => t,
                    None => return CallResult::void(),
                };
                // Reuse the heap object as a builder.
                if let Some(obj) = self.heap.get_mut(this) {
                    if matches!(obj, Object::Instance { .. }) {
                        *obj = Object::Builder {
                            buf: String::new(),
                            prov: Provenance::default(),
                        };
                    }
                }
                if let Some(s) = self.arg_str(args, 1) {
                    if let Some(Object::Builder { buf, .. }) = self.heap.get_mut(this) {
                        buf.push_str(&s);
                    }
                }
                CallResult::void()
            }
            "append" => {
                let Some(this) = self.arg_obj(args, 0) else {
                    return CallResult::void();
                };
                let text = match args.get(1) {
                    Some(Value::Obj(0)) => "null".to_string(),
                    Some(Value::Obj(id)) => match self.heap.get(*id) {
                        Some(Object::Str { value, .. }) => value.clone(),
                        Some(Object::Builder { buf, .. }) => buf.clone(),
                        Some(Object::Array { bytes, .. }) => {
                            String::from_utf8_lossy(bytes).into_owned()
                        }
                        _ => self.render_value(args[1]),
                    },
                    Some(v) => self.render_value(*v),
                    None => String::new(),
                };
                let prov = self.arg_prov(args, 1);
                if let Some(Object::Builder { buf, prov: bp }) = self.heap.get_mut(this) {
                    buf.push_str(&text);
                    bp.merge(&prov);
                    bp.add(Tag::Built);
                }
                CallResult::new(Some(Value::obj(this)), None)
            }
            "toString" => {
                let Some(this) = self.arg_obj(args, 0) else {
                    return CallResult::void();
                };
                let s = match self.heap.get(this) {
                    Some(Object::Builder { buf, .. }) => buf.clone(),
                    _ => String::new(),
                };
                let mut prov = self.arg_prov(args, 0);
                prov.add(Tag::Built);
                // Return a fresh immutable string, so later appends do not
                // alias the value the sample already captured.
                CallResult::obj(self.new_string(s, prov))
            }
            "length" => {
                let Some(this) = self.arg_obj(args, 0) else {
                    return CallResult::int(0);
                };
                match self.heap.get(this) {
                    Some(Object::Builder { buf, .. }) => {
                        CallResult::int(buf.chars().count() as i32)
                    }
                    _ => CallResult::int(0),
                }
            }
            "reverse" => {
                let Some(this) = self.arg_obj(args, 0) else {
                    return CallResult::void();
                };
                if let Some(Object::Builder { buf, .. }) = self.heap.get_mut(this) {
                    *buf = buf.chars().rev().collect();
                }
                CallResult::new(Some(Value::obj(this)), None)
            }
            "setLength" | "delete" | "insert" | "replace" => {
                CallResult::new(Some(args.first().copied().unwrap_or(Value::NULL)), None)
            }
            _ => CallResult::void(),
        }
    }

    fn java_object(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "toString" => {
                let s = self.arg_obj(args, 0).and_then(|id| {
                    self.heap
                        .get(id)
                        .and_then(|o| o.as_str())
                        .map(|s| s.to_string())
                });
                match s {
                    Some(s) => CallResult::obj(self.new_string(s, Provenance::default())),
                    None => CallResult::obj(self.new_string(
                        self.render_value(args.first().copied().unwrap_or(Value::NULL)),
                        Provenance::default(),
                    )),
                }
            }
            "hashCode" => {
                let v = self.arg_obj(args, 0).unwrap_or(0);
                CallResult::int(v as i32)
            }
            "equals" => {
                let a = args.first().copied().unwrap_or(Value::NULL);
                let b = args.get(1).copied().unwrap_or(Value::NULL);
                CallResult::int((a == b) as i32)
            }
            "getClass" => {
                let Some(id) = self.arg_obj(args, 0) else {
                    return CallResult::obj(Value::NULL);
                };
                let class = self
                    .heap
                    .get(id)
                    .map(|o| o.class_name().to_string())
                    .unwrap_or_default();
                match self.heap.alloc(Object::Class { descriptor: class }) {
                    Some(id) => CallResult::obj(Value::obj(id)),
                    None => CallResult::obj(Value::NULL),
                }
            }
            _ => CallResult::void(),
        }
    }

    fn java_class(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getName" | "getCanonicalName" => {
                let Some(id) = self.arg_obj(args, 0) else {
                    return CallResult::obj(Value::NULL);
                };
                let desc = match self.heap.get(id) {
                    Some(Object::Class { descriptor }) => descriptor.clone(),
                    _ => String::new(),
                };
                let dotted = unhusk_dex::model::dotted(&desc);
                CallResult::obj(self.new_string(dotted, Provenance::constant()))
            }
            "getSimpleName" => {
                let Some(id) = self.arg_obj(args, 0) else {
                    return CallResult::obj(Value::NULL);
                };
                let desc = match self.heap.get(id) {
                    Some(Object::Class { descriptor }) => descriptor.clone(),
                    _ => String::new(),
                };
                let simple = unhusk_dex::model::dotted(&desc)
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .to_string();
                CallResult::obj(self.new_string(simple, Provenance::constant()))
            }
            "forName" => {
                let n = self.arg_str_or(args, 0);
                let desc = format!("L{};", n.replace('.', "/"));
                match self.heap.alloc(Object::Class {
                    descriptor: desc.clone(),
                }) {
                    Some(id) => {
                        let mut o = obs(Level::Notable, "reflect", format!("Class.forName({n})"));
                        o.prov = Some(Provenance::of(Tag::Constant));
                        CallResult::new(Some(Value::obj(id)), Some(o))
                    }
                    None => CallResult::obj(Value::NULL),
                }
            }
            "getDeclaredMethods" | "getMethods" | "getDeclaredFields" | "getInterfaces"
            | "getAnnotations" => CallResult::obj(
                match self
                    .heap
                    .new_obj_array("[Ljava/lang/Object;", vec![], Provenance::default())
                {
                    Some(id) => Value::obj(id),
                    None => Value::NULL,
                },
            ),
            "getMethod" | "getDeclaredMethod" => {
                // Return a Method model object carrying class/name/params.
                let target = self.arg_obj(args, 0);
                let mname = self.arg_str_or(args, 1);
                let m = match self.new_model_default("Ljava/lang/reflect/Method;") {
                    Value::Obj(id) => {
                        if let Some(t) = target {
                            if let Some(Object::Class { descriptor }) = self.heap.get(t) {
                                let d = descriptor.clone();
                                self.set_model_field(id, "class", ObjectValue::Str(d));
                            }
                        }
                        self.set_model_field(id, "name", ObjectValue::Str(mname.clone()));
                        Value::obj(id)
                    }
                    v => v,
                };
                let mut o = obs(Level::Notable, "reflect", format!("getMethod({mname})"));
                o.prov = Some(Provenance::constant());
                CallResult::new(Some(m), Some(o))
            }
            "getField" | "getDeclaredField" | "getConstructor" => {
                let fname = self.arg_str_or(args, 1);
                let m = match self.new_model_default("Ljava/lang/reflect/Field;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "name", ObjectValue::Str(fname.clone()));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::new(
                    Some(m),
                    Some(obs(
                        Level::Notable,
                        "reflect",
                        format!("getDeclaredField({fname})"),
                    )),
                )
            }
            "getClassLoader" => CallResult::obj(self.new_model_default("Ljava/lang/ClassLoader;")),
            "newInstance" => {
                let class_desc = self
                    .arg_obj(args, 0)
                    .and_then(|id| match self.heap.get(id) {
                        Some(Object::Class { descriptor }) => Some(descriptor.clone()),
                        _ => None,
                    });
                match class_desc {
                    Some(desc) => self.instantiate_and_init(&desc, &[]),
                    None => CallResult::obj(Value::NULL),
                }
            }
            "isAssignableFrom" | "isInstance" => CallResult::int(1),
            _ => CallResult::void(),
        }
    }

    /// Instantiate a sample class and run its no-arg constructor. Used by
    /// reflection paths and by the engine when it seeds an Application object.
    pub fn instantiate_and_init(&mut self, descriptor: &str, args: &[Value]) -> CallResult {
        let Some(id) = self.heap.alloc(Object::Instance {
            class: descriptor.to_string(),
            fields: Default::default(),
            prov: Provenance::default(),
        }) else {
            return CallResult::obj(Value::NULL);
        };
        let ctor = self
            .program
            .find_method_in_class(descriptor, "<init>", &[], "V")
            .or_else(|| {
                self.program
                    .methods_named(descriptor, "<init>")
                    .first()
                    .copied()
            });
        if let Some(ctor) = ctor {
            let mut call_args = vec![Value::obj(id)];
            call_args.extend_from_slice(args);
            let _ = self.push_frame(ctor, call_args, None, None);
        }
        CallResult::obj(Value::obj(id))
    }

    fn java_class_loader(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "loadClass" => {
                let n = self
                    .arg_str(args, 1)
                    .or_else(|| self.arg_str(args, 0))
                    .unwrap_or_default();
                let desc = format!("L{};", n.replace('.', "/"));
                // If the class lives in a DEX we already recovered, initialise
                // and run it now: that is the packer's "now execute" moment.
                self.note_class_load(&n);
                match self.heap.alloc(Object::Class { descriptor: desc }) {
                    Some(id) => {
                        let mut o = obs(Level::Notable, "load", format!("loadClass({n})"));
                        o.prov = Some(Provenance::constant());
                        CallResult::new(Some(Value::obj(id)), Some(o))
                    }
                    None => CallResult::obj(Value::NULL),
                }
            }
            _ => CallResult::void(),
        }
    }

    /// Shared handler for every `*ClassLoader` the platform exposes.
    pub(crate) fn dalvik_loader(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match name {
            "<init>" => {
                let this = self.arg_obj(args, 0);
                // InMemoryDexClassLoader(ByteBuffer) / (ByteBuffer, parent)
                if class.ends_with("InMemoryDexClassLoader") {
                    let buf = args.get(1).copied();
                    let src = format!("InMemoryDexClassLoader@{}", self.budget.instructions);
                    self.in_memory_loader(buf, src);
                    if let Some(this) = this {
                        self.set_model_field(this, "kind", ObjectValue::Str("in-memory".into()));
                    }
                    return CallResult::void();
                }
                // DexClassLoader(dexPath, optimizedDir, libPath, parent)
                let path = self.arg_str_or(args, 1);
                if let Some(this) = this {
                    self.set_model_field(this, "path", ObjectValue::Str(path.clone()));
                    self.set_model_field(this, "kind", ObjectValue::Str(class.to_string()));
                }
                if !path.is_empty() {
                    self.load_dex_from_path(&path, class);
                }
                CallResult::void()
            }
            "loadClass" => {
                // PathClassLoader.loadClass(name) is the common "now run it" call.
                let n = self
                    .arg_str(args, 1)
                    .or_else(|| self.arg_str(args, 0))
                    .unwrap_or_default();
                self.note_class_load(&n);
                let desc = format!("L{};", n.replace('.', "/"));
                match self.heap.alloc(Object::Class { descriptor: desc }) {
                    Some(id) => CallResult::obj(Value::obj(id)),
                    None => CallResult::obj(Value::NULL),
                }
            }
            _ => CallResult::void(),
        }
    }

    fn dalvik_dex_file(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "loadDex" => {
                let path = self.arg_str_or(args, 0);
                self.load_dex_from_path(&path, "dalvik/system/DexFile");
                CallResult::obj(self.new_model_default("Ldalvik/system/DexFile;"))
            }
            "loadClass" => {
                let n = self.arg_str_or(args, 1);
                let desc = format!("L{};", n.replace('.', "/"));
                match self.heap.alloc(Object::Class { descriptor: desc }) {
                    Some(id) => CallResult::obj(Value::obj(id)),
                    None => CallResult::obj(Value::NULL),
                }
            }
            _ => CallResult::void(),
        }
    }

    fn java_reflect_method(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "setAccessible" => CallResult::void(),
            "invoke" => {
                // Reflectively call a method on a target object.
                let Some(method_id) = self.arg_obj(args, 0) else {
                    return CallResult::obj(Value::NULL);
                };
                let target = args.get(1).copied().unwrap_or(Value::NULL);
                let mname = self.model_string(method_id, "name").unwrap_or_default();
                let class = self.model_string(method_id, "class").unwrap_or_default();
                let mut call_args = vec![target];
                if let Some(Value::Obj(arr)) = args.get(2) {
                    if let Some(Object::ObjArray { items, .. }) = self.heap.get(*arr) {
                        call_args.extend(items.iter().copied());
                    }
                }
                let o = obs(
                    Level::Notable,
                    "reflect",
                    format!("Method.invoke({class}.{mname})"),
                );
                // Dispatch into sample code when we can resolve it.
                if let Some(handle) = self.program.methods_named(&class, &mname).first().copied() {
                    if self.program.method(handle).code.is_some() {
                        let result_reg = self.next_move_result_reg_pub();
                        let _ = self.push_frame(
                            handle,
                            call_args,
                            None,
                            result_reg.map(|r| (r, false, true)),
                        );
                        return CallResult::new(None, Some(o));
                    }
                }
                CallResult::new(Some(Value::NULL), Some(o))
            }
            _ => CallResult::void(),
        }
    }

    pub(crate) fn next_move_result_reg_pub(&self) -> Option<u16> {
        let frame = self.frames.last()?;
        let code = self.program.method(frame.method).code.as_ref()?;
        let next = code.instructions.get(frame.ip)?;
        if matches!(next.op, 0x0a..=0x0c) {
            Some(next.a)
        } else {
            None
        }
    }

    fn java_system(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "currentTimeMillis" => CallResult::new(
                Some(Value::J(self.env.clock.now_ms())),
                Some(obs(Level::Notable, "time", "System.currentTimeMillis")),
            ),
            "nanoTime" => CallResult::new(
                Some(Value::J(self.env.clock.uptime_ms() * 1_000_000)),
                Some(obs(Level::Routine, "time", "System.nanoTime")),
            ),
            "elapsedRealtime" => CallResult::new(
                Some(Value::J(self.env.clock.elapsed_realtime_ms())),
                Some(obs(Level::Routine, "time", "SystemClock.elapsedRealtime")),
            ),
            "getProperty" => {
                let key = self.arg_str_or(args, 0);
                let v = match key.as_str() {
                    "os.name" => "Linux".to_string(),
                    "os.arch" => "aarch64".to_string(),
                    "java.vendor" => "The Android Project".to_string(),
                    "file.separator" => "/".to_string(),
                    "line.separator" => "\n".to_string(),
                    "java.version" => "0".to_string(),
                    "user.dir" => "/".to_string(),
                    _ => String::new(),
                };
                CallResult::obj(self.new_string(v, Provenance::of(Tag::Device)))
            }
            "getenv" => CallResult::obj(self.new_string("", Provenance::of(Tag::Device))),
            "arraycopy" => {
                // System.arraycopy(src, srcPos, dst, dstPos, len)
                let (Some(src), Some(dst)) = (self.arg_obj(args, 0), self.arg_obj(args, 2)) else {
                    return CallResult::void();
                };
                let src_pos = self.arg_i32(args, 1).max(0) as usize;
                let dst_pos = self.arg_i32(args, 3).max(0) as usize;
                let len = self.arg_i32(args, 4).max(0) as usize;
                let data = match self.heap.get(src) {
                    Some(Object::Array { bytes, .. }) => {
                        bytes.get(src_pos..src_pos + len).map(|s| s.to_vec())
                    }
                    _ => None,
                };
                if let (Some(data), Some(Object::Array { bytes, prov, .. })) =
                    (data, self.heap.get_mut(dst))
                {
                    if dst_pos + len <= bytes.len() {
                        bytes[dst_pos..dst_pos + len].copy_from_slice(&data);
                        prov.add(Tag::Built);
                    }
                }
                CallResult::void()
            }
            _ => CallResult::void(),
        }
    }

    fn java_runtime(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getRuntime" => CallResult::new(
                Some(self.new_model_default("Ljava/lang/Runtime;")),
                Some(obs(Level::Notable, "exec", "Runtime.getRuntime()")),
            ),
            "exec" => {
                // exec(String) or exec(String[])
                let cmd = self
                    .arg_str(args, 1)
                    .or_else(|| {
                        self.arg_bytes(args, 1)
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                    })
                    .unwrap_or_default();
                if cmd.is_empty() {
                    return CallResult::void();
                }
                let o = self.run_shell(&cmd);
                CallResult::new(Some(self.new_model_default("Ljava/lang/Process;")), Some(o))
            }
            "availableProcessors" => CallResult::int(8),
            "maxMemory" | "totalMemory" | "freeMemory" => {
                CallResult::new(Some(Value::J(268_435_456)), None)
            }
            "loadLibrary" | "load" => {
                let n = self.arg_str_or(args, 1);
                if !n.is_empty() {
                    self.note_native_library(&n);
                }
                CallResult::new(
                    None,
                    Some(obs(
                        Level::Critical,
                        "load",
                        format!("Runtime.loadLibrary({n})"),
                    )),
                )
            }
            "addShutdownHook" | "exit" | "halt" => CallResult::void(),
            _ => CallResult::void(),
        }
    }

    fn java_process_builder(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "<init>" => CallResult::void(),
            "start" => {
                let cmd = self.arg_str_or(args, 0);
                CallResult::new(
                    Some(self.new_model_default("Ljava/lang/Process;")),
                    Some(self.run_shell(&cmd)),
                )
            }
            _ => CallResult::void(),
        }
    }

    /// Execute a shell command against the virtual filesystem. Only a handful of
    /// commands have observable semantics; everything else returns an empty
    /// stream and is still recorded, which is exactly what the analyst needs.
    fn run_shell(&mut self, cmd: &str) -> Observation {
        let trimmed = cmd.trim();
        let mut output = String::new();
        if let Some(rest) = trimmed.strip_prefix("getprop") {
            let key = rest.trim();
            output = match key {
                "ro.product.model" | "ro.product.device" | "ro.product.name" => {
                    self.env.profile.model.clone()
                }
                "ro.build.version.sdk" => self.env.sdk_int.to_string(),
                "ro.product.manufacturer" => self.env.profile.manufacturer.clone(),
                "ro.kernel.qemu" | "ro.boot.qemu" => "0".to_string(),
                "ro.debuggable" => "0".to_string(),
                "ro.secure" => "1".to_string(),
                k if k.starts_with("ro.") => String::new(),
                _ => String::new(),
            };
        } else if trimmed.starts_with("ls ") || trimmed == "ls" {
            let dir = trimmed.trim_start_matches("ls").trim();
            let dir = if dir.is_empty() { "/" } else { dir };
            output = self.env.fs.list(dir).join("\n");
        } else if trimmed.starts_with("cat ") {
            let path = trimmed.trim_start_matches("cat").trim();
            if let Some(data) = self.env.fs.read(path) {
                output = String::from_utf8_lossy(data).into_owned();
            } else if path == "/proc/cpuinfo" {
                output = self.env.profile.cpuinfo.clone();
            } else if path == "/proc/version" {
                output = format!(
                    "Linux version 5.10.107-android13 (build@{}) #1 SMP PREEMPT",
                    self.env.profile.build_host
                );
            }
        } else if trimmed.starts_with("which ") || trimmed.starts_with("command -v ") {
            let name = trimmed.rsplit(' ').next().unwrap_or("");
            if self.env.fs.exists(&format!("/system/bin/{name}")) {
                output = format!("/system/bin/{name}");
            }
        } else if trimmed.starts_with("id") {
            output = format!("uid={} gid={} groups=0", self.env.uid, self.env.uid);
        } else if trimmed.starts_with("su") {
            // Root is not available in the hardened profile.
            output = String::new();
        } else if trimmed.starts_with("pm list packages") {
            output = self
                .env
                .profile
                .installed_packages
                .iter()
                .map(|p| format!("package:{}", p.name))
                .collect::<Vec<_>>()
                .join("\n");
        }
        let mut o = obs(
            Level::Critical,
            "exec",
            format!("exec({trimmed:?}) -> {} bytes", output.len()),
        );
        if !output.is_empty() {
            o.result = format!("exec({trimmed:?}) -> {:?}", truncate(&output, 120));
        }
        o
    }

    fn java_io(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        // File(path) model; stream constructors attach their path.
        match name {
            "<init>" => {
                // The path may arrive as a String or as a `File` whose model
                // already carries one, depending on which overload was used.
                let path = self
                    .arg_str(args, 1)
                    .or_else(|| self.value_path(args.get(1)))
                    .unwrap_or_default();
                let this = self.arg_obj(args, 0);
                if let Some(this) = this {
                    // `new-instance` gives every object an `Instance`; replace
                    // it with a `Model` so the path (and later connection or
                    // buffer fields) can be attached to the same handle.
                    let descriptor = match class {
                        "java/io/File" => "Ljava/io/File;",
                        "java/io/FileInputStream" | "java/io/FileReader" => {
                            "Ljava/io/FileInputStream;"
                        }
                        "java/io/FileOutputStream" | "java/io/FileWriter" => {
                            "Ljava/io/FileOutputStream;"
                        }
                        "java/io/PrintStream" => "Ljava/io/PrintStream;",
                        "java/io/RandomAccessFile" => "Ljava/io/RandomAccessFile;",
                        "java/io/OutputStream" => "Ljava/io/OutputStream;",
                        "java/io/InputStream" => "Ljava/io/InputStream;",
                        "java/io/DataInputStream" => "Ljava/io/DataInputStream;",
                        "java/io/DataOutputStream" => "Ljava/io/DataOutputStream;",
                        _ => "Ljava/io/File;",
                    };
                    if let Some(obj) = self.heap.get_mut(this) {
                        *obj = Object::Model {
                            class: descriptor.into(),
                            fields: [("path".to_string(), ObjectValue::Str(path.clone()))]
                                .into_iter()
                                .collect(),
                            prov: Provenance::default(),
                        };
                    }
                }
                CallResult::void()
            }
            "exists" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                let exists = self.env.fs.exists(&path) || self.env.fs.is_file(&path);
                let mut o = obs(Level::Notable, "file", format!("exists({path}) = {exists}"));
                if is_root_probe(&path) {
                    o.level = Level::Critical;
                    o.category = "evasion";
                    o.result = format!("root/emulator path probe: {path}");
                }
                CallResult::new(Some(Value::I(exists as i32)), Some(o))
            }
            "canRead" | "canWrite" | "isFile" | "isDirectory" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                CallResult::int(self.env.fs.exists(&path) as i32)
            }
            "delete" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                let ok = self.env.fs.remove(&path);
                CallResult::new(
                    Some(Value::I(ok as i32)),
                    Some(obs(
                        Level::Notable,
                        "file",
                        format!("deleteFile({path}) = {ok}"),
                    )),
                )
            }
            "length" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                CallResult::new(Some(Value::J(self.env.fs.size(&path) as i64)), None)
            }
            "getAbsolutePath" | "getPath" | "toString" | "getCanonicalPath" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                CallResult::obj(self.new_string(path, Provenance::default()))
            }
            "getName" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                let n = path.rsplit('/').next().unwrap_or(&path).to_string();
                CallResult::obj(self.new_string(n, Provenance::default()))
            }
            "getParent" | "getParentFile" => CallResult::obj(Value::NULL),
            "listFiles" | "list" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                let names = self.env.fs.list(&path);
                let items: Vec<Value> = names
                    .into_iter()
                    .map(|n| self.new_string(format!("{path}/{n}"), Provenance::default()))
                    .collect();
                CallResult::obj(
                    match self.heap.new_obj_array(
                        "[Ljava/lang/String;",
                        items,
                        Provenance::default(),
                    ) {
                        Some(id) => Value::obj(id),
                        None => Value::NULL,
                    },
                )
            }
            "mkdirs" | "mkdir" | "createNewFile" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                CallResult::new(
                    Some(Value::I(1)),
                    Some(obs(Level::Routine, "file", format!("create({path})"))),
                )
            }
            "read" | "readBytes" => {
                let path = self.value_path(args.first()).unwrap_or_default();
                match self.env.fs.read(&path).map(|d| d.to_vec()) {
                    Some(data) => {
                        self.budget.charge_apk_read(data.len() as u64);
                        CallResult::new(
                            Some(self.new_bytes(data, Provenance::of(Tag::PackedData))),
                            None,
                        )
                    }
                    None => CallResult::int(-1),
                }
            }
            "write" => {
                // `write` appears on file streams, HTTP bodies, byte-array
                // streams and plain OutputStreams. Route by what the receiver
                // actually is, so an exfiltrating POST is not mistaken for a
                // file write.
                let this = self.arg_obj(args, 0);
                let data = match self.arg_bytes(args, 1) {
                    Some(d) => d,
                    // write(int): a single byte on a stream.
                    None => vec![self.arg_i32(args, 1) as u8],
                };
                let prov = self.arg_prov(args, 1);
                let cap = self.budget.limits.max_allocation_bytes;
                if data.len() > cap {
                    self.budget
                        .stop(crate::limits::StopReason::Budget, "write too large");
                    return CallResult::void();
                }
                // 1. HTTP body: the stream remembers the connection it belongs to.
                if let Some(conn) =
                    this.and_then(|id| self.model_field(id, "conn").map(|v| v.as_i64() as u32))
                {
                    let url = self.model_string(conn, "url").unwrap_or_default();
                    let method = self
                        .model_string(conn, "method")
                        .unwrap_or_else(|| "POST".into());
                    if let Some(Object::Model { fields, .. }) = self.heap.get_mut(conn) {
                        let entry = fields
                            .entry("body".to_string())
                            .or_insert_with(|| ObjectValue::Bytes(Vec::new()));
                        if let ObjectValue::Bytes(b) = entry {
                            b.extend_from_slice(&data);
                        }
                    }
                    self.record_egress(&method, &url, &data, &prov);
                    let n = data.len();
                    let mut o = obs(
                        Level::Critical,
                        "egress",
                        format!(
                            "{method} {url} <- {n} bytes {:?}",
                            crate::events::summarize_bytes(&data, 96)
                        ),
                    );
                    o.prov = Some(prov);
                    o.target = Some(url);
                    return CallResult::new(Some(Value::I(n as i32)), Some(o));
                }
                // 2. Byte-array stream: accumulate into its buffer.
                if this
                    .map(|id| self.model_field(id, "buf").is_some())
                    .unwrap_or(false)
                {
                    if let Some(Object::Model {
                        fields, prov: p, ..
                    }) = this.and_then(|id| self.heap.get_mut(id))
                    {
                        if let Some(ObjectValue::Bytes(buf)) = fields.get_mut("buf") {
                            buf.extend_from_slice(&data);
                        }
                        p.merge(&prov);
                        p.add(Tag::Built);
                    }
                    return CallResult::int(data.len() as i32);
                }
                // 3. File stream.
                let path = this
                    .and_then(|id| self.model_string(id, "path"))
                    .unwrap_or_default();
                if path.is_empty() {
                    return CallResult::void();
                }
                self.env.fs.write(&path, data.clone());
                let is_dex = k::looks_like_dex(&data);
                let mut o = obs(
                    if is_dex {
                        Level::Critical
                    } else {
                        Level::Notable
                    },
                    "file",
                    format!(
                        "writeFile({path}, {} bytes{})",
                        data.len(),
                        if is_dex { ", DEX payload" } else { "" }
                    ),
                );
                o.prov = Some(prov);
                if is_dex {
                    // A DEX written to disk is a payload we will load when the
                    // sample constructs a DexClassLoader on it.
                    self.note_dynamic_file(path.clone(), data.clone());
                }
                CallResult::new(Some(Value::I(data.len() as i32)), Some(o))
            }
            "close" | "flush" | "skip" | "available" => CallResult::void(),
            _ => CallResult::void(),
        }
    }

    fn java_byte_stream(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        let Some(this) = self.arg_obj(args, 0) else {
            return CallResult::void();
        };
        match name {
            "<init>" => {
                if class.ends_with("ByteArrayOutputStream") {
                    self.set_model_field(this, "buf", ObjectValue::Bytes(Vec::new()));
                }
                CallResult::void()
            }
            "write" => {
                if let Some(data) = self.arg_bytes(args, 1) {
                    let prov = self.arg_prov(args, 1);
                    if let Some(Object::Model {
                        fields, prov: p, ..
                    }) = self.heap.get_mut(this)
                    {
                        if let Some(ObjectValue::Bytes(buf)) = fields.get_mut("buf") {
                            buf.extend_from_slice(&data);
                        }
                        p.merge(&prov);
                        p.add(Tag::Built);
                    }
                }
                CallResult::void()
            }
            "toByteArray" => {
                let data = match self.heap.get(this) {
                    Some(Object::Model { fields, prov, .. }) => {
                        let prov = prov.clone();
                        match fields.get("buf") {
                            Some(ObjectValue::Bytes(b)) => Some((b.clone(), prov)),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                match data {
                    Some((b, mut prov)) => {
                        prov.add(Tag::Built);
                        CallResult::obj(self.new_bytes(b, prov))
                    }
                    None => CallResult::obj(self.new_bytes(vec![], Provenance::default())),
                }
            }
            _ => CallResult::void(),
        }
    }

    fn java_boxed(&mut self, _class: &str, name: &str, args: &[Value]) -> CallResult {
        match name {
            "parseInt" | "parseLong" | "valueOf" | "parseShort" | "parseByte" | "decode" => {
                let s = self.arg_str_or(args, args.len().saturating_sub(1));
                let radix = if args.len() > 2 {
                    self.arg_i32(args, 2)
                } else {
                    10
                };
                let v = i64::from_str_radix(
                    s.trim().trim_start_matches("0x"),
                    radix.clamp(2, 36) as u32,
                )
                .unwrap_or(0);
                CallResult::new(Some(Value::I(v as i32)), None)
            }
            "toString" | "toHexString" | "toBinaryString" => {
                let v = self.arg_i32(args, args.len().saturating_sub(1));
                let s = match name {
                    "toHexString" => format!("{v:x}"),
                    "toBinaryString" => format!("{v:b}"),
                    _ => v.to_string(),
                };
                CallResult::obj(self.new_string(s, Provenance::constant()))
            }
            "intValue" | "longValue" | "byteValue" | "shortValue" => {
                CallResult::new(Some(Value::I(self.arg_i32(args, 0))), None)
            }
            "doubleValue" | "floatValue" => {
                CallResult::new(Some(Value::f32(self.arg_i32(args, 0) as f32)), None)
            }
            "booleanValue" => CallResult::new(Some(Value::I(self.arg_i32(args, 0))), None),
            "MAX_VALUE" | "MIN_VALUE" => CallResult::int(i32::MAX),
            _ => CallResult::void(),
        }
    }

    fn java_math(&mut self, name: &str, args: &[Value]) -> CallResult {
        let a = self.arg_i64(args, 0);
        let b = self.arg_i64(args, 1);
        match name {
            "abs" => CallResult::new(Some(Value::J(a.abs())), None),
            "max" => CallResult::new(Some(Value::J(a.max(b))), None),
            "min" => CallResult::new(Some(Value::J(a.min(b))), None),
            "pow" => CallResult::new(Some(Value::f64((a as f64).powf(b as f64))), None),
            "sqrt" => CallResult::new(Some(Value::f64((a as f64).sqrt())), None),
            _ => CallResult::void(),
        }
    }

    fn java_arrays(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "copyOf" | "copyOfRange" => {
                let data = self.arg_bytes(args, 0).unwrap_or_default();
                let n = self.arg_i32(args, 1).max(0) as usize;
                let mut out = data;
                out.resize(n, 0);
                CallResult::obj(self.new_bytes(out, self.arg_prov(args, 0)))
            }
            "fill" => CallResult::void(),
            "toString" => CallResult::obj(self.new_string("[]", Provenance::constant())),
            "equals" => {
                let a = self.arg_bytes(args, 0);
                let b = self.arg_bytes(args, 1);
                CallResult::int((a == b) as i32)
            }
            _ => CallResult::void(),
        }
    }

    fn java_base64(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "encode" | "encodeToString" => {
                let data = self
                    .arg_bytes(args, args.len().saturating_sub(1))
                    .unwrap_or_default();
                let s = k::base64_encode(&data);
                let mut o = obs(Level::Routine, "decode", "Base64.encode");
                o.prov = Some(self.derived_prov(args, Tag::Decoded));
                CallResult::new(
                    Some(self.new_string(s, Provenance::of(Tag::Built))),
                    Some(o),
                )
            }
            "decode" => {
                let s = self.arg_str_or(args, args.len().saturating_sub(1));
                let bytes = k::base64_decode(&s).unwrap_or_default();
                let mut prov = self.derived_prov(args, Tag::Decoded);
                prov.add(Tag::Built);
                let decoded_dex = k::looks_like_dex(&bytes);
                let mut o = obs(
                    if decoded_dex {
                        Level::Critical
                    } else {
                        Level::Notable
                    },
                    "decode",
                    format!(
                        "Base64.decode -> {} bytes{}",
                        bytes.len(),
                        if decoded_dex { " (DEX)" } else { "" }
                    ),
                );
                o.prov = Some(prov.clone());
                if decoded_dex {
                    o.payload = Some(bytes.clone());
                }
                CallResult::new(Some(self.new_bytes(bytes, prov)), Some(o))
            }
            _ => CallResult::void(),
        }
    }

    fn java_thread(&mut self, name: &str, _args: &[Value]) -> CallResult {
        match name {
            "currentThread" => CallResult::obj(self.new_model_default("Ljava/lang/Thread;")),
            "getName" => CallResult::obj(self.new_string("main", Provenance::of(Tag::Device))),
            "sleep" => CallResult::void(),
            _ => CallResult::void(),
        }
    }

    fn java_message_digest(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getInstance" => {
                let alg = self.arg_str_or(args, 0);
                let v = match self.new_model_default("Ljava/security/MessageDigest;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "alg", ObjectValue::Str(alg));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            "digest" => {
                let alg = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "alg"))
                    .unwrap_or_else(|| "SHA-256".into());
                let data = self.arg_bytes(args, 1).unwrap_or_default();
                let out = match k::HashAlg::from_java_name(&alg) {
                    Some(h) => h.digest(&data),
                    None => Vec::new(),
                };
                let mut o = obs(
                    Level::Notable,
                    "crypto",
                    format!("MessageDigest({alg}).digest -> {} bytes", out.len()),
                );
                o.prov = Some(self.derived_prov(args, Tag::Decoded));
                CallResult::new(
                    Some(self.new_bytes(out, Provenance::of(Tag::Decoded))),
                    Some(o),
                )
            }
            "update" | "reset" => CallResult::void(),
            _ => CallResult::void(),
        }
    }

    fn javax_cipher(&mut self, name: &str, args: &[Value]) -> CallResult {
        match name {
            "getInstance" => {
                let alg = self.arg_str_or(args, 0);
                let v = match self.new_model_default("Ljavax/crypto/Cipher;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "alg", ObjectValue::Str(alg));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            "init" => {
                let Some(this) = self.arg_obj(args, 0) else {
                    return CallResult::void();
                };
                let mode = self.arg_i32(args, 1);
                // init(mode, key) or init(mode, key, iv)
                let key_arg = self
                    .arg_obj(args, 2)
                    .and_then(|k| self.model_field(k, "key").cloned());
                let key_bytes = match key_arg {
                    Some(ObjectValue::Bytes(b)) => b,
                    _ => self.arg_bytes(args, 3).unwrap_or_default(),
                };
                let iv_bytes = self
                    .arg_obj(args, 3)
                    .and_then(|iv| self.model_field(iv, "iv").cloned());
                let iv = match iv_bytes {
                    Some(ObjectValue::Bytes(b)) => b,
                    _ => self.arg_bytes(args, 4).unwrap_or_default(),
                };
                self.set_model_field(this, "mode", ObjectValue::Int(mode as i64));
                self.set_model_field(this, "key", ObjectValue::Bytes(key_bytes));
                self.set_model_field(this, "iv", ObjectValue::Bytes(iv));
                CallResult::void()
            }
            "doFinal" => {
                let Some(this) = self.arg_obj(args, 0) else {
                    return CallResult::void();
                };
                let alg = self.model_string(this, "alg").unwrap_or_default();
                let mode = self
                    .model_field(this, "mode")
                    .map(|v| v.as_i64() as i32)
                    .unwrap_or(2);
                let key = self
                    .model_field(this, "key")
                    .and_then(|v| match v {
                        ObjectValue::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let iv = self
                    .model_field(this, "iv")
                    .and_then(|v| match v {
                        ObjectValue::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let data = self.arg_bytes(args, 1).unwrap_or_default();
                let out = apply_cipher(&alg, mode, &key, &iv, &data);
                let decoded = out.1;
                let bytes = out.0;
                let is_dex = k::looks_like_dex(&bytes);
                let printable = k::printable_ratio(&bytes);
                let notable = decoded && (is_dex || printable > 0.85);
                let mut prov = self.derived_prov(args, Tag::Decoded);
                prov.add(Tag::Built);
                let mut o = obs(
                    if is_dex {
                        Level::Critical
                    } else if notable {
                        Level::Notable
                    } else {
                        Level::Routine
                    },
                    "crypto",
                    format!(
                        "Cipher({alg}, mode={mode}).doFinal -> {} bytes{}{}",
                        bytes.len(),
                        if is_dex { " (DEX!)" } else { "" },
                        if decoded {
                            ""
                        } else {
                            " [primitives unsupported]"
                        }
                    ),
                );
                o.prov = Some(prov.clone());
                if is_dex {
                    o.payload = Some(bytes.clone());
                }
                CallResult::new(Some(self.new_bytes(bytes, prov)), Some(o))
            }
            _ => CallResult::void(),
        }
    }

    fn javax_key_spec(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        if name != "<init>" {
            return CallResult::void();
        }
        let this = self.arg_obj(args, 0);
        let data = self
            .arg_bytes(args, 1)
            .or_else(|| self.arg_bytes(args, 0))
            .unwrap_or_default();
        if let Some(this) = this {
            let key = if class.ends_with("IvParameterSpec") {
                "iv"
            } else {
                "key"
            };
            self.set_model_field(this, key, ObjectValue::Bytes(data));
        }
        CallResult::void()
    }

    fn java_nio(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match (class, name) {
            ("java/nio/charset/Charset", "forName") => {
                let n = self.arg_str_or(args, 0);
                CallResult::obj(self.new_string(n, Provenance::constant()))
            }
            ("java/nio/charset/Charset", "defaultCharset") => {
                CallResult::obj(self.new_string("UTF-8", Provenance::constant()))
            }
            ("java/nio/ByteBuffer", "wrap") => {
                let data = self.arg_bytes(args, 0).unwrap_or_default();
                let v = match self.new_model_default("Ljava/nio/ByteBuffer;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "buf", ObjectValue::Bytes(data));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            ("java/nio/ByteBuffer", "array") => {
                let data = self
                    .arg_obj(args, 0)
                    .and_then(|id| match self.model_field(id, "buf") {
                        Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                CallResult::obj(self.new_bytes(data, Provenance::default()))
            }
            _ => CallResult::void(),
        }
    }

    fn java_random(&mut self, _class: &str, name: &str, args: &[Value]) -> CallResult {
        match name {
            "<init>" => {
                if let Some(this) = self.arg_obj(args, 0) {
                    let seed = self
                        .arg_i64(args, 1)
                        .wrapping_add(0x9E3779B97F4A7C15u64 as i64)
                        as u64;
                    self.set_model_field(this, "seed", ObjectValue::Int(seed as i64));
                }
                CallResult::void()
            }
            "nextInt" | "nextLong" | "nextBytes" | "nextFloat" | "nextDouble" => {
                let this = self.arg_obj(args, 0);
                let mut seed = this
                    .and_then(|id| self.model_field(id, "seed").map(|v| v.as_i64()))
                    .unwrap_or(0) as u64;
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                if let Some(this) = this {
                    self.set_model_field(this, "seed", ObjectValue::Int(seed as i64));
                }
                let v = (seed >> 33) as i32;
                match name {
                    "nextInt" => CallResult::int(if args.len() > 1 {
                        v.abs() % self.arg_i32(args, 1).max(1)
                    } else {
                        v
                    }),
                    "nextLong" => CallResult::new(Some(Value::J(seed as i64)), None),
                    "nextFloat" => {
                        CallResult::new(Some(Value::f32((v as f32) / (i32::MAX as f32))), None)
                    }
                    "nextDouble" => {
                        CallResult::new(Some(Value::f64((v as f64) / (i32::MAX as f64))), None)
                    }
                    _ => CallResult::new(Some(Value::J(seed as i64)), None),
                }
            }
            _ => CallResult::void(),
        }
    }

    fn java_collections(&mut self, _class: &str, name: &str, _args: &[Value]) -> CallResult {
        match name {
            "size" => CallResult::int(0),
            "get" | "remove" | "put" => CallResult::obj(Value::NULL),
            "isEmpty" => CallResult::int(1),
            "containsKey" | "contains" | "containsValue" => CallResult::int(0),
            "keySet" | "values" | "entrySet" => CallResult::obj(Value::NULL),
            "<init>" => CallResult::void(),
            _ => CallResult::void(),
        }
    }

    fn java_json(&mut self, _class: &str, name: &str, args: &[Value]) -> CallResult {
        match name {
            "<init>" => CallResult::void(),
            "put" | "getString" | "getInt" => {
                if name == "getString" {
                    CallResult::obj(self.new_string("", Provenance::constant()))
                } else if name == "getInt" {
                    CallResult::int(0)
                } else {
                    CallResult::new(Some(args.first().copied().unwrap_or(Value::NULL)), None)
                }
            }
            "toString" => CallResult::obj(self.new_string("{}", Provenance::constant())),
            _ => CallResult::void(),
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}

fn is_root_probe(path: &str) -> bool {
    crate::env::EMULATOR_ARTIFACTS.contains(&path)
        || path.contains("/su")
        || path.contains("superuser")
        || path.contains("Superuser")
}

/// Apply a JCE cipher transformation. Returns (bytes, recognised).
///
/// Unrecognised transformations return the input unchanged with `false`, which
/// keeps the trace honest: we never claim a decode we did not perform.
fn apply_cipher(alg: &str, mode: i32, key: &[u8], iv: &[u8], data: &[u8]) -> (Vec<u8>, bool) {
    let a = alg.to_ascii_uppercase();
    let encrypt = mode == 1; // Cipher.ENCRYPT_MODE
                             // Try the transformations we implement.
    if a.starts_with("AES") {
        let r = if a.contains("CBC") {
            if encrypt {
                k::aes_cbc_encrypt(data, key, iv)
            } else {
                k::aes_cbc_decrypt(data, key, iv)
            }
        } else if a.contains("CTR") {
            k::aes_ctr(data, key, iv)
        } else if a.contains("ECB") {
            k::aes_ecb_decrypt(data, key)
        } else {
            // Default transformation for `AES` on Android is AES/ECB/PKCS5.
            k::aes_ecb_decrypt(data, key)
        };
        if let Ok(out) = r {
            if encrypt {
                return (out, true);
            }
            let (stripped, _ok) = k::strip_pkcs7(&out);
            return (stripped, true);
        }
        return (data.to_vec(), false);
    }
    if a.starts_with("DES") || a.starts_with("DESEDE") {
        return (data.to_vec(), false);
    }
    // Android's "AES" fallback is handled above; anything else is unsupported.
    (data.to_vec(), false)
}
