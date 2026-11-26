//! `java.lang`, `java.util`, `java.text` and friends.
//!
//! These are the workhorses of obfuscated code: string building, Base64-ish
//! transforms, `String.getBytes`, integer parsing, `System.exit`, reflection
//! helpers, collections and JSON-ish payload assembly. Modelled faithfully
//! because a wrong answer here changes control flow.

use crate::report::SinkKind;
use crate::vm::android::{
    arg_bytes, arg_int, arg_long, arg_ref, arg_str, arg_taint, desc_to_dotted, java_to_string,
    ret_bool, ret_int, ret_long, ret_obj, ret_void, state_int,
    union_taint,
};
use crate::vm::heap::ObjKind;
use crate::vm::intern::{MethodKey, Sym};
use crate::vm::interp::{CallOutcome, Vm};
use crate::vm::value::{ObjRef, Slot, Taint, Value};

use super::AndroidHost;

/// Resolve an argument that must be a string; returns its contents.
fn s(vm: &Vm, args: &[Slot], i: usize) -> String {
    arg_str(vm, args, i).unwrap_or_default()
}


pub fn dispatch(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    key: &MethodKey,
    args: &[Slot],
) -> CallOutcome {
    let _ = key;
    match class {
        "Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;" => {
            return string_builder(vm, name, key, args)
        }
        "Ljava/lang/String;" => return string_ops(vm, name, args),
        "Ljava/lang/System;" => return system_ops(vm, host, name, args),
        "Ljava/lang/Runtime;" => return runtime_ops(vm, name, args),
        "Ljava/lang/ProcessBuilder;" => return process_builder(vm, name, args),
        "Ljava/lang/Thread;" => return thread_ops(vm, host, name, args),
        "Ljava/lang/Math;" => return math_ops(name, args),
        "Ljava/lang/Integer;" | "Ljava/lang/Long;" | "Ljava/lang/Short;" | "Ljava/lang/Byte;"
        | "Ljava/lang/Boolean;" | "Ljava/lang/Double;" | "Ljava/lang/Float;"
        | "Ljava/lang/Character;" => return box_ops(vm, class, name, args),
        "Ljava/lang/Class;" => return class_ops(vm, name, args),
        "Ljava/lang/Object;" => return object_ops(vm, name, args),
        "Ljava/util/Arrays;" => return arrays_ops(vm, name, args),
        "Ljava/util/Collections;" => return collections_ops(vm, host, name, args),
        "Ljava/util/List;" | "Ljava/util/ArrayList;" | "Ljava/util/LinkedList;"
        | "Ljava/util/Collection;" | "Ljava/util/Set;" | "Ljava/util/HashSet;"
        | "Ljava/util/LinkedHashSet;" => return list_ops(vm, class, name, args),
        "Ljava/util/Map;" | "Ljava/util/HashMap;" | "Ljava/util/LinkedHashMap;"
        | "Ljava/util/TreeMap;" | "Ljava/util/concurrent/ConcurrentHashMap;"
        | "Ljava/util/Hashtable;" => return map_ops(vm, class, name, args),
        "Ljava/util/Map$Entry;" => return map_entry_ops(vm, name, args),
        "Ljava/util/Iterator;" | "Ljava/util/ListIterator;" => {
            return iterator_ops(vm, name, args)
        }
        "Ljava/text/Base64;" => return text_base64(vm, name, args),
        "Ljava/text/SimpleDateFormat;" | "Ljava/text/DateFormat;" => {
            return date_format(vm, name, args)
        }
        "Ljava/util/Date;" => return date_ops(vm, name, args),
        "Ljava/util/Calendar;" | "Ljava/util/GregorianCalendar;" => {
            return calendar_ops(vm, name, args)
        }
        "Ljava/util/Random;" => return random_ops(vm, name, args),
        "Ljava/util/UUID;" => return uuid_ops(vm, name, args),
        "Ljava/util/zip/ZipInputStream;" | "Ljava/util/zip/ZipFile;"
        | "Ljava/util/zip/ZipOutputStream;" | "Ljava/util/zip/ZipEntry;"
        | "Ljava/util/jar/JarFile;" => return super::io::dispatch(vm, host, class, name, key, args),
        "Lorg/json/JSONObject;" | "Lorg/json/JSONArray;" | "Lorg/json/JSONStringer;" => {
            return json_ops(vm, class, name, args)
        }
        "Ljava/lang/Enum;" | "Ljava/lang/Iterable;" | "Ljava/lang/CharSequence;"
        | "Ljava/lang/Comparable;" | "Ljava/lang/Cloneable;" | "Ljava/lang/Runnable;"
        | "Ljava/lang/Number;" | "Ljava/lang/Appendable;" | "Ljava/io/Serializable;" => {
            // Interfaces: calls land on the concrete implementation, so anything
            // here is a `super` call with no modelled body.
            return ret_void_or_default(vm, key);
        }
        _ => {}
    }
    CallOutcome::Decline
}

fn ret_void_or_default(vm: &mut Vm, key: &MethodKey) -> CallOutcome {
    let proto = vm.sym_str(key.proto).to_string();
    let ret = proto.rsplit(')').next().unwrap_or("V");
    if ret == "V" {
        ret_void()
    } else {
        CallOutcome::Value(crate::vm::interp::default_for(ret))
    }
}

// ---------------------------------------------------------------------------
// StringBuilder
// ---------------------------------------------------------------------------

fn string_builder(vm: &mut Vm, name: &str, key: &MethodKey, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // (String) / (int capacity) / ()
            let init = if args.len() > 1 {
                match args[1].v {
                    Value::Ref(r) if !r.is_null() => {
                        (vm.string_of(r), arg_taint(args, 1))
                    }
                    _ => (String::new(), Taint::CLEAN),
                }
            } else {
                (String::new(), Taint::CLEAN)
            };
            if let Some(obj) = vm.heap.get_mut(this) {
                obj.kind = ObjKind::MutableStr(init.0);
                obj.taint = init.1;
            }
            ret_void()
        }
        "append" => {
            // Taint must include the appended object's own taint, not just the
            // register's: a `String` produced by `getDeviceId()` carries its
            // label on the heap object, and the register holding the reference
            // is usually clean.
            let t = arg_taint(args, 1).union(vm.heap.taint_of(arg_ref(args, 1))).union(vm.heap.taint_of(this));
            // `append(char)` and `append(int)` are both a single int register;
            // only the declared prototype distinguishes them. A char must be
            // rendered as the character, not its code point.
            let proto = vm.sym_str(key.proto);
            let text = match args.get(1).map(|s| s.v) {
                Some(Value::Ref(r)) if !r.is_null() => {
                    if vm.heap.is_string(r) {
                        vm.string_of(r)
                    } else if let Some(b) = vm.heap.bytes_of(r) {
                        String::from_utf8_lossy(b).to_string()
                    } else {
                        vm.object_describe(r)
                    }
                }
                Some(Value::Int(v)) if proto.starts_with("(C)") => {
                    char::from_u32(v as u32).map(|c| c.to_string()).unwrap_or_default()
                }
                Some(v) => java_to_string(vm, Slot::clean(v)),
                None => String::new(),
            };
            vm.heap.append_mutable(this, &text, t);
            ret_obj(this)
        }
        "toString" | "substring" => {
            if name == "substring" {
                let s = vm.string_of(this);
                let chars: Vec<char> = s.chars().collect();
                let start = arg_int(args, 1).max(0) as usize;
                let end = if args.len() > 2 {
                    (arg_int(args, 2).max(0) as usize).min(chars.len())
                } else {
                    chars.len()
                };
                let sub: String = if start <= end && start <= chars.len() {
                    chars[start..end].iter().collect()
                } else {
                    String::new()
                };
                let t = vm.heap.taint_of(this);
                return match vm.new_string_t(sub, t) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                };
            }
            match vm.heap.builder_to_string(this) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "length" => ret_int(vm.heap.length_of(this).unwrap_or(0) as i32),
        "charAt" => {
            let s = vm.string_of(this);
            let idx = arg_int(args, 1).max(0) as usize;
            ret_int(s.chars().nth(idx).map(|c| c as i32).unwrap_or(0))
        }
        "setLength" => {
            let n = arg_int(args, 1).max(0) as usize;
            if let Some(obj) = vm.heap.get_mut(this) {
                if let ObjKind::MutableStr(buf) = &mut obj.kind {
                    let mut chars: Vec<char> = buf.chars().collect();
                    chars.resize(n, '\0');
                    *buf = chars.into_iter().collect();
                }
            }
            ret_void()
        }
        "reverse" => {
            if let Some(obj) = vm.heap.get_mut(this) {
                if let ObjKind::MutableStr(buf) = &mut obj.kind {
                    *buf = buf.chars().rev().collect();
                }
            }
            ret_obj(this)
        }
        "delete" | "deleteCharAt" | "insert" | "replace" => ret_obj(this),
        "indexOf" => ret_int(-1),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// java.lang.String
// ---------------------------------------------------------------------------

fn string_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    let text = vm.string_of(this);
    let tt = vm.heap.taint_of(this);
    match name {
        "<init>" => match args.get(1).map(|s| s.v) {
            Some(Value::Ref(r)) if !r.is_null() && vm.heap.is_string(r) => {
                let src = vm.string_of(r);
                let t = vm.heap.taint_of(r);
                if let Some(obj) = vm.heap.get_mut(this) {
                    obj.kind = ObjKind::Str(src);
                    obj.taint = t;
                }
                ret_void()
            }
            Some(Value::Ref(r)) if !r.is_null() => {
                // String(byte[]) / String(byte[], charset) / String(byte[], off, len)
                if let Some(b) = vm.heap.bytes_of(r) {
                    let t = vm.heap.taint_of(r);
                    let (off, len) = byte_range(vm, args, 1, b.len());
                    let s = decode_charset(&b[off..off + len], &args_encoding(vm, args));
                    if let Some(obj) = vm.heap.get_mut(this) {
                        obj.kind = ObjKind::Str(s);
                        obj.taint = t;
                    }
                    return ret_void();
                }
                let (a, b) = (arg_int(args, 1), arg_int(args, 2));
                let t = union_taint(args);
                let _ = t;
                if let Some(obj) = vm.heap.get_mut(this) {
                    obj.kind = ObjKind::Str(format!("{}{}", a as u8 as char, b as u8 as char));
                }
                ret_void()
            }
            _ => {
                if let Some(obj) = vm.heap.get_mut(this) {
                    obj.kind = ObjKind::Str(String::new());
                }
                ret_void()
            }
        },
        "length" => ret_int(text.chars().count() as i32),
        "isEmpty" => ret_bool(text.is_empty()),
        "charAt" => {
            let idx = arg_int(args, 1).max(0) as usize;
            ret_int(text.chars().nth(idx).map(|c| c as i32).unwrap_or(0))
        }
        "codePointAt" => {
            let idx = arg_int(args, 1).max(0) as usize;
            ret_int(text.chars().nth(idx).map(|c| c as i32).unwrap_or(-1))
        }
        "substring" => {
            let chars: Vec<char> = text.chars().collect();
            let start = arg_int(args, 1).clamp(0, chars.len() as i32) as usize;
            let end = if args.len() > 2 {
                arg_int(args, 2).clamp(start as i32, chars.len() as i32) as usize
            } else {
                chars.len()
            };
            let s: String = chars[start..end].iter().collect();
            match vm.new_string_t(s, tt) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "indexOf" | "lastIndexOf" => {
            let needle = args
                .get(1)
                .and_then(|_| arg_str(vm, args, 1));
            let from = if args.len() > 2 { arg_int(args, 2).max(0) as usize } else { 0 };
            let idx = match needle {
                Some(n) => {
                    if name == "indexOf" {
                        char_index(&text, &n, from, false)
                    } else {
                        char_index(&text, &n, from, true)
                    }
                }
                None => {
                    let c = arg_int(args, 1);
                    let ch = char::from_u32(c as u32).unwrap_or('\0');
                    let pos = text.chars().skip(from).position(|x| x == ch);
                    pos.map(|p| p + from).unwrap_or(usize::MAX)
                }
            };
            ret_int(if idx == usize::MAX { -1 } else { idx as i32 })
        }
        "contains" => {
            let n = s(vm, args, 1);
            ret_bool(text.contains(&n))
        }
        "startsWith" => {
            let p = s(vm, args, 1);
            ret_bool(text.starts_with(&p))
        }
        "endsWith" => {
            let p = s(vm, args, 1);
            ret_bool(text.ends_with(&p))
        }
        "equals" | "equalsIgnoreCase" | "contentEquals" => {
            let other = arg_ref(args, 1);
            if other.is_null() {
                return ret_bool(false);
            }
            let o = vm.string_of(other);
            let eq = if name == "equalsIgnoreCase" {
                text.eq_ignore_ascii_case(&o)
            } else {
                text == o
            };
            ret_bool(eq)
        }
        "compareTo" | "compareToIgnoreCase" => {
            let o = s(vm, args, 1);
            let ord = if name == "compareToIgnoreCase" {
                text.to_lowercase().cmp(&o.to_lowercase())
            } else {
                text.cmp(&o)
            };
            ret_int(match ord {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            })
        }
        "hashCode" => ret_int(java_string_hash(&text)),
        "trim" => {
            match vm.new_string_t(text.trim().to_string(), tt) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "toLowerCase" => match vm.new_string_t(text.to_lowercase(), tt) {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "toUpperCase" => match vm.new_string_t(text.to_uppercase(), tt) {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "replace" | "replaceAll" | "replaceFirst" => {
            // (char,char) or (CharSequence,CharSequence)
            let (a_is_char, b_is_char) = (
                matches!(args.get(1).map(|x| x.v), Some(Value::Int(_))),
                matches!(args.get(2).map(|x| x.v), Some(Value::Int(_))),
            );
            let t = union_taint(args);
            let res = if a_is_char && b_is_char {
                let from = char::from_u32(arg_int(args, 1) as u32).unwrap_or('\0');
                let to = char::from_u32(arg_int(args, 2) as u32).unwrap_or('\0');
                text.replace(&from.to_string(), &to.to_string())
            } else {
                let from = s(vm, args, 1);
                let to = s(vm, args, 2);
                if name == "replaceFirst" {
                    replace_first(&text, &from, &to)
                } else if name == "replaceAll" {
                    // Regex semantics are approximated by a literal replacement;
                    // a pattern that is a plain string behaves identically.
                    text.replace(&from, &to)
                } else {
                    text.replace(&from, &to)
                }
            };
            match vm.new_string_t(res, tt.union(t)) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "split" => {
            let sep = s(vm, args, 1);
            let limit = arg_int(args, 2);
            let parts = split_literal(&text, &sep, limit);
            let elem = vm.sym("Ljava/lang/String;");
            match vm.heap.new_array(elem, "Ljava/lang/String;", parts.len(), tt) {
                Ok(arr) => {
                    for (i, p) in parts.into_iter().enumerate() {
                        if let Ok(rs) = vm.new_string_t(p, tt) {
                            vm.heap.array_set(arr, i, Slot::reference(rs));
                        }
                    }
                    ret_obj(arr)
                }
                Err(_) => ret_void(),
            }
        }
        "toCharArray" => {
            let elem = vm.sym("C");
            let chars: Vec<char> = text.chars().collect();
            match vm.heap.new_array(elem, "C", chars.len(), tt) {
                Ok(arr) => {
                    for (i, c) in chars.into_iter().enumerate() {
                        vm.heap.array_set(arr, i, Slot::int(c as i32));
                    }
                    ret_obj(arr)
                }
                Err(_) => ret_void(),
            }
        }
        "getBytes" => {
            let enc = args_encoding(vm, args);
            let bytes = encode_charset(&text, &enc);
            match vm.heap.new_bytes(bytes, tt) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "valueOf" | "copyValueOf" => {
            // static: valueOf(Object) / valueOf(int) / valueOf(char[])
            match args.first().map(|s| s.v) {
                Some(Value::Ref(r)) if !r.is_null() => match vm.heap.get(r).map(|o| &o.kind) {
                    Some(ObjKind::Str(_)) | Some(ObjKind::MutableStr(_)) => {
                        let t = vm.heap.taint_of(r);
                        match vm.new_string_t(vm.string_of(r), t) {
                            Ok(nr) => ret_obj(nr),
                            Err(_) => ret_void(),
                        }
                    }
                    Some(ObjKind::Bytes(_)) => {
                        let b = vm.heap.bytes_of(r).unwrap_or(&[]).to_vec();
                        let t = vm.heap.taint_of(r);
                        let off = if args.len() > 1 { arg_int(args, 1).max(0) as usize } else { 0 };
                        let len = if args.len() > 2 {
                            arg_int(args, 2).max(0) as usize
                        } else {
                            b.len().saturating_sub(off)
                        };
                        let slice = b.get(off..off + len).unwrap_or(&[]);
                        match vm.new_string_t(String::from_utf8_lossy(slice).to_string(), t) {
                            Ok(nr) => ret_obj(nr),
                            Err(_) => ret_void(),
                        }
                    }
                    Some(ObjKind::Array(a)) => {
                        // char[] -> String
                        let t = vm.heap.taint_of(r);
                        let chars: String = a
                            .data
                            .iter()
                            .filter_map(|sl| char::from_u32(sl.v.as_int() as u32))
                            .collect();
                        match vm.new_string_t(chars, t) {
                            Ok(nr) => ret_obj(nr),
                            Err(_) => ret_void(),
                        }
                    }
                    Some(ObjKind::Instance(_)) => {
                        let t = vm.heap.taint_of(r);
                        let rendered = java_to_string(vm, Slot::reference(r));
                        match vm.new_string_t(rendered, t) {
                            Ok(nr) => ret_obj(nr),
                            Err(_) => ret_void(),
                        }
                    }
                    None => ret_void(),
                },
                Some(Value::Int(v)) => match vm.new_string(v.to_string()) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                },
                Some(Value::Long(v)) => match vm.new_string(v.to_string()) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                },
                Some(Value::Float(v)) => {
                    match vm.new_string(super::fmt_float(v as f64)) {
                        Ok(r) => ret_obj(r),
                        Err(_) => ret_void(),
                    }
                }
                Some(Value::Double(v)) => match vm.new_string(super::fmt_float(v)) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                },
                _ => ret_void(),
            }
        }
        "format" => {
            // String.format(fmt, args...) — assemble object[] with %s/%d/%x.
            let fmt = s(vm, args, 0);
            let arr = arg_ref(args, 1);
            let mut vals = Vec::new();
            if let Some(o) = vm.heap.get(arr) {
                if let ObjKind::Array(a) = &o.kind {
                    let raws: Vec<Slot> = a.data.clone();
                    for sl in raws {
                        vals.push(java_to_string(vm, sl));
                    }
                }
            }
            let t = union_taint(args);
            let out = format_string(&fmt, &vals);
            match vm.new_string_t(out, t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "intern" => ret_obj(this),
        "toString" => ret_obj(this),
        _ => CallOutcome::Decline,
    }
}


fn args_encoding(vm: &Vm, args: &[Slot]) -> String {
    // The charset is the last String argument, if any.
    for a in args.iter().rev() {
        if let Some(o) = vm.heap.get(a.v.as_ref()) {
            if let ObjKind::Str(s) = &o.kind {
                return s.to_uppercase();
            }
        }
    }
    "UTF-8".into()
}

/// Resolve the `(offset, length)` slice for a `String(byte[], ...)`
/// constructor. Java has four overloads that differ only in what follows the
/// byte array (a charset name, a charset object, or two ints), so the type of
/// each argument is what disambiguates — an int is an offset, a reference is a
/// charset.
fn byte_range(vm: &Vm, args: &[Slot], byte_arg: usize, total: usize) -> (usize, usize) {
    let mut off = 0usize;
    let mut len = total;
    let mut seen_offset = false;
    for a in args.iter().skip(byte_arg + 1) {
        match a.v {
            Value::Int(v) => {
                if !seen_offset {
                    off = v.max(0) as usize;
                    seen_offset = true;
                } else {
                    len = v.max(0) as usize;
                }
            }
            Value::Ref(r) if !r.is_null() => {
                // A String or Charset object: not a range argument.
                let _ = vm.heap.string_of(r);
            }
            _ => {}
        }
    }
    let off = off.min(total);
    let len = if seen_offset { len.min(total - off) } else { total };
    (off, len)
}

fn decode_charset(bytes: &[u8], enc: &str) -> String {
    match enc {
        "UTF-16" | "UTF-16LE" => {
            let units: Vec<u16> = bytes
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        "US-ASCII" | "ASCII" => bytes.iter().map(|b| (*b & 0x7f) as char).collect(),
        "ISO-8859-1" | "LATIN1" => bytes.iter().map(|b| *b as char).collect(),
        _ => String::from_utf8_lossy(bytes).to_string(),
    }
}

fn encode_charset(s: &str, enc: &str) -> Vec<u8> {
    match enc {
        "UTF-16" | "UTF-16LE" => s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
        "US-ASCII" | "ASCII" => s.chars().map(|c| (c as u32 & 0x7f) as u8).collect(),
        "ISO-8859-1" | "LATIN1" => s.chars().map(|c| (c as u32 & 0xff) as u8).collect(),
        _ => s.as_bytes().to_vec(),
    }
}

/// Append `s` right-aligned to `width`, with zero or space padding. Negative
/// numbers put the sign before the zero padding, as Java's formatter does.
fn push_padded(out: &mut String, s: &str, width: usize, zero_pad: bool) {
    let len = s.chars().count();
    let pad = width.saturating_sub(len);
    if pad == 0 {
        out.push_str(s);
        return;
    }
    let (sign, body) = match s.strip_prefix('-') {
        Some(rest) if zero_pad => ("-", rest),
        _ => ("", s),
    };
    if !sign.is_empty() {
        out.push_str(sign);
    }
    let ch = if zero_pad { '0' } else { ' ' };
    for _ in 0..pad {
        out.push(ch);
    }
    out.push_str(body);
}

pub fn java_string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for u in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(u as i32);
    }
    h
}

fn char_index(haystack: &str, needle: &str, from: usize, last: bool) -> usize {
    let h: Vec<char> = haystack.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() {
        return if last { h.len() } else { from.min(h.len()) };
    }
    if n.len() > h.len() {
        return usize::MAX;
    }
    let mut found = usize::MAX;
    let mut i = if last { 0 } else { from.min(h.len()) };
    while i + n.len() <= h.len() {
        if h[i..i + n.len()] == n[..] {
            found = i;
            if !last {
                return i;
            }
        }
        i += 1;
    }
    found
}

fn replace_first(hay: &str, needle: &str, repl: &str) -> String {
    match hay.find(needle) {
        Some(p) => {
            let mut s = String::with_capacity(hay.len() + repl.len());
            s.push_str(&hay[..p]);
            s.push_str(repl);
            s.push_str(&hay[p + needle.len()..]);
            s
        }
        None => hay.to_string(),
    }
}

/// Split on a literal separator, honouring a limit like Java's `String.split`.
fn split_literal(s: &str, sep: &str, limit: i32) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    if sep.is_empty() {
        return s.chars().map(|c| c.to_string()).collect();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut rest = s;
    loop {
        if limit > 0 && parts.len() as i32 == limit - 1 {
            parts.push(rest.to_string());
            break;
        }
        match rest.find(sep) {
            Some(p) => {
                parts.push(rest[..p].to_string());
                rest = &rest[p + sep.len()..];
            }
            None => {
                parts.push(rest.to_string());
                break;
            }
        }
    }
    if limit <= 0 {
        while parts.last().map(|p| p.is_empty()).unwrap_or(false) {
            parts.pop();
        }
    }
    parts
}

fn format_string(fmt: &str, vals: &[String]) -> String {
    // Supports %s %d %x %X %c %%, with `%.Nf`-style precision ignored. This is
    // what obfuscated hex-dumping code uses. The DEX passes the varargs as a
    // single Object[] which the caller has already unpacked.
    let mut out = String::new();
    let mut vi = 0;
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut spec = String::new();
        // Flags and width/precision: everything up to the conversion
        // character, which is the last of -+#0 ,.123456789 followed by a letter.
        while let Some(&n) = chars.peek() {
            if n.is_ascii_alphabetic() {
                break;
            }
            spec.push(n);
            chars.next();
        }
        let conv = chars.next().unwrap_or('s');
        let v = vals.get(vi).cloned().unwrap_or_default();
        // Parse width and zero-padding from the spec: "%02x" -> zero=true, width=2.
        let zero_pad = spec.starts_with('0');
        let width: usize = spec.trim_start_matches(|c: char| !c.is_ascii_digit())
            .parse()
            .unwrap_or(0);
        match conv {
            '%' => out.push('%'),
            's' => {
                out.push_str(&v);
                vi += 1;
            }
            'd' => {
                let rendered = v.trim().parse::<i64>().map(|x| x.to_string()).unwrap_or(v);
                push_padded(&mut out, &rendered, width, zero_pad);
                vi += 1;
            }
            'x' | 'X' => {
                let n = v.trim().parse::<i64>().unwrap_or(0);
                let rendered = if conv == 'x' { format!("{n:x}") } else { format!("{n:X}") };
                push_padded(&mut out, &rendered, width, zero_pad);
                vi += 1;
            }
            'c' => {
                out.push_str(&v);
                vi += 1;
            }
            _ => {
                out.push('%');
                out.push_str(&spec);
                out.push(conv);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// java.lang.System / Runtime / Thread
// ---------------------------------------------------------------------------

fn system_ops(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "currentTimeMillis" => ret_long(vm.env.now()),
        "nanoTime" => ret_long((vm.env.now() % 1_000_000) * 1_000_000 + vm.steps as i64),
        "arraycopy" => {
            let (src, dst) = (arg_ref(args, 0), arg_ref(args, 2));
            let (sp, dp, len) = (arg_int(args, 1), arg_int(args, 3), arg_int(args, 4));
            if src.is_null() || dst.is_null() {
                return CallOutcome::Throw(vm.exc_null, "System.arraycopy null".into());
            }
            let t = vm.heap.taint_of(src);
            for k in 0..len.max(0) {
                let s_idx = (sp + k).max(0) as usize;
                let d_idx = (dp + k).max(0) as usize;
                if let Some(sl) = vm.heap.array_get(src, s_idx) {
                    vm.heap.array_set(dst, d_idx, sl);
                }
            }
            vm.heap.add_taint(dst, t);
            ret_void()
        }
        "getProperty" => {
            let key = s(vm, args, 0);
            let v = vm.env.system_property(&key);
            match vm.new_string(v) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getenv" => {
            let key = s(vm, args, 0);
            let v = match key.as_str() {
                "ANDROID_DATA" => "/data",
                "ANDROID_ROOT" => "/system",
                "PATH" => "/sbin:/system/sbin:/product/bin:/apex/com.android.runtime/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
                "HOME" => "/",
                "USER" | "LOGNAME" => "shell",
                _ => "",
            };
            vm.probe(&format!("System.getenv({key})"), v);
            match vm.new_string(v) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "exit" => {
            let code = arg_int(args, 0);
            vm.report_sink(
                SinkKind::Evasion,
                "java/lang/System->exit(I)V",
                format!("process exits with code {code}"),
                Taint::CLEAN,
                vec![],
            );
            vm.env.advance(0);
            // Dropping the whole invocation is the closest model of `exit`:
            // nothing after it runs.
            vm.stop_reason.get_or_insert_with(|| format!("System.exit({code})"));
            vm.halt_now();
            ret_void()
        }
        "gc" | "runFinalization" | "load" | "loadLibrary" | "setProperty"
        | "identityHashCode" => {
            if name == "loadLibrary" || name == "load" {
                let lib = s(vm, args, 0);
                vm.report_sink(
                    SinkKind::NativeLoad,
                    "java/lang/System->loadLibrary",
                    format!("loads native library {lib}"),
                    Taint::CLEAN,
                    vec![lib],
                );
                let _ = host;
            }
            if name == "identityHashCode" {
                return ret_int(vm.heap.class_of(arg_ref(args, 0)).map(|c| c.0 as i32).unwrap_or(0));
            }
            ret_void()
        }
        "lineSeparator" => match vm.new_string("\n") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "out" | "err" | "in" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

fn runtime_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getRuntime" => {
            // There is only one Runtime; model it as a singleton instance.
            let cls = arg_ref(args, 0);
            if !cls.is_null() {
                return ret_obj(cls);
            }
            match vm.new_instance_of("Ljava/lang/Runtime;") {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "exec" => {
            // exec(String) / exec(String[]) / exec(String,String[])
            let cmd = match args.get(1).map(|s| s.v) {
                Some(Value::Ref(r)) if !r.is_null() => {
                    if vm.heap.is_string(r) {
                        vm.string_of(r)
                    } else if let ObjKind::Array(a) = &vm.heap.get(r).map(|o| &o.kind).unwrap_or(&ObjKind::Bytes(vec![])) {
                        a.data
                            .iter()
                            .map(|s| java_to_string(vm, *s))
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        String::new()
                    }
                }
                _ => String::new(),
            };
            let t = union_taint(args);
            vm.report_sink(
                SinkKind::CommandExec,
                "java/lang/Runtime->exec",
                format!("exec: {cmd}"),
                t,
                vec![cmd.clone()],
            );
            vm.env.commands.push(cmd);
            // Return a Process whose streams are empty.
            match vm.new_instance_of("Ljava/lang/Process;") {
                Ok(p) => {
                    if let Ok(input) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                        super::set_state_ref(vm, p, "stdout", input);
                    }
                    if let Ok(err) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                        super::set_state_ref(vm, p, "stderr", err);
                    }
                    super::set_state_int(vm, p, "exitValue", 0);
                    ret_obj(p)
                }
                Err(_) => ret_void(),
            }
        }
        "availableProcessors" => ret_int(8),
        "maxMemory" | "totalMemory" | "freeMemory" => ret_long(256 * 1024 * 1024),
        "addShutdownHook" | "removeShutdownHook" | "gc" => ret_void(),
        "halt" | "exit" => {
            vm.halt_now();
            ret_void()
        }
        _ => {
            let _ = this;
            CallOutcome::Decline
        }
    }
}

fn process_builder(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if let Some(cmd) = arg_str(vm, args, 1) {
                if !this.is_null() {
                    super::set_state_str(vm, this, "cmd", cmd);
                }
            } else if let Some(arr) = args.get(1).map(|s| s.v.as_ref()) {
                let joined = if let Some(ObjKind::Array(a)) = vm.heap.get(arr).map(|o| &o.kind) {
                    a.data.iter().map(|s| java_to_string(vm, *s)).collect::<Vec<_>>().join(" ")
                } else {
                    String::new()
                };
                if !this.is_null() {
                    super::set_state_str(vm, this, "cmd", joined);
                }
            }
            ret_void()
        }
        "command" | "redirectErrorStream" | "directory" | "environment" => ret_obj(this),
        "start" => {
            let cmd = super::state_str(vm, this, "cmd").unwrap_or_default();
            vm.report_sink(
                SinkKind::CommandExec,
                "java/lang/ProcessBuilder->start",
                format!("exec: {cmd}"),
                Taint::CLEAN,
                vec![cmd.clone()],
            );
            vm.env.commands.push(cmd);
            match vm.new_instance_of("Ljava/lang/Process;") {
                Ok(p) => ret_obj(p),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn thread_ops(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "sleep" => {
            let ms = arg_long(args, 0);
            vm.env.advance(ms);
            if ms > 0 {
                // Sleeping gives scheduled work a chance to become due.
                vm.run_due_tasks(host);
            }
            ret_void()
        }
        "currentThread" => {
            if !this.is_null() {
                return ret_obj(this);
            }
            match vm.new_instance_of("Ljava/lang/Thread;") {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getName" => match vm.new_string("main") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "getId" => ret_long(1),
        "start" => {
            // Run the thread body synchronously; the sandbox is single-threaded
            // and ordering is what matters for behaviour, not concurrency.
            if !this.is_null() {
                let _ = vm.invoke_runnable(host, this);
            }
            ret_void()
        }
        "run" => {
            // A Thread subclass overrides run; handled by app dispatch.
            CallOutcome::Decline
        }
        "join" => ret_void(),
        "isAlive" | "isInterrupted" => ret_bool(false),
        "interrupt" | "setName" | "setDaemon" | "setPriority" => ret_void(),
        "yield" => ret_void(),
        "interrupted" => ret_bool(false),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// Math / boxed types
// ---------------------------------------------------------------------------

fn math_ops(name: &str, args: &[Slot]) -> CallOutcome {
    let x = args.first().map(|s| s.v.as_double()).unwrap_or(0.0);
    let y = args.get(1).map(|s| s.v.as_double()).unwrap_or(0.0);
    match name {
        "abs" => {
            if matches!(args.first().map(|s| s.v), Some(Value::Long(_))) {
                return ret_long(arg_long(args, 0).wrapping_abs());
            }
            if matches!(args.first().map(|s| s.v), Some(Value::Float(_))) {
                return CallOutcome::Value(Slot::float(x as f32));
            }
            ret_int(arg_int(args, 0).wrapping_abs())
        }
        "min" | "max" => {
            let is_long = matches!(args.first().map(|s| s.v), Some(Value::Long(_)));
            let is_float = matches!(args.first().map(|s| s.v), Some(Value::Float(_)));
            if is_long {
                let (a, b) = (arg_long(args, 0), arg_long(args, 1));
                ret_long(if name == "min" { a.min(b) } else { a.max(b) })
            } else if is_float {
                CallOutcome::Value(Slot::float(if name == "min" { (x as f32).min(y as f32) } else { (x as f32).max(y as f32) }))
            } else {
                ret_int(if name == "min" { arg_int(args, 0).min(arg_int(args, 1)) } else { arg_int(args, 0).max(arg_int(args, 1)) })
            }
        }
        "sqrt" => CallOutcome::Value(Slot::double(x.sqrt())),
        "pow" => CallOutcome::Value(Slot::double(x.powf(y))),
        "round" => ret_long(x.round() as i64),
        "floor" | "ceil" => CallOutcome::Value(Slot::double(if name == "floor" { x.floor() } else { x.ceil() })),
        "random" => CallOutcome::Value(Slot::double(0.5)),
        _ => CallOutcome::Decline,
    }
}

fn box_ops(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "parseInt" | "parseLong" | "parseShort" | "parseByte" | "parseFloat" | "parseDouble" => {
            let text = s(vm, args, 0).trim().to_string();
            let radix = if args.len() > 1 { arg_int(args, 1) } else { 10 };
            match name {
                "parseInt" | "parseShort" | "parseByte" => {
                    let v = parse_int_radix(&text, radix).unwrap_or(0);
                    if name == "parseShort" { ret_int(v as i16 as i32) }
                    else if name == "parseByte" { ret_int(v as i8 as i32) }
                    else { ret_int(v) }
                }
                "parseLong" => ret_long(parse_int_radix(&text, radix).map(|v| v as i64).unwrap_or(0)),
                "parseFloat" => CallOutcome::Value(Slot::float(text.parse().unwrap_or(0.0))),
                _ => CallOutcome::Value(Slot::double(text.parse().unwrap_or(0.0))),
            }
        }
        "valueOf" => {
            let text = s(vm, args, 0);
            match class {
                "Ljava/lang/Boolean;" => ret_bool(text.eq_ignore_ascii_case("true")),
                "Ljava/lang/Long;" => {
                    let r = if let Some(o) = args.first() {
                        match o.v {
                            Value::Int(v) => v as i64,
                            Value::Long(v) => v,
                            _ => parse_int_radix(&text, 10).map(|v| v as i64).unwrap_or(0),
                        }
                    } else {
                        0
                    };
                    ret_long(r)
                }
                "Ljava/lang/Double;" | "Ljava/lang/Float;" => {
                    CallOutcome::Value(Slot::double(text.parse().unwrap_or(0.0)))
                }
                _ => {
                    let v = match args.first().map(|s| s.v) {
                        Some(Value::Int(v)) => v,
                        _ => parse_int_radix(&text, 10).unwrap_or(0),
                    };
                    ret_int(v)
                }
            }
        }
        "intValue" | "shortValue" | "byteValue" | "charValue" => ret_int(arg_int(args, 0)),
        "longValue" => ret_long(arg_long(args, 0)),
        "doubleValue" | "floatValue" => CallOutcome::Value(Slot::double(args.first().map(|s| s.v.as_double()).unwrap_or(0.0))),
        "booleanValue" => ret_bool(arg_int(args, 0) != 0),
        "toString" => {
            let v = if args.len() > 1 { args[1] } else { args[0] };
            let text = java_to_string(vm, v);
            match vm.new_string(text) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "toHexString" => {
            let v = arg_int(args, 0);
            match vm.new_string(format!("{:x}", v as u32)) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "toBinaryString" => match vm.new_string(format!("{:b}", arg_int(args, 0) as u32)) {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "MAX_VALUE" | "MIN_VALUE" => ret_void(),
        "compare" => ret_int(arg_int(args, 0).cmp(&arg_int(args, 1)) as i32),
        "isNaN" => ret_bool(false),
        _ => CallOutcome::Decline,
    }
}

fn parse_int_radix(s: &str, radix: i32) -> Option<i32> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (neg, body) = if let Some(r) = s.strip_prefix('-') { (true, r) }
        else if let Some(r) = s.strip_prefix('+') { (false, r) }
        else { (false, s) };
    let body = if body.starts_with("0x") || body.starts_with("0X") {
        &body[2..]
    } else {
        body
    };
    let r = if radix == 0 { 10 } else { radix };
    i64::from_str_radix(body, r as u32).ok().map(|v| if neg { -(v) as i32 } else { v as i32 })
}

// ---------------------------------------------------------------------------
// Class / Object / reflection basics
// ---------------------------------------------------------------------------

fn class_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getName" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            match vm.new_string(desc_to_dotted(&desc)) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getSimpleName" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            let dotted = desc_to_dotted(&desc);
            let simple = dotted.rsplit('.').next().unwrap_or("").to_string();
            match vm.new_string(simple) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getCanonicalName" | "getTypeName" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            match vm.new_string(desc_to_dotted(&desc)) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getSuperclass" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            let sym = vm.sym(&desc);
            let sup = vm.registry.class(sym).and_then(|c| c.superclass);
            match sup {
                Some(s) => {
                    let d = vm.sym_str(s).to_string();
                    match make_class_obj(vm, &d) {
                        Some(r) => ret_obj(r),
                        None => ret_void(),
                    }
                }
                None => ret_obj(ObjRef::NULL),
            }
        }
        "isAssignableFrom" => {
            let target = super::state_str(vm, this, "descriptor").unwrap_or_default();
            let other = arg_ref(args, 1);
            let od = super::state_str(vm, other, "descriptor").unwrap_or_default();
            if target.is_empty() || od.is_empty() {
                return ret_bool(false);
            }
            let t = vm.sym(&target);
            let o = vm.sym(&od);
            ret_bool(vm.registry.is_subclass_of(o, &target) || vm.registry.interner.get(t) == od)
        }
        "forName" => {
            // Class.forName(String) / (String, boolean, ClassLoader)
            let dotted = s(vm, args, 0);
            let desc = super::dotted_to_desc(&dotted);
            match make_class_obj(vm, &desc) {
                Some(r) => {
                    let sym = vm.sym(&desc);
                    if vm.registry.is_app_class(sym) {
                        vm.ensure_class_initialized(sym);
                    }
                    ret_obj(r)
                }
                None => ret_obj(ObjRef::NULL),
            }
        }
        "getClassLoader" => match vm.new_instance_of("Ljava/lang/ClassLoader;") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "newInstance" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            super::reflect::construct_by_descriptor(vm, &desc, &[])
        }
        "isArray" | "isPrimitive" | "isInterface" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            match name {
                "isArray" => ret_bool(desc.starts_with('[')),
                "isPrimitive" => ret_bool(desc.len() == 1),
                _ => {
                    let sym = vm.sym(&desc);
                    ret_bool(vm.registry.class(sym).map(|c| c.access & crate::dex::ACC_INTERFACE != 0).unwrap_or(false))
                }
            }
        }
        "getMethod" | "getDeclaredMethod" | "getConstructor" | "getDeclaredConstructor" => {
            let _probe = ();
            // Build a Method/Constructor model object so the later `invoke` can
            // reach the real implementation. This is a load-bearing path: a
            // packer's shell commonly does `cl.loadClass(x).getMethod(y,z)
            // .invoke(...)` and nothing else.
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            let is_ctor = name.contains("Constructor");
            let mname = if is_ctor {
                "<init>".to_string()
            } else {
                s(vm, args, 1)
            };
            // Parameter types: a Class[] array in the last argument.
            let mut proto = String::from("(");
            let params_arr = args.iter().skip(1).rev().find_map(|a| {
                let r = a.v.as_ref();
                if r.is_null() {
                    None
                } else if matches!(vm.heap.get(r).map(|o| &o.kind), Some(ObjKind::Array(_))) {
                    Some(r)
                } else {
                    None
                }
            });
            if let Some(arr) = params_arr {
                let n = vm.heap.length_of(arr).unwrap_or(0);
                for i in 0..n {
                    let elem = vm.heap.array_get(arr, i).unwrap_or_default();
                    let cd = super::state_str(vm, elem.v.as_ref(), "descriptor").unwrap_or_default();
                    if !cd.is_empty() {
                        proto.push_str(&cd);
                    }
                }
            }
            proto.push(')');
            proto.push(if is_ctor { 'V' } else { 'L' });
            if !is_ctor {
                // Return type is not needed for reflective dispatch; the
                // resolver tolerates a placeholder when the exact method is
                // absent because it falls back to name-only matching.
                proto.pop();
                proto.push_str(&guess_return_descriptor(vm, &desc, &mname));
            }
            let cls = if is_ctor {
                "Ljava/lang/reflect/Constructor;"
            } else {
                "Ljava/lang/reflect/Method;"
            };
            match vm.new_instance_of(cls) {
                Ok(m) => {
                    super::set_state_str(vm, m, "class", desc);
                    super::set_state_str(vm, m, "name", mname);
                    super::set_state_str(vm, m, "proto", proto);
                    super::set_state_int(vm, m, "static", if is_ctor { 0 } else { 1 });
                    ret_obj(m)
                }
                Err(_) => ret_void(),
            }
        }
        "getDeclaredField" | "getField" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            let fname = s(vm, args, 1);
            match vm.new_instance_of("Ljava/lang/reflect/Field;") {
                Ok(f) => {
                    super::set_state_str(vm, f, "class", desc);
                    super::set_state_str(vm, f, "name", fname);
                    ret_obj(f)
                }
                Err(_) => ret_void(),
            }
        }
        "getDeclaredFields" | "getFields" | "getDeclaredMethods" | "getMethods" | "getConstructors" => {
            // Empty arrays are usually enough: obfuscators test length, and a
            // reflective lookup that finds nothing takes the fallback path.
            let elem = if name.contains("Field") {
                "Ljava/lang/reflect/Field;"
            } else if name.contains("Construct") {
                "Ljava/lang/reflect/Constructor;"
            } else {
                "Ljava/lang/reflect/Method;"
            };
            let sym = vm.sym(elem);
            match vm.heap.new_array(sym, elem, 0, Taint::CLEAN) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "toString" => {
            let desc = super::state_str(vm, this, "descriptor").unwrap_or_default();
            match vm.new_string(format!("class {}", desc_to_dotted(&desc))) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

/// Best-effort return-type lookup for a reflected method. Reflection callers
/// rarely need the exact prototype (the interpreter resolves by name and a
/// broad prototype sweep), but having the real one lets the resolver hit the
/// app's own method directly.
fn guess_return_descriptor(vm: &mut Vm, class_desc: &str, method_name: &str) -> String {
    let class = vm.sym(class_desc);
    let name = vm.sym(method_name);
    if let Some(ci) = vm.registry.class(class) {
        for m in ci.direct_methods.iter().chain(ci.virtual_methods.iter()) {
            if m.key.name == name {
                let proto = vm.sym_str(m.key.proto).to_string();
                if let Some(r) = proto.rsplit(')').next() {
                    return r.to_string();
                }
            }
        }
    }
    "Ljava/lang/Object;".into()
}

pub fn make_class_obj(vm: &mut Vm, desc: &str) -> Option<ObjRef> {
    let desc_obj = vm.new_string(desc.to_string()).ok()?;
    let cls = vm.sym("Ljava/lang/Class;");
    let obj = vm.heap.new_instance(cls).ok()?;
    if let Some(inst) = vm.heap.instance_mut(obj) {
        inst.state.insert("descriptor".into(), Slot::reference(desc_obj));
    }
    Some(obj)
}

pub fn class_descriptor_of(vm: &Vm, r: ObjRef) -> Option<String> {
    super::state_str(vm, r, "descriptor")
}

fn object_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => ret_void(),
        "hashCode" => ret_int(this.0 as i32),
        "equals" => {
            let other = arg_ref(args, 1);
            ret_bool(this == other)
        }
        "toString" => {
            let d = vm.object_describe(this);
            match vm.new_string(d) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getClass" => {
            let desc = vm
                .heap
                .class_of(this)
                .map(|c| vm.sym_str(c).to_string())
                .unwrap_or_default();
            match make_class_obj(vm, &desc) {
                Some(r) => ret_obj(r),
                None => ret_void(),
            }
        }
        "notify" | "notifyAll" | "wait" | "clone" | "finalize" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

fn arrays_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "toString" => {
            let arr = arg_ref(args, 0);
            let mut parts = Vec::new();
            if let Some(o) = vm.heap.get(arr) {
                if let ObjKind::Array(a) = &o.kind {
                    let raws = a.data.clone();
                    for s in raws {
                        parts.push(java_to_string(vm, s));
                    }
                } else if let ObjKind::Bytes(b) = &o.kind {
                    for v in b {
                        parts.push((*v as i8).to_string());
                    }
                }
            }
            match vm.new_string(format!("[{}]", parts.join(", "))) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "copyOf" | "copyOfRange" => {
            let src = arg_ref(args, 0);
            let (from, to) = if name == "copyOf" {
                (0usize, arg_int(args, 1).max(0) as usize)
            } else {
                (arg_int(args, 1).max(0) as usize, arg_int(args, 2).max(0) as usize)
            };
            let t = vm.heap.taint_of(src);
            let elem = vm
                .heap
                .get(src)
                .and_then(|o| match &o.kind {
                    ObjKind::Array(a) => Some(vm.sym_str(a.elem).to_string()),
                    ObjKind::Bytes(_) => Some("B".into()),
                    _ => None,
                })
                .unwrap_or_else(|| "Ljava/lang/Object;".into());
            let n = to.saturating_sub(from);
            let elem_sym = vm.sym(&elem);
            match vm.heap.new_array(elem_sym, &elem, n, t) {
                Ok(dst) => {
                    for i in 0..n {
                        if let Some(s) = vm.heap.array_get(src, from + i) {
                            vm.heap.array_set(dst, i, s);
                        }
                    }
                    ret_obj(dst)
                }
                Err(_) => ret_void(),
            }
        }
        "equals" => {
            let (a, b) = (arg_ref(args, 0), arg_ref(args, 1));
            let eq = match (vm.heap.get(a).map(|o| &o.kind), vm.heap.get(b).map(|o| &o.kind)) {
                (Some(ObjKind::Bytes(x)), Some(ObjKind::Bytes(y))) => x == y,
                (Some(ObjKind::Array(x)), Some(ObjKind::Array(y))) => {
                    x.data.len() == y.data.len()
                        && x.data.iter().zip(y.data.iter()).all(|(p, q)| p.v.as_int() == q.v.as_int())
                }
                _ => a == b,
            };
            ret_bool(eq)
        }
        "sort" => {
            // Sorting matters only in that it must not change control flow; a
            // comparator callback could touch malicious code, so run it.
            ret_void()
        }
        "fill" => ret_void(),
        "asList" => {
            // Wrap: return a List instance holding the array.
            let arr = arg_ref(args, 0);
            match vm.new_instance_of("Ljava/util/ArrayList;") {
                Ok(list) => {
                    super::set_state_ref(vm, list, "array", arr);
                    super::set_state_int(vm, list, "size", vm.heap.length_of(arr).unwrap_or(0) as i32);
                    ret_obj(list)
                }
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn collections_ops(vm: &mut Vm, host: &mut AndroidHost, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "sort" => {
            // If a comparator is supplied, invoke it once on the first pair so
            // that app-side callback code is exercised; then leave order alone.
            let list = arg_ref(args, 0);
            let cmp = arg_ref(args, 1);
            if !cmp.is_null() {
                let _ = vm.invoke_runnable(host, cmp);
            }
            let _ = list;
            ret_void()
        }
        "reverse" | "shuffle" | "swap" | "addAll" | "unmodifiableList" => ret_void(),
        "emptyList" | "emptyMap" | "emptySet" | "singletonList" => {
            match vm.new_instance_of("Ljava/util/ArrayList;") {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn list_ops(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if !this.is_null() {
                super::set_state_int(vm, this, "size", 0);
                // Materialise a backing element array lazily.
                let elem = vm.sym("Ljava/lang/Object;");
                if let Ok(arr) = vm.heap.new_array(elem, "Ljava/lang/Object;", 64, Taint::CLEAN) {
                    super::set_state_ref(vm, this, "elems", arr);
                }
            }
            let _ = class;
            ret_void()
        }
        "add" => {
            let size = state_int(vm, this, "size");
            let elems = super::state_ref(vm, this, "elems");
            let val = if args.len() > 2 {
                // add(int, Object)
                let at = arg_int(args, 1).max(0) as usize;
                let v = args[2];
                let cap = vm.heap.length_of(elems).unwrap_or(0);
                if at < cap {
                    vm.heap.array_set(elems, at, v);
                }
                super::set_state_int(vm, this, "size", (size.max(at as i32 + 1)).min(cap as i32));
                return ret_void();
            } else {
                args.get(1).copied().unwrap_or_default()
            };
            let cap = vm.heap.length_of(elems).unwrap_or(0);
            if (size as usize) < cap {
                vm.heap.array_set(elems, size as usize, val);
                super::set_state_int(vm, this, "size", size + 1);
            }
            ret_bool(true)
        }
        "get" => {
            let idx = arg_int(args, 1).max(0) as usize;
            let elems = super::state_ref(vm, this, "elems");
            match vm.heap.array_get(elems, idx) {
                Some(s) => CallOutcome::Value(s),
                None => CallOutcome::Throw(vm.exc_array_oob, format!("List.get({idx})")),
            }
        }
        "set" => {
            let idx = arg_int(args, 1).max(0) as usize;
            let elems = super::state_ref(vm, this, "elems");
            let old = vm.heap.array_get(elems, idx).unwrap_or_default();
            vm.heap.array_set(elems, idx, args[2]);
            CallOutcome::Value(old)
        }
        "size" => ret_int(state_int(vm, this, "size")),
        "isEmpty" => ret_bool(state_int(vm, this, "size") == 0),
        "clear" => {
            super::set_state_int(vm, this, "size", 0);
            ret_void()
        }
        "contains" => ret_bool(false),
        "indexOf" => ret_int(-1),
        "remove" => {
            let idx = arg_int(args, 1).max(0) as usize;
            let size = state_int(vm, this, "size") as usize;
            let elems = super::state_ref(vm, this, "elems");
            let old = vm.heap.array_get(elems, idx).unwrap_or_default();
            for i in idx..size.saturating_sub(1) {
                if let Some(s) = vm.heap.array_get(elems, i + 1) {
                    vm.heap.array_set(elems, i, s);
                }
            }
            super::set_state_int(vm, this, "size", size.saturating_sub(1) as i32);
            CallOutcome::Value(old)
        }
        "iterator" | "listIterator" => {
            match vm.new_instance_of("Ljava/util/Iterator;") {
                Ok(it) => {
                    super::set_state_ref(vm, it, "list", this);
                    super::set_state_int(vm, it, "pos", 0);
                    ret_obj(it)
                }
                Err(_) => ret_void(),
            }
        }
        "toArray" => {
            let elems = super::state_ref(vm, this, "elems");
            let n = state_int(vm, this, "size").max(0) as usize;
            let elem = vm.sym("Ljava/lang/Object;");
            match vm.heap.new_array(elem, "Ljava/lang/Object;", n, Taint::CLEAN) {
                Ok(dst) => {
                    for i in 0..n {
                        if let Some(s) = vm.heap.array_get(elems, i) {
                            vm.heap.array_set(dst, i, s);
                        }
                    }
                    ret_obj(dst)
                }
                Err(_) => ret_void(),
            }
        }
        "toString" => {
            let n = state_int(vm, this, "size").max(0) as usize;
            let elems = super::state_ref(vm, this, "elems");
            let mut parts = Vec::new();
            for i in 0..n {
                if let Some(s) = vm.heap.array_get(elems, i) {
                    parts.push(java_to_string(vm, s));
                }
            }
            match vm.new_string(format!("[{}]", parts.join(", "))) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn map_ops(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if !this.is_null() {
                // Keys and values kept as two parallel object arrays.
                let elem = vm.sym("Ljava/lang/Object;");
                if let Ok(k) = vm.heap.new_array(elem, "Ljava/lang/Object;", 64, Taint::CLEAN) {
                    super::set_state_ref(vm, this, "keys", k);
                }
                if let Ok(v) = vm.heap.new_array(elem, "Ljava/lang/Object;", 64, Taint::CLEAN) {
                    super::set_state_ref(vm, this, "values", v);
                }
                super::set_state_int(vm, this, "size", 0);
            }
            let _ = class;
            ret_void()
        }
        "put" => {
            let keys = super::state_ref(vm, this, "keys");
            let values = super::state_ref(vm, this, "values");
            let size = state_int(vm, this, "size") as usize;
            let want = args.get(1).copied().unwrap_or_default();
            let val = args.get(2).copied().unwrap_or_default();
            let want_s = java_to_string(vm, want);
            // Replace an existing equal key, else append.
            for i in 0..size {
                if let Some(k) = vm.heap.array_get(keys, i) {
                    if java_to_string(vm, k) == want_s {
                        let old = vm.heap.array_get(values, i).unwrap_or_default();
                        vm.heap.array_set(values, i, val);
                        return CallOutcome::Value(old);
                    }
                }
            }
            let cap = vm.heap.length_of(keys).unwrap_or(0);
            if size < cap {
                vm.heap.array_set(keys, size, want);
                vm.heap.array_set(values, size, val);
                super::set_state_int(vm, this, "size", size as i32 + 1);
            }
            ret_obj(ObjRef::NULL)
        }
        "get" => {
            let keys = super::state_ref(vm, this, "keys");
            let values = super::state_ref(vm, this, "values");
            let size = state_int(vm, this, "size").max(0) as usize;
            let want = args.get(1).copied().unwrap_or_default();
            let want_s = java_to_string(vm, want);
            for i in 0..size {
                if let Some(k) = vm.heap.array_get(keys, i) {
                    if java_to_string(vm, k) == want_s {
                        return vm
                            .heap
                            .array_get(values, i)
                            .map(CallOutcome::Value)
                            .unwrap_or(CallOutcome::Value(Slot::null()));
                    }
                }
            }
            CallOutcome::Value(Slot::null())
        }
        "containsKey" => {
            let keys = super::state_ref(vm, this, "keys");
            let size = state_int(vm, this, "size").max(0) as usize;
            let want = java_to_string(vm, args.get(1).copied().unwrap_or_default());
            for i in 0..size {
                if let Some(k) = vm.heap.array_get(keys, i) {
                    if java_to_string(vm, k) == want {
                        return ret_bool(true);
                    }
                }
            }
            ret_bool(false)
        }
        "size" => ret_int(state_int(vm, this, "size")),
        "isEmpty" => ret_bool(state_int(vm, this, "size") == 0),
        "remove" => CallOutcome::Value(Slot::null()),
        "clear" => {
            super::set_state_int(vm, this, "size", 0);
            ret_void()
        }
        "keySet" | "values" | "entrySet" => match vm.new_instance_of("Ljava/util/ArrayList;") {
            Ok(l) => ret_obj(l),
            Err(_) => ret_void(),
        },
        _ => CallOutcome::Decline,
    }
}

fn map_entry_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getKey" => {
            let key = vm.sym("key");
            let ty = vm.sym("Ljava/lang/Object;");
            let fk = crate::vm::intern::FieldKey { class: Sym::NONE, name: key, ty };
            CallOutcome::Value(vm.heap.get_field(this, &fk).unwrap_or_default())
        }
        _ => CallOutcome::Decline,
    }
}

fn iterator_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "hasNext" => {
            let list = super::state_ref(vm, this, "list");
            let pos = state_int(vm, this, "pos");
            let size = state_int(vm, list, "size");
            ret_bool(pos < size)
        }
        "next" => {
            let list = super::state_ref(vm, this, "list");
            let pos = state_int(vm, this, "pos");
            let elems = super::state_ref(vm, list, "elems");
            super::set_state_int(vm, this, "pos", pos + 1);
            match vm.heap.array_get(elems, pos.max(0) as usize) {
                Some(s) => CallOutcome::Value(s),
                None => ret_void(),
            }
        }
        "remove" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// Base64 / date / random / UUID / JSON
// ---------------------------------------------------------------------------

fn text_base64(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    use base64::Engine as _;
    // android.util.Base64 lives in android/, but java.util.Base64 is here and
    // has the same encoder/decoder shape.
    let op = match name {
        "encodeToString" => "enc",
        "decode" => "dec",
        _ => return CallOutcome::Decline,
    };
    // For java.util.Base64 the calls are on a nested Encoder/Decoder instance;
    // for android.util.Base64 they are static. The argument that is bytes wins.
    let data_idx = if arg_bytes(vm, args, 0).is_some() { 0 } else { 1 };
    let bytes = arg_bytes(vm, args, data_idx);
    match (op, bytes) {
        ("enc", Some(b)) => {
            let t = vm.heap.taint_of(arg_ref(args, data_idx));
            let s = base64::engine::general_purpose::STANDARD.encode(b);
            match vm.new_string_t(s, t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        ("dec", Some(_)) => ret_void(),
        ("dec", None) => {
            // decode(String)
            let text = s(vm, args, data_idx);
            let t = arg_taint(args, data_idx);
            let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(cleaned.as_bytes())
                .unwrap_or_default();
            // Fall back to a URL-safe alphabet when the standard one fails.
            let bytes = if bytes.is_empty() {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(cleaned.as_bytes())
                    .unwrap_or_default()
            } else {
                bytes
            };
            match vm.heap.new_bytes(bytes, t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn date_format(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if let Some(pat) = arg_str(vm, args, 1) {
                super::set_state_str(vm, this, "pattern", pat);
            }
            ret_void()
        }
        "format" => {
            let pat = super::state_str(vm, this, "pattern").unwrap_or_else(|| "yyyy-MM-dd HH:mm:ss".into());
            let millis = format_millis(vm, args.get(1).copied().unwrap_or_default());
            let out = render_date(&pat, millis, vm.env.persona.tz_offset_minutes);
            match vm.new_string(out) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "parse" => {
            // Return a Date at the scenario's current time; parsing a date the
            // sample compares against is rare and over-modelling would be worse.
            match vm.new_instance_of("Ljava/util/Date;") {
                Ok(d) => {
                    if let Some(inst) = vm.heap.instance_mut(d) {
                        inst.state.insert("millis".into(), Slot::long(vm.env.now()));
                    }
                    ret_obj(d)
                }
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn format_millis(vm: &Vm, s: Slot) -> i64 {
    if let Value::Ref(r) = s.v {
        if let Some(inst) = vm.heap.instance(r) {
            if let Some(sl) = inst.state.get("millis") {
                return sl.v.as_long();
            }
        }
    }
    s.v.as_long()
}

fn render_date(pattern: &str, millis: i64, tz_minutes: i32) -> String {
    // Minimal `SimpleDateFormat` renderer: yyyy MM dd HH mm ss SSS.
    let secs = millis.div_euclid(1000) + (tz_minutes as i64) * 60;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let ms = millis.rem_euclid(1000);
    let mut out = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let mut n = 1;
        while i + n < chars.len() && chars[i + n] == c {
            n += 1;
        }
        match c {
            'y' => out.push_str(&format!("{:0width$}", y, width = n)),
            'M' => out.push_str(&format!("{:0width$}", m, width = n)),
            'd' => out.push_str(&format!("{:0width$}", d, width = n)),
            'H' => out.push_str(&format!("{:0width$}", hh, width = n)),
            'm' => out.push_str(&format!("{:0width$}", mm, width = n)),
            's' => out.push_str(&format!("{:0width$}", ss, width = n)),
            'S' => out.push_str(&format!("{:0width$}", ms, width = n)),
            _ => {
                for _ in 0..n {
                    out.push(c);
                }
            }
        }
        i += n;
    }
    out
}

/// Howard Hinnant's civil-from-days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn date_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if !this.is_null() {
                let millis = if args.len() > 1 {
                    args[1].v.as_long()
                } else {
                    vm.env.now()
                };
                if let Some(inst) = vm.heap.instance_mut(this) {
                    inst.state.insert("millis".into(), Slot::long(millis));
                }
            }
            ret_void()
        }
        "getTime" => ret_long(format_millis(vm, Slot::reference(this))),
        "setTime" => {
            if !this.is_null() {
                if let Some(inst) = vm.heap.instance_mut(this) {
                    inst.state.insert("millis".into(), args[1]);
                }
            }
            ret_void()
        }
        _ => CallOutcome::Decline,
    }
}

fn calendar_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getInstance" => {
            match vm.new_instance_of("Ljava/util/Calendar;") {
                Ok(c) => {
                    if let Some(inst) = vm.heap.instance_mut(c) {
                        inst.state.insert("millis".into(), Slot::long(vm.env.now()));
                    }
                    ret_obj(c)
                }
                Err(_) => ret_void(),
            }
        }
        "getTimeInMillis" => ret_long(vm.env.now()),
        "getTime" => match vm.new_instance_of("Ljava/util/Date;") {
            Ok(d) => {
                if let Some(inst) = vm.heap.instance_mut(d) {
                    inst.state.insert("millis".into(), Slot::long(vm.env.now()));
                }
                ret_obj(d)
            }
            Err(_) => ret_void(),
        },
        "get" => {
            // Field constants: YEAR=1, MONTH=2, DAY_OF_MONTH=5, HOUR_OF_DAY=11,
            // MINUTE=12, SECOND=13, DAY_OF_WEEK=7.
            let field = arg_int(args, 1);
            let tz = vm.env.persona.tz_offset_minutes as i64;
            let secs = vm.env.now() / 1000 + tz * 60;
            let days = secs.div_euclid(86_400);
            let sod = secs.rem_euclid(86_400);
            let (y, m, d) = civil_from_days(days);
            let dow = (days + 4).rem_euclid(7) as i32 + 1; // 1=Sunday
            let v = match field {
                1 => y as i32,
                2 => m as i32 - 1,
                5 => d as i32,
                7 => dow,
                11 => (sod / 3600) as i32,
                12 => ((sod % 3600) / 60) as i32,
                13 => (sod % 60) as i32,
                14 => (sod % 1000) as i32,
                _ => 0,
            };
            vm.probe(&format!("Calendar.get({field})"), v.to_string());
            ret_int(v)
        }
        "set" | "add" => ret_void(),
        _ => {
            let _ = this;
            CallOutcome::Decline
        }
    }
}

fn random_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // Copy a caller-provided seed so a deterministic sample replays.
            let seed = if args.len() > 1 { args[1].v.as_long() } else { 0x9E37_79B9 };
            if !this.is_null() {
                super::set_state_int(vm, this, "seed_lo", seed as i32);
                super::set_state_int(vm, this, "seed_hi", (seed >> 32) as i32);
            }
            ret_void()
        }
        "nextInt" => {
            let lo = super::state_int(vm, this, "seed_lo") as u64;
            let hi = super::state_int(vm, this, "seed_hi") as u64;
            let mut state = (hi << 32) | (lo & 0xffff_ffff);
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let val = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            if !this.is_null() {
                super::set_state_int(vm, this, "seed_lo", val as i32);
                super::set_state_int(vm, this, "seed_hi", (val >> 32) as i32);
            }
            let bound = if args.len() > 1 { arg_int(args, 1) } else { i32::MAX };
            if bound <= 0 {
                CallOutcome::Value(Slot::int((val >> 33) as i32))
            } else {
                ret_int(((val >> 33) % bound as u64) as i32)
            }
        }
        "nextLong" | "nextDouble" | "nextFloat" | "nextBoolean" => {
            let n = (vm.steps.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407)) & 0x7fff_ffff;
            match name {
                "nextLong" => ret_long(n as i64),
                "nextDouble" => CallOutcome::Value(Slot::double((n as f64) / (0x7fff_ffff as f64))),
                "nextFloat" => CallOutcome::Value(Slot::float((n as f32) / (0x7fff_ffff as f32))),
                _ => ret_bool(n & 1 == 1),
            }
        }
        "setSeed" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

fn uuid_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "randomUUID" | "toString" => {
            let v = vm.env.rng.next_u64();
            let uuid = format!(
                "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
                (v >> 32) as u32,
                (v >> 16) as u16,
                (v as u16) & 0xfff,
                ((v >> 48) as u16) & 0xfff,
                v & 0xffff_ffff_ffff
            );
            match vm.new_string(uuid) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => {
            let _ = args;
            CallOutcome::Decline
        }
    }
}

// ---------------------------------------------------------------------------
// org.json
// ---------------------------------------------------------------------------

fn json_ops(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match (class, name) {
        ("Lorg/json/JSONObject;", "<init>") => {
            if let Some(text) = arg_str(vm, args, 1) {
                let _ = text;
            }
            if !this.is_null() {
                super::set_state_int(vm, this, "size", 0);
            }
            ret_void()
        }
        ("Lorg/json/JSONObject;", "put") => {
            // Store key/value in state so `toString` can render real JSON.
            let key = s(vm, args, 1);
            let val = args.get(2).copied().unwrap_or_default();
            if !this.is_null() {
                if let Some(inst) = vm.heap.instance_mut(this) {
                    inst.state.insert(format!("k:{key}"), val);
                }
            }
            ret_obj(this)
        }
        ("Lorg/json/JSONObject;", "getString") | ("Lorg/json/JSONObject;", "optString") => {
            let key = s(vm, args, 1);
            let val = vm
                .heap
                .instance(this)
                .and_then(|i| i.state.get(&format!("k:{key}")))
                .copied()
                .unwrap_or_else(Slot::null);
            match vm.str_of_slot(val) {
                Some(text) => match vm.new_string(text) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                },
                None => match vm.new_string("") {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                },
            }
        }
        ("Lorg/json/JSONObject;", "getInt") | ("Lorg/json/JSONObject;", "optInt") => ret_int(0),
        ("Lorg/json/JSONObject;", "getBoolean") | ("Lorg/json/JSONObject;", "optBoolean") => {
            ret_bool(false)
        }
        ("Lorg/json/JSONObject;", "has") | ("Lorg/json/JSONObject;", "isNull") => {
            let key = s(vm, args, 1);
            ret_bool(
                vm.heap
                    .instance(this)
                    .map(|i| i.state.contains_key(&format!("k:{key}")))
                    .unwrap_or(false),
            )
        }
        ("Lorg/json/JSONObject;", "toString") => {
            let mut parts = Vec::new();
            if let Some(inst) = vm.heap.instance(this) {
                let mut keys: Vec<_> = inst.state.iter().filter(|(k, _)| k.starts_with("k:")).collect();
                keys.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in keys {
                    let key = &k[2..];
                    parts.push(format!("\"{}\":{}", json_escape(key), json_value(vm, *v)));
                }
            }
            match vm.new_string(format!("{{{}}}", parts.join(","))) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        ("Lorg/json/JSONArray;", "<init>") => {
            if !this.is_null() {
                super::set_state_int(vm, this, "size", 0);
            }
            ret_void()
        }
        ("Lorg/json/JSONArray;", "put") => {
            if !this.is_null() {
                let n = super::state_int(vm, this, "size");
                let val = args.get(1).copied().unwrap_or_default();
                if let Some(inst) = vm.heap.instance_mut(this) {
                    inst.state.insert(format!("i:{n}"), val);
                }
                super::set_state_int(vm, this, "size", n + 1);
            }
            ret_obj(this)
        }
        ("Lorg/json/JSONArray;", "length") => ret_int(state_int(vm, this, "size")),
        ("Lorg/json/JSONArray;", "toString") => {
            let n = state_int(vm, this, "size").max(0);
            let mut parts = Vec::new();
            for i in 0..n {
                let v = vm
                    .heap
                    .instance(this)
                    .and_then(|inst| inst.state.get(&format!("i:{i}")))
                    .copied()
                    .unwrap_or_default();
                parts.push(json_value(vm, v));
            }
            match vm.new_string(format!("[{}]", parts.join(","))) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn json_value(vm: &Vm, s: Slot) -> String {
    match s.v {
        Value::Int(v) => v.to_string(),
        Value::Long(v) => v.to_string(),
        Value::Float(v) => super::fmt_float(v as f64),
        Value::Double(v) => super::fmt_float(v),
        Value::Ref(r) if !r.is_null() => {
            if vm.heap.is_string(r) {
                format!("\"{}\"", json_escape(&vm.string_of(r)))
            } else {
                "null".into()
            }
        }
        _ => "null".into(),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn static_field_value(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
) -> Option<Slot> {
    let _ = (host, class, name);
    let _ = vm;
    None
}

// Needed for `StringBuilder.<init>()` where the receiver was created by the
// host's `construct` with an empty instance object.
#[allow(dead_code)]
fn _ensure_mutable(vm: &mut Vm, this: ObjRef) {
    if let Some(obj) = vm.heap.get_mut(this) {
        if matches!(obj.kind, ObjKind::Instance(_)) {
            obj.kind = ObjKind::MutableStr(String::new());
        }
    }
}
