//! `java.io`, `java.nio`, `java.util.zip` and jar/apk reading.
//!
//! File I/O reads and writes the scenario's in-memory filesystem. Stream reads
//! are taint-sources: a sample that decrypts a payload into a file and later
//! reads it back must not lose the label.

use crate::report::SinkKind;
use crate::vm::android::state::TaintSource;
use crate::vm::android::{
    arg_bytes, arg_int, arg_long, arg_ref, arg_str, arg_taint, ret_bool, ret_int, ret_long, ret_obj, ret_void,
    set_state_int, set_state_ref, state_int, state_ref, state_str,
};
use crate::vm::heap::ObjKind;
use crate::vm::intern::MethodKey;
use crate::vm::interp::{CallOutcome, Vm};
use crate::vm::value::{ObjRef, Slot, Taint, Value};

use super::AndroidHost;

pub fn dispatch(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    key: &MethodKey,
    args: &[Slot],
) -> CallOutcome {
    let _ = host;
    match class {
        "Ljava/io/File;" => return file_ops(vm, name, args),
        "Ljava/io/FileInputStream;" | "Ljava/io/RandomAccessFile;" => return file_input(vm, name, args),
        "Ljava/io/FileOutputStream;" | "Ljava/io/FileWriter;" | "Ljava/io/PrintWriter;" => {
            return file_output(vm, name, args);
        }
        "Ljava/io/FileReader;" => return file_input(vm, name, args),
        "Ljava/io/ByteArrayInputStream;" => return byte_input(vm, name, args),
        "Ljava/io/ByteArrayOutputStream;" => return byte_output(vm, name, args),
        "Ljava/io/BufferedInputStream;" | "Ljava/io/BufferedOutputStream;"
        | "Ljava/io/DataInputStream;" | "Ljava/io/DataOutputStream;"
        | "Ljava/io/ObjectInputStream;" | "Ljava/io/ObjectOutputStream;"
        | "Ljava/io/InputStreamReader;" | "Ljava/io/OutputStreamWriter;"
        | "Ljava/io/BufferedReader;" | "Ljava/io/BufferedWriter;" | "Ljava/io/PrintStream;"
        | "Ljava/io/FilterInputStream;" | "Ljava/io/FilterOutputStream;" => {
            return wrapper_stream(vm, name, args);
        }
        "Ljava/io/InputStream;" | "Ljava/io/OutputStream;" | "Ljava/io/Reader;" | "Ljava/io/Writer;"
        | "Ljava/io/Closeable;" | "Ljava/io/Flushable;" | "Ljava/lang/AutoCloseable;"
        | "Ljava/io/Serializable;" => return stream_base(vm, name, args),
        "Ljava/io/FileNotFoundException;" | "Ljava/io/IOException;" => return CallOutcome::Decline,
        "Ljava/nio/charset/Charset;" => return match name {
            "forName" => match vm.new_instance_of("Ljava/nio/charset/Charset;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            },
            "defaultCharset" => match vm.new_instance_of("Ljava/nio/charset/Charset;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            },
            _ => CallOutcome::Decline,
        },
        _ if class.starts_with("Ljava/util/zip/") => return zip_ops(vm, class, name, args),
        _ if class.starts_with("Ljava/util/jar/") => return zip_ops(vm, class, name, args),
        _ => {}
    }
    let _ = key;
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// java.io.File
// ---------------------------------------------------------------------------

fn new_file_obj(vm: &mut Vm, path: String) -> CallOutcome {
    match vm.new_instance_of("Ljava/io/File;") {
        Ok(o) => {
            if let Ok(p) = vm.new_string(path) {
                set_state_ref(vm, o, "path", p);
            }
            ret_obj(o)
        }
        Err(_) => ret_void(),
    }
}

fn file_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // (String path) / (String parent, String child) / (File, String)
            let path = if args.len() >= 3 {
                let parent = if let Some(p) = arg_str(vm, args, 1) {
                    p
                } else {
                    let pp = arg_ref(args, 1);
                    state_str(vm, pp, "path").unwrap_or_default()
                };
                let child = arg_str(vm, args, 2).unwrap_or_default();
                if parent.is_empty() {
                    child
                } else {
                    format!("{}/{}", parent.trim_end_matches('/'), child)
                }
            } else {
                arg_str(vm, args, 1).unwrap_or_default()
            };
            set_state_str_into(vm, this, "path", path.clone());
            let t = arg_taint(args, 1);
            if !t.is_clean() {
                vm.heap.add_taint(this, t);
            }
            ret_void()
        }
        "getPath" | "getAbsolutePath" | "getCanonicalPath" => ret_obj(state_ref(vm, this, "path")),
        "getName" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            let n = p.rsplit('/').next().unwrap_or("").to_string();
            string_obj(vm, n)
        }
        "getParent" | "getParentFile" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            match p.rfind('/') {
                Some(i) => new_file_obj(vm, p[..i].to_string()),
                None => ret_obj(ObjRef::NULL),
            }
        }
        "getAbsoluteFile" | "getCanonicalFile" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            new_file_obj(vm, p)
        }
        "exists" | "isFile" | "canRead" | "canWrite" | "isDirectory" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            let exists = vm.env.file_exists(&p);
            match name {
                "exists" => ret_bool(exists),
                "isFile" => ret_bool(exists),
                "canRead" => ret_bool(exists),
                "canWrite" => ret_bool(true),
                _ => ret_bool(false),
            }
        }
        "length" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            ret_long(vm.env.read_file(&p).map(|b| b.len() as i64).unwrap_or(0))
        }
        "lastModified" => ret_long(vm.env.now()),
        "delete" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            vm.env.files.remove(&p);
            ret_bool(true)
        }
        "mkdir" | "mkdirs" | "createNewFile" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            if !vm.env.file_exists(&p) {
                vm.env.write_file(p, Vec::new());
            }
            ret_bool(true)
        }
        "list" | "listFiles" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            let prefix = format!("{}/", p.trim_end_matches('/'));
            let names: Vec<String> = vm
                .env
                .files
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .map(|k| k.rsplit('/').next().unwrap_or("").to_string())
                .collect();
            if name == "list" {
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
            } else {
                let elem = vm.sym("Ljava/io/File;");
                match vm.heap.new_array(elem, "Ljava/io/File;", names.len(), Taint::CLEAN) {
                    Ok(arr) => {
                        for (i, n) in names.into_iter().enumerate() {
                            if let Ok(f) = vm.new_instance_of("Ljava/io/File;") {
                                if let Ok(rp) = vm.new_string(format!("{prefix}{n}")) {
                                    set_state_ref(vm, f, "path", rp);
                                }
                                vm.heap.array_set(arr, i, Slot::reference(f));
                            }
                        }
                        ret_obj(arr)
                    }
                    Err(_) => ret_void(),
                }
            }
        }
        "toString" => {
            let p = state_str(vm, this, "path").unwrap_or_default();
            string_obj(vm, p)
        }
        "renameTo" => ret_bool(true),
        "setReadable" | "setWritable" | "setExecutable" | "setLastModified" => ret_bool(true),
        "getUsableSpace" | "getFreeSpace" | "getTotalSpace" => ret_long(4_000_000_000),
        _ => CallOutcome::Decline,
    }
}

fn string_obj(vm: &mut Vm, s: String) -> CallOutcome {
    match vm.new_string(s) {
        Ok(r) => ret_obj(r),
        Err(_) => ret_void(),
    }
}

fn set_state_str_into(vm: &mut Vm, obj: ObjRef, key: &str, value: String) {
    if let Ok(r) = vm.new_string(value) {
        set_state_ref(vm, obj, key, r);
    }
}

// ---------------------------------------------------------------------------
// Input streams
// ---------------------------------------------------------------------------

/// Resolve the byte buffer a stream reads from.
fn stream_buffer(vm: &Vm, obj: ObjRef) -> ObjRef {
    let buf = state_ref(vm, obj, "buf");
    if !buf.is_null() {
        return buf
    }
    // FileInputStream: lazily read from the environment on first access.
    buf
}

fn stream_read_state(vm: &mut Vm, obj: ObjRef) -> (ObjRef, usize) {
    // Ensure a buffer exists: for file streams, load the file now.
    let mut buf = stream_buffer(vm, obj);
    if buf.is_null() {
        let path = state_str(vm, obj, "path");
        if let Some(p) = path {
            let data = vm.env.read_file(&p).map(|b| b.to_vec()).unwrap_or_default();
            let t = if data.is_empty() {
                Taint::CLEAN
            } else {
                vm.mint_taint(TaintSource::FileContents.label())
            };
            if let Ok(b) = vm.heap.new_bytes(data, t) {
                set_state_ref(vm, obj, "buf", b);
                buf = b;
            }
        }
    }
    let pos = state_int(vm, obj, "pos").max(0) as usize;
    (buf, pos)
}

fn file_input(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            let path = if let Some(s) = arg_str(vm, args, 1) {
                s
            } else {
                let f = arg_ref(args, 1);
                state_str(vm, f, "path").unwrap_or_default()
            };
            if !this.is_null() {
                set_state_str_into(vm, this, "path", path.clone());
                set_state_int(vm, this, "pos", 0);
                // Eager load so `available()` and early reads agree.
                if let Some(data) = vm.env.read_file(&path).map(|b| b.to_vec()) {
                    let t = vm.mint_taint(TaintSource::FileContents.label());
                    if let Ok(b) = vm.heap.new_bytes(data, t) {
                        set_state_ref(vm, this, "buf", b);
                    }
                }
            }
            ret_void()
        }
        "read" => read_impl(vm, this, args),
        "available" => {
            let (buf, pos) = stream_read_state(vm, this);
            let len = vm.heap.length_of(buf).unwrap_or(0);
            ret_int(len.saturating_sub(pos) as i32)
        }
        "skip" => {
            let n = arg_long(args, 1).max(0);
            let pos = state_int(vm, this, "pos");
            set_state_int(vm, this, "pos", (pos as i64 + n) as i32);
            ret_long(n)
        }
        "close" | "mark" | "reset" => ret_void(),
        "getChannel" => match vm.new_instance_of("Ljava/nio/channels/FileChannel;") {
            Ok(o) => {
                set_state_ref(vm, o, "stream", this);
                ret_obj(o)
            }
            Err(_) => ret_void(),
        },
        "seek" => {
            set_state_int(vm, this, "pos", arg_long(args, 1) as i32);
            ret_void()
        }
        "getFilePointer" => ret_long(state_int(vm, this, "pos") as i64),
        _ => CallOutcome::Decline,
    }
}

fn read_impl(vm: &mut Vm, this: ObjRef, args: &[Slot]) -> CallOutcome {
    let (buf, pos) = stream_read_state(vm, this);
    let t = vm.heap.taint_of(buf);
    let Some(bytes) = vm.heap.bytes_of(buf).map(|b| b.to_vec()) else {
        return ret_int(-1);
    };
    match args.len() {
        1 => {
            // read(): one byte or -1
            if pos >= bytes.len() {
                ret_int(-1)
            } else {
                set_state_int(vm, this, "pos", pos as i32 + 1);
                CallOutcome::Value(Slot::int(bytes[pos] as i32).with_taint(t))
            }
        }
        2 => {
            // read(byte[]) -> count, or read(byte[], off, len)
            let dst = arg_ref(args, 1);
            let n = vm.heap.length_of(dst).unwrap_or(0);
            let count = n.min(bytes.len() - pos);
            for i in 0..count {
                vm.heap.array_set(dst, i, Slot::int(bytes[pos + i] as i32));
            }
            vm.heap.add_taint(dst, t);
            set_state_int(vm, this, "pos", (pos + count) as i32);
            if count == 0 { ret_int(-1) } else { ret_int(count as i32) }
        }
        _ => {
            let dst = arg_ref(args, 1);
            let off = arg_int(args, 2).max(0) as usize;
            let len = arg_int(args, 3).max(0) as usize;
            let count = len.min(bytes.len().saturating_sub(pos));
            for i in 0..count {
                vm.heap.array_set(dst, off + i, Slot::int(bytes[pos + i] as i32));
            }
            vm.heap.add_taint(dst, t);
            set_state_int(vm, this, "pos", (pos + count) as i32);
            if count == 0 { ret_int(-1) } else { ret_int(count as i32) }
        }
    }
}

fn byte_input(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // (byte[]) / (byte[], off, len) / ()
            let src = arg_ref(args, 1);
            if !src.is_null() {
                let data = vm.heap.bytes_of(src).map(|b| b.to_vec()).unwrap_or_default();
                let t = vm.heap.taint_of(src);
                if let Ok(b) = vm.heap.new_bytes(data, t) {
                    set_state_ref(vm, this, "buf", b);
                }
            }
            set_state_int(vm, this, "pos", 0);
            ret_void()
        }
        "read" => read_impl(vm, this, args),
        "available" => {
            let (buf, pos) = stream_read_state(vm, this);
            ret_int(vm.heap.length_of(buf).unwrap_or(0).saturating_sub(pos) as i32)
        }
        "close" | "mark" | "reset" | "skip" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// Output streams
// ---------------------------------------------------------------------------

fn file_output(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            let path = if let Some(s) = arg_str(vm, args, 1) {
                s
            } else {
                let f = arg_ref(args, 1);
                state_str(vm, f, "path").unwrap_or_default()
            };
            set_state_str_into(vm, this, "path", path.clone());
            if let Ok(buf) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                set_state_ref(vm, this, "buf", buf);
            }
            if !path.is_empty() {
                vm.env.write_file(path, Vec::new());
            }
            ret_void()
        }
        "write" => write_impl(vm, this, args),
        "print" | "println" | "printf" | "format" => {
            // PrintWriter/PrintStream over a byte buffer: append text.
            let text = if args.len() > 1 {
                super::java_to_string(vm, args[1])
            } else {
                String::new()
            };
            let suffix = if name == "println" { "\n" } else { "" };
            let buf = state_ref(vm, this, "buf");
            let mut data = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
            data.extend_from_slice(text.as_bytes());
            data.extend_from_slice(suffix.as_bytes());
            let t = if args.len() > 1 { args[1].t } else { Taint::CLEAN };
            if let Ok(nb) = vm.heap.new_bytes(data, t) {
                set_state_ref(vm, this, "buf", nb);
            }
            ret_void()
        }
        "flush" => ret_void(),
        "close" => flush_output(vm, this),
        "append" => write_impl(vm, this, &[args[0], args[1]]),
        _ => CallOutcome::Decline,
    }
}

fn flush_output(vm: &mut Vm, this: ObjRef) -> CallOutcome {
    let buf = state_ref(vm, this, "buf");
    let data = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
    let t = vm.heap.taint_of(buf).union(vm.heap.taint_of(this));
    let path = state_str(vm, this, "path").unwrap_or_default();
    if !path.is_empty() {
        // Writing outside the app sandbox is reported.
        if !path.starts_with("/data/user/0/") && !path.starts_with("/data/data/") {
            vm.report_sink(
                SinkKind::FileWrite,
                "java/io/FileOutputStream->close",
                format!("write {} bytes to {path}", data.len()),
                t,
                data_preview(&data),
            );
        }
        vm.env.write_file(path, data);
    }
    ret_void()
}

fn write_impl(vm: &mut Vm, this: ObjRef, args: &[Slot]) -> CallOutcome {
    let buf = state_ref(vm, this, "buf");
    let mut data = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
    let append: Vec<u8> = if let Some(bytes) = arg_bytes(vm, args, 1) {
        // write(byte[]) / write(byte[], off, len)
        let off = arg_int(args, 2).max(0) as usize;
        let len = if args.len() > 3 { arg_int(args, 3).max(0) as usize } else { bytes.len() - off.min(bytes.len()) };
        bytes.get(off..off + len).unwrap_or(&[]).to_vec()
    } else {
        // write(char[]) / write(int b) / write(String)
        match args.get(1).map(|s| s.v) {
            Some(Value::Ref(r)) if !r.is_null() => {
                if let Some(o) = vm.heap.get(r) {
                    match &o.kind {
                        ObjKind::Str(s) => s.as_bytes().to_vec(),
                        ObjKind::Array(a) => a
                            .data
                            .iter()
                            .map(|sl| sl.v.as_int() as u8)
                            .collect(),
                        _ => vec![],
                    }
                } else {
                    vec![]
                }
            }
            Some(Value::Int(b)) => vec![b as u8],
            _ => vec![],
        }
    };
    let t = if args.len() > 1 { args[1].t } else { Taint::CLEAN };
    if data.len() + append.len() > 64 * 1024 * 1024 {
        return CallOutcome::Throw(vm.exc_io, "output buffer too large".into());
    }
    data.extend_from_slice(&append);
    if let Ok(nb) = vm.heap.new_bytes(data, vm.heap.taint_of(buf).union(t)) {
        set_state_ref(vm, this, "buf", nb);
    }
    ret_void()
}

fn byte_output(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            if let Ok(b) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                set_state_ref(vm, this, "buf", b);
            }
            ret_void()
        }
        "write" => write_impl(vm, this, args),
        "writeTo" => {
            let dst = arg_ref(args, 1);
            let buf = state_ref(vm, this, "buf");
            let data = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
            let t = vm.heap.taint_of(buf);
            if !dst.is_null() {
                set_state_ref(vm, dst, "buf", buf);
                vm.heap.add_taint(dst, t);
            }
            let _ = data;
            ret_void()
        }
        "toByteArray" => ret_obj(state_ref(vm, this, "buf")),
        "toString" => {
            let buf = state_ref(vm, this, "buf");
            let data = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
            let t = vm.heap.taint_of(buf);
            match vm.new_string_t(String::from_utf8_lossy(&data).to_string(), t) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "size" => {
            let buf = state_ref(vm, this, "buf");
            ret_int(vm.heap.length_of(buf).unwrap_or(0) as i32)
        }
        "reset" => {
            if let Ok(b) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                set_state_ref(vm, this, "buf", b);
            }
            ret_void()
        }
        "flush" | "close" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

fn wrapper_stream(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // Wrap another stream: share its buffer and path.
            let inner = arg_ref(args, 1);
            if !inner.is_null() {
                if let Some(o) = vm.heap.get(inner) {
                    if matches!(o.kind, ObjKind::Instance(_)) {
                        let buf = state_ref(vm, inner, "buf");
                        if !buf.is_null() {
                            set_state_ref(vm, this, "buf", buf);
                        }
                        let path = state_str(vm, inner, "path");
                        if let Some(p) = path {
                            set_state_str_into(vm, this, "path", p);
                        }
                        let pos = state_int(vm, inner, "pos");
                        set_state_int(vm, this, "pos", pos);
                    }
                }
            }
            ret_void()
        }
        "read" | "readLine" => {
            if name == "readLine" {
                return read_line(vm, this)
            }
            // Forward to the same read path as FileInputStream.
            read_impl(vm, this, args)
        }
        "readFully" | "readInt" | "readLong" | "readUTF" | "readByte" | "readShort" => {
            read_primitive(vm, this, name)
        }
        "write" | "print" | "println" | "writeInt" | "writeLong" | "writeUTF"
        | "writeBytes" | "writeByte" | "writeShort" | "newLine" => write_impl(vm, this, args),
        "flush" | "close" => flush_output(vm, this),
        "available" | "size" => {
            let (buf, pos) = stream_read_state(vm, this);
            ret_int(vm.heap.length_of(buf).unwrap_or(0).saturating_sub(pos) as i32)
        }
        "toByteArray" | "toString" => ret_obj(state_ref(vm, this, "buf")),
        "mark" | "reset" => ret_void(),
        "skip" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

fn read_line(vm: &mut Vm, this: ObjRef) -> CallOutcome {
    let (buf, pos) = stream_read_state(vm, this);
    let t = vm.heap.taint_of(buf);
    let Some(bytes) = vm.heap.bytes_of(buf).map(|b| b.to_vec()) else {
        return ret_obj(ObjRef::NULL)
    };
    if pos >= bytes.len() {
        return ret_obj(ObjRef::NULL)
    }
    let end = bytes[pos..].iter().position(|b| *b == b'\n').map(|p| pos + p).unwrap_or(bytes.len());
    let line = String::from_utf8_lossy(&bytes[pos..end]).trim_end_matches('\r').to_string();
    set_state_int(vm, this, "pos", (end + 1).min(bytes.len()) as i32);
    match vm.new_string_t(line, t) {
        Ok(r) => ret_obj(r),
        Err(_) => ret_void(),
    }
}

fn read_primitive(vm: &mut Vm, this: ObjRef, name: &str) -> CallOutcome {
    let (buf, pos) = stream_read_state(vm, this);
    let t = vm.heap.taint_of(buf);
    let bytes = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
    let width = match name {
        "readByte" => 1,
        "readShort" => 2,
        "readInt" => 4,
        "readLong" => 8,
        "readFully" => 0,
        _ => 4,
    };
    if pos + width > bytes.len() {
        return CallOutcome::Throw(vm.exc_io, "EOF reading primitive".into());
    }
    let mut v: u64 = 0;
    for i in 0..width {
        v = (v << 8) | bytes[pos + i] as u64; // DataInputStream is big-endian
    }
    set_state_int(vm, this, "pos", (pos + width) as i32);
    let slot = match name {
        "readByte" => Slot::int(v as i8 as i32),
        "readShort" => Slot::int(v as i16 as i32),
        "readLong" => Slot::long(v as i64),
        _ => Slot::int(v as i32),
    };
    CallOutcome::Value(slot.with_taint(t))
}

fn stream_base(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "read" => read_impl(vm, this, args),
        "write" => write_impl(vm, this, args),
        "close" | "flush" | "mark" | "reset" => ret_void(),
        _ => CallOutcome::Decline,
    }
}

fn data_preview(data: &[u8]) -> Vec<String> {
    if data.is_empty() {
        return vec![];
    }
    let head = &data[..data.len().min(160)];
    let text = String::from_utf8_lossy(head).to_string();
    let hex: String = head.iter().take(32).map(|b| format!("{b:02x}")).collect();
    vec![format!("bytes={} head=\"{}\" hex={}", data.len(), text.replace(['\n', '\r'], "."), hex)]
}

// ---------------------------------------------------------------------------
// java.util.zip / jar
// ---------------------------------------------------------------------------

fn zip_ops(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    if class.starts_with("Ljava/util/zip/ZipEntry;") {
        return match name {
            "<init>" => {
                if let Some(n) = arg_str(vm, args, 1) {
                    set_state_str_into(vm, this, "name", n);
                }
                ret_void()
            }
            "getName" => ret_obj(state_ref(vm, this, "name")),
            "getSize" => ret_long(1024),
            "getCompressedSize" => ret_long(512),
            "isDirectory" => ret_bool(false),
            "getTime" => ret_long(vm.env.now()),
            _ => ret_void(),
        };
    }
    if class.starts_with("Ljava/util/zip/ZipInputStream;") {
        return match name {
            "<init>" => {
                // Wrap the input stream; entries are read on demand.
                let inner = arg_ref(args, 1);
                if !inner.is_null() {
                    let buf = state_ref(vm, inner, "buf");
                    if !buf.is_null() {
                        set_state_ref(vm, this, "data", buf);
                    }
                }
                set_state_int(vm, this, "entry", -1);
                ret_void()
            }
            "getNextEntry" => ret_obj(ObjRef::NULL),
            "closeEntry" => ret_void(),
            "read" => read_impl(vm, this, args),
            "close" => ret_void(),
            _ => CallOutcome::Decline,
        };
    }
    if class.starts_with("Ljava/util/zip/ZipFile;") || class.starts_with("Ljava/util/jar/JarFile;") {
        return match name {
            "<init>" => {
                // Open a zip from disk (or from an app asset path we serve).
                let path = if let Some(p) = arg_str(vm, args, 1) {
                    p
                } else {
                    let f = arg_ref(args, 1);
                    state_str(vm, f, "path").unwrap_or_default()
                };
                let data = vm.env.read_file(&path).map(|b| b.to_vec()).unwrap_or_default();
                if !data.is_empty() {
                    match zip::ZipArchive::new(std::io::Cursor::new(data)) {
                        Ok(ar) => {
                            let names: Vec<String> = ar.file_names().map(|s| s.to_string()).collect();
                            let elem = vm.sym("Ljava/lang/String;");
                            let arr = vm.heap.new_array(elem, "Ljava/lang/String;", names.len(), Taint::CLEAN).ok();
                            if let Some(arr) = arr {
                                for (i, n) in names.iter().enumerate() {
                                    if let Ok(r) = vm.new_string(n.clone()) {
                                        vm.heap.array_set(arr, i, Slot::reference(r));
                                    }
                                }
                                if let Some(inst) = vm.heap.instance_mut(this) {
                                    inst.state.insert("zipnames".into(), Slot::int(names.len() as i32));
                                    inst.state.insert("names".into(), Slot::reference(arr));
                                }
                            }
                        }
                        Err(_) => vm.env.gap(&format!("ZipFile open failed for {path}")),
                    }
                }
                set_state_str_into(vm, this, "path", path);
                ret_void()
            }
            "entries" => match vm.new_instance_of("Ljava/util/Enumeration;") {
                Ok(e) => {
                    set_state_ref(vm, e, "zip", this);
                    set_state_int(vm, e, "pos", 0);
                    ret_obj(e)
                }
                Err(_) => ret_void(),
            },
            "getEntry" => match vm.new_instance_of("Ljava/util/zip/ZipEntry;") {
                Ok(e) => {
                    let n = arg_str(vm, args, 1).unwrap_or_default();
                    set_state_str_into(vm, e, "name", n);
                    ret_obj(e)
                }
                Err(_) => ret_void(),
            },
            "getInputStream" => match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                Ok(s) => {
                    // Feed the entry's bytes if we can find them.
                    let zip_path = state_str(vm, this, "path").unwrap_or_default();
                    let entry = arg_ref(args, 1);
                    let entry_name = state_str(vm, entry, "name").unwrap_or_default();
                    let bytes = read_zip_entry(vm, &zip_path, &entry_name);
                    if let Ok(b) = vm.heap.new_bytes(bytes, Taint::CLEAN) {
                        set_state_ref(vm, s, "buf", b);
                    }
                    set_state_int(vm, s, "pos", 0);
                    ret_obj(s)
                }
                Err(_) => ret_void(),
            },
            "size" => ret_int(state_int(vm, this, "zipnames")),
            "getName" => ret_obj(state_ref(vm, this, "path")),
            "close" => ret_void(),
            _ => CallOutcome::Decline,
        };
    }
    if class.starts_with("Ljava/util/Enumeration;") {
        return match name {
            "hasMoreElements" => {
                let zip = state_ref(vm, this, "zip");
                let pos = state_int(vm, this, "pos");
                ret_bool(pos < state_int(vm, zip, "zipnames"))
            }
            "nextElement" => {
                let zip = state_ref(vm, this, "zip");
                let pos = state_int(vm, this, "pos");
                let names = state_ref(vm, zip, "names");
                set_state_int(vm, this, "pos", pos + 1);
                let name = vm.heap.array_get(names, pos.max(0) as usize).unwrap_or_default();
                match vm.new_instance_of("Ljava/util/zip/ZipEntry;") {
                    Ok(e) => {
                        set_state_ref(vm, e, "name", name.v.as_ref());
                        ret_obj(e)
                    }
                    Err(_) => ret_void(),
                }
            }
            _ => CallOutcome::Decline,
        };
    }
    if class.starts_with("Ljava/util/zip/ZipOutputStream;") {
        return match name {
            "<init>" | "putNextEntry" | "write" | "closeEntry" | "close" | "flush" => ret_void(),
            _ => CallOutcome::Decline,
        };
    }
    CallOutcome::Decline
}

fn read_zip_entry(vm: &mut Vm, zip_path: &str, entry: &str) -> Vec<u8> {
    let Some(data) = vm.env.read_file(zip_path).map(|b| b.to_vec()) else {
        return Vec::new()
    };
    let Ok(mut ar) = zip::ZipArchive::new(std::io::Cursor::new(data)) else {
        return Vec::new()
    };
    let Ok(mut f) = ar.by_name(entry) else {
        return Vec::new()
    };
    use std::io::Read;
    let mut out = Vec::new();
    let _ = f.read_to_end(&mut out);
    out
}

