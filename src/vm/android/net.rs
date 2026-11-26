//! Networking model: `java.net` sockets/URLs, OkHttp-shaped traffic and
//! `android.net` HTTP helpers.
//!
//! Nothing leaves the machine. A URL is recorded, matched against the
//! scenario's scripted rules, and a response is fabricated. The request's
//! taint tells the reporter whether harvested device data went into the URL or
//! body — which is the moment an exfiltration finding becomes worth showing.

use crate::report::SinkKind;
use crate::vm::android::{
    arg_int, arg_ref, arg_str, ret_bool, ret_int, ret_obj, ret_void, set_state_int,
    set_state_ref, state_int, state_ref, state_str,
};
use crate::vm::env::RequestRecord;
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
    let _ = (host, key);
    match class {
        "Ljava/net/URL;" => return url_ops(vm, name, args),
        "Ljava/net/HttpURLConnection;" | "Ljavax/net/ssl/HttpsURLConnection;" => {
            return http_conn(vm, name, args)
        }
        "Ljava/net/URLConnection;" => return http_conn(vm, name, args),
        "Ljava/net/Socket;" | "Ljavax/net/ssl/SSLSocket;" => return socket_ops(vm, name, args),
        "Ljava/net/InetAddress;" | "Ljava/net/Inet4Address;" => return inet_ops(vm, name, args),
        "Ljava/net/NetworkInterface;" => return match name {
            "getNetworkInterfaces" => ret_obj(ObjRef::NULL),
            "getHardwareAddress" => match vm.heap.new_bytes(vec![0xa4, 0x50, 0x46, 0x1b, 0x2c, 0x3d], Taint::CLEAN) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            },
            _ => CallOutcome::Decline,
        },
        _ => {}
    }
    if class.starts_with("Lokhttp3/") {
        return okhttp(vm, class, name, args)
    }
    if class.starts_with("Ljava/net/URI;") {
        return match name {
            "<init>" | "create" => match vm.new_instance_of("Ljava/net/URI;") {
                Ok(o) => {
                    if let Some(s) = arg_str(vm, args, 1) {
                        if let Ok(rs) = vm.new_string(s) {
                            set_state_ref(vm, o, "url", rs);
                        }
                    }
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            },
            "toString" | "getPath" | "getHost" => ret_obj(state_ref(vm, arg_ref(args, 0), "url")),
            _ => CallOutcome::Decline,
        };
    }
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

fn url_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // URL(String) / URL(String protocol, String host, int port, String file)
            let url = if args.len() >= 3 {
                let proto = arg_str(vm, args, 1).unwrap_or_default();
                let host = arg_str(vm, args, 2).unwrap_or_default();
                let port = arg_int(args, 3);
                let file = arg_str(vm, args, 4).unwrap_or_default();
                if port > 0 {
                    format!("{proto}://{host}:{port}{file}")
                } else {
                    format!("{proto}://{host}{file}")
                }
            } else {
                arg_str(vm, args, 1).unwrap_or_default()
            };
            let t = if args.len() >= 3 {
                (1..args.len()).fold(Taint::CLEAN, |a, k| a.union(super::eff_taint(vm, args, k)))
            } else {
                super::eff_taint(vm, args, 1)
            };
            if !this.is_null() {
                if let Ok(r) = vm.new_string_t(url.clone(), t) {
                    set_state_ref(vm, this, "url", r);
                }
                vm.heap.add_taint(this, t);
            }
            ret_void()
        }
        "toString" | "toExternalForm" | "getFile" | "getPath" | "getQuery" | "getProtocol"
        | "getHost" | "getAuthority" | "getRef" => ret_obj(state_ref(vm, this, "url")),
        "getPort" => ret_int(-1),
        "openConnection" => {
            let url = state_str(vm, this, "url").unwrap_or_default();
            let t = vm.heap.taint_of(this);
            match vm.new_instance_of("Ljava/net/HttpURLConnection;") {
                Ok(conn) => {
                    if let Ok(r) = vm.new_string_t(url, t) {
                        set_state_ref(vm, conn, "url", r);
                    }
                    set_state_int(vm, conn, "method", 0); // GET
                    vm.heap.add_taint(conn, t);
                    ret_obj(conn)
                }
                Err(_) => ret_void(),
            }
        }
        "openStream" => {
            let url = state_str(vm, this, "url").unwrap_or_default();
            let t = vm.heap.taint_of(this);
            perform_request(vm, "GET", &url, Taint::CLEAN, t, &[], "");
            let (_, body, _) = vm.env.http_response(&url);
            match vm.heap.new_bytes(body.into_bytes(), Taint::CLEAN) {
                Ok(b) => {
                    let s = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                        Ok(o) => o,
                        Err(_) => return ret_void(),
                    };
                    set_state_ref(vm, s, "buf", b);
                    set_state_int(vm, s, "pos", 0);
                    ret_obj(s)
                }
                Err(_) => ret_void(),
            }
        }
        "equals" | "sameFile" => ret_bool(true),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// HttpURLConnection
// ---------------------------------------------------------------------------

fn http_conn(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "setRequestMethod" => {
            let m = arg_str(vm, args, 1).unwrap_or_else(|| "GET".into());
            let code = if m.eq_ignore_ascii_case("POST") {
                1
            } else if m.eq_ignore_ascii_case("PUT") {
                2
            } else {
                0
            };
            set_state_int(vm, this, "method", code);
            ret_void()
        }
        "setRequestProperty" | "addRequestProperty" => {
            let k = arg_str(vm, args, 1).unwrap_or_default();
            let v = arg_str(vm, args, 2).unwrap_or_default();
            let val_obj = vm.new_string(v).unwrap_or(ObjRef::NULL);
            if let Some(inst) = vm.heap.instance_mut(this) {
                inst.state.insert(format!("hdr:{k}"), Slot::reference(val_obj));
            }
            ret_void()
        }
        "setDoOutput" | "setDoInput" | "setUseCaches" | "setConnectTimeout"
        | "setReadTimeout" | "setInstanceFollowRedirects" | "setChunkedStreamingMode"
        | "setFixedLengthStreamingMode" | "setDefaultUseCaches" => {
            if name == "setDoOutput" {
                set_state_int(vm, this, "doOutput", arg_int(args, 1));
            }
            if name == "setConnectTimeout" {
                set_state_int(vm, this, "timeout", arg_int(args, 1));
            }
            ret_void()
        }
        "getOutputStream" => {
            match vm.new_instance_of("Ljava/io/ByteArrayOutputStream;") {
                Ok(s) => {
                    if let Ok(b) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                        set_state_ref(vm, s, "buf", b);
                    }
                    // Remember it so `connect` can read the posted body.
                    set_state_ref(vm, this, "out", s);
                    ret_obj(s)
                }
                Err(_) => ret_void(),
            }
        }
        "getInputStream" | "connect" | "getResponseCode" | "getContent" | "getErrorStream" => {
            let url = state_str(vm, this, "url").unwrap_or_default();
            let t = vm.heap.taint_of(this);
            let method = match state_int(vm, this, "method") {
                1 => "POST",
                2 => "PUT",
                _ => "GET",
            };
            // Body from the output stream, if any.
            let out = state_ref(vm, this, "out");
            let body_bytes = vm.heap.bytes_of(state_ref(vm, out, "buf")).map(|b| b.to_vec()).unwrap_or_default();
            let body_taint = vm.heap.taint_of(state_ref(vm, out, "buf"));
            let body = String::from_utf8_lossy(&body_bytes).to_string();
            let headers = collect_headers(vm, this);
            if vm.env.persona.network.reachable {
                perform_request(vm, method, &url, body_taint, t, &headers, &body);
            }
            vm.set_state_int_on(this, "requested", 1);
            let (status, resp, _ctype) = vm.env.http_response(&url);
            set_state_int(vm, this, "status", status);
            if name == "getResponseCode" {
                return ret_int(status)
            }
            if name == "connect" {
                return ret_void()
            }
            match vm.heap.new_bytes(resp.into_bytes(), Taint::CLEAN) {
                Ok(b) => {
                    let s = match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
                        Ok(o) => o,
                        Err(_) => return ret_void(),
                    };
                    set_state_ref(vm, s, "buf", b);
                    set_state_int(vm, s, "pos", 0);
                    ret_obj(s)
                }
                Err(_) => ret_void(),
            }
        }
        "disconnect" => ret_void(),
        "getResponseMessage" => match vm.new_string("OK") {
            Ok(r) => ret_obj(r),
            Err(_) => ret_void(),
        },
        "getContentLength" | "getContentLengthLong" => ret_int(16),
        "getHeaderField" | "getHeaderFieldKey" | "getContentType" => {
            let h = arg_str(vm, args, 1).unwrap_or_default();
            if h.eq_ignore_ascii_case("content-type") {
                match vm.new_string("text/plain") {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                }
            } else {
                ret_obj(ObjRef::NULL)
            }
        }
        "getURL" => ret_obj(state_ref(vm, this, "url")),
        _ => CallOutcome::Decline,
    }
}

trait SetState {
    fn set_state_int_on(&mut self, obj: ObjRef, key: &str, v: i32);
}
impl SetState for Vm {
    fn set_state_int_on(&mut self, obj: ObjRef, key: &str, v: i32) {
        if !obj.is_null() {
            set_state_int(self, obj, key, v);
        }
    }
}


fn collect_headers(vm: &Vm, conn: ObjRef) -> Vec<(String, String)> {
    let Some(inst) = vm.heap.instance(conn) else { return Vec::new() };
    inst.state
        .iter()
        .filter(|(k, _)| k.starts_with("hdr:"))
        .filter_map(|(k, v)| {
            let name = k[4..].to_string();
            let val = vm.heap.string_of(v.v.as_ref()).map(|s| s.to_string())?;
            Some((name, val))
        })
        .collect()
}

/// Record an outbound request and emit a finding when data flowed into it.
fn perform_request(
    vm: &mut Vm,
    method: &str,
    url: &str,
    body_taint: Taint,
    url_taint: Taint,
    headers: &[(String, String)],
    body: &str,
) {
    let taint = body_taint.union(url_taint);
    vm.env.requests.push(RequestRecord {
        method: method.to_string(),
        url: url.to_string(),
        body: body.to_string(),
        headers: headers.to_vec(),
        at_millis: vm.env.now(),
    });
    let kind = if taint.is_clean() {
        SinkKind::Network
    } else {
        SinkKind::SensitiveFlow
    };
    let mut evidence = vec![format!("{method} {url}")];
    if !body.is_empty() {
        evidence.push(format!("body({}B): {}", body.len(), body.chars().take(240).collect::<String>()));
    }
    for (k, v) in headers.iter().take(6) {
        evidence.push(format!("{k}: {v}"));
    }
    vm.report_sink(
        kind,
        format!("{method} {url}"),
        if body.is_empty() {
            format!("{method} {url}")
        } else {
            format!("{method} {url} body={}B", body.len())
        },
        taint,
        evidence,
    );
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

fn socket_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // Socket(String host, int port) / Socket(InetAddress, int)
            let host = arg_str(vm, args, 1).unwrap_or_else(|| {
                let ia = arg_ref(args, 1);
                state_str(vm, ia, "host").unwrap_or_default()
            });
            let port = arg_int(args, 2);
            if !this.is_null() {
                if let Ok(h) = vm.new_string(format!("{host}:{port}")) {
                    set_state_ref(vm, this, "addr", h);
                }
            }
            vm.report_sink(
                SinkKind::Network,
                "java/net/Socket-><init>",
                format!("connect {host}:{port}"),
                Taint::CLEAN,
                vec![format!("{host}:{port}")],
            );
            ret_void()
        }
        "connect" => {
            let addr = arg_ref(args, 1);
            let a = state_str(vm, addr, "host").or_else(|| state_str(vm, this, "addr")).unwrap_or_default();
            vm.report_sink(
                SinkKind::Network,
                "java/net/Socket->connect",
                format!("connect {a}"),
                Taint::CLEAN,
                vec![a],
            );
            ret_void()
        }
        "getInputStream" => match vm.new_instance_of("Ljava/io/ByteArrayInputStream;") {
            Ok(s) => {
                if let Ok(b) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                    set_state_ref(vm, s, "buf", b);
                }
                ret_obj(s)
            }
            Err(_) => ret_void(),
        },
        "getOutputStream" => match vm.new_instance_of("Ljava/io/ByteArrayOutputStream;") {
            Ok(s) => {
                if let Ok(b) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                    set_state_ref(vm, s, "buf", b);
                }
                ret_obj(s)
            }
            Err(_) => ret_void(),
        },
        "setSoTimeout" | "setTcpNoDelay" | "setKeepAlive" | "close" | "shutdownInput"
        | "shutdownOutput" => ret_void(),
        "isConnected" | "isClosed" => ret_bool(true),
        "getInetAddress" => match vm.new_instance_of("Ljava/net/InetAddress;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        _ => CallOutcome::Decline,
    }
}

fn inet_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getByName" | "getHostAddress" | "getHostName" => {
            if name == "getByName" {
                let h = arg_str(vm, args, 0).unwrap_or_default();
                match vm.new_instance_of("Ljava/net/InetAddress;") {
                    Ok(o) => {
                        if let Ok(r) = vm.new_string(h) {
                            set_state_ref(vm, o, "host", r);
                        }
                        ret_obj(o)
                    }
                    Err(_) => ret_void(),
                }
            } else {
                ret_obj(state_ref(vm, this, "host"))
            }
        }
        "getLocalHost" | "getByAddress" => match vm.new_instance_of("Ljava/net/InetAddress;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "getAllByName" => match vm.new_instance_of("Ljava/net/InetAddress;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        "isReachable" => ret_bool(true),
        _ => CallOutcome::Decline,
    }
}

// ---------------------------------------------------------------------------
// OkHttp-shaped traffic
// ---------------------------------------------------------------------------

fn okhttp(vm: &mut Vm, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    // Class names: okhttp3/OkHttpClient, okhttp3/Request$Builder,
    // okhttp3/RequestBody, okhttp3/Response, okhttp3/Call.
    let this = arg_ref(args, 0);
    match name {
        "newCall" => {
            let req = arg_ref(args, 1);
            match vm.new_instance_of("Lokhttp3/Call;") {
                Ok(call) => {
                    let url = state_str(vm, req, "url").unwrap_or_default();
                    let method = state_str(vm, this, "method").or_else(|| state_str(vm, req, "method")).unwrap_or_else(|| "GET".into());
                    if let Ok(u) = vm.new_string_t(url.clone(), vm.heap.taint_of(req)) {
                        set_state_ref(vm, call, "url", u);
                    }
                    if let Ok(m) = vm.new_string(method) {
                        set_state_ref(vm, call, "method", m);
                    }
                    ret_obj(call)
                }
                Err(_) => ret_void(),
            }
        }
        "execute" | "enqueue" => {
            // The call object carries the URL and request body.
            let url = state_str(vm, this, "url").unwrap_or_default();
            let method = state_str(vm, this, "method").unwrap_or_else(|| "GET".into());
            let body = state_str(vm, this, "body").unwrap_or_default();
            let t = vm.heap.taint_of(this);
            perform_request(vm, &method, &url, t, Taint::CLEAN, &[], &body);
            match vm.new_instance_of("Lokhttp3/Response;") {
                Ok(resp) => {
                    let (status, body, _) = vm.env.http_response(&url);
                    set_state_int(vm, resp, "code", status);
                    if let Ok(b) = vm.new_string(body) {
                        set_state_ref(vm, resp, "body", b);
                    }
                    ret_obj(resp)
                }
                Err(_) => ret_void(),
            }
        }
        "url" | "get" | "post" | "put" | "delete" | "header" | "addHeader" => {
            if matches!(name, "url" | "get" | "post" | "put" | "delete") || name == "addHeader" {
                if let Some(v) = args.get(1) {
                    if vm.heap.is_string(v.v.as_ref()) {
                        let s = vm.string_of(v.v.as_ref());
                        let key = if name == "url" { "url" } else if name == "addHeader" { "header" } else { "body" };
                        if let Ok(r) = vm.new_string_t(s, v.t) {
                            set_state_ref(vm, this, key, r);
                        }
                    }
                    if name == "post" || name == "put" {
                        set_state_str_into(vm, this, "method", name.to_uppercase());
                    }
                }
            }
            ret_obj(this)
        }
        "build" => ret_obj(this),
        "string" | "body" => ret_obj(state_ref(vm, this, "body")),
        "code" | "getStatusCode" => ret_int(state_int(vm, this, "code")),
        "isSuccessful" => ret_bool(state_int(vm, this, "code") < 400),
        "create" | "newBuilder" => ret_obj(this),
        "parse" => match vm.new_instance_of("Ljava/net/URI;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        _ => {
            let _ = class;
            // Unknown okhttp3 family call: return the receiver so fluent chains
            // keep working, and count it as a coverage gap upstream.
            if matches!(args.first().map(|s| s.v), Some(Value::Ref(r)) if !r.is_null()) {
                CallOutcome::Decline
            } else {
                CallOutcome::Value(Slot::reference(ObjRef::NULL))
            }
        }
    }
}

fn set_state_str_into(vm: &mut Vm, obj: ObjRef, key: &str, value: String) {
    if let Ok(r) = vm.new_string(value) {
        set_state_ref(vm, obj, key, r);
    }
}

