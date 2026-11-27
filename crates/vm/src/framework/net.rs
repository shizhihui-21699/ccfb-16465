//! Network model: `HttpURLConnection`, Apache HttpClient and OkHttp.
//!
//! Default policy is record-only. Exfiltration is the point of most of these
//! samples, so the *attempt* is what matters for the report; whether the bytes
//! physically left is a deployment decision (`allow_egress`) and is never
//! required to produce a finding.

use super::{obs, CallResult, Level};
use crate::heap::{Object, ObjectValue};
use crate::interp::state::Machine;
use crate::value::{Provenance, Tag, Value};

impl Machine {
    pub(crate) fn net_api(&mut self, class: &str, name: &str, args: &[Value]) -> CallResult {
        match (class, name) {
            ("java/net/URL", "<init>") => {
                // `new-instance` already allocated an Object::Instance for the
                // receiver; replace it in place with the URL model so later
                // calls find the url field on the object the sample holds.
                let url = self.arg_str(args, 1).unwrap_or_default();
                if let Some(this) = self.arg_obj(args, 0) {
                    if let Some(obj) = self.heap.get_mut(this) {
                        *obj = Object::Model {
                            class: "Ljava/net/URL;".into(),
                            fields: [("url".to_string(), ObjectValue::Str(url))]
                                .into_iter()
                                .collect(),
                            prov: Provenance::default(),
                        };
                    }
                }
                CallResult::void()
            }
            ("java/net/URL", "openConnection") | ("java/net/URL", "openStream") => {
                let url = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                self.new_conn(url)
            }
            ("java/net/HttpURLConnection", "getURL") | ("java/net/URLConnection", "getURL") => {
                let url = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                CallResult::obj(self.new_url(url))
            }
            ("java/net/URL", "toString")
            | ("java/net/URL", "getHost")
            | ("java/net/URL", "getPath") => {
                let url = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                CallResult::obj(self.new_string(url, Provenance::constant()))
            }
            ("java/net/HttpURLConnection", "setRequestMethod") => {
                if let (Some(this), Some(m)) = (self.arg_obj(args, 0), self.arg_str(args, 1)) {
                    self.set_model_field(this, "method", ObjectValue::Str(m));
                }
                CallResult::void()
            }
            ("java/net/HttpURLConnection", "setRequestProperty_never")
            | ("java/net/HttpURLConnection", "setRequestProperty")
            | ("java/net/HttpURLConnection", "addRequestProperty")
            | ("java/net/HttpURLConnection", "setDoOutput")
            | ("java/net/HttpURLConnection", "setConnectTimeout")
            | ("java/net/HttpURLConnection", "setReadTimeout") => {
                if name == "setRequestProperty" {
                    if let Some(this) = self.arg_obj(args, 0) {
                        let k = self.arg_str(args, 1).unwrap_or_default();
                        let v = self.arg_str(args, 2).unwrap_or_default();
                        let field = format!("hdr:{k}");
                        self.set_model_field(this, &field, ObjectValue::Str(v));
                    }
                }
                CallResult::void()
            }
            ("java/net/HttpURLConnection", "getOutputStream") => {
                let this = self.arg_obj(args, 0);
                let v = match self.new_model_default("Ljava/io/OutputStream;") {
                    Value::Obj(id) => {
                        if let Some(t) = this {
                            self.set_model_field(id, "conn", ObjectValue::Int(t as i64));
                        }
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            ("java/net/HttpURLConnection", "getInputStream")
            | ("java/net/HttpURLConnection", "getErrorStream") => {
                let this = self.arg_obj(args, 0);
                let body = self.env.net.default_response.clone();
                let v = match self.new_model_default("Ljava/io/InputStream;") {
                    Value::Obj(id) => {
                        if let Some(t) = this {
                            self.set_model_field(id, "conn", ObjectValue::Int(t as i64));
                        }
                        self.set_model_field(id, "buf", ObjectValue::Bytes(body));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            ("java/net/HttpURLConnection", "getResponseCode") => {
                CallResult::int(self.env.net.default_status)
            }
            ("java/net/HttpURLConnection", "disconnect")
            | ("java/net/HttpURLConnection", "connect") => CallResult::void(),
            ("java/net/HttpURLConnection", "setFollowRedirects") => CallResult::void(),
            // Apache HttpClient
            ("org/apache/http/impl/client/DefaultHttpClient", "<init>") => CallResult::void(),
            ("org/apache/http/impl/client/DefaultHttpClient", "execute") => {
                // execute(HttpUriRequest) — the request model carries the URL.
                let req = self.arg_obj(args, 1);
                let url = req
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                let body = req
                    .and_then(|id| match self.model_field(id, "body") {
                        Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let prov = req
                    .and_then(|id| self.heap.get(id).and_then(|o| o.prov()).cloned())
                    .unwrap_or_default();
                self.record_egress("HTTP", &url, &body, &prov);
                CallResult::obj(self.new_model_default("Lorg/apache/http/HttpResponse;"))
            }
            ("org/apache/http/impl/client/DefaultHttpClient$1", _) => CallResult::void(),
            // OkHttp
            ("okhttp3/Request$Builder", "url") => {
                let url = self.arg_str(args, 1).unwrap_or_default();
                if let Some(this) = self.arg_obj(args, 0) {
                    self.set_model_field(this, "url", ObjectValue::Str(url));
                }
                CallResult::obj(args.first().copied().unwrap_or(Value::NULL))
            }
            ("okhttp3/Request$Builder", "post")
            | ("okhttp3/Request$Builder", "put")
            | ("okhttp3/Request$Builder", "method") => {
                let body = self.arg_obj(args, 2).or_else(|| self.arg_obj(args, 1));
                let data = body
                    .and_then(|id| match self.model_field(id, "body") {
                        Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                if let (Some(this), Some(body_id)) = (self.arg_obj(args, 0), body) {
                    self.set_model_field(this, "body", ObjectValue::Bytes(data));
                    self.set_model_field(this, "body_ref", ObjectValue::Int(body_id as i64));
                }
                CallResult::obj(args.first().copied().unwrap_or(Value::NULL))
            }
            ("okhttp3/Request$Builder", "build") => {
                let url = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                let body = self
                    .arg_obj(args, 0)
                    .and_then(|id| match self.model_field(id, "body") {
                        Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let v = match self.new_model_default("Lokhttp3/Request;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "url", ObjectValue::Str(url));
                        self.set_model_field(id, "body", ObjectValue::Bytes(body));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            ("okhttp3/OkHttpClient", "newCall") => {
                let req = self.arg_obj(args, 1);
                let url = req
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                let body = req
                    .and_then(|id| match self.model_field(id, "body") {
                        Some(ObjectValue::Bytes(b)) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let prov = req
                    .and_then(|id| self.heap.get(id).and_then(|o| o.prov()).cloned())
                    .unwrap_or_default();
                self.record_egress("OkHttp", &url, &body, &prov);
                let v = match self.new_model_default("Lokhttp3/Call;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "url", ObjectValue::Str(url));
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            ("okhttp3/Call", "execute") | ("okhttp3/Call", "enqueue") => {
                let url = self
                    .arg_obj(args, 0)
                    .and_then(|id| self.model_string(id, "url"))
                    .unwrap_or_default();
                let v = match self.new_model_default("Lokhttp3/Response;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "url", ObjectValue::Str(url));
                        self.set_model_field(
                            id,
                            "code",
                            ObjectValue::Int(self.env.net.default_status as i64),
                        );
                        Value::obj(id)
                    }
                    v => v,
                };
                CallResult::obj(v)
            }
            ("okhttp3/Response", "body") => {
                CallResult::obj(self.new_model_default("Lokhttp3/ResponseBody;"))
            }
            ("okhttp3/ResponseBody", "string") | ("okhttp3/ResponseBody", "bytes") => {
                let body = self.env.net.default_response.clone();
                CallResult::obj(self.new_bytes(body, Provenance::of(Tag::Network)))
            }
            ("okhttp3/Response", "isSuccessful") => CallResult::int(1),
            ("okhttp3/RequestBody", "create") => {
                let body = self
                    .arg_bytes(args, args.len().saturating_sub(1))
                    .unwrap_or_default();
                let prov = self.arg_prov(args, args.len().saturating_sub(1));
                let v = match self.new_model_default("Lokhttp3/RequestBody;") {
                    Value::Obj(id) => {
                        self.set_model_field(id, "body", ObjectValue::Bytes(body));
                        Value::obj(id)
                    }
                    v => v,
                };
                if let Some(Value::Obj(id)) = Some(v) {
                    if let Some(Object::Model { prov: p, .. }) = self.heap.get_mut(id) {
                        p.merge(&prov);
                    }
                }
                CallResult::obj(v)
            }
            ("okhttp3/MediaType", "parse") => {
                CallResult::obj(self.new_model_default("Lokhttp3/MediaType;"))
            }
            _ => {
                let _ = args;
                CallResult::void()
            }
        }
    }

    fn new_conn(&mut self, url: String) -> CallResult {
        let v = match self.new_model_default("Ljava/net/HttpURLConnection;") {
            Value::Obj(id) => {
                self.set_model_field(id, "url", ObjectValue::Str(url));
                Value::obj(id)
            }
            v => v,
        };
        CallResult::obj(v)
    }

    fn new_url(&mut self, url: String) -> Value {
        match self.heap.alloc(Object::Model {
            class: "Ljava/net/URL;".into(),
            fields: [("url".to_string(), ObjectValue::Str(url))]
                .into_iter()
                .collect(),
            prov: Provenance::default(),
        }) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }

    /// Record an egress attempt with everything the analyst needs to pivot.
    pub fn record_egress(&mut self, method: &str, url: &str, body: &[u8], prov: &Provenance) {
        use crate::env::RecordedRequest;
        let caller = self.current_method_display();
        let headers = vec![(
            "User-Agent".to_string(),
            "Dalvik/2.1.0 (Linux; U; Android 13)".to_string(),
        )];
        self.env.net.requests.push(RecordedRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers,
            body: body.to_vec(),
            caller: caller.clone(),
            body_provenance: prov.label(),
        });
        let mut o = obs(
            Level::Critical,
            "egress",
            format!(
                "{method} {url} body={} bytes{}",
                body.len(),
                if body.is_empty() {
                    String::new()
                } else {
                    format!(
                        " {:?}",
                        String::from_utf8_lossy(&body[..body.len().min(96)])
                    )
                }
            ),
        );
        o.prov = Some(prov.clone());
        o.target = Some(url.to_string());
        // The egress event itself is emitted by the caller through `record_call`
        // when it returns; here we only accumulate.
        let _ = o;
    }
}
