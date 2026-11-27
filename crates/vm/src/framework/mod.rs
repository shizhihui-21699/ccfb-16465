//! The framework model: a slice of the Android SDK and the JDK implemented in
//! terms of the sandbox.
//!
//! Every handler returns `(result, observation)`. The observation is what the
//! report consumes: the API name, the concrete arguments the sample passed,
//! the result value, and any provenance that should flow to the result. When
//! `observation` is `None` the call is considered uninteresting and is only
//! recorded in verbose mode.

pub mod android;
pub mod java;
pub mod net;
pub mod statics;

use crate::heap::{Heap, Object, ObjectValue};
use crate::interp::state::Machine;
use crate::value::{Provenance, Tag, Value};
use unhusk_dex::model::MethodRef;

/// What a modeled call produced.
#[derive(Debug, Clone)]
pub struct Observation {
    pub level: Level,
    /// Short category, e.g. "crypto", "telephony", "reflect".
    pub category: &'static str,
    pub result: String,
    /// Provenance to merge into the result object.
    pub prov: Option<Provenance>,
    /// For decoded payloads: the bytes themselves, so the engine can recover
    /// them as DEX.
    pub payload: Option<Vec<u8>>,
    /// For egress: the concrete target.
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Ordinary API traffic (only recorded in verbose mode).
    Routine,
    /// Interesting: device fingerprint, file write, reflection.
    Notable,
    /// Directly malicious capability or evasion.
    Critical,
}

#[derive(Debug, Clone)]
pub struct CallResult {
    pub value: Option<Value>,
    pub obs: Option<Observation>,
}

impl CallResult {
    pub fn void() -> Self {
        Self::new(None, None)
    }

    pub fn int(v: i32) -> Self {
        Self::new(Some(Value::I(v)), None)
    }

    pub fn obj(v: Value) -> Self {
        Self::new(Some(v), None)
    }

    pub fn new(value: Option<Value>, obs: Option<Observation>) -> Self {
        Self { value, obs }
    }
}

/// Helper to build observations.
pub fn obs(level: Level, category: &'static str, result: impl Into<String>) -> Observation {
    Observation {
        level,
        category,
        result: result.into(),
        prov: None,
        payload: None,
        target: None,
    }
}

impl Machine {
    /// Route a model call to the right handler by class.
    pub(crate) fn call_model(
        &mut self,
        mr: &MethodRef,
        args: &[Value],
    ) -> (Option<Value>, Option<Observation>) {
        let class = mr.class.trim_start_matches('L').trim_end_matches(';');
        let r = if class.starts_with("java/")
            || class.starts_with("javax/")
            || class.starts_with("sun/")
            || class.starts_with("org/json/")
            || class.starts_with("org/apache/")
            || class.starts_with("kotlin")
        {
            self.call_java(mr, args)
        } else {
            self.call_android(mr, args)
        };
        (r.value, r.obs)
    }

    pub fn record_call(&mut self, mr: &MethodRef, args: &[Value], o: &Observation) {
        let caller = self.current_method_display();
        self.record_call_from(mr, args, o, caller);
    }

    /// Record an API observation, attributing it to `caller` explicitly. The
    /// explicit form matters for handlers that push a frame (reflection), where
    /// the top of the stack at record time is the callee, not the invoker.
    pub fn record_call_from(
        &mut self,
        mr: &MethodRef,
        args: &[Value],
        o: &Observation,
        caller: String,
    ) {
        use crate::events::{Event, EventKind, Layer};
        let level_ok = self.policy.record_all_apis || o.level != Level::Routine;
        if !level_ok {
            return;
        }
        let display_args: Vec<String> =
            args.iter().take(6).map(|v| self.render_value(*v)).collect();
        let kind = match o.category {
            "egress" => EventKind::Egress,
            "evasion" => EventKind::Evasion,
            "crypto" | "decode" => EventKind::Decode,
            "file" => EventKind::FileOp,
            "exec" => EventKind::Exec,
            "reflect" | "load" => EventKind::DynamicLoad,
            "permission" | "telephony" | "sms" => EventKind::PrivilegedApi,
            _ => EventKind::ApiCall,
        };
        let line = self.frames.last().and_then(|f| {
            self.program
                .method(f.method)
                .code
                .as_ref()
                .and_then(|c| c.line_for(f.pc))
        });
        self.trace.push(Event {
            seq: 0,
            insn: self.budget.instructions,
            kind,
            layer: Layer::Framework,
            caller,
            subject: mr.signature(),
            args: display_args,
            result: Some(o.result.clone()),
            prov: o.prov.clone(),
            line,
        });
        if let Some(bytes) = &o.payload {
            let name = mr.signature();
            self.note_payload(bytes.clone(), &name, o.category);
        }
    }

    // -- helpers available to model handlers ------------------------------

    pub fn arg_str(&self, args: &[Value], i: usize) -> Option<String> {
        let v = args.get(i)?;
        match v {
            Value::Obj(0) => None,
            Value::Obj(id) => self.heap.string_of(*id),
            _ => Some(self.render_value(*v)),
        }
    }

    pub fn arg_bytes(&self, args: &[Value], i: usize) -> Option<Vec<u8>> {
        let id = args.get(i).and_then(|v| v.as_obj())?;
        match self.heap.get(id)? {
            Object::Array { bytes, .. } => Some(bytes.clone()),
            Object::Str { value, .. } => Some(value.as_bytes().to_vec()),
            _ => None,
        }
    }

    pub fn arg_obj(&self, args: &[Value], i: usize) -> Option<u32> {
        args.get(i).and_then(|v| v.as_obj())
    }

    pub fn arg_i32(&self, args: &[Value], i: usize) -> i32 {
        args.get(i).map(|v| v.as_i32()).unwrap_or(0)
    }

    pub fn arg_i64(&self, args: &[Value], i: usize) -> i64 {
        args.get(i).map(|v| v.as_i64()).unwrap_or(0)
    }

    pub fn arg_bool(&self, args: &[Value], i: usize, default: bool) -> bool {
        match args.get(i) {
            Some(v) => v.as_i32() != 0,
            None => default,
        }
    }

    pub fn arg_prov(&self, args: &[Value], i: usize) -> Provenance {
        args.get(i)
            .and_then(|v| v.as_obj())
            .and_then(|id| self.heap.get(id))
            .and_then(|o| o.prov().cloned())
            .unwrap_or_default()
    }

    pub fn new_string(&mut self, s: impl Into<String>, prov: Provenance) -> Value {
        match self.heap.new_string(s, prov) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }

    pub fn new_bytes(&mut self, b: Vec<u8>, prov: Provenance) -> Value {
        match self.heap.new_bytes(b, prov) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }

    pub fn new_model(&mut self, class: impl Into<String>) -> Value {
        match self.heap.new_model(class, Provenance::default()) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }

    pub fn new_model_default(&mut self, class: impl Into<String>) -> Value {
        match self.heap.new_model(class, Provenance::default()) {
            Some(id) => Value::obj(id),
            None => Value::NULL,
        }
    }

    pub fn model_field(&self, id: u32, key: &str) -> Option<&ObjectValue> {
        match self.heap.get(id)? {
            Object::Model { fields, .. } => fields.get(key),
            _ => None,
        }
    }

    pub fn set_model_field(&mut self, id: u32, key: &str, value: ObjectValue) {
        if let Some(Object::Model { fields, .. }) = self.heap.get_mut(id) {
            fields.insert(key.to_string(), value);
        }
    }

    pub fn model_string(&self, id: u32, key: &str) -> Option<String> {
        self.model_field(id, key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    pub fn value_path(&self, v: Option<&Value>) -> Option<String> {
        let v = v?;
        match v {
            Value::Obj(0) => None,
            Value::Obj(id) => match self.heap.get(*id)? {
                Object::Str { value, .. } => Some(value.clone()),
                Object::Model { .. } => self.model_string(*id, "path"),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn derived_prov(&self, args: &[Value], extra: Tag) -> Provenance {
        let mut p = Provenance::default();
        for a in args.iter().take(4) {
            if let Some(id) = a.as_obj() {
                if let Some(op) = self.heap.get(id).and_then(|o| o.prov()) {
                    p.merge(op);
                }
            }
        }
        p.add(extra);
        p
    }
}

pub fn heap_bytes(heap: &Heap, id: u32) -> Option<Vec<u8>> {
    match heap.get(id)? {
        Object::Array { bytes, .. } => Some(bytes.clone()),
        _ => None,
    }
}
