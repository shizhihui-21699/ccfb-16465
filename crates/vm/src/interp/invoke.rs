//! Method invocation: resolving a `method_id`, deciding whether the callee is
//! sample code or modeled framework code, and delivering the result.

use crate::interp::program::MethodHandle;
use crate::interp::state::Machine;
use crate::limits::StopReason;
use crate::value::Value;
use unhusk_dex::insn::{Format, Insn};
use unhusk_dex::model::MethodRef;

/// A resolved call target.
#[derive(Debug, Clone)]
pub enum Target {
    /// Sample bytecode.
    Code(MethodHandle),
    /// A framework/JDK method handled by the model.
    Model(MethodRef),
    /// Native method: emulate the library, or answer with a default.
    Native(MethodRef),
}

impl Machine {
    /// Collect the argument values for an invoke, including `this` for
    /// non-static calls. Register arguments are taken in order.
    fn invoke_args(&self, insn: &Insn) -> Vec<Value> {
        let n = insn.a as usize;
        if matches!(insn.format, Format::F35c | Format::F45cc) {
            insn.regs[..n.min(5)]
                .iter()
                .map(|&r| self.reg(r as u16))
                .collect()
        } else {
            (0..n)
                .map(|i| self.reg(insn.c.wrapping_add(i as u16)))
                .collect()
        }
    }

    pub(crate) fn op_invoke(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame_method) = self.frames.last().map(|f| f.method) else {
            return Ok(());
        };
        let dex = frame_method.dex;
        let Some(method_ref) = self.program.dex(dex).method_at(insn.b as u32).cloned() else {
            self.budget.stop(
                StopReason::Unsupported,
                format!("invoke references method_id {} out of range", insn.b),
            );
            return Err(StopReason::Unsupported);
        };
        let args = self.invoke_args(insn);
        let kind = insn.op;
        // Capture the caller before dispatch: a modelled handler may push a
        // frame (reflective calls do), and the event must name the *invoker*.
        let caller_display = self.current_method_display();
        // A static invocation is an active use of the target class.
        if (kind == 0x71 || kind == 0x77)
            && self.program.class_exists(&method_ref.class)
            && self.init_before_use(&method_ref.class, insn.pc)?
        {
            return Ok(());
        }

        // Ignore "invoke" on the modelled superclass of a class we synthesize.
        let target = self.resolve_target(&method_ref, kind, &args);

        match target {
            Target::Code(handle) => {
                // Widths: a wide result needs its register pair, object results
                // need to be delivered as references.
                let wide = matches!(method_ref.proto.return_type.as_str(), "J" | "D");
                let obj = method_ref.proto.return_type.starts_with('L')
                    || method_ref.proto.return_type.starts_with('[');
                // The `move-result` that follows writes to a register we find
                // by scanning forward; Dalvik guarantees it is the next
                // instruction, so we record the destination there.
                let result_reg = self.next_move_result_reg();
                let call_site = Some((frame_method, insn.pc));
                self.budget.charge_dynamic_load();
                match self.push_frame(
                    handle,
                    args.clone(),
                    call_site,
                    result_reg.map(|r| (r, wide, obj)),
                ) {
                    Ok(()) => Ok(()),
                    Err(StopReason::Unsupported) => {
                        // Declared method with no body (abstract/native).
                        self.handle_native_or_abstract(&method_ref, &args, wide, obj)
                    }
                    Err(r) => Err(r),
                }
            }
            Target::Native(mr) => {
                // Try the real library first: if a shipped `.so` exports this
                // JNI entry point we can run its decryptor, which is where most
                // packers keep the payload cipher.
                if let Some(v) = self.call_native(&mr, &args) {
                    self.deliver_result(Some(v), &mr);
                    return Ok(());
                }
                self.handle_native_or_abstract(&mr, &args, is_wide(&mr), is_obj(&mr))
            }
            Target::Model(mr) => {
                let (value, event) = self.call_model(&mr, &args);
                if let Some(ev) = event {
                    self.record_call_from(&mr, &args, &ev, caller_display);
                }
                self.deliver_result(value, &mr);
                Ok(())
            }
        }
    }

    fn resolve_target(&mut self, mr: &MethodRef, opcode: u8, args: &[Value]) -> Target {
        let is_static = opcode == 0x71 || opcode == 0x77;
        let class = mr.class.as_str();
        // A class that the platform provides is always modelled, even if the
        // sample ships a DEX that declares a class with the same name (packers
        // deliberately shadow `dalvik.system.*` to confuse analysis).
        if is_bootstrap_class(class) {
            return Target::Model(mr.clone());
        }
        // If we have bytecode for this exact method and the class is in the
        // program, run it.
        if self.program.class_exists(class) {
            if let Some(h) = self.program.find_method_in_class(
                class,
                &mr.name,
                &mr.proto.params,
                &mr.proto.return_type,
            ) {
                if self.program.method(h).code.is_some() {
                    return Target::Code(h);
                }
                return Target::Native(mr.clone());
            }
            // Virtual dispatch: the receiver's runtime class decides.
            if !is_static {
                if let Some(this) = args.first().and_then(|v| v.as_obj()) {
                    let runtime = self.heap.get(this).map(|o| o.class_name().to_string());
                    if let Some(runtime) = runtime {
                        if runtime != class {
                            if let Some(h) = self.program.resolve_virtual(
                                &runtime,
                                &mr.name,
                                &mr.proto.params,
                                &mr.proto.return_type,
                            ) {
                                return Target::Code(h);
                            }
                        }
                    }
                }
            }
            // Abstract or missing: fall through to the model.
        }
        if self.program.class_exists(class) {
            Target::Native(mr.clone())
        } else {
            // Unknown class: either a framework class we have not modelled, or
            // an app class that lives in a DEX we have not recovered yet.
            Target::Model(mr.clone())
        }
    }

    /// The register addressed by the `move-result*` immediately following the
    /// current instruction, if any.
    fn next_move_result_reg(&self) -> Option<u16> {
        let frame = self.frames.last()?;
        let code = self.program.method(frame.method).code.as_ref()?;
        let next = code.instructions.get(frame.ip)?;
        if matches!(next.op, 0x0a..=0x0c) {
            Some(next.a)
        } else {
            None
        }
    }

    fn deliver_result(&mut self, value: Option<Value>, mr: &MethodRef) {
        let Some(v) = value else { return };
        if let Some(reg) = self.next_move_result_reg() {
            if is_wide(mr) {
                self.set_reg_pair(reg, v);
            } else {
                self.set_reg(reg, v);
            }
        }
    }

    fn handle_native_or_abstract(
        &mut self,
        mr: &MethodRef,
        args: &[Value],
        wide: bool,
        obj: bool,
    ) -> Result<(), StopReason> {
        // Native methods from the framework are modelled; native methods on
        // sample classes are a signal we surface rather than guess about.
        if self.program.class_exists(&mr.class) {
            let caller = self.current_method_display();
            self.emit(
                crate::events::EventKind::DynamicLoad,
                crate::events::Layer::Native,
                caller,
                mr.signature(),
                args.iter().map(|v| self.render_value(*v)).collect(),
                Some("native method (not emulated)".into()),
            );
            if let Some(reg) = self.next_move_result_reg() {
                self.set_reg(
                    reg,
                    if obj {
                        Value::NULL
                    } else if wide {
                        Value::J(0)
                    } else {
                        Value::I(0)
                    },
                );
            }
            return Ok(());
        }
        // Framework native: model it by name.
        let (value, event) = self.call_model(mr, args);
        if let Some(ev) = event {
            self.record_call(mr, args, &ev);
        }
        if let Some(reg) = self.next_move_result_reg() {
            self.set_reg(
                reg,
                value.unwrap_or(if obj {
                    Value::NULL
                } else if wide {
                    Value::J(0)
                } else {
                    Value::I(0)
                }),
            );
        }
        Ok(())
    }

    pub fn render_value(&self, v: Value) -> String {
        match v {
            Value::I(i) => i.to_string(),
            Value::J(j) => format!("{j}L"),
            Value::F(bits) => format!("{}f", f32::from_bits(bits)),
            Value::D(bits) => format!("{}d", f64::from_bits(bits)),
            Value::Obj(0) => "null".into(),
            Value::Obj(id) => self.describe_object(id),
        }
    }
}

pub fn is_wide(mr: &MethodRef) -> bool {
    matches!(mr.proto.return_type.as_str(), "J" | "D")
}

pub fn is_obj(mr: &MethodRef) -> bool {
    mr.proto.return_type.starts_with('L') || mr.proto.return_type.starts_with('[')
}

/// Classes provided by the Android runtime or the JDK, whose bodies are not in
/// the APK (unless the APK contains a DEX that declares them, checked first).
pub fn is_bootstrap_class(class: &str) -> bool {
    let c = class.trim_start_matches('L').trim_end_matches(';');
    c.starts_with("java/")
        || c.starts_with("javax/")
        || c.starts_with("android/")
        || c.starts_with("androidx/")
        || c.starts_with("dalvik/")
        || c.starts_with("sun/")
        || c.starts_with("org/apache/http/")
        || c.starts_with("org/json/")
        || c.starts_with("org/xml/")
        || c.starts_with("kotlin/")
        || c.starts_with("kotlinx/")
}
