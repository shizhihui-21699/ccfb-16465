//! The bytecode execution loop.
//!
//! Design notes:
//!  * The interpreter is a tree walker over `unhusk_dex::insn::Insn`, not a
//!    pre-compiled design. Decoding is already a single pass per method and is
//!    cached in the parsed DEX, so this stays within budget for realistic
//!    payloads while remaining simple enough to audit.
//!  * Every opcode implementation is pure with respect to the machine except
//!    through explicit `Machine` mutations, which keeps the anti-analysis and
//!    provenance logic in one auditable place.
//!  * Anything we cannot model stops execution with `StopReason::Unsupported`
//!    rather than silently producing wrong results.

use crate::events::{Event, EventKind, Layer, DEFAULT_TRACE_CAP};
use crate::heap::{Heap, Object};
use crate::interp::program::{MethodHandle, Program};
pub use crate::interp::state::Machine;
use crate::interp::state::{Frame, Policy};
use crate::limits::{Budget, Limits, StopReason};
use crate::value::Value;
use unhusk_dex::insn::InsnKind;
use unhusk_dex::DexFile;

/// Outcome of starting execution.
pub struct RunStats {
    pub stop: StopReason,
    pub detail: Option<String>,
    pub instructions: u64,
    pub elapsed: std::time::Duration,
    pub methods_entered: usize,
}

impl Machine {
    pub fn new(program: Program, env: crate::env::Env, limits: Limits, policy: Policy) -> Self {
        let trace_cap = if policy.record_all_apis { DEFAULT_TRACE_CAP } else { DEFAULT_TRACE_CAP / 2 };
        Self {
            program,
            heap: Heap::new(limits.max_heap_objects),
            env,
            trace: crate::events::Trace::new(trace_cap),
            budget: Budget::new(limits),
            policy,
            frames: Vec::new(),
            handlers: Vec::new(),
            statics: std::collections::HashMap::new(),
            this_obj: None,
            methods_entered: 0,
            loop_counts: std::collections::HashMap::new(),
            last_call_depth_peak: 0,
            pending_files: Default::default(),
            recovered_payloads: Vec::new(),
            recovered: Vec::new(),
            app_class: None,
            granted_permissions: Vec::new(),
            executed: Vec::new(),
            entered: Default::default(),
            class_states: Default::default(),
            init_stack: Vec::new(),
        }
    }

    pub fn emit(&mut self, kind: EventKind, layer: Layer, caller: String, subject: String, args: Vec<String>, result: Option<String>) {
        let insn = self.budget.instructions;
        self.trace.push(Event {
            seq: 0,
            insn,
            kind,
            layer,
            caller,
            subject,
            args,
            result,
            prov: None,
            line: None,
        });
    }

    pub fn current_method_display(&self) -> String {
        match self.frames.last() {
            Some(f) => self.program.method(f.method).display(),
            None => "<none>".to_string(),
        }
    }

    /// Push a frame for `handle` with the given argument values.
    pub fn push_frame(&mut self, handle: MethodHandle, args: Vec<Value>, call_site: Option<(MethodHandle, u32)>, result_to: Option<(u16, bool, bool)>) -> Result<(), StopReason> {
        if self.frames.len() >= self.budget.limits.max_call_depth {
            self.budget.stop(StopReason::Budget, "call depth limit");
            return Err(StopReason::Budget);
        }
        let method = self.program.method(handle);
        let Some(code) = method.code.as_ref() else {
            return Err(StopReason::Unsupported);
        };
        let total = code.registers_size as usize;
        let ins = code.ins_size as usize;
        if total < ins || total > crate::interp::state::MAX_REGISTERS {
            self.budget.stop(StopReason::Unsupported, "invalid register count");
            return Err(StopReason::Unsupported);
        }
        let mut frame = Frame::new(handle, total, call_site);
        let base = total - ins;
        for (i, v) in args.into_iter().take(ins).enumerate() {
            frame.regs[base + i] = v;
        }
        frame.result_to = result_to;
        let first_entry = self.entered.insert(handle);
        self.frames.push(frame);
        self.methods_entered += 1;
        if first_entry {
            // One MethodEnter per method body, so the call graph records the
            // first call site rather than a hot loop's last iteration.
            let caller = if self.frames.len() >= 2 {
                let parent = self.frames[self.frames.len() - 2].method;
                self.program.method(parent).display()
            } else {
                "<entry>".to_string()
            };
            let callee = self.program.method(handle).display();
            let (rec, insn) = (self.recovered.len(), self.budget.instructions);
            self.trace.push(Event {
                seq: 0,
                insn,
                kind: EventKind::MethodEnter,
                layer: if self.program.origins[handle.dex as usize] == crate::interp::program::MethodOrigin::Recovered {
                    Layer::RecoveredDex
                } else {
                    Layer::Dex
                },
                caller,
                subject: callee,
                args: Vec::new(),
                result: None,
                prov: None,
                line: None,
            });
            let _ = rec;
        }
        if self.methods_entered > self.budget.limits.max_methods {
            self.budget.stop(StopReason::Budget, "method entry limit");
            return Err(StopReason::Budget);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Execution loop
// ---------------------------------------------------------------------------

impl Machine {
    /// Run until the frame stack empties, the top frame returns, or a budget
    /// stops the machine.
    pub fn run(&mut self) -> StopReason {
        loop {
            if self.budget.is_stopped() {
                return self.budget.stop.unwrap_or(StopReason::Budget);
            }
            let Some(frame) = self.frames.last() else {
                if !self.init_stack.is_empty() {
                    self.finish_class_init();
                }
                return StopReason::Completed;
            };
            if frame.pending_exception.is_some() {
                if let Err(r) = self.dispatch_pending_exception() {
                    return r;
                }
                continue;
            }
            let method = self.program.method(frame.method);
            let Some(code) = method.code.as_ref() else {
                self.frames.pop();
                continue;
            };
            if frame.ip >= code.instructions.len() {
                // Fell off the end of the method without a return: treat as a
                // void return, which is what ART's verifier would have rejected.
                if let Err(r) = self.do_return(None) {
                    return r;
                }
                continue;
            }
            let insn = code.instructions[frame.ip].clone();
            if insn.kind != InsnKind::Real {
                self.frames.last_mut().unwrap().ip += 1;
                continue;
            }
            if !self.budget.tick(1) {
                return self.budget.stop.unwrap_or(StopReason::Budget);
            }
            // Keep the frame's pc in sync for branch handling and reporting.
            self.frames.last_mut().unwrap().pc = insn.pc;
            self.frames.last_mut().unwrap().ip += 1;
            if std::env::var("UNHUSK_TRACE").is_ok() {
                eprintln!("  [{:04x}] {} | regs={:?}", insn.pc, unhusk_dex::insn::render(&insn),
                    self.frames.last().map(|f| f.regs.clone()).unwrap_or_default());
            }
            if let Err(r) = self.step(&insn) {
                return r;
            }
        }
    }

    fn dispatch_pending_exception(&mut self) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last_mut() else {
            return Err(StopReason::Completed);
        };
        let Some(exc) = frame.pending_exception.take() else {
            return Ok(());
        };
        // Find a try block in this frame covering the throw pc.
        let code = self.program.method(frame.method).code.clone();
        if let Some(code) = code {
            let pc = frame.pc;
            for tr in &code.tries {
                if pc >= tr.start_pc && pc < tr.start_pc + tr.insn_count {
                    if let Some((_, handler)) = tr.handlers.iter().find(|_| true) {
                        let h = *handler;
                        // Store the exception object in the register the
                        // handler's move-exception reads.
                        let ip = code.insn_index_at(h).unwrap_or(code.instructions.len());
                        let f = self.frames.last_mut().unwrap();
                        f.pc = h;
                        f.ip = ip;
                        let reg = self.program.method(f.method).code.as_ref()
                            .and_then(|c| c.insn_at(h))
                            .map(|i| i.a);
                        if let Some(reg) = reg {
                            if (reg as usize) < f.regs.len() {
                                f.regs[reg as usize] = Value::obj(exc);
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
        // No handler here: propagate to the caller.
        self.frames.pop();
        if let Some(parent) = self.frames.last_mut() {
            parent.pending_exception = Some(exc);
            Ok(())
        } else {
            self.emit(
                EventKind::Policy,
                Layer::Sandbox,
                "<entry>".into(),
                "uncaught-exception".into(),
                vec![self.describe_object(exc)],
                None,
            );
            self.budget.stop(StopReason::Exception, "uncaught exception");
            Err(StopReason::Exception)
        }
    }

    // Helpers shared with the opcode modules.

    pub(crate) fn field_id_at(&mut self, idx: u32) -> u32 {
        let Some(frame) = self.frames.last() else { return 0 };
        let dex_idx = frame.method.dex;
        let sig = self
            .program
            .dex(dex_idx)
            .field_at(idx)
            .map(|f| format!("{}->{}:{}", f.class, f.name, f.ty))
            .unwrap_or_default();
        self.program.field_id(&sig)
    }

    /// (class, name) of a field reference in the current DEX.
    pub(crate) fn field_ref(&self, idx: u32) -> Option<(String, String)> {
        let dex_idx = self.frames.last()?.method.dex;
        let f = self.program.dex(dex_idx).field_at(idx)?;
        Some((f.class.clone(), f.name.clone()))
    }

    pub(crate) fn static_field(&mut self, field: u32) -> Value {
        if let Some(v) = self.statics.get(&field) {
            return *v;
        }
        // First read of a static: materialise its declared constant, if it has
        // one. Caching in `statics` keeps later reads cheap and lets `sput`
        // override the constant the way a class initialiser would.
        let declared = self.declared_static(field);
        match declared {
            Some(v) => {
                self.statics.insert(field, v);
                v
            }
            None => {
                let default = Value::I(0);
                self.statics.insert(field, default);
                default
            }
        }
    }

    /// Raise a modelled exception. Returns `Err` only when the machine stopped.
    pub(crate) fn throw_class(&mut self, class: &str, message: impl Into<String>) -> Result<(), StopReason> {
        let msg = message.into();
        let Some(id) = self.heap.alloc(Object::Throwable { class: class.to_string(), message: msg.clone() }) else {
            return self.heap_oom();
        };
        if let Some(f) = self.frames.last_mut() {
            f.pending_exception = Some(id);
        }
        Ok(())
    }

    pub(crate) fn heap_oom(&mut self) -> Result<(), StopReason> {
        self.budget.stop(StopReason::Budget, "heap object limit");
        Err(StopReason::Budget)
    }

    pub fn describe_object(&self, id: u32) -> String {
        match self.heap.get(id) {
            Some(Object::Str { value, .. }) => format!("{value:?}"),
            Some(Object::Builder { buf, .. }) => format!("{buf:?}"),
            Some(Object::Array { bytes, .. }) => format!("byte[{}]", bytes.len()),
            Some(Object::ObjArray { items, .. }) => format!("array[{}]", items.len()),
            Some(Object::Model { class, .. }) => format!("<{class}>"),
            Some(Object::Instance { class, .. }) => format!("<{class} instance>"),
            Some(Object::Throwable { class, message }) => format!("<{class}: {message}>"),
            Some(Object::Class { descriptor }) => format!("<class {descriptor}>"),
            None => "<null>".to_string(),
        }
    }

    /// Return from the top frame, delivering `value` to the caller.
    fn do_return(&mut self, value: Option<Value>) -> Result<(), StopReason> {
        let frame = match self.frames.pop() {
            Some(f) => f,
            None => return Ok(()),
        };
        self.handlers.retain(|(depth, _)| *depth <= self.frames.len());
        if let Some((reg, wide, obj)) = frame.result_to {
            let v = match value {
                Some(v) => v,
                None => {
                    if obj {
                        Value::NULL
                    } else if wide {
                        Value::J(0)
                    } else {
                        Value::I(0)
                    }
                }
            };
            if let Some(caller) = self.frames.last_mut() {
                let r = reg as usize;
                if r < caller.regs.len() {
                    caller.regs[r] = v;
                    if wide && r + 1 < caller.regs.len() {
                        caller.regs[r + 1] = v;
                    }
                }
            }
        }
        Ok(())
    }

    fn step(&mut self, insn: &unhusk_dex::insn::Insn) -> Result<(), StopReason> {
        use unhusk_dex::insn::render;
        let _ = render; // used by debug builds via trace
        match insn.op {
            // --- no-ops, moves, returns ---
            0x00 => Ok(()),
            0x01 | 0x04 | 0x07 => self.op_move(insn),
            0x02 | 0x05 | 0x08 => self.op_move(insn),
            0x03 | 0x06 | 0x09 => self.op_move(insn),
            0x0e => self.do_return(None),
            0x0f | 0x10 | 0x11 => {
                let v = self.reg(insn.a);
                self.do_return(Some(v))
            }
            0x0a | 0x0b | 0x0c | 0x0d => {
                // move-result-family: the value was already written by the call.
                Ok(())
            }
            0x12 | 0x13 | 0x14 | 0x15 => {
                self.set_reg(insn.a, Value::I(insn.literal as i32));
                Ok(())
            }
            0x16 | 0x17 | 0x18 | 0x19 => {
                self.set_reg(insn.a, Value::J(insn.literal));
                Ok(())
            }
            0x1a | 0x1b => self.op_const_string(insn),
            0x1c => self.op_const_class(insn),
            0x1d | 0x1e => Ok(()),
            0x1f => self.op_check_cast(insn),
            0x20 => self.op_instance_of(insn),
            0x21 => self.op_array_length(insn),
            0x22 => self.op_new_instance(insn),
            0x23 => self.op_new_array(insn),
            0x24 | 0x25 => self.op_filled_new_array(insn),
            0x26 => self.op_fill_array_data(insn),
            0x27 => self.op_throw(insn),
            0x28 | 0x29 | 0x2a => self.op_goto(insn),
            0x2b | 0x2c => self.op_switch(insn),
            0x2d..=0x31 => self.op_cmp(insn),
            0x32..=0x37 => self.op_if(insn),
            0x38..=0x3d => self.op_ifz(insn),
            0x44..=0x4a => self.op_aget(insn),
            0x4b..=0x51 => self.op_aput(insn),
            0x52..=0x58 => self.op_iget(insn),
            0x59..=0x5f => self.op_iput(insn),
            0x60..=0x66 => self.op_sget(insn),
            0x67..=0x6d => self.op_sput(insn),
            0x6e..=0x72 => self.op_invoke(insn),
            0x74..=0x78 => self.op_invoke(insn),
            0x7b..=0x8f => self.op_unop(insn),
            0x90..=0xaf => self.op_binop(insn),
            0xb0..=0xcf => self.op_binop_2addr(insn),
            0xd0..=0xd7 => self.op_binop_lit16(insn),
            0xd8..=0xe2 => self.op_binop_lit8(insn),
            // Unsupported for now (invoke-polymorphic/custom, method handles).
            0xfa..=0xff => {
                self.budget.stop(
                    StopReason::Unsupported,
                    format!("opcode 0x{:02x} ({}) is not modelled", insn.op, insn.mnemonic()),
                );
                Err(StopReason::Unsupported)
            }
            other => {
                self.budget.stop(
                    StopReason::Unsupported,
                    format!("unhandled opcode 0x{other:02x}"),
                );
                Err(StopReason::Unsupported)
            }
        }
    }

    // --- register access ---

    #[inline]
    pub fn reg(&self, i: u16) -> Value {
        self.frames
            .last()
            .and_then(|f| f.regs.get(i as usize).copied())
            .unwrap_or(Value::I(0))
    }

    #[inline]
    pub fn set_reg(&mut self, i: u16, v: Value) {
        if let Some(f) = self.frames.last_mut() {
            if let Some(slot) = f.regs.get_mut(i as usize) {
                *slot = v;
            }
        }
    }

    #[inline]
    pub fn set_reg_pair(&mut self, i: u16, v: Value) {
        self.set_reg(i, v);
        self.set_reg(i.wrapping_add(1), v);
    }

    /// Rewind the instruction pointer of the frame at `depth` to `pc`, so the
    /// instruction re-executes once a lazily-pushed `<clinit>` returns.
    ///
    /// The depth is explicit because by the time the caller notices that a
    /// class initialiser was pushed, the initialiser frame is on top — rewinding
    /// "the last frame" would rewind the wrong one.
    pub(crate) fn rewind_frame(&mut self, depth: usize, pc: u32) {
        let Some(f) = self.frames.get_mut(depth) else { return };
        if let Some(ip) = self
            .program
            .method(f.method)
            .code
            .as_ref()
            .and_then(|c| c.insn_index_at(pc))
        {
            f.ip = ip;
        }
    }

    /// Ensure `descriptor` is initialised and, if a `<clinit>` frame was
    /// pushed, rewind the *current* instruction so it retries afterwards.
    /// Returns `true` when the caller should return immediately.
    pub(crate) fn init_before_use(&mut self, descriptor: &str, pc: u32) -> Result<bool, StopReason> {
        let depth = self.frames.len().saturating_sub(1);
        if self.ensure_class_initialised(descriptor)? {
            self.rewind_frame(depth, pc);
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn jump_to(&mut self, target: u32) {
        if let Some(f) = self.frames.last_mut() {
            if let Some(ip) = self
                .program
                .method(f.method)
                .code
                .as_ref()
                .and_then(|c| c.insn_index_at(target))
            {
                f.ip = ip;
                f.pc = target;
            } else {
                f.ip = usize::MAX - 1; // fall off the end -> implicit return
            }
        }
    }

    pub(crate) fn branch_taken(&mut self, target: u32) -> Result<(), StopReason> {
        // Backward branch: count iterations per (method, target) so a hostile
        // infinite loop degrades quickly and predictably.
        let Some(top) = self.frames.last() else { return Ok(()) };
        let key = (top.method.slot ^ top.method.class.rotate_left(13), target);
        let count = self.loop_counts.entry(key).or_insert(0);
        *count += 1;
        let limit = self.policy.loop_unroll.max(self.budget.limits.max_loop_iterations);
        if *count > limit {
            self.budget.stop(
                StopReason::Budget,
                format!("loop at pc {target:#x} exceeded {limit} iterations"),
            );
            return Err(StopReason::Budget);
        }
        self.jump_to(target);
        Ok(())
    }
}
