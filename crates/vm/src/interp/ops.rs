//! Opcode implementations for the Dalvik core instruction set.

use crate::heap::Object;
use crate::interp::state::Machine;
use crate::limits::StopReason;
use crate::value::{Provenance, Tag, Value};
use unhusk_dex::insn::Insn;

impl Machine {
    // -- moves -------------------------------------------------------------

    pub(crate) fn op_move(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let v = self.reg(insn.b);
        match insn.op {
            0x04..=0x06 => self.set_reg_pair(insn.a, v),
            _ => self.set_reg(insn.a, v),
        }
        Ok(())
    }

    // -- constants ---------------------------------------------------------

    pub(crate) fn op_const_string(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let idx = if insn.op == 0x1b {
            insn.literal as u32
        } else {
            insn.b as u32
        };
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let s = self
            .program
            .dex(frame.method.dex)
            .string(idx)
            .unwrap_or("")
            .to_string();
        match self.heap.new_string(s, Provenance::constant()) {
            Some(id) => {
                self.set_reg(insn.a, Value::obj(id));
                Ok(())
            }
            None => self.heap_oom(),
        }
    }

    pub(crate) fn op_const_class(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let descriptor = self
            .program
            .dex(frame.method.dex)
            .type_at(insn.b as u32)
            .unwrap_or("Ljava/lang/Object;")
            .to_string();
        match self.heap.alloc(Object::Class { descriptor }) {
            Some(id) => {
                self.set_reg(insn.a, Value::obj(id));
                Ok(())
            }
            None => self.heap_oom(),
        }
    }

    // -- type checks -------------------------------------------------------

    pub(crate) fn op_check_cast(&mut self, insn: &Insn) -> Result<(), StopReason> {
        // A null passes any cast. A non-null object whose class we know and
        // that is provably unrelated would throw ClassCastException; samples
        // rely on this to detect instrumentation, so we honour it.
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let Some(target) = self
            .program
            .dex(frame.method.dex)
            .type_at(insn.b as u32)
            .map(str::to_string)
        else {
            return Ok(());
        };
        let v = self.reg(insn.a);
        let Some(obj) = v.as_obj() else { return Ok(()) };
        let class = self
            .heap
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_default();
        if class.is_empty() || class == target {
            return Ok(());
        }
        // Arrays and interfaces are looser than our model can prove, so only
        // reject when both sides are concrete classes in the program.
        let both_concrete = class.starts_with('L') && target.starts_with('L');
        if both_concrete
            && !self.program.is_subclass_of(&class, &target)
            && !self.program.is_subclass_of(&target, &class)
            && self.program.class_exists(&target)
        {
            return self.throw_class(
                "Ljava/lang/ClassCastException;",
                format!("{class} -> {target}"),
            );
        }
        Ok(())
    }

    pub(crate) fn op_instance_of(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let target = self
            .program
            .dex(frame.method.dex)
            .type_at(insn.c as u32)
            .unwrap_or("Ljava/lang/Object;")
            .to_string();
        let v = self.reg(insn.b);
        let result = match v.as_obj() {
            None => 0,
            Some(obj) => {
                let class = self
                    .heap
                    .get(obj)
                    .map(|o| o.class_name().to_string())
                    .unwrap_or_default();
                if class == target
                    || (class.starts_with('L')
                        && target.starts_with('L')
                        && (self.program.is_subclass_of(&class, &target)
                            || self.program.is_subclass_of(&target, &class)
                            || !self.program.class_exists(&target)))
                {
                    1
                } else {
                    0
                }
            }
        };
        self.set_reg(insn.a, Value::I(result));
        Ok(())
    }

    // -- arrays ------------------------------------------------------------

    pub(crate) fn op_array_length(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let v = self.reg(insn.b);
        let len = match v.as_obj().and_then(|id| self.heap.get(id)) {
            Some(Object::Array { bytes, elem, .. }) => {
                (bytes.len() / element_width(elem).max(1)) as i32
            }
            Some(Object::ObjArray { items, .. }) => items.len() as i32,
            Some(Object::Str { value, .. }) => value.chars().count() as i32,
            _ => {
                self.set_reg(insn.a, Value::I(0));
                return Ok(());
            }
        };
        self.set_reg(insn.a, Value::I(len));
        Ok(())
    }

    pub(crate) fn op_new_instance(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let descriptor = self
            .program
            .dex(frame.method.dex)
            .type_at(insn.b as u32)
            .unwrap_or("Ljava/lang/Object;")
            .to_string();
        // `new-instance` is an active use, so the class must be initialised.
        if self.program.class_exists(&descriptor) && self.init_before_use(&descriptor, insn.pc)? {
            return Ok(());
        }
        let id = self.heap.alloc(Object::Instance {
            class: descriptor,
            fields: std::collections::HashMap::new(),
            prov: Provenance::default(),
        });
        match id {
            Some(id) => {
                self.set_reg(insn.a, Value::obj(id));
                Ok(())
            }
            None => self.heap_oom(),
        }
    }

    pub(crate) fn op_new_array(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let elem = self
            .program
            .dex(frame.method.dex)
            .type_at(insn.c as u32)
            .unwrap_or("[I")
            .to_string();
        let count = self.reg(insn.b).as_i32();
        if count < 0 {
            return self.throw_class("Ljava/lang/NegativeArraySizeException;", count.to_string());
        }
        if count as usize > self.budget.limits.max_allocation_bytes {
            self.budget
                .stop(StopReason::Budget, "array allocation too large");
            return Err(StopReason::Budget);
        }
        let width = element_width(&elem);
        let bytes = vec![0u8; count as usize * width];
        let id = self.heap.new_array(elem, bytes, Provenance::default());
        match id {
            Some(id) => {
                self.set_reg(insn.a, Value::obj(id));
                Ok(())
            }
            None => self.heap_oom(),
        }
    }

    pub(crate) fn op_filled_new_array(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let elem = self
            .program
            .dex(frame.method.dex)
            .type_at(insn.b as u32)
            .unwrap_or("[Ljava/lang/Object;")
            .to_string();
        // Collect registers: either the explicit list or a range.
        let regs: Vec<u16> = if matches!(insn.format, unhusk_dex::insn::Format::F35c) {
            insn.regs[..insn.a.min(5) as usize]
                .iter()
                .map(|&r| r as u16)
                .collect()
        } else {
            (0..insn.a).map(|i| insn.c + i).collect()
        };
        let mut values = Vec::with_capacity(regs.len());
        for r in &regs {
            values.push(self.reg(*r));
        }
        // `filled-new-array` does not write to a register: its result is
        // consumed by the `move-result-object` that must follow it, and the
        // invoke engine picks the object up from `pending_result`.
        match self.heap.new_obj_array(elem, values, Provenance::default()) {
            Some(id) => {
                self.pending_result = Some(Value::obj(id));
                Ok(())
            }
            None => self.heap_oom(),
        }
    }

    pub(crate) fn op_fill_array_data(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let Some(code) = self.program.method(frame.method).code.as_ref() else {
            return Ok(());
        };
        let Some(target) = insn.target else {
            return Ok(());
        };
        // Locate the payload and copy its raw bytes into the array.
        let payload = code.instructions.iter().find(|i| i.pc == target);
        let Some(payload) = payload else {
            return Ok(());
        };
        let base = (target as usize) + 4; // skip ident, width, size(2)
        let Some(units) = code.units.get(base..) else {
            return Ok(());
        };
        let mut data = Vec::with_capacity(payload.width as usize * 2);
        for u in units
            .iter()
            .take((payload.width as usize).saturating_sub(4))
        {
            data.extend_from_slice(&u.to_le_bytes());
        }
        let array_reg = insn.a;
        let v = self.reg(array_reg);
        let Some(id) = v.as_obj() else { return Ok(()) };
        if let Some(Object::Array { bytes, .. }) = self.heap.get_mut(id) {
            let n = bytes.len().min(data.len());
            bytes[..n].copy_from_slice(&data[..n]);
        }
        Ok(())
    }

    // -- control flow ------------------------------------------------------

    pub(crate) fn op_throw(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let v = self.reg(insn.a);
        let Some(obj) = v.as_obj() else {
            // `throw null` is a NullPointerException in Dalvik.
            return self.throw_class("Ljava/lang/NullPointerException;", "throw null");
        };
        if let Some(f) = self.frames.last_mut() {
            f.pending_exception = Some(obj);
        }
        Ok(())
    }

    pub(crate) fn op_goto(&mut self, insn: &Insn) -> Result<(), StopReason> {
        match insn.target {
            Some(t) => self.branch_taken(t),
            None => Ok(()),
        }
    }

    pub(crate) fn op_switch(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let key = self.reg(insn.a).as_i32();
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        let Some(code) = self.program.method(frame.method).code.as_ref() else {
            return Ok(());
        };
        let Some(target_pc) = insn.target else {
            return Ok(());
        };
        let Some(payload) = code.instructions.iter().find(|i| i.pc == target_pc) else {
            return Ok(());
        };
        let base = (target_pc as usize) + 2;
        let mut dest: Option<u32> = None;
        if matches!(payload.kind, unhusk_dex::insn::InsnKind::PackedSwitch) {
            let Some(units) = code.units.get(base..) else {
                return Ok(());
            };
            if units.len() < 2 {
                return Ok(());
            }
            let size = units[0] as usize;
            let first_key = ((units[1] as u32) | ((units[2] as u32) << 16)) as i32;
            let idx = key.wrapping_sub(first_key);
            if idx >= 0 && (idx as usize) < size {
                let off_pos = 2 + idx as usize * 2;
                if let Some(w) = code.units.get(base + off_pos..base + off_pos + 2) {
                    dest = Some(((w[0] as u32) | ((w[1] as u32) << 16)).wrapping_add(insn.pc));
                }
            }
        } else {
            let Some(units) = code.units.get(base..) else {
                return Ok(());
            };
            if units.is_empty() {
                return Ok(());
            }
            let size = units[0] as usize;
            for i in 0..size {
                let kp = 1 + i * 2;
                let Some(kw) = code.units.get(base + kp..base + kp + 2) else {
                    break;
                };
                let k = ((kw[0] as u32) | ((kw[1] as u32) << 16)) as i32;
                if k == key {
                    let tp = 1 + size * 2 + i * 2;
                    if let Some(tw) = code.units.get(base + tp..base + tp + 2) {
                        dest =
                            Some(((tw[0] as u32) | ((tw[1] as u32) << 16)).wrapping_add(insn.pc));
                    }
                    break;
                }
            }
        }
        match dest {
            Some(t) => self.branch_taken(t),
            None => {
                if let Some(f) = self.frames.last_mut() {
                    f.ip += 0; // switch does not fall through to `next`; handled by op width
                }
                Ok(())
            }
        }
    }

    pub(crate) fn op_cmp(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let a = self.reg(insn.b);
        let b = self.reg(insn.c);
        let r = match insn.op {
            0x2d => float_cmp(a.as_f32(), b.as_f32(), false),
            0x2e => float_cmp(a.as_f32(), b.as_f32(), true),
            0x2f => float_cmp(a.as_f64() as f32, b.as_f64() as f32, false),
            0x30 => float_cmp(a.as_f64() as f32, b.as_f64() as f32, true),
            _ => {
                let x = a.as_i64();
                let y = b.as_i64();
                match x.cmp(&y) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }
            }
        };
        // cmpl-double / cmpg-double need 64-bit comparison; redo precisely.
        let r = match insn.op {
            0x2f => float_cmp64(a.as_f64(), b.as_f64(), false),
            0x30 => float_cmp64(a.as_f64(), b.as_f64(), true),
            _ => r,
        };
        self.set_reg(insn.a, Value::I(r));
        Ok(())
    }

    pub(crate) fn op_if(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let a = self.reg(insn.a).as_i32();
        let b = self.reg(insn.b).as_i32();
        // Object comparisons in `if-eq`/`if-ne` compare references; using the
        // handle value is exactly that.
        let taken = match insn.op {
            0x32 => a == b,
            0x33 => a != b,
            0x34 => a < b,
            0x35 => a >= b,
            0x36 => a > b,
            0x37 => a <= b,
            _ => false,
        };
        if taken {
            if let Some(t) = insn.target {
                return self.branch_taken(t);
            }
        }
        Ok(())
    }

    pub(crate) fn op_ifz(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let v = self.reg(insn.a);
        let a = v.as_i32();
        let is_null = v.is_null();
        let taken = match insn.op {
            0x38 => a == 0 || is_null,
            0x39 => !(a == 0 || is_null),
            0x3a => a < 0,
            0x3b => a >= 0,
            0x3c => a > 0,
            0x3d => a <= 0,
            _ => false,
        };
        if taken {
            if let Some(t) = insn.target {
                return self.branch_taken(t);
            }
        }
        Ok(())
    }

    // -- array element access ---------------------------------------------

    pub(crate) fn op_aget(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let arr = self.reg(insn.b);
        let idx = self.reg(insn.c).as_i32();
        let Some(id) = arr.as_obj() else {
            return self.throw_class("Ljava/lang/NullPointerException;", "aget on null");
        };
        if idx < 0 {
            return self.throw_class(
                "Ljava/lang/ArrayIndexOutOfBoundsException;",
                idx.to_string(),
            );
        }
        let mut value;
        let mut prov = Provenance::default();
        match self.heap.get(id) {
            Some(Object::Array {
                bytes,
                elem,
                prov: p,
            }) => {
                prov.merge(p);
                let width = element_width(elem);
                let start = idx as usize * width;
                if start + width > bytes.len() {
                    return self.throw_class(
                        "Ljava/lang/ArrayIndexOutOfBoundsException;",
                        format!("{idx} of {}", bytes.len() / width.max(1)),
                    );
                }
                value = match width {
                    8 => Value::J(i64::from_le_bytes(
                        bytes[start..start + 8].try_into().unwrap(),
                    )),
                    4 => Value::I(i32::from_le_bytes(
                        bytes[start..start + 4].try_into().unwrap(),
                    )),
                    2 => Value::I(
                        i16::from_le_bytes(bytes[start..start + 2].try_into().unwrap()) as i32,
                    ),
                    _ => Value::I(bytes[start] as i8 as i32),
                };
                if matches!(insn.op, 0x47) {
                    // aget-boolean: Dalvik stores booleans as 0/1 bytes, so
                    // any non-zero byte reads as true.
                    value = Value::I((value.as_i32() != 0) as i32);
                }
            }
            Some(Object::ObjArray { items, prov: p, .. }) => {
                prov.merge(p);
                value = items.get(idx as usize).copied().unwrap_or(Value::NULL);
            }
            _ => {
                return self
                    .throw_class("Ljava/lang/ArrayIndexOutOfBoundsException;", "not an array")
            }
        }
        self.set_reg(insn.a, value);
        Ok(())
    }

    pub(crate) fn op_aput(&mut self, insn: &Insn) -> Result<(), StopReason> {
        // Format 23x: A = value, B = array, C = index.
        let val = self.reg(insn.a);
        let arr = self.reg(insn.b);
        let idx = self.reg(insn.c).as_i32();
        let Some(id) = arr.as_obj() else {
            return self.throw_class("Ljava/lang/NullPointerException;", "aput on null");
        };
        if idx < 0 {
            return self.throw_class(
                "Ljava/lang/ArrayIndexOutOfBoundsException;",
                idx.to_string(),
            );
        }
        // Provenance of the stored value propagates to the array.
        let val_prov = val
            .as_obj()
            .and_then(|o| self.heap.get(o))
            .and_then(|o| o.prov().cloned());
        // Validate the index before mutating, so an out-of-range store can
        // still raise a modelled exception.
        let (width, cap) = match self.heap.get(id) {
            Some(Object::Array { bytes, elem, .. }) => (
                element_width(elem),
                bytes.len() / element_width(elem).max(1),
            ),
            Some(Object::ObjArray { items, .. }) => (1, items.len()),
            _ => (0, 0),
        };
        if idx as usize >= cap {
            return self.throw_class(
                "Ljava/lang/ArrayIndexOutOfBoundsException;",
                format!("{idx} of {cap}"),
            );
        }
        let _ = width;
        let new_prov = val_prov.clone();
        match self.heap.get_mut(id) {
            Some(Object::Array { bytes, elem, prov }) => {
                let width = element_width(elem);
                let start = idx as usize * width;
                let raw: Vec<u8> = match width {
                    8 => val.as_i64().to_le_bytes().to_vec(),
                    4 => val.as_i32().to_le_bytes().to_vec(),
                    2 => (val.as_i32() as u16).to_le_bytes().to_vec(),
                    _ => vec![val.as_i32() as u8],
                };
                bytes[start..start + width].copy_from_slice(&raw);
                if let Some(p) = &new_prov {
                    prov.merge(p);
                }
            }
            Some(Object::ObjArray { items, prov, .. }) => {
                if idx as usize >= items.len() {
                    return self.throw_class(
                        "Ljava/lang/ArrayIndexOutOfBoundsException;",
                        idx.to_string(),
                    );
                }
                items[idx as usize] = val;
                if let Some(p) = &new_prov {
                    prov.merge(p);
                }
            }
            _ => {
                return self
                    .throw_class("Ljava/lang/ArrayIndexOutOfBoundsException;", "not an array")
            }
        }
        Ok(())
    }

    // -- fields ------------------------------------------------------------

    pub(crate) fn op_iget(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let obj = self.reg(insn.b);
        let Some(id) = obj.as_obj() else {
            return self.throw_class("Ljava/lang/NullPointerException;", "iget on null");
        };
        let field = self.field_id_at(insn.c as u32);
        let value = match self.heap.get(id) {
            Some(Object::Instance { fields, .. }) => {
                fields.get(&field).copied().unwrap_or(Value::I(0))
            }
            Some(Object::Model { fields, .. }) => {
                // Model objects expose fields by name for the framework layer.
                let name = self.program.field_name(field).to_string();
                match fields.get(&name) {
                    Some(crate::heap::ObjectValue::Int(v)) => Value::I(*v as i32),
                    Some(crate::heap::ObjectValue::Bool(b)) => Value::I(*b as i32),
                    Some(crate::heap::ObjectValue::Obj(o)) => Value::obj(*o),
                    _ => Value::I(0),
                }
            }
            _ => Value::I(0),
        };
        self.set_reg(insn.a, value);
        Ok(())
    }

    pub(crate) fn op_iput(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let obj = self.reg(insn.b);
        let val = self.reg(insn.a);
        let Some(id) = obj.as_obj() else {
            return self.throw_class("Ljava/lang/NullPointerException;", "iput on null");
        };
        let field = self.field_id_at(insn.c as u32);
        if let Some(Object::Instance { fields, prov, .. }) = self.heap.get_mut(id) {
            fields.insert(field, val);
            if val.is_null() {
                prov.add(Tag::Built);
            }
        }
        Ok(())
    }

    pub(crate) fn op_sget(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let Some((class, name)) = self.field_ref(insn.b as u32) else {
            return Ok(());
        };
        // Reading a static field is an active use: the declaring class must be
        // initialised first, or a packer's key/blob is still null.
        if self.init_before_use(&class, insn.pc)? {
            return Ok(());
        }
        // Framework statics (Build.FINGERPRINT, System.out, ...) are modelled
        // before the sample's own static storage.
        if std::env::var("UNHUSK_DEBUG").is_ok() {
            eprintln!(
                "  sget op={:#x} reg=v{} field={class}->{name}",
                insn.op, insn.a
            );
        }
        if let Some(v) = self.framework_static(&class, &name) {
            if std::env::var("UNHUSK_DEBUG").is_ok() {
                eprintln!(
                    "    -> v{} = {:?} (heap len {} get={:?})",
                    insn.a,
                    v,
                    self.heap.len(),
                    v.as_obj()
                        .and_then(|i| self.heap.get(i))
                        .map(|o| o.class_name().to_string())
                );
            }
            if matches!(insn.op, 0x63 | 0x67) {
                // sget-boolean normalises to 0/1.
                self.set_reg(insn.a, Value::I((v.as_i32() != 0) as i32));
            } else {
                self.set_reg(insn.a, v);
            }
            return Ok(());
        }
        let field = self.field_id_at(insn.b as u32);
        let v = self.static_field(field);
        self.set_reg(insn.a, v);
        Ok(())
    }

    pub(crate) fn op_sput(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let v = self.reg(insn.a);
        if let Some((class, name)) = self.field_ref(insn.b as u32) {
            if self.init_before_use(&class, insn.pc)? {
                return Ok(());
            }
            if self.set_framework_static(&class, &name, v) {
                return Ok(());
            }
        }
        let field = self.field_id_at(insn.b as u32);
        self.statics.insert(field, v);
        Ok(())
    }

    // -- unary / binary arithmetic ----------------------------------------

    pub(crate) fn op_unop(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let v = self.reg(insn.b);
        let r = match insn.op {
            0x7b => Value::I(v.as_i32().wrapping_neg()),
            0x7c => Value::I(!v.as_i32()),
            0x7d => Value::J(v.as_i64().wrapping_neg()),
            0x7e => Value::J(!v.as_i64()),
            0x7f => Value::f32(-v.as_f32()),
            0x80 => Value::f64(-v.as_f64()),
            0x81 => Value::J(v.as_i32() as i64),
            0x82 => Value::f32(v.as_i32() as f32),
            0x83 => Value::f64(v.as_i32() as f64),
            0x84 => Value::I(v.as_i64() as i32),
            0x85 => Value::f32(v.as_i64() as f32),
            0x86 => Value::f64(v.as_i64() as f64),
            0x87 => Value::I(v.as_f32() as i32),
            0x88 => Value::J(v.as_f32() as i64),
            0x89 => Value::f64(v.as_f32() as f64),
            0x8a => Value::I(v.as_f64() as i32),
            0x8b => Value::J(v.as_f64() as i64),
            0x8c => Value::f32(v.as_f64() as f32),
            0x8d => Value::I(v.as_i32() as i8 as i32),
            0x8e => Value::I(v.as_i32() as u16 as i32),
            0x8f => Value::I(v.as_i32() as i16 as i32),
            _ => v,
        };
        self.set_reg(insn.a, r);
        Ok(())
    }

    pub(crate) fn op_binop(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let a = self.reg(insn.b);
        let b = self.reg(insn.c);
        let r = binop(insn.op, a, b);
        self.set_reg(insn.a, r);
        Ok(())
    }

    pub(crate) fn op_binop_2addr(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let a = self.reg(insn.a);
        let b = self.reg(insn.b);
        let r = binop(insn.op - 0x20, a, b);
        self.set_reg(insn.a, r);
        Ok(())
    }

    pub(crate) fn op_binop_lit16(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let a = self.reg(insn.b);
        let lit = Value::I(insn.literal as i32);
        // rsub-int reverses operands.
        let (x, y) = if insn.op == 0xd1 { (lit, a) } else { (a, lit) };
        let r = binop(insn.op, x, y);
        self.set_reg(insn.a, r);
        Ok(())
    }

    pub(crate) fn op_binop_lit8(&mut self, insn: &Insn) -> Result<(), StopReason> {
        let a = self.reg(insn.b);
        let lit = Value::I(insn.literal as i32);
        let (x, y) = if insn.op == 0xd9 { (lit, a) } else { (a, lit) };
        let op = if insn.op >= 0xe0 {
            insn.op - 0x08
        } else {
            insn.op
        };
        let r = binop(op, x, y);
        self.set_reg(insn.a, r);
        Ok(())
    }
}

/// Width in bytes of one array element, from the array's *type descriptor*
/// (`[B`, `[I`, `[[Ljava/lang/String;`, ...).
pub(crate) fn element_width(array_type: &str) -> usize {
    // Strip exactly one leading '[' to get the element type.
    let elem = array_type.strip_prefix('[').unwrap_or(array_type);
    match elem {
        "J" | "D" => 8,
        "I" | "F" => 4,
        "S" | "C" => 2,
        "Z" | "B" => 1,
        _ => 4, // references are handles
    }
}

fn float_cmp(a: f32, b: f32, nan_greater: bool) -> i32 {
    if a.is_nan() || b.is_nan() {
        if nan_greater {
            1
        } else {
            -1
        }
    } else if a < b {
        -1
    } else if a > b {
        1
    } else {
        0
    }
}

fn float_cmp64(a: f64, b: f64, nan_greater: bool) -> i32 {
    if a.is_nan() || b.is_nan() {
        if nan_greater {
            1
        } else {
            -1
        }
    } else if a < b {
        -1
    } else if a > b {
        1
    } else {
        0
    }
}

/// Shared arithmetic for the three binary formats. `op` is the base opcode
/// (0x90 is `add-int`).
fn binop(op: u8, a: Value, b: Value) -> Value {
    // Normalise to the 0x90-0xaf base range.
    let base = match op {
        0x90..=0xaf => op,
        0xd0..=0xd7 => match op {
            0xd0 => 0x90,
            0xd1 => 0x91,
            0xd2 => 0x92,
            0xd3 => 0x93,
            0xd4 => 0x94,
            0xd5 => 0x95,
            0xd6 => 0x96,
            0xd7 => 0x97,
            _ => op,
        },
        0xd8..=0xdf => match op {
            0xd8 => 0x90,
            0xd9 => 0x91,
            0xda => 0x92,
            0xdb => 0x93,
            0xdc => 0x94,
            0xdd => 0x95,
            0xde => 0x96,
            0xdf => 0x97,
            _ => op,
        },
        0xe0 => 0x98,
        0xe1 => 0x99,
        0xe2 => 0x9a,
        _ => op,
    };
    match base {
        // int arithmetic
        0x90 => Value::I(a.as_i32().wrapping_add(b.as_i32())),
        0x91 => Value::I(a.as_i32().wrapping_sub(b.as_i32())),
        0x92 => Value::I(a.as_i32().wrapping_mul(b.as_i32())),
        0x93 => {
            let d = b.as_i32();
            if d == 0 {
                Value::I(0)
            } else {
                Value::I(a.as_i32().wrapping_div(d))
            }
        }
        0x94 => {
            let d = b.as_i32();
            if d == 0 {
                Value::I(0)
            } else {
                Value::I(a.as_i32().wrapping_rem(d))
            }
        }
        0x95 => Value::I(a.as_i32() & b.as_i32()),
        0x96 => Value::I(a.as_i32() | b.as_i32()),
        0x97 => Value::I(a.as_i32() ^ b.as_i32()),
        0x98 => Value::I(a.as_i32().wrapping_shl(b.as_i32() as u32 & 31)),
        0x99 => Value::I(a.as_i32().wrapping_shr(b.as_i32() as u32 & 31)),
        0x9a => Value::I(((a.as_i32() as u32).wrapping_shr(b.as_i32() as u32 & 31)) as i32),
        // long arithmetic
        0x9b => Value::J(a.as_i64().wrapping_add(b.as_i64())),
        0x9c => Value::J(a.as_i64().wrapping_sub(b.as_i64())),
        0x9d => Value::J(a.as_i64().wrapping_mul(b.as_i64())),
        0x9e => {
            let d = b.as_i64();
            if d == 0 {
                Value::J(0)
            } else {
                Value::J(a.as_i64().wrapping_div(d))
            }
        }
        0x9f => {
            let d = b.as_i64();
            if d == 0 {
                Value::J(0)
            } else {
                Value::J(a.as_i64().wrapping_rem(d))
            }
        }
        0xa0 => Value::J(a.as_i64() & b.as_i64()),
        0xa1 => Value::J(a.as_i64() | b.as_i64()),
        0xa2 => Value::J(a.as_i64() ^ b.as_i64()),
        0xa3 => Value::J(a.as_i64().wrapping_shl(b.as_i32() as u32 & 63)),
        0xa4 => Value::J(a.as_i64().wrapping_shr(b.as_i32() as u32 & 63)),
        0xa5 => Value::J(((a.as_i64() as u64).wrapping_shr(b.as_i32() as u32 & 63)) as i64),
        // float arithmetic
        0xa6 => Value::f32(a.as_f32() + b.as_f32()),
        0xa7 => Value::f32(a.as_f32() - b.as_f32()),
        0xa8 => Value::f32(a.as_f32() * b.as_f32()),
        0xa9 => Value::f32(a.as_f32() / b.as_f32()),
        0xaa => Value::f32(a.as_f32() % b.as_f32()),
        // double arithmetic
        0xab => Value::f64(a.as_f64() + b.as_f64()),
        0xac => Value::f64(a.as_f64() - b.as_f64()),
        0xad => Value::f64(a.as_f64() * b.as_f64()),
        0xae => Value::f64(a.as_f64() / b.as_f64()),
        0xaf => Value::f64(a.as_f64() % b.as_f64()),
        _ => a,
    }
}
