//! Lazy class initialisation.
//!
//! ART runs `<clinit>` before the first *active use* of a class: a static field
//! read/write, a static method call, or `new-instance`. Packers rely on this —
//! the decryption key and the payload blob are usually assigned in `<clinit>`,
//! never in the method that uses them, so a VM that skips class init sees the
//! default null and the unpacking loop silently does nothing.
//!
//! The `S_INIT` intermediate state is required by the spec: static initialisers
//! are allowed to observe their own class in a partially-initialised state, and
//! a recursive request must not re-enter.

use crate::interp::program::MethodHandle;
use crate::interp::state::Machine;
use crate::limits::StopReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassState {
    /// Not yet touched.
    Uninitialised,
    /// `<clinit>` is on the stack right now.
    Initialising,
    /// `<clinit>` ran to completion (or there was none).
    Initialised,
    /// `<clinit>` threw; per JVM/Dalvik semantics later uses see the error.
    Failed,
}

impl Machine {
    /// Ensure `descriptor` is initialised. Pushes `<clinit>` as a synthetic
    /// frame if it has one, and returns `true` when a frame was pushed so the
    /// caller can defer the original instruction.
    ///
    /// The caller's contract: after this returns `true`, the instruction that
    /// triggered initialisation must be re-executed once the stack unwinds.
    pub(crate) fn ensure_class_initialised(&mut self, descriptor: &str) -> Result<bool, StopReason> {
        if self.frames.len() >= self.budget.limits.max_call_depth {
            self.budget.stop(StopReason::Budget, "call depth limit in class init");
            return Err(StopReason::Budget);
        }
        match self.class_states.get(descriptor).copied().unwrap_or(ClassState::Uninitialised) {
            ClassState::Initialised | ClassState::Initialising => return Ok(false),
            ClassState::Failed => return Ok(false),
            ClassState::Uninitialised => {}
        }
        // No `<clinit>` means the class is trivially initialised.
        let clinit: Option<MethodHandle> = self
            .program
            .methods_named(descriptor, "<clinit>")
            .iter()
            .copied()
            .find(|h| self.program.method(*h).code.is_some());
        let Some(clinit) = clinit else {
            self.class_states.insert(descriptor.to_string(), ClassState::Initialised);
            return Ok(false);
        };
        self.class_states.insert(descriptor.to_string(), ClassState::Initialising);
        match self.push_frame(clinit, Vec::new(), None, None) {
            Ok(()) => {
                self.init_stack.push(descriptor.to_string());
                Ok(true)
            }
            Err(r) => {
                self.class_states.insert(descriptor.to_string(), ClassState::Failed);
                Err(r)
            }
        }
    }

    /// Called when the frame stack empties after an initialiser. Marks every
    /// `<clinit>` that just finished as completed, or failed if it was aborted
    /// by an exception.
    pub(crate) fn finish_class_init(&mut self) {
        while let Some(desc) = self.init_stack.pop() {
            self.class_states
                .insert(desc, if self.budget.is_stopped() { ClassState::Failed } else { ClassState::Initialised });
        }
    }
}
