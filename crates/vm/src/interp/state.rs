//! Interpreter state: call frames, exception dispatch, and the shared handles
//! to everything the interpreter can touch.

use crate::env::Env;
use crate::events::Trace;
use crate::heap::Heap;
use crate::interp::program::{MethodHandle, Program};
use crate::limits::Budget;
use crate::value::Value;

/// Maximum value that fits in a Dalvik register array.
pub const MAX_REGISTERS: usize = 65_535;

/// One activation record.
#[derive(Debug, Clone)]
pub struct Frame {
    pub method: MethodHandle,
    /// Registers. Locals and parameters share the array: Dalvik numbers them
    /// from 0, with parameters at the top.
    pub regs: Vec<Value>,
    pub pc: u32,
    /// Index into the current method's instruction table.
    pub ip: usize,
    /// Invocation site, for the report.
    pub call_site: Option<(MethodHandle, u32)>,
    /// Line number in the source, when known.
    pub line: Option<u32>,
    /// Result register for this frame's caller, encoded as
    /// (register, is_wide, is_object).
    pub result_to: Option<(u16, bool, bool)>,
    /// Exception currently being dispatched into this frame.
    pub pending_exception: Option<u32>,
}

impl Frame {
    pub fn new(
        method: MethodHandle,
        register_count: usize,
        call_site: Option<(MethodHandle, u32)>,
    ) -> Self {
        Self {
            method,
            regs: vec![Value::I(0); register_count.min(MAX_REGISTERS)],
            pc: 0,
            ip: 0,
            call_site,
            line: None,
            result_to: None,
            pending_exception: None,
        }
    }
}

/// Where the interpreter should resume after a call returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    /// Normal instruction at this pc.
    Next,
    /// Throw the object at `pc` (used for exception propagation).
    Throw(u32),
}

/// Runtime policy knobs that the engine sets.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Stop after this many recovered DEX files.
    pub max_recovered_dex: u32,
    /// Follow network-derived DEX loads.
    pub follow_network_loads: bool,
    /// Record even non-suspicious API calls (verbose trace).
    pub record_all_apis: bool,
    /// Treat the run as an evasion probe: log every environment access.
    pub log_env_probes: bool,
    /// Execute native libraries through the AArch64 interpreter.
    pub emulate_native: bool,
    /// Hard stop for "we already have enough evidence".
    pub stop_on_first_payload: bool,
    /// Maximum iterations of any single loop head before we widen it.
    pub loop_unroll: u32,
    /// AArch64 steps allowed per native call.
    pub native_steps: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_recovered_dex: 8,
            follow_network_loads: false,
            record_all_apis: false,
            log_env_probes: true,
            emulate_native: true,
            stop_on_first_payload: false,
            loop_unroll: 64,
            native_steps: 2_000_000,
        }
    }
}

/// The complete machine state handed to opcode implementations.
pub struct Machine {
    pub program: Program,
    pub heap: Heap,
    pub env: Env,
    pub trace: Trace,
    pub budget: Budget,
    pub policy: Policy,
    pub frames: Vec<Frame>,
    /// Open exception handlers, innermost last: (frame depth, handler pc).
    pub handlers: Vec<(usize, u32)>,
    /// Static field storage, keyed by interned field id. Unset means default.
    pub statics: std::collections::HashMap<u32, Value>,
    /// Objects pinned as roots for a synthetic call (e.g. the Application).
    pub this_obj: Option<u32>,
    /// Count of methods entered, for the `max_methods` budget.
    pub methods_entered: usize,
    /// Loop iteration counter per backward-branch target, reset on return.
    pub loop_counts: std::collections::HashMap<(u32, u32), u32>,
    /// The DEX index the current frame belongs to, to detect cross-DEX flow.
    pub last_call_depth_peak: usize,
    /// DEX files written to the virtual filesystem, keyed by normalized path.
    pub pending_files: std::collections::HashMap<String, Vec<u8>>,
    /// Recovered DEX payloads kept in memory for optional extraction.
    pub recovered_payloads: Vec<(String, Vec<u8>)>,
    /// Recovered DEX summaries, in discovery order.
    pub recovered: Vec<crate::interp::program::RecoveredDex>,
    /// Application class from the manifest, if any.
    pub app_class: Option<String>,
    /// Permissions the app declared (granted at install time).
    pub granted_permissions: Vec<String>,
    /// Methods the driver deliberately entered, in order.
    pub executed: Vec<String>,
    /// Per-class initialisation state.
    pub class_states: std::collections::HashMap<String, crate::interp::classinit::ClassState>,
    /// Classes whose `<clinit>` is currently on the frame stack.
    pub init_stack: Vec<String>,
    /// Native libraries available for dispatch: (apk path, bytes).
    pub native_libraries: Vec<(String, Vec<u8>)>,
    /// Libraries the sample explicitly loaded.
    pub loaded_libraries: Vec<String>,
    /// Result of an instruction that writes to the following `move-result`
    /// rather than to a register (filled-new-array).
    pub pending_result: Option<Value>,
    /// Every method body entered at least once, so seeding never repeats work
    /// the sample already did itself.
    pub entered: std::collections::HashSet<MethodHandle>,
}
