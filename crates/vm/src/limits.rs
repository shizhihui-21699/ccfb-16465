//! Deterministic resource accounting. Every analysis run gets a fixed budget;
//! the interpreter polls it at backward branches and calls, so a hostile
//! sample degrades into a partial trace instead of hanging the pipeline.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Limits {
    /// Total Dalvik instructions the interpreter may retire.
    pub max_instructions: u64,
    /// Max call depth.
    pub max_call_depth: usize,
    /// Max objects live at once.
    pub max_heap_objects: usize,
    /// Max bytes for a single string or array allocation.
    pub max_allocation_bytes: usize,
    /// Wall-clock ceiling; checked every N instructions.
    pub max_wall: Duration,
    /// Max total bytes the model may read from the APK (assets, resources).
    pub max_apk_read_bytes: u64,
    /// Max number of distinct methods entered (bounds the call graph).
    pub max_methods: usize,
    /// Max loop iterations for a single backward branch target.
    pub max_loop_iterations: u32,
    /// How many times a native/reflective load may be attempted.
    pub max_dynamic_loads: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_instructions: 40_000_000,
            max_call_depth: 384,
            max_heap_objects: 4_000_000,
            max_allocation_bytes: 32 * 1024 * 1024,
            max_wall: Duration::from_secs(60),
            max_apk_read_bytes: 128 * 1024 * 1024,
            max_methods: 200_000,
            max_loop_iterations: 100_000,
            max_dynamic_loads: 64,
        }
    }
}

impl Limits {
    /// A tighter profile for the "fast triage" pass.
    pub fn fast() -> Self {
        Self {
            max_instructions: 6_000_000,
            max_wall: Duration::from_secs(20),
            max_call_depth: 192,
            ..Self::default()
        }
    }

    /// Scale every time/step bound by a factor; used for per-sample budgets
    /// when many samples are queued.
    pub fn scaled(mut self, factor: f64) -> Self {
        let f = factor.clamp(0.05, 10.0);
        self.max_instructions = ((self.max_instructions as f64) * f) as u64;
        self.max_wall = Duration::from_secs_f64((self.max_wall.as_secs_f64() * f).max(1.0));
        self
    }
}

/// Why execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Ran to completion.
    Completed,
    /// The budget ran out.
    Budget,
    /// Hit an unsupported construct we cannot model.
    Unsupported,
    /// The sample threw an uncaught exception.
    Exception,
    /// Deliberate halt (e.g. we reached the behavior we came for).
    Halt,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Completed => "completed",
            StopReason::Budget => "budget-exhausted",
            StopReason::Unsupported => "unsupported",
            StopReason::Exception => "uncaught-exception",
            StopReason::Halt => "halted",
        }
    }
}

/// Live budget state.
pub struct Budget {
    pub limits: Limits,
    pub instructions: u64,
    pub started: Instant,
    pub apk_bytes_read: u64,
    pub dynamic_loads: u32,
    pub stop: Option<StopReason>,
    pub stop_detail: Option<String>,
    /// Instructions retired at the last wall-clock check.
    check_counter: u32,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            instructions: 0,
            started: Instant::now(),
            apk_bytes_read: 0,
            dynamic_loads: 0,
            stop: None,
            stop_detail: None,
            check_counter: 0,
        }
    }

    pub fn stop(&mut self, reason: StopReason, detail: impl Into<String>) {
        if self.stop.is_none() {
            self.stop = Some(reason);
            self.stop_detail = Some(detail.into());
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.is_some()
    }

    /// Account for `n` retired instructions; returns false once stopped.
    #[inline]
    pub fn tick(&mut self, n: u64) -> bool {
        if self.stop.is_some() {
            return false;
        }
        self.instructions += n;
        if self.instructions >= self.limits.max_instructions {
            self.stop = Some(StopReason::Budget);
            self.stop_detail = Some(format!(
                "instruction budget {} exhausted",
                self.limits.max_instructions
            ));
            return false;
        }
        self.check_counter += 1;
        if self.check_counter >= 16_384 {
            self.check_counter = 0;
            if self.started.elapsed() >= self.limits.max_wall {
                self.stop = Some(StopReason::Budget);
                self.stop_detail = Some(format!(
                    "wall-clock budget {}s exhausted",
                    self.limits.max_wall.as_secs()
                ));
                return false;
            }
        }
        true
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn charge_apk_read(&mut self, n: u64) {
        self.apk_bytes_read = self.apk_bytes_read.saturating_add(n);
        if self.apk_bytes_read > self.limits.max_apk_read_bytes {
            self.stop(
                StopReason::Budget,
                format!("APK read budget {} bytes exhausted", self.limits.max_apk_read_bytes),
            );
        }
    }

    pub fn charge_dynamic_load(&mut self) -> bool {
        self.dynamic_loads += 1;
        if self.dynamic_loads > self.limits.max_dynamic_loads {
            self.stop(
                StopReason::Budget,
                format!("dynamic load budget {} exhausted", self.limits.max_dynamic_loads),
            );
            return false;
        }
        true
    }
}
