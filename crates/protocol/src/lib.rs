//! guest agent（设备内 ART/JNI hook）与 Rust 控制面之间的事件协议。
//!
//! 传输层是 JSONL：一行一个 [`Event`]。选择 JSONL 而不是 protobuf，是因为
//!
//! 1. 真机/模拟器上落盘与 `adb pull` 最简单；
//! 2. 分析员可以直接 `jq` 审计；
//! 3. 事件量可控（每条事件在 hook 侧做过采样/聚合）。
//!
//! 性能成为瓶颈时可在不改语义的前提下增加二进制帧（见 docs/architecture.md）。

pub mod event;
pub mod method;
pub mod trace;

pub use event::{ArgValue, CallFrame, EnvProbeKind, Event, EventKind, LoadedDex};
pub use method::MethodRef;
pub use trace::read_jsonl;
