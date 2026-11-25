//! 模拟器后端抽象与连接池。
//!
//! 控制面不直接绑定 AVD/Cuttlefish 的具体命令，而是依赖 [`Backend`] trait：
//! - [`mock`]：回放预置 trace，CI 与无虚拟化环境（macOS 开发机）可跑完整流水线；
//! - [`cuttlefish`]：生产后端的占位实现，真正的 `cvd`/快照管理在部署迭代中补全。
//!
//! 连接池用快照预热（snapshot warm-up）解决吞吐问题：槽位提前启动到
//! `boot_completed` 后的干净快照，样本分析结束直接回滚快照而不是冷启动。

pub mod cuttlefish;
pub mod mock;

use std::sync::{Arc, Mutex};

use droidunpack_core::{Error, Result};
use droidunpack_evasion::CountermeasurePlan;
use droidunpack_protocol::Event;
use droidunpack_unpack::MemoryBlob;

/// 一次动态分析的输入。
#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    pub apk_path: String,
    pub package: String,
    /// 本次分析的反检测方案
    pub plan: CountermeasurePlan,
    /// 刺激预算（事件数上限/时长由编排层的 TimeBudget 控制）
    pub stimulation_events: u32,
}

/// 一次动态分析的原始产物：事件流 + 内存快照。
#[derive(Debug, Clone, Default)]
pub struct AnalysisArtifact {
    pub events: Vec<Event>,
    pub memory_blobs: Vec<MemoryBlob>,
}

/// 模拟器实例句柄。
pub trait Backend: Send + Sync {
    /// 后端名称（日志/指标标签）。
    fn name(&self) -> &str;

    /// 借出一个已恢复到干净快照的实例。
    fn acquire(&self) -> Result<Box<dyn Instance>>;

    /// 池容量。
    fn capacity(&self) -> usize;
}

pub trait Instance: Send {
    /// 安装并启动样本，按请求执行刺激，收集 trace 与内存快照。
    fn run(&mut self, req: &AnalysisRequest) -> Result<AnalysisArtifact>;

    /// 归还实例（回滚快照）。drop 时也必须保证回滚，避免污染下个样本。
    fn recycle(self: Box<Self>) -> Result<()>;
}

/// 带租约计数的连接池包装，用于并发编排。
pub struct Pool {
    backend: Arc<dyn Backend>,
    leased: Arc<Mutex<usize>>,
}

impl Pool {
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Pool {
            backend,
            leased: Arc::new(Mutex::new(0)),
        }
    }

    pub fn capacity(&self) -> usize {
        self.backend.capacity()
    }

    pub fn leased(&self) -> usize {
        *self.leased.lock().unwrap()
    }

    /// 借实例；池满时返回错误，由编排层排队而不是阻塞线程。
    pub fn acquire(&self) -> Result<Lease> {
        let mut leased = self.leased.lock().unwrap();
        if *leased >= self.backend.capacity() {
            return Err(Error::Emulator("模拟器池已满，请求应排队".into()));
        }
        let instance = self.backend.acquire()?;
        *leased += 1;
        Ok(Lease {
            instance: Some(instance),
            leased: self.leased.clone(),
        })
    }
}

/// 租约：drop 自动归还计数（实例回滚由内部 Instance::recycle 负责）。
pub struct Lease {
    instance: Option<Box<dyn Instance>>,
    leased: Arc<Mutex<usize>>,
}

impl Lease {
    pub fn run(mut self, req: &AnalysisRequest) -> Result<(AnalysisArtifact, Result<()>)> {
        let mut inst = self.instance.take().expect("租约只能执行一次");
        let artifact = inst.run(req)?;
        let recycle = inst.recycle();
        *self.leased.lock().unwrap() -= 1;
        Ok((artifact, recycle))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.instance.is_some() {
            // 未显式 run 就被丢弃：回收实例并释放槽位
            if let Some(inst) = self.instance.take() {
                let _ = inst.recycle();
            }
            *self.leased.lock().unwrap() -= 1;
        }
    }
}
