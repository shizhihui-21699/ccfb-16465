//! Cuttlefish 生产后端占位。
//!
//! 真实实现的职责（部署迭代补全）：
//! 1. `cvd create` 预启动实例池并保存 `boot_completed` 干净快照；
//! 2. acquire = `cvd snapshot_restore`，recycle = 回滚同一快照；
//! 3. 通过 vsock（而非 adb over tcp，避免网络特征暴露）下发控制命令；
//! 4. guest agent 经 vsock 推送 JSONL 事件与内存转储；
//! 5. KVM 硬件加速，ARM 真机镜像优先（x86 转译本身是检测维度）。
//!
//! 当前环境（macOS 开发机）没有 Cuttlefish，调用即返回 Unsupported，
//! 保证工作区在任何平台都能编译、测试通过。

use droidunpack_core::{Error, Result};

use crate::{AnalysisArtifact, AnalysisRequest, Backend, Instance};

pub struct CuttlefishBackend {
    pub pool_size: usize,
}

impl Backend for CuttlefishBackend {
    fn name(&self) -> &str {
        "cuttlefish-kvm"
    }

    fn acquire(&self) -> Result<Box<dyn Instance>> {
        Err(Error::Unsupported(
            "Cuttlefish 后端仅在 Linux KVM 分析节点可用，本地请使用 mock-replay".into(),
        ))
    }

    fn capacity(&self) -> usize {
        self.pool_size
    }
}

/// 部署时的实例骨架，保留接口形态供后续填充。
#[allow(dead_code)]
pub struct CuttlefishInstance {
    serial: String,
    vsock_port: u32,
}

impl Instance for CuttlefishInstance {
    fn run(&mut self, _req: &AnalysisRequest) -> Result<AnalysisArtifact> {
        Err(Error::Unsupported(
            "见模块文档：cvd/vsock 集成待部署迭代".into(),
        ))
    }

    fn recycle(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}
