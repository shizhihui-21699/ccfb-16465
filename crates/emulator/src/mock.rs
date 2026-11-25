//! Mock 后端：回放合成/录制的 trace，用于 CI 与离线开发。
//!
//! 合成 trace 刻意覆盖「环境探测 → 动态加载 → 隐私读取 → 加密 → 外泄」的
//! 完整恶意链路，让端到端测试不依赖任何虚拟化设施。

use sha1::Digest;

use droidunpack_core::{Error, Result, SampleId};
use droidunpack_protocol::{
    ArgValue, CallFrame, EnvProbeKind, Event, EventKind, LoadedDex, MethodRef,
};
use droidunpack_unpack::MemoryBlob;

use crate::{AnalysisArtifact, AnalysisRequest, Backend, Instance};

pub struct MockBackend {
    capacity: usize,
}

impl MockBackend {
    pub fn new(capacity: usize) -> Self {
        MockBackend { capacity }
    }
}

impl Backend for MockBackend {
    fn name(&self) -> &str {
        "mock-replay"
    }

    fn acquire(&self) -> Result<Box<dyn Instance>> {
        Ok(Box::new(MockInstance))
    }

    fn capacity(&self) -> usize {
        self.capacity
    }
}

struct MockInstance;

impl Instance for MockInstance {
    fn run(&mut self, req: &AnalysisRequest) -> Result<AnalysisArtifact> {
        let sample = SampleId("mock-0001".into());
        let mut seq = 0u64;
        let mut next = |ts: u64, kind: EventKind| -> Event {
            seq += 1;
            Event {
                ts_ms: ts,
                sample: sample.clone(),
                seq,
                kind,
            }
        };

        let events = vec![
            next(
                1,
                EventKind::ProcessStart {
                    pid: 1234,
                    package: req.package.clone(),
                },
            ),
            next(
                5,
                EventKind::EnvProbe {
                    probe: EnvProbeKind::BuildProp,
                    detail: "Build.HARDWARE".into(),
                    spoofed: Some(req.plan.device.build_hardware.clone()),
                },
            ),
            next(
                6,
                EventKind::EnvProbe {
                    probe: EnvProbeKind::Sensor,
                    detail: "SensorManager.getSensorList".into(),
                    spoofed: Some(req.plan.device.sensors.len().to_string()),
                },
            ),
            next(
                7,
                EventKind::EnvProbe {
                    probe: EnvProbeKind::Debugger,
                    detail: "/proc/self/status TracerPid".into(),
                    spoofed: Some("0".into()),
                },
            ),
            next(
                20,
                EventKind::DexLoad(LoadedDex {
                    origin: "/data/data/com.mock/app_dex/payload.dex".into(),
                    magic: "dex\n035".into(),
                    size: 0x100,
                    sha1: "synthetic".into(),
                    object_key: None,
                }),
            ),
            next(
                21,
                EventKind::ClassLoad {
                    class: "Lcom/mock/Payload;".into(),
                },
            ),
            next(
                30,
                EventKind::Call(CallFrame {
                    method: MethodRef::from_dotted("com.mock.Payload", "onReceive", "()V"),
                    args: vec![],
                    result: None,
                    thread: "main".into(),
                    backtrace: vec![],
                }),
            ),
            next(
                40,
                EventKind::Sms {
                    direction: "receive".into(),
                    address: Some("10086".into()),
                    body: "VERIFY-CODE-4242".into(),
                },
            ),
            next(
                41,
                EventKind::PrivacyRead {
                    source: "sms".into(),
                    detail: "content://sms/inbox".into(),
                },
            ),
            next(
                50,
                EventKind::Call(CallFrame {
                    method: MethodRef::from_dotted(
                        "javax.crypto.Cipher",
                        "getInstance",
                        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                    ),
                    args: vec![ArgValue::String("AES/GCM/NoPadding".into())],
                    result: None,
                    thread: "main".into(),
                    backtrace: vec![
                        MethodRef::from_dotted("com.mock.Payload", "encrypt", "([B)[B"),
                        MethodRef::from_dotted(
                            "com.mock.Payload",
                            "onReceive",
                            "(Landroid/content/Context;Landroid/content/Intent;)V",
                        ),
                    ],
                }),
            ),
            next(
                51,
                EventKind::Crypto {
                    algorithm: "AES".into(),
                    key_sha1: Some("keyhash".into()),
                    iv_sha1: Some("ivhash".into()),
                },
            ),
            next(
                60,
                EventKind::Call(CallFrame {
                    method: MethodRef::from_dotted(
                        "java.lang.Runtime",
                        "exec",
                        "(Ljava/lang/String;)Ljava/lang/Process;",
                    ),
                    args: vec![ArgValue::String("su -c cat /data/misc/wifi/*.conf".into())],
                    result: None,
                    thread: "main".into(),
                    backtrace: vec![
                        MethodRef::from_dotted(
                            "com.mock.Payload",
                            "rootCmd",
                            "(Ljava/lang/String;)V",
                        ),
                        MethodRef::from_dotted(
                            "com.mock.Payload",
                            "onReceive",
                            "(Landroid/content/Context;Landroid/content/Intent;)V",
                        ),
                    ],
                }),
            ),
            next(
                61,
                EventKind::Exec {
                    argv: vec![
                        "su".into(),
                        "-c".into(),
                        "cat /data/misc/wifi/*.conf".into(),
                    ],
                    env: None,
                },
            ),
            next(
                70,
                EventKind::Network {
                    // 与短信 body 同源，命中 EXFIL-SMS-CRYPTO-NET 的联动规则
                    url: "VERIFY-CODE-4242".into(),
                    ip: "203.0.113.7".into(),
                    port: 443,
                    op: "connect".into(),
                },
            ),
            next(
                80,
                EventKind::Mmap {
                    addr: 0x7000_0000,
                    len: 0x1000,
                    prot: "r-xp".into(),
                    backing: None,
                },
            ),
        ];

        // 内存快照：在噪声中埋一个结构完整的 dex，验证抓取链路
        let mut mem = vec![0xCCu8; 64];
        let dex = synthetic_dex();
        let dex_addr = 0x7000_0000u64;
        mem.extend(dex);
        mem.resize(512, 0xDD);
        let blob = MemoryBlob::new("mock-heap", dex_addr, mem);

        Ok(AnalysisArtifact {
            events,
            memory_blobs: vec![blob],
        })
    }

    fn recycle(self: Box<Self>) -> Result<()> {
        // mock 无状态；真实后端在这里回滚快照
        Ok(())
    }
}

/// 构造一个最小合法 DEX（magic/checksum/signature/header 全部自洽）。
fn synthetic_dex() -> Vec<u8> {
    let size = 0x80usize;
    let mut d = Vec::with_capacity(size);
    d.extend_from_slice(b"dex\n035\0");
    d.extend_from_slice(&0u32.to_le_bytes()); // checksum 占位 @0x08
    d.extend(std::iter::repeat_n(0, 20)); // signature 占位 @0x0c
    d.extend_from_slice(&(size as u32).to_le_bytes()); // file_size @0x20
    d.extend_from_slice(&0x70u32.to_le_bytes());
    d.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    d.resize(size, 0x44);
    let sig = sha1::Sha1::digest(&d[0x20..]);
    d[0x0c..0x20].copy_from_slice(&sig);
    let checksum = adler::adler32_slice(&d[0x0c..]);
    d[0x08..0x0c].copy_from_slice(&checksum.to_le_bytes());
    d
}

/// 供测试断言使用：mock trace 的样本 id。
pub fn mock_sample_id() -> SampleId {
    SampleId("mock-0001".into())
}

/// 仅用于触发错误路径的测试后端。
pub struct FailingBackend;

impl Backend for FailingBackend {
    fn name(&self) -> &str {
        "failing"
    }
    fn acquire(&self) -> Result<Box<dyn Instance>> {
        Err(Error::Emulator("模拟后端故障".into()))
    }
    fn capacity(&self) -> usize {
        1
    }
}
