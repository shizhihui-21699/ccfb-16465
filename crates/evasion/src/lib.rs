//! 反检测策略（设备指纹、虚拟时钟、传感器回放、网络画像）。
//!
//! 设计原则：**不追求“骗过所有检测”，而是让每一次探测都留痕并可评估**。
//! guest 侧 hook 把应用的探测动作以 `EnvProbe` 事件上报，本 crate 根据样本的
//! 探测组合挑选设备画像与伪装值；若样本探测了画像未覆盖的维度，标记为
//! `coverage_gap`，编排层据此决定是否换更强的系统镜像复跑，而不是静默放过。

use serde::{Deserialize, Serialize};

use droidunpack_protocol::EnvProbeKind;

/// 一台“真实感”设备的画像。生产环境维护一个画像库，按地区/价位/机型分布抽样，
/// 避免所有样本都看到同一台设备（那本身就是特征）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub label: String,
    pub build_brand: String,
    pub build_model: String,
    pub build_hardware: String,
    pub build_fingerprint: String,
    pub android_release: String,
    pub sdk: u32,
    /// 开机时随机化、生命周期内稳定的标识
    pub imei: String,
    pub imsi: String,
    pub phone_number: String,
    /// 传感器型号与噪声参数（高斯噪声 sigma，单位按传感器类型）
    pub sensors: Vec<SensorSpec>,
    /// 初始 GPS
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorSpec {
    pub kind: String,
    pub vendor: String,
    /// 静止状态下读数的随机抖动 sigma；0 表示恒定值（会被样本识别为模拟器）
    pub noise_sigma: f64,
}

/// 虚拟时钟策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockPolicy {
    /// 单调时钟与墙钟的偏移基准（epoch 毫秒）
    pub base_epoch_ms: u64,
    /// 对应用可见的时间流速倍率，正常 1.0；加速分析时 guest 内部仍呈现 1.0
    pub apparent_rate: f64,
    /// 随机小幅抖动幅度（毫秒），消除“每次调用间隔完全一致”的模拟器特征
    pub jitter_ms: u64,
}

/// 传感器回放策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReplay {
    /// 真机录制的轨迹文件对象 key
    pub trace_object_key: String,
    /// 回放循环时是否加相位抖动，避免多台模拟器输出完全相同序列
    pub phase_jitter: bool,
}

/// 针对单个样本的反检测方案。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountermeasurePlan {
    pub device: DeviceProfile,
    pub clock: ClockPolicy,
    pub sensors: SensorReplay,
    /// 需要在 guest 层抹除/伪装的属性与设备节点
    pub scrub: ScrubList,
    /// 样本探测了但当前画像无法覆盖的维度，需要升级镜像复跑
    pub coverage_gaps: Vec<EnvProbeKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScrubList {
    pub build_props: Vec<PropOverride>,
    pub hidden_nodes: Vec<String>,
    pub hidden_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropOverride {
    pub name: String,
    pub fake_value: String,
}

/// 样本探测维度集合 -> 反检测方案。
///
/// `profile` 由画像库选出（这里由调用方注入），本函数负责补全 scrub 列表与
/// 覆盖缺口评估。
pub fn plan_for(
    probes: &[EnvProbeKind],
    device: DeviceProfile,
    clock: ClockPolicy,
    sensors: SensorReplay,
) -> CountermeasurePlan {
    let unique: std::collections::BTreeSet<EnvProbeKind> = probes.iter().copied().collect();
    let mut scrub = ScrubList::default();
    let mut gaps = Vec::new();

    for probe in unique {
        match probe {
            EnvProbeKind::BuildProp => {
                scrub.build_props.extend([
                    PropOverride {
                        name: "ro.kernel.qemu".into(),
                        fake_value: "0".into(),
                    },
                    PropOverride {
                        name: "ro.hardware".into(),
                        fake_value: device.build_hardware.clone(),
                    },
                    PropOverride {
                        name: "ro.product.model".into(),
                        fake_value: device.build_model.clone(),
                    },
                    PropOverride {
                        name: "ro.build.fingerprint".into(),
                        fake_value: device.build_fingerprint.clone(),
                    },
                ]);
            }
            EnvProbeKind::DeviceNode => {
                scrub.hidden_nodes.extend([
                    "/dev/qemu_pipe".into(),
                    "/dev/goldfish_pipe".into(),
                    "/sys/qemu_trace".into(),
                    "/system/lib/libc_malloc_debug_qemu.so".into(),
                ]);
            }
            EnvProbeKind::PackageList => {
                // 常见分析/hooking 框架包名
                scrub.hidden_packages.extend([
                    "com.saurik.substrate".into(),
                    "de.robv.android.xposed.installer".into(),
                    "re.frida.server".into(),
                    "io.github.virtualxposed".into(),
                ]);
            }
            EnvProbeKind::Debugger
            | EnvProbeKind::Telephony
            | EnvProbeKind::Sensor
            | EnvProbeKind::Time
            | EnvProbeKind::Network
            | EnvProbeKind::FileArtifact => {
                // 这些维度由对应 hook/回放组件处理；若画像缺传感器数据则记缺口
                if probe == EnvProbeKind::Sensor
                    && device.sensors.iter().all(|s| s.noise_sigma == 0.0)
                {
                    gaps.push(EnvProbeKind::Sensor);
                }
            }
        }
    }

    CountermeasurePlan {
        device,
        clock,
        sensors,
        scrub,
        coverage_gaps: gaps,
    }
}

/// 从 trace 中提取样本实际做过的环境探测（去重、保序）。
pub fn probes_from_trace(events: &[droidunpack_protocol::Event]) -> Vec<EnvProbeKind> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for ev in events {
        if let droidunpack_protocol::EventKind::EnvProbe { probe, .. } = &ev.kind {
            if seen.insert(*probe) {
                out.push(*probe);
            }
        }
    }
    out
}

/// 内置一台像素风格画像，供离线测试与默认车道使用。
pub fn default_pixel_profile() -> DeviceProfile {
    DeviceProfile {
        label: "Pixel-8-pro".into(),
        build_brand: "google".into(),
        build_model: "Pixel 8 Pro".into(),
        build_hardware: "shiba".into(),
        build_fingerprint: "google/shiba/shiba:14/UP1A.231005.007/11010452:user/release-keys"
            .into(),
        android_release: "14".into(),
        sdk: 34,
        imei: "358240051111110".into(),
        imsi: "460001357924680".into(),
        phone_number: "13800138000".into(),
        sensors: vec![
            SensorSpec {
                kind: "accelerometer".into(),
                vendor: "Bosch".into(),
                noise_sigma: 0.018,
            },
            SensorSpec {
                kind: "gyroscope".into(),
                vendor: "Bosch".into(),
                noise_sigma: 0.004,
            },
            SensorSpec {
                kind: "magnetometer".into(),
                vendor: "Yamaha".into(),
                noise_sigma: 0.06,
            },
        ],
        latitude: 31.2304,
        longitude: 121.4737,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_probe_yields_scrub_rules() {
        let plan = plan_for(
            &[EnvProbeKind::BuildProp, EnvProbeKind::DeviceNode],
            default_pixel_profile(),
            ClockPolicy {
                base_epoch_ms: 1_700_000_000_000,
                apparent_rate: 1.0,
                jitter_ms: 12,
            },
            SensorReplay {
                trace_object_key: "obj/sensor-1".into(),
                phase_jitter: true,
            },
        );
        assert!(plan
            .scrub
            .build_props
            .iter()
            .any(|p| p.name == "ro.kernel.qemu"));
        assert!(plan
            .scrub
            .hidden_nodes
            .iter()
            .any(|n| n.contains("goldfish")));
        assert!(plan.coverage_gaps.is_empty());
    }

    #[test]
    fn flat_sensor_profile_flags_coverage_gap() {
        let mut profile = default_pixel_profile();
        profile.sensors.clear();
        let plan = plan_for(
            &[EnvProbeKind::Sensor],
            profile,
            ClockPolicy {
                base_epoch_ms: 1,
                apparent_rate: 1.0,
                jitter_ms: 0,
            },
            SensorReplay {
                trace_object_key: "x".into(),
                phase_jitter: false,
            },
        );
        assert!(plan.coverage_gaps.contains(&EnvProbeKind::Sensor));
    }
}
