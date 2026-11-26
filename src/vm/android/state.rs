//! Shared model state names and the taint-source vocabulary.
//!
//! Strings here are the internal keys host hooks use to stash things on heap
//! objects (`inst.state`). Keeping them named prevents two subsystems from
//! disagreeing about what a `Cipher` stores its key under.

/// Source labels minted when sensitive data is read. Findings print these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintSource {
    Imei,
    Imsi,
    Iccid,
    PhoneNumber,
    AndroidId,
    Serial,
    Location,
    Contacts,
    SmsInbox,
    CallLog,
    InstalledApps,
    Accounts,
    Clipboard,
    FileContents,
    DeviceInfo,
    ExternalStorage,
}

impl TaintSource {
    pub fn label(self) -> &'static str {
        match self {
            TaintSource::Imei => "imei",
            TaintSource::Imsi => "imsi",
            TaintSource::Iccid => "iccid",
            TaintSource::PhoneNumber => "phone-number",
            TaintSource::AndroidId => "android-id",
            TaintSource::Serial => "serial",
            TaintSource::Location => "location",
            TaintSource::Contacts => "contacts",
            TaintSource::SmsInbox => "sms-inbox",
            TaintSource::CallLog => "call-log",
            TaintSource::InstalledApps => "installed-apps",
            TaintSource::Accounts => "accounts",
            TaintSource::Clipboard => "clipboard",
            TaintSource::FileContents => "file-contents",
            TaintSource::DeviceInfo => "device-info",
            TaintSource::ExternalStorage => "external-storage",
        }
    }
}

/// Class names whose constructors are dynamic code loaders. When one is
/// constructed with a valid DEX path or buffer, the loader hook parses and
/// registers the payload.
pub const DEX_LOADER_CLASSES: [&str; 4] = [
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ldalvik/system/BaseDexClassLoader;",
];
