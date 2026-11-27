//! AndroidManifest semantics: components, permissions and the attributes that
//! matter to a sandbox (debuggable, exported, native libs, target SDK).

use crate::axml::{Document, Element, Value};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Component {
    pub kind: ComponentKind,
    pub name: String,
    /// `android:exported`, as declared.
    pub exported: Option<bool>,
    /// True when the effective exported state is true: explicit `exported`, or
    /// an intent-filter on a pre-Android-12 target without explicit opt-out.
    pub effectively_exported: bool,
    pub permission: Option<String>,
    pub intent_actions: Vec<String>,
    pub intent_categories: Vec<String>,
    pub process: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentKind {
    #[default]
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ComponentKind::Activity => "activity",
            ComponentKind::ActivityAlias => "activity-alias",
            ComponentKind::Service => "service",
            ComponentKind::Receiver => "receiver",
            ComponentKind::Provider => "provider",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub package: String,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub max_sdk: Option<i32>,
    pub debugabble: bool,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
    pub extract_native_libs: Option<bool>,
    pub shared_user_id: Option<String>,
    pub shared_user_label: Option<String>,
    pub main_activity: Option<String>,
    pub application_class: Option<String>,
    pub components: Vec<Component>,
    pub permissions: Vec<String>,
    pub declared_permissions: Vec<String>,
    pub features: Vec<String>,
    pub libraries: Vec<String>,
    /// True when the document mentions `android:usesCleartextTraffic` at all.
    pub has_cleartext_attr: bool,
    /// Permission count and names as declared with `<uses-permission-sdk-23>`.
    pub sdk23_permissions: Vec<String>,
}

/// Which attribute holds a component's class name.
fn component_name(el: &Element) -> Option<String> {
    el.attributes
        .iter()
        .find(|a| a.name == "name" || a.name.ends_with(":name"))
        .and_then(|a| a.value.as_str().map(|s| s.to_string()))
}

fn exported(el: &Element) -> Option<bool> {
    el.attributes
        .iter()
        .find(|a| {
            a.name == "exported"
                || a.name.ends_with(":exported")
                || a.name_res == 0x0101_0012
        })
        .and_then(|a| a.value.as_bool())
}

fn permission(el: &Element) -> Option<String> {
    el.attributes
        .iter()
        .find(|a| a.name == "permission" || a.name.ends_with(":permission"))
        .and_then(|a| a.value.as_str().map(|s| s.to_string()))
}

fn process(el: &Element) -> Option<String> {
    el.attributes
        .iter()
        .find(|a| a.name == "process" || a.name.ends_with(":process"))
        .and_then(|a| a.value.as_str().map(|s| s.to_string()))
}

fn enabled(el: &Element) -> bool {
    el.attributes
        .iter()
        .find(|a| a.name == "enabled" || a.name.ends_with(":enabled"))
        .and_then(|a| a.value.as_bool())
        .unwrap_or(true)
}

fn collect_intent_filters(el: &Element) -> (Vec<String>, Vec<String>) {
    let mut actions = Vec::new();
    let mut categories = Vec::new();
    for filter in el.children("intent-filter") {
        for action in filter.children("action") {
            if let Some(name) = &component_name(action) {
                actions.push(name.clone());
            } else if let Some(a) = action
                .attributes
                .iter()
                .find(|a| a.name == "name" || a.name.ends_with(":name"))
            {
                if let Some(s) = a.value.as_str() {
                    actions.push(s.to_string());
                }
            }
        }
        for cat in filter.children("category") {
            if let Some(a) = cat
                .attributes
                .iter()
                .find(|a| a.name == "name" || a.name.ends_with(":name"))
            {
                if let Some(s) = a.value.as_str() {
                    categories.push(s.to_string());
                }
            }
        }
    }
    (actions, categories)
}

fn uses_sdk(el: &Element) -> (Option<i32>, Option<i32>, Option<i32>) {
    let min = el
        .attributes
        .iter()
        .find(|a| a.name == "minSdkVersion" || a.name.ends_with(":minSdkVersion"))
        .and_then(|a| a.value.as_i32());
    let target = el
        .attributes
        .iter()
        .find(|a| a.name == "targetSdkVersion" || a.name.ends_with(":targetSdkVersion"))
        .and_then(|a| a.value.as_i32());
    let max = el
        .attributes
        .iter()
        .find(|a| a.name == "maxSdkVersion" || a.name.ends_with(":maxSdkVersion"))
        .and_then(|a| a.value.as_i32());
    (min, target, max)
}

fn attr_bool(el: &Element, local: &str) -> Option<bool> {
    el.attributes
        .iter()
        .find(|a| a.name == local || a.name.ends_with(&format!(":{local}")))
        .and_then(|a| a.value.as_bool())
}

fn attr_str(el: &Element, local: &str) -> Option<String> {
    el.attributes
        .iter()
        .find(|a| a.name == local || a.name.ends_with(&format!(":{local}")))
        .and_then(|a| match &a.value {
            Value::String(s) => Some(s.clone()),
            Value::Reference(r) => Some(format!("@{r:#010x}")),
            _ => None,
        })
}

/// Interpret a decoded AXML tree as an `AndroidManifest.xml`.
pub fn interpret(doc: &Document) -> Manifest {
    let root = &doc.root;
    let mut m = Manifest {
        package: attr_str(root, "package").unwrap_or_default(),
        ..Default::default()
    };

    // The manifest-level `versionCode` can be a plain number or a resource ref.
    m.version_name = attr_str(root, "versionName");
    m.version_code = root
        .attributes
        .iter()
        .find(|a| a.name == "versionCode" || a.name.ends_with(":versionCode"))
        .and_then(|a| match &a.value {
            Value::Int(i) => Some(*i as i64),
            Value::String(s) => s.parse().ok(),
            _ => None,
        });
    m.shared_user_id = attr_str(root, "sharedUserId");
    m.shared_user_label = attr_str(root, "sharedUserLabel");

    for child in &root.children {
        match child.name.as_str() {
            "uses-sdk" => {
                let (min, target, max) = uses_sdk(child);
                m.min_sdk = min;
                m.target_sdk = target;
                m.max_sdk = max;
            }
            "uses-permission" => {
                if let Some(name) = attr_str(child, "name") {
                    m.permissions.push(name);
                }
            }
            "uses-permission-sdk-23" => {
                if let Some(name) = attr_str(child, "name") {
                    m.sdk23_permissions.push(name);
                }
            }
            "permission" => {
                if let Some(name) = attr_str(child, "name") {
                    m.declared_permissions.push(name);
                }
            }
            "uses-feature" => {
                if let Some(name) = attr_str(child, "name") {
                    m.features.push(name);
                }
            }
            "uses-library" => {
                if let Some(name) = attr_str(child, "name") {
                    m.libraries.push(name);
                }
            }
            "application" => {
                m.application_class = attr_str(child, "name");
                m.debugabble = attr_bool(child, "debuggable").unwrap_or(false);
                m.allow_backup = attr_bool(child, "allowBackup");
                m.has_cleartext_attr = child
                    .attributes
                    .iter()
                    .any(|a| a.name == "usesCleartextTraffic" || a.name.ends_with(":usesCleartextTraffic"));
                m.uses_cleartext_traffic = attr_bool(child, "usesCleartextTraffic");
                m.network_security_config = attr_str(child, "networkSecurityConfig");
                m.extract_native_libs = attr_bool(child, "extractNativeLibs");
                for comp_el in &child.children {
                    let kind = match comp_el.name.as_str() {
                        "activity" => ComponentKind::Activity,
                        "activity-alias" => ComponentKind::ActivityAlias,
                        "service" => ComponentKind::Service,
                        "receiver" => ComponentKind::Receiver,
                        "provider" => ComponentKind::Provider,
                        _ => continue,
                    };
                    let Some(name) = component_name(comp_el) else { continue };
                    let (actions, categories) = collect_intent_filters(comp_el);
                    let declared_exported = exported(comp_el);
                    let has_filter = !actions.is_empty();
                    // Android 12+ requires an explicit `exported`; below that,
                    // an intent filter implies exported.
                    let target = m.target_sdk.unwrap_or(1);
                    let effectively_exported = match declared_exported {
                        Some(v) => v,
                        None => has_filter && target < 31,
                    };
                    let is_main = actions
                        .iter()
                        .any(|a| a == "android.intent.action.MAIN")
                        && categories
                            .iter()
                            .any(|c| c == "android.intent.category.LAUNCHER");
                    if is_main && m.main_activity.is_none() {
                        m.main_activity = Some(name.clone());
                    }
                    m.components.push(Component {
                        kind,
                        name,
                        exported: declared_exported,
                        effectively_exported,
                        permission: permission(comp_el),
                        intent_actions: actions,
                        intent_categories: categories,
                        process: process(comp_el),
                        enabled: enabled(comp_el),
                    });
                }
            }
            _ => {}
        }
    }
    // If no launcher activity is declared, fall back to the first activity.
    if m.main_activity.is_none() {
        m.main_activity = m
            .components
            .iter()
            .find(|c| c.kind == ComponentKind::Activity)
            .map(|c| c.name.clone());
    }
    m
}
