use serde::{Deserialize, Serialize};

/// Java/Native 方法的稳定引用。Java 方法用 `class#name(signature)` 形式，
/// native 函数用 `libname!symbol` 形式。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodRef {
    /// 类名（Java 描述符内部格式，如 `Lcom/foo/Bar;`）或 native 库名
    pub owner: String,
    pub name: String,
    /// Java 类型描述符，如 `(Ljava/lang/String;)V`；native 可为空
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl MethodRef {
    /// 解析 `Lcom/foo/Bar;->onReceive(Landroid/content/Context;...)V` 这类常见文本形式。
    pub fn parse(text: &str) -> Option<Self> {
        let (owner, rest) = text.split_once("->")?;
        let (name, sig) = match rest.split_once('(') {
            Some((n, s)) => (n.to_string(), format!("({s}")),
            None => (rest.to_string(), String::new()),
        };
        Some(MethodRef {
            owner: owner.to_string(),
            name: name.to_string(),
            signature: sig,
        })
    }

    /// 规则里用点分类名书写更易读，统一归一化为内部格式。
    pub fn from_dotted(class: &str, name: &str, signature: &str) -> Self {
        MethodRef {
            owner: format!("L{};", class.replace('.', "/")),
            name: name.to_string(),
            signature: signature.to_string(),
        }
    }

    /// 点分类名，用于报告展示。
    pub fn dotted_class(&self) -> String {
        self.owner
            .trim_start_matches('L')
            .trim_end_matches(';')
            .replace('/', ".")
    }

    /// 调用图节点键：包含完整签名，避免同名不同参方法撞键。
    pub fn node_key(&self) -> String {
        if self.signature.is_empty() {
            format!("{}#{}", self.owner, self.name)
        } else {
            format!("{}#{}#{}", self.owner, self.name, self.signature)
        }
    }

    pub fn display(&self) -> String {
        if self.signature.is_empty() {
            format!("{}#{}", self.owner, self.name)
        } else {
            format!("{}->{} {}", self.dotted_class(), self.name, self.signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_method_ref() {
        let m = MethodRef::parse("Lcom/foo/Bar;->onReceive(Landroid/content/Context;)V").unwrap();
        assert_eq!(m.owner, "Lcom/foo/Bar;");
        assert_eq!(m.name, "onReceive");
        assert_eq!(m.signature, "(Landroid/content/Context;)V");
        assert_eq!(m.dotted_class(), "com.foo.Bar");
    }

    #[test]
    fn dotted_roundtrip() {
        let m = MethodRef::from_dotted("com.foo.Bar", "run", "()V");
        assert_eq!(m.owner, "Lcom/foo/Bar;");
        assert!(m.display().contains("com.foo.Bar->run"));
    }
}
