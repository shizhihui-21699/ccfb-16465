use std::fmt;

#[derive(Debug, Clone)]
pub struct ApkError {
    pub context: String,
}

impl ApkError {
    pub fn new(context: impl Into<String>) -> Self {
        Self { context: context.into() }
    }
}

impl fmt::Display for ApkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.context)
    }
}

impl std::error::Error for ApkError {}

impl From<std::io::Error> for ApkError {
    fn from(e: std::io::Error) -> Self {
        ApkError::new(e.to_string())
    }
}

impl From<zip::result::ZipError> for ApkError {
    fn from(e: zip::result::ZipError) -> Self {
        ApkError::new(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ApkError>;
