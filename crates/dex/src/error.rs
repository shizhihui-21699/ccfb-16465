//! Errors raised while decoding Dalvik executables.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexError {
    pub kind: ErrorKind,
    pub context: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The buffer is too short for what the header claims.
    Truncated,
    /// Magic number is not `dex\n`.
    BadMagic,
    /// A structural field (index, offset, size) is out of range.
    OutOfRange,
    /// The file is well formed but uses something we do not support.
    Unsupported,
    /// A string pool entry is not valid MUTF-8.
    BadString,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Truncated => "truncated",
            ErrorKind::BadMagic => "bad-magic",
            ErrorKind::OutOfRange => "out-of-range",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::BadString => "bad-string",
        }
    }
}

impl DexError {
    pub fn new(kind: ErrorKind, context: impl Into<String>) -> Self {
        Self {
            kind,
            context: context.into(),
            offset: None,
        }
    }

    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn truncated(context: impl Into<String>) -> Self {
        Self::new(ErrorKind::Truncated, context)
    }

    pub fn out_of_range(context: impl Into<String>) -> Self {
        Self::new(ErrorKind::OutOfRange, context)
    }
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.context)?;
        if let Some(off) = self.offset {
            write!(f, " (at 0x{off:x})")?;
        }
        Ok(())
    }
}

impl std::error::Error for DexError {}

impl From<DexError> for String {
    fn from(e: DexError) -> String {
        e.to_string()
    }
}

pub type Result<T> = std::result::Result<T, DexError>;
