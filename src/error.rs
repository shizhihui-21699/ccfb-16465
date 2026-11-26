//! Error types shared across the crate.
//!
//! Parsing untrusted input never panics: every failure is a typed error that
//! the caller turns into a per-artifact finding rather than aborting the run.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A DEX/APK structure was malformed. Carries a human-readable location.
    BadFormat(String),
    /// A read or index went outside the bounds of the input.
    OutOfBounds { what: &'static str, offset: usize, len: usize },
    /// An APK was not a readable zip container.
    Zip(String),
    /// The interpreter exceeded a resource limit (steps, depth, heap, wall clock).
    LimitExceeded(&'static str),
    /// The sample asked for something the framework model cannot do.
    Unsupported(String),
    /// I/O around the artifact on disk.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadFormat(m) => write!(f, "malformed input: {m}"),
            Error::OutOfBounds { what, offset, len } => {
                write!(f, "out-of-bounds {what}: offset {offset} in {len} bytes")
            }
            Error::Zip(m) => write!(f, "zip: {m}"),
            Error::LimitExceeded(what) => write!(f, "limit exceeded: {what}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Io(m) => write!(f, "io: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Bounds-checked byte cursor over untrusted input. All reads are relative to
/// an absolute base so that offsets in the DEX header can be checked directly.
#[derive(Clone, Copy)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], offset: usize) -> Result<Self> {
        if offset > data.len() {
            return Err(Error::OutOfBounds { what: "cursor base", offset, len: data.len() });
        }
        Ok(Cursor { data, pos: offset })
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn seek(&mut self, offset: usize) -> Result<()> {
        if offset > self.data.len() {
            return Err(Error::OutOfBounds { what: "seek", offset, len: self.data.len() });
        }
        self.pos = offset;
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.seek(self.pos.checked_add(n).ok_or(Error::OutOfBounds {
            what: "skip",
            offset: self.pos,
            len: self.data.len(),
        })?)
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::OutOfBounds { what, offset: self.pos, len: self.data.len() })?;
        if end > self.data.len() {
            return Err(Error::OutOfBounds { what, offset: self.pos, len: self.data.len() });
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1, "u8")?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let s = self.take(2, "u16")?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let s = self.take(4, "u32")?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n, "bytes")
    }

    /// Unsigned LEB128, capped at 5 bytes (32-bit values as used by DEX).
    pub fn uleb128(&mut self) -> Result<u32> {
        let mut result: u32 = 0;
        for i in 0..5 {
            let b = self.u8()?;
            result |= ((b & 0x7f) as u32) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(Error::BadFormat("uleb128 longer than 5 bytes".into()))
    }

    /// Signed LEB128, capped at 5 bytes.
    pub fn sleb128(&mut self) -> Result<i32> {
        let mut result: i32 = 0;
        let mut shift = 0u32;
        for _ in 0..5 {
            let b = self.u8()?;
            result |= ((b & 0x7f) as i32) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 32 && (b & 0x40) != 0 {
                    result |= -1i32 << shift;
                }
                return Ok(result);
            }
        }
        Err(Error::BadFormat("sleb128 longer than 5 bytes".into()))
    }
}

/// Decode a DEX MUTF-8 byte string that is *not* NUL-terminated.
///
/// MUTF-8 differs from UTF-8 in two ways that matter for fidelity: U+0000 is
/// encoded as C0 80, and supplementary characters are encoded as two separate
/// 3-byte surrogates rather than a 4-byte sequence. Malware frequently hides
/// payload metadata in strings that exercise both.
pub fn decode_mutf8(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            out.push(b as u16);
            i += 1;
        } else if b & 0xe0 == 0xc0 {
            if i + 1 >= bytes.len() {
                break;
            }
            out.push((((b & 0x1f) as u16) << 6) | (bytes[i + 1] & 0x3f) as u16);
            i += 2;
        } else if b & 0xf0 == 0xe0 {
            if i + 2 >= bytes.len() {
                break;
            }
            out.push(
                (((b & 0x0f) as u16) << 12)
                    | (((bytes[i + 1] & 0x3f) as u16) << 6)
                    | (bytes[i + 2] & 0x3f) as u16,
            );
            i += 3;
        } else {
            // Invalid lead byte; treat as U+FFFD and advance by one so a
            // corrupt string cannot loop forever.
            out.push(0xFFFD);
            i += 1;
        }
    }
    out
}

/// Reassemble UTF-16 units (including surrogate pairs) into a `String`,
/// replacing unpaired surrogates with U+FFFD.
pub fn utf16_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}
