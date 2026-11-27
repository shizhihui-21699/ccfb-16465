//! Bounds-checked little-endian reads plus LEB128 and MUTF-8 decoding.

use crate::error::{DexError, ErrorKind, Result};

#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Result<Self> {
        if pos > data.len() {
            return Err(DexError::truncated(format!(
                "seek to 0x{pos:x} past end 0x{:x}",
                data.len()
            )));
        }
        Ok(Self { data, pos })
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(DexError::truncated(format!(
                "seek to 0x{pos:x} past end 0x{:x}",
                self.data.len()
            )));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.seek(self.pos.saturating_add(n))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| DexError::truncated("length overflow"))?;
        if end > self.data.len() {
            return Err(DexError::truncated(format!(
                "need {n} bytes at 0x{:x}, only {} left",
                self.pos,
                self.remaining()
            )));
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn uleb128(&mut self) -> Result<u32> {
        let mut result: u32 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift >= 32 && (byte & 0x7f) != 0 {
                return Err(DexError::new(
                    ErrorKind::OutOfRange,
                    "uleb128 wider than 32 bits",
                ));
            }
            result |= ((byte & 0x7f) as u32) << shift.min(28);
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                return Err(DexError::new(
                    ErrorKind::OutOfRange,
                    "uleb128 too long",
                ));
            }
        }
        Ok(result)
    }

    pub fn uleb128_padded(&mut self) -> Result<u32> {
        // 5-byte padded form used in code_item headers.
        let mut result = 0u32;
        for i in 0..5 {
            let byte = self.u8()?;
            result |= ((byte & 0x7f) as u32) << (7 * i);
            if byte & 0x80 == 0 {
                // pad to 5 bytes
                for _ in i + 1..5 {
                    let _ = self.u8()?;
                }
                return Ok(result);
            }
        }
        Err(DexError::new(ErrorKind::OutOfRange, "padded uleb128 too long"))
    }

    pub fn sleb128(&mut self) -> Result<i32> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= -1i64 << shift;
                }
                break;
            }
            if shift > 35 {
                return Err(DexError::new(ErrorKind::OutOfRange, "sleb128 too long"));
            }
        }
        Ok(result as i32)
    }
}

/// Decode one Modified-UTF-8 string (as found in the DEX string pool).
///
/// MUTF-8 differs from UTF-8 in two ways: `U+0000` is encoded as the two byte
/// sequence `C0 80`, and supplementary characters are emitted as two separate
/// three-byte sequences (surrogate pairs), exactly like a UTF-16 string.
pub fn mutf8_to_string(bytes: &[u8]) -> Result<String> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            return Err(DexError::new(
                ErrorKind::BadString,
                "NUL inside MUTF-8 string data",
            ));
        }
        if b < 0x80 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xe0 == 0xc0 {
            if i + 1 >= bytes.len() {
                return Err(DexError::new(ErrorKind::BadString, "truncated 2-byte seq"));
            }
            let b2 = bytes[i + 1];
            if b2 & 0xc0 != 0x80 {
                return Err(DexError::new(ErrorKind::BadString, "bad continuation byte"));
            }
            units.push((((b & 0x1f) as u16) << 6) | (b2 & 0x3f) as u16);
            i += 2;
        } else if b & 0xf0 == 0xe0 {
            if i + 2 >= bytes.len() {
                return Err(DexError::new(ErrorKind::BadString, "truncated 3-byte seq"));
            }
            let b2 = bytes[i + 1];
            let b3 = bytes[i + 2];
            if b2 & 0xc0 != 0x80 || b3 & 0xc0 != 0x80 {
                return Err(DexError::new(ErrorKind::BadString, "bad continuation byte"));
            }
            units.push(
                (((b & 0x0f) as u16) << 12)
                    | (((b2 & 0x3f) as u16) << 6)
                    | (b3 & 0x3f) as u16,
            );
            i += 3;
        } else {
            return Err(DexError::new(
                ErrorKind::BadString,
                format!("invalid MUTF-8 lead byte 0x{b:02x}"),
            ));
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Encode a Rust string as MUTF-8 (used by tests and the fixture writer).
pub fn string_to_mutf8(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 1);
    for unit in s.encode_utf16() {
        match unit {
            0 => out.extend_from_slice(&[0xc0, 0x80]),
            0x0001..=0x007f => out.push(unit as u8),
            0x0080..=0x07ff => {
                out.push(0xc0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3f) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
        }
    }
    out.push(0);
    out
}
