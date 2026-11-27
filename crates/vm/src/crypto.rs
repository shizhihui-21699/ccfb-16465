//! Cryptographic and encoding primitives a loader is likely to use, plus the
//! *recognition* logic that decides when a value should be tagged `Decoded`.
//!
//! Everything here is pure and bounded: no key comes from outside the sample,
//! and every call is capped so a hostile sample cannot burn the analysis budget
//! in one AES call on a 200 MB buffer.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::Aes256;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// Upper bound for any single primitive invocation.
pub const MAX_CRYPTO_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    BadKeyLength(usize),
    BadIvLength(usize),
    NotBlockAligned(usize),
    TooLarge(usize),
    Unsupported(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::BadKeyLength(n) => write!(f, "bad key length {n}"),
            CryptoError::BadIvLength(n) => write!(f, "bad IV length {n}"),
            CryptoError::NotBlockAligned(n) => write!(f, "not block aligned ({n} bytes)"),
            CryptoError::TooLarge(n) => write!(f, "input too large ({n} bytes)"),
            CryptoError::Unsupported(s) => write!(f, "unsupported {s}"),
        }
    }
}

fn check_len(data: &[u8]) -> Result<(), CryptoError> {
    if data.len() > MAX_CRYPTO_BYTES {
        return Err(CryptoError::TooLarge(data.len()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// XOR family
// ---------------------------------------------------------------------------

pub fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

pub fn xor_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

/// Rolling XOR with a per-iteration index, a pattern seen in many DEX packers:
/// `b ^= (key + i)`.
pub fn xor_rolling(data: &[u8], key: u8) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key.wrapping_add(i as u8))
        .collect()
}

// ---------------------------------------------------------------------------
// RC4
// ---------------------------------------------------------------------------

pub fn rc4(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len(data)?;
    if key.is_empty() {
        return Err(CryptoError::BadKeyLength(0));
    }
    let mut s: [u8; 256] = [0; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i = 0u8;
    j = 0;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        out.push(b ^ k);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// AES (ECB/CBC/CTR built from the block primitive)
// ---------------------------------------------------------------------------

enum AesBlock {
    A128(Box<Aes128>),
    A256(Box<Aes256>),
}

impl AesBlock {
    fn enc(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        match self {
            AesBlock::A128(c) => c.encrypt_block(b),
            AesBlock::A256(c) => c.encrypt_block(b),
        }
    }

    fn dec(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        match self {
            AesBlock::A128(c) => c.decrypt_block(b),
            AesBlock::A256(c) => c.decrypt_block(b),
        }
    }
}

fn aes_new(key: &[u8]) -> Result<AesBlock, CryptoError> {
    match key.len() {
        16 => Ok(AesBlock::A128(Box::new(
            Aes128::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength(key.len()))?,
        ))),
        32 => Ok(AesBlock::A256(Box::new(
            Aes256::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength(key.len()))?,
        ))),
        // AES-192 is legal but rare in Android malware; support it via the
        // generic API would need another import.
        n => Err(CryptoError::BadKeyLength(n)),
    }
}

pub fn aes_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len(data)?;
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::NotBlockAligned(data.len()));
    }
    if iv.len() != 16 {
        return Err(CryptoError::BadIvLength(iv.len()));
    }
    let cipher = aes_new(key)?;
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let cipher_block = block;
        cipher.dec(&mut block);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        prev = cipher_block;
        out.extend_from_slice(&block);
    }
    Ok(out)
}

pub fn aes_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len(data)?;
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::NotBlockAligned(data.len()));
    }
    if iv.len() != 16 {
        return Err(CryptoError::BadIvLength(iv.len()));
    }
    let cipher = aes_new(key)?;
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        cipher.enc(&mut block);
        prev = block;
        out.extend_from_slice(&block);
    }
    Ok(out)
}

pub fn aes_ecb_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len(data)?;
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::NotBlockAligned(data.len()));
    }
    let cipher = aes_new(key)?;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        cipher.dec(&mut block);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

pub fn aes_ctr(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len(data)?;
    if iv.len() != 16 {
        return Err(CryptoError::BadIvLength(iv.len()));
    }
    let cipher = aes_new(key)?;
    let mut counter = [0u8; 16];
    counter.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = counter;
        cipher.enc(&mut ks);
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        // Increment big-endian counter.
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
    Ok(out)
}

/// Strip PKCS#7 padding after a block-mode decrypt. Returns the plaintext and
/// whether the padding looked valid; a loader that ignores padding errors is a
/// useful signal in itself.
pub fn strip_pkcs7(data: &[u8]) -> (Vec<u8>, bool) {
    let Some(&pad) = data.last() else {
        return (Vec::new(), false);
    };
    let n = pad as usize;
    if n == 0 || n > 16 || n > data.len() {
        return (data.to_vec(), false);
    }
    if data[data.len() - n..].iter().all(|&b| b == pad) {
        (data[..data.len() - n].to_vec(), true)
    } else {
        (data.to_vec(), false)
    }
}

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // Android's Base64.DEFAULT accepts URL-safe alphabets depending on flags;
    // try standard then URL-safe.
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(cleaned.as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(cleaned.as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cleaned.as_bytes()))
        .ok()
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlg {
    pub fn from_java_name(name: &str) -> Option<Self> {
        let n = name.to_ascii_uppercase().replace('-', "");
        Some(match n.as_str() {
            "MD5" => HashAlg::Md5,
            "SHA1" | "SHA" => HashAlg::Sha1,
            "SHA256" => HashAlg::Sha256,
            "SHA512" => HashAlg::Sha512,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Md5 => "MD5",
            HashAlg::Sha1 => "SHA-1",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha512 => "SHA-512",
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Md5 => {
                let mut h = Md5::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashAlg::Sha1 => {
                let mut h = Sha1::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashAlg::Sha256 => {
                let mut h = Sha256::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashAlg::Sha512 => {
                let mut h = Sha512::new();
                h.update(data);
                h.finalize().to_vec()
            }
        }
    }
}

/// Detectors used to tag provenance. These are deliberately conservative: a
/// false "decoded" tag only adds noise to an already-flagged call.
pub fn looks_like_dex(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..4] == b"dex\n" && data[7] == 0
}

pub fn looks_like_zip(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0x50, 0x4b, 0x03, 0x04]
}

/// Entropy in bits/byte over the first `n` bytes.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Heuristic: does this look like text that a human could read (URLs, JSON,
/// config) as opposed to still-encrypted noise? Used to decide whether a
/// decode attempt produced something worth reporting.
pub fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        .count();
    printable as f64 / data.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_known_vector() {
        // RC4("Key", "Plaintext") = BBF316E8D940AF0AD3
        let out = rc4(b"Plaintext", b"Key").unwrap();
        assert_eq!(
            out.iter().map(|b| format!("{b:02X}")).collect::<String>(),
            "BBF316E8D940AF0AD3"
        );
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let plain = b"0123456789abcdef0123456789abcdef";
        let ct = aes_cbc_encrypt(plain, &key, &iv).unwrap();
        assert_ne!(&ct[..], &plain[..]);
        let pt = aes_cbc_decrypt(&ct, &key, &iv).unwrap();
        assert_eq!(&pt[..], &plain[..]);
    }

    #[test]
    fn aes_ctr_roundtrip_is_stream_like() {
        let key = [0x33u8; 32];
        let iv = [0x44u8; 16];
        let plain = b"short";
        let ct = aes_ctr(plain, &key, &iv).unwrap();
        assert_eq!(ct.len(), plain.len());
        let pt = aes_ctr(&ct, &key, &iv).unwrap();
        assert_eq!(pt, plain);
    }

    #[test]
    fn pkcs7_strip() {
        let (out, ok) = strip_pkcs7(&[1, 2, 3, 4, 4, 4, 4]);
        assert!(ok);
        assert_eq!(out, vec![1, 2, 3]);
        let (out, ok) = strip_pkcs7(&[1, 2, 9]);
        assert!(!ok);
        assert_eq!(out, vec![1, 2, 9]);
    }

    #[test]
    fn base64_and_hex() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn detects_dex_magic() {
        assert!(looks_like_dex(b"dex\n035\0rest"));
        assert!(!looks_like_dex(b"PK\x03\x04rest"));
        assert!(looks_like_zip(b"PK\x03\x04rest"));
    }

    #[test]
    fn hash_known_vectors() {
        assert_eq!(
            HashAlg::Md5
                .digest(b"abc")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            HashAlg::Sha256
                .digest(b"abc")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
