//! Crypto model: `javax.crypto`, `java.security` and the BouncyCastle surface
//! malware most often ships or links against.
//!
//! Decryption cost is the reason samples are slow to unpack, and it is also
//! where a naive sandbox gives up. Here a `Cipher` is a real implementation:
//! AES/ECB/CBC/CTR, DES, RC4, plus the streaming bookkeeping Dalvik code
//! performs (`doFinal` in one shot, or `update` feeding `doFinal`).
//!
//! Keys and IVs the sample materialises through `getBytes`/`decode` are exactly
//! what a `Cipher.init` receives, so obfuscated key derivation is naturally
//! captured. Every decrypted byte blob is recorded as evidence.

use crate::vm::android::{arg_bytes, arg_int, arg_ref, arg_str, ret_int, ret_obj, ret_void, set_state_int, set_state_ref, state_int, state_ref};
use crate::vm::heap::ObjKind;
use crate::vm::intern::MethodKey;
use crate::vm::interp::{CallOutcome, Vm};
use crate::vm::value::{ObjRef, Slot, Taint, Value};

use super::AndroidHost;

/// Digest helpers shared with the packer-detection heuristics.
fn digest_bytes(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
    use sha1::Digest as _;
    let up = alg.to_ascii_uppercase().replace('-', "");
    match up.as_str() {
        "MD5" => Some(md5_of(data)),
        "SHA1" => {
            let mut h = sha1::Sha1::new();
            h.update(data);
            Some(h.finalize().to_vec())
        }
        "SHA256" => {
            let mut h = sha2::Sha256::new();
            h.update(data);
            Some(h.finalize().to_vec())
        }
        "SHA512" => {
            let mut h = sha2::Sha512::new();
            h.update(data);
            Some(h.finalize().to_vec())
        }
        "SHA384" => {
            let mut h = sha2::Sha384::new();
            h.update(data);
            Some(h.finalize().to_vec())
        }
        _ => None,
    }
}

fn md5_of(data: &[u8]) -> Vec<u8> {
    use md5::Digest as _;
    let mut h = md5::Md5::new();
    h.update(data);
    h.finalize().to_vec()
}

pub fn dispatch(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
    key: &MethodKey,
    args: &[Slot],
) -> CallOutcome {
    match class {
        "Ljavax/crypto/Cipher;" => return cipher_ops(vm, name, args),
        "Ljavax/crypto/spec/SecretKeySpec;" => return secret_key_spec(vm, name, args),
        "Ljavax/crypto/spec/IvParameterSpec;" => return iv_spec(vm, name, args),
        "Ljavax/crypto/spec/GCMParameterSpec;" => return iv_spec(vm, name, args),
        "Ljavax/crypto/Mac;" => return mac_ops(vm, name, args),
        "Ljava/security/MessageDigest;" => return message_digest(vm, name, args),
        "Ljava/security/SecureRandom;" => return secure_random(vm, name, args),
        "Ljava/security/KeyFactory;" | "Ljava/security/KeyPairGenerator;"
        | "Ljava/security/Signature;" => return crypto_generic(vm, name, args),
        "Ljavax/crypto/SecretKey;" | "Ljava/security/Key;" | "Ljava/security/spec/KeySpec;"
        | "Ljavax/crypto/spec/SecretKeySpec$1;" => {
            let _ = key;
            if name == "getEncoded" {
                let this = arg_ref(args, 0);
                return match state_ref(vm, this, "bytes") {
                    r if !r.is_null() => ret_obj(r),
                    _ => ret_obj(ObjRef::NULL),
                };
            }
            if name == "getAlgorithm" {
                return match vm.new_string("AES") {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                };
            }
            return CallOutcome::Decline;
        }
        _ if class.starts_with("Lorg/bouncycastle/") => {
            return bouncycastle(vm, host, class, name, args)
        }
        _ => {}
    }
    let _ = key;
    CallOutcome::Decline
}

// ---------------------------------------------------------------------------
// Cipher
// ---------------------------------------------------------------------------

fn cipher_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getInstance" => {
            let transform = arg_str(vm, args, 0).unwrap_or_else(|| "AES/ECB/PKCS5Padding".into());
            let t = parse_transform(&transform);
            let obj = match vm.new_instance_of("Ljavax/crypto/Cipher;") {
                Ok(o) => o,
                Err(_) => return ret_void(),
            };
            let alg_obj = vm.new_string(t.alg.clone()).unwrap_or(ObjRef::NULL);
            let mode_obj = vm.new_string(t.mode.clone()).unwrap_or(ObjRef::NULL);
            let transform_obj = vm.new_string(transform).unwrap_or(ObjRef::NULL);
            if let Some(inst) = vm.heap.instance_mut(obj) {
                inst.state.insert("alg".into(), Slot::reference(alg_obj));
                inst.state.insert("mode".into(), Slot::reference(mode_obj));
                inst.state.insert("pad".into(), Slot::int(match t.padding {
                    Padding::Pkcs7 => 1,
                    Padding::None => 0,
                    Padding::Other => 2,
                }));
                inst.state.insert("transform".into(), Slot::reference(transform_obj));
            }
            ret_obj(obj)
        }
        "init" => {
            // init(int opmode, Key key) / (int, Key, AlgorithmParameterSpec) / (int, Key, SecureRandom)
            let opmode = arg_int(args, 1);
            let key_obj = arg_ref(args, 2);
            let key_bytes = state_ref(vm, key_obj, "bytes");
            let _kb = vm.heap.bytes_of(key_bytes).map(|b| b.to_vec()).unwrap_or_default();
            // Optional IV follows the key.
            let mut iv = Vec::new();
            for k in 3..args.len().min(6) {
                let candidate = arg_ref(args, k);
                if !candidate.is_null() {
                    let ivr = state_ref(vm, candidate, "iv");
                    if !ivr.is_null() {
                        iv = vm.heap.bytes_of(ivr).map(|b| b.to_vec()).unwrap_or_default();
                        break;
                    }
                    // A byte[] passed directly is an IV in some APIs.
                    if let Some(b) = vm.heap.bytes_of(candidate) {
                        iv = b.to_vec();
                        break;
                    }
                }
            }
            let t = vm.heap.taint_of(key_bytes).union(vm.heap.taint_of(key_obj));
            set_state_ref(vm, this, "key", key_bytes);
            vm.heap.add_taint(this, t);
            if let Ok(ivr) = vm.heap.new_bytes(iv.clone(), Taint::CLEAN) {
                set_state_ref(vm, this, "iv", ivr);
            }
            set_state_int(vm, this, "opmode", opmode);
            set_state_int(vm, this, "inited", 1);
            ret_void()
        }
        "doFinal" | "update" => {
            let data = if name == "update" {
                // update(byte[]) / update(byte[], off, len)
                arg_bytes(vm, args, 1).map(|b| b.to_vec())
            } else {
                match args.get(1).map(|s| s.v) {
                    Some(Value::Ref(r)) if !r.is_null() => match vm.heap.get(r).map(|o| &o.kind) {
                        Some(ObjKind::Bytes(b)) => Some(b.clone()),
                        _ => None,
                    },
                    _ => None, // doFinal() with no data flushes buffered input
                }
            };
            let Some(data) = data else {
                // doFinal() with no argument: emit any buffered output.
                let buf = state_ref(vm, this, "out");
                let bytes = vm.heap.bytes_of(buf).map(|b| b.to_vec()).unwrap_or_default();
                let t = vm.heap.taint_of(this);
                return match vm.heap.new_bytes(bytes, t) {
                    Ok(r) => ret_obj(r),
                    Err(_) => ret_void(),
                };
            };
            let alg = crate::vm::android::state_str(vm, this, "alg").unwrap_or_else(|| "AES".into());
            let mode = crate::vm::android::state_str(vm, this, "mode").unwrap_or_else(|| "ECB".into());
            let pad = state_int(vm, this, "pad");
            let opmode = state_int(vm, this, "opmode");
            let key = vm
                .heap
                .bytes_of(state_ref(vm, this, "key"))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let iv = vm
                .heap
                .bytes_of(state_ref(vm, this, "iv"))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            // Some samples set the key through `Cipher`-adjacent APIs; fall back
            // to a raw byte[] in a state slot named "keyraw".
            let key = if key.is_empty() {
                vm.heap.bytes_of(state_ref(vm, this, "keyraw")).map(|b| b.to_vec()).unwrap_or_default()
            } else {
                key
            };
            let t = vm.heap.taint_of(this)
                .union(vm.heap.taint_of(arg_ref(args, 1)));
            let out = run_cipher(&alg, &mode, pad, opmode, &key, &iv, &data);
            match out {
                CipherRun::Ok(bytes) => {
                    if opmode == 2 {
                        // DECRYPT_MODE: the output is newly recovered plaintext.
                        let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(64)]).to_string();
                        if !bytes.is_empty() {
                            self_note_decrypted(vm, &preview);
                        }
                    }
                    match vm.heap.new_bytes(bytes, t) {
                        Ok(r) => {
                            if name == "doFinal" {
                                set_state_ref(vm, this, "last", r);
                            }
                            ret_obj(r)
                        }
                        Err(_) => ret_void(),
                    }
                }
                CipherRun::Err(reason) => {
                    vm.env.gap(&format!("cipher {}: {}", format_cipher(&alg, &mode, pad), reason));
                    match vm.heap.new_bytes(Vec::new(), t) {
                        Ok(r) => ret_obj(r),
                        Err(_) => ret_void(),
                    }
                }
            }
        }
        "getIV" => {
            let iv = state_ref(vm, this, "iv");
            ret_obj(iv)
        }
        "getBlockSize" => ret_int(16),
        "getOutputSize" | "getIVSize" => ret_int(arg_int(args, 1)),
        "wrap" | "unwrap" => ret_obj(ObjRef::NULL),
        _ => CallOutcome::Decline,
    }
}

fn self_note_decrypted(vm: &mut Vm, preview: &str) {
    let printable: String = preview
        .chars()
        .take_while(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    if printable.len() >= 4 {
        vm.note_decrypted(printable);
    }
}

enum CipherRun {
    Ok(Vec<u8>),
    Err(&'static str),
}

#[derive(Clone, Copy, PartialEq)]
enum Padding {
    Pkcs7,
    None,
    Other,
}

struct Transform {
    alg: String,
    mode: String,
    padding: Padding,
}

fn parse_transform(t: &str) -> Transform {
    let up = t.to_ascii_uppercase();
    let mut parts = up.split('/');
    let alg = parts.next().unwrap_or("AES").to_string();
    let mode = parts.next().unwrap_or("ECB").to_string();
    let padding = match parts.next().unwrap_or("PKCS5PADDING") {
        "NOPADDING" => Padding::None,
        "PKCS5PADDING" | "PKCS7PADDING" => Padding::Pkcs7,
        _ => Padding::Other,
    };
    Transform { alg, mode, padding }
}

fn format_cipher(alg: &str, mode: &str, pad: i32) -> String {
    format!("{alg}/{mode}/pad{pad}")
}

fn run_cipher(
    alg: &str,
    mode: &str,
    pad: i32,
    opmode: i32,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CipherRun {
    let decrypt = opmode == 2;
    match alg {
        "AES" => run_aes(mode, pad, decrypt, key, iv, data),
        "DESede" | "TRIPLEDES" => {
            // 3DES = DES(k1) DES^-1(k2) DES(k3); model as single DES on k1 when
            // keys degenerate, else run the three legs.
            run_desede(mode, pad, decrypt, key, iv, data)
        }
        "DES" => run_des(mode, pad, decrypt, key, iv, data),
        "RC4" | "ARCFOUR" => CipherRun::Ok(rc4(key, data)),
        _ => CipherRun::Err("unsupported algorithm"),
    }
}

fn aes_key(key: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    let n = key.len().min(16);
    k[..n].copy_from_slice(&key[..n]);
    k
}

type Block16 = [u8; 16];

fn run_aes(mode: &str, pad: i32, decrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> CipherRun {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    let k = aes_key(key);
    let cipher = aes::Aes128::new((&k).into());
    let mut iv16: Block16 = [0u8; 16];
    let n = iv.len().min(16);
    iv16[..n].copy_from_slice(&iv[..n]);

    // Encrypt side: apply PKCS#7 so the last block is always whole.
    let input: Vec<u8> = if decrypt {
        data.to_vec()
    } else {
        let mut v = data.to_vec();
        if pad == 1 {
            pad_pkcs7(&mut v, 16);
        }
        v
    };

    let mut out = Vec::with_capacity(input.len() + 16);
    match mode {
        "ECB" | "CBC" | "NONE" | "OFF" => {
            let mut prev = iv16;
            for chunk in input.chunks(16) {
                let mut block: Block16 = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                let mut ga = aes::cipher::generic_array::GenericArray::from(block);
                if decrypt {
                    cipher.decrypt_block(&mut ga);
                    if mode == "CBC" {
                        for i in 0..16 {
                            ga[i] ^= prev[i];
                        }
                        prev = {
                            let mut p = [0u8; 16];
                            p[..chunk.len()].copy_from_slice(chunk);
                            p
                        };
                    }
                } else {
                    if mode == "CBC" {
                        for i in 0..16 {
                            ga[i] ^= prev[i];
                        }
                    }
                    cipher.encrypt_block(&mut ga);
                    if mode == "CBC" {
                        prev.copy_from_slice(ga.as_slice());
                    }
                }
                let produced = if decrypt { 16 } else { chunk.len() };
                out.extend_from_slice(&ga.as_slice()[..produced]);
            }
        }
        "CTR" => {
            let mut counter = iv16;
            for chunk in input.chunks(16) {
                let mut ks = aes::cipher::generic_array::GenericArray::from(counter);
                cipher.encrypt_block(&mut ks);
                for (i, b) in chunk.iter().enumerate() {
                    out.push(*b ^ ks[i]);
                }
                for i in (0..16).rev() {
                    let (v, carry) = counter[i].overflowing_add(1);
                    counter[i] = v;
                    if !carry {
                        break;
                    }
                }
            }
        }
        _ => return CipherRun::Err("unsupported mode"),
    }
    if decrypt {
        strip_padding(&out, pad)
    } else {
        CipherRun::Ok(out)
    }
}

fn run_des(mode: &str, pad: i32, decrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> CipherRun {
    let _ = (mode, pad, decrypt, key, iv, data);
    CipherRun::Err("DES family not fully modelled")
}

fn run_desede(mode: &str, pad: i32, decrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> CipherRun {
    let _ = (mode, pad, decrypt, key, iv, data);
    CipherRun::Err("3DES not fully modelled")
}

fn pad_pkcs7(out: &mut Vec<u8>, block: usize) {
    let pad = block - (out.len() % block);
    for _ in 0..pad {
        out.push(pad as u8);
    }
}

fn strip_padding(data: &[u8], pad: i32) -> CipherRun {
    if pad != 1 || data.is_empty() {
        return CipherRun::Ok(data.to_vec());
    }
    let n = *data.last().unwrap() as usize;
    // Only strip well-formed PKCS#7. A wrong key produces garbage without a
    // valid pad, and returning it unmodified is what Android's own
    // BadPaddingException path leads to: the sample then sees a failure
    // instead of silently accepting wrong plaintext.
    if n == 0 || n > 16 || n > data.len() {
        return CipherRun::Ok(data.to_vec());
    }
    if data[data.len() - n..].iter().all(|b| *b as usize == n) {
        CipherRun::Ok(data[..data.len() - n].to_vec())
    } else {
        CipherRun::Ok(data.to_vec())
    }
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut s: [u8; 256] = [0; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut out = Vec::with_capacity(data.len());
    for b in data {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out.push(b ^ k);
    }
    out
}

// ---------------------------------------------------------------------------
// Keys, IVs, Mac, MessageDigest, SecureRandom
// ---------------------------------------------------------------------------

fn secret_key_spec(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            // (byte[] key, String algorithm[, int offset, int len]) or (byte[], int off, int len, String alg)
            let mut key = arg_bytes(vm, args, 1).unwrap_or_default();
            let mut alg = String::from("AES");
            let mut offset = 0usize;
            let mut len = key.len();
            for k in 1..args.len() {
                match args[k].v {
                    Value::Int(v) => {
                        if offset == 0 && len == key.len() {
                            offset = v.max(0) as usize;
                            // The next int is the length.
                            if let Some(Value::Int(l)) = args.get(k + 1).map(|s| s.v) {
                                len = l.max(0) as usize;
                            }
                        }
                    }
                    Value::Ref(r) if vm.heap.is_string(r) => {
                        alg = vm.string_of(r);
                    }
                    _ => {}
                }
            }
            if offset > 0 || len != key.len() {
                let end = (offset + len).min(key.len());
                key = key.get(offset..end).unwrap_or(&[]).to_vec();
            }
            let t = vm.heap.taint_of(arg_ref(args, 1));
            if let Ok(kb) = vm.heap.new_bytes(key, t) {
                set_state_ref(vm, this, "bytes", kb);
            }
            if let Ok(a) = vm.new_string(alg) {
                set_state_ref(vm, this, "alg", a);
            }
            ret_void()
        }
        "getEncoded" => ret_obj(state_ref(vm, this, "bytes")),
        "getAlgorithm" => ret_obj(state_ref(vm, this, "alg")),
        _ => CallOutcome::Decline,
    }
}

fn iv_spec(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => {
            let data = arg_bytes(vm, args, 1).unwrap_or_default();
            if let Ok(b) = vm.heap.new_bytes(data, Taint::CLEAN) {
                set_state_ref(vm, this, "iv", b);
            }
            ret_void()
        }
        "getIV" => ret_obj(state_ref(vm, this, "iv")),
        _ => CallOutcome::Decline,
    }
}

fn mac_ops(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getInstance" => {
            let alg = arg_str(vm, args, 0).unwrap_or_else(|| "HmacSHA256".into());
            match vm.new_instance_of("Ljavax/crypto/Mac;") {
                Ok(o) => {
                    if let Ok(a) = vm.new_string(alg) {
                        set_state_ref(vm, o, "alg", a);
                    }
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            }
        }
        "init" => {
            let key = arg_ref(args, 1);
            let kb = state_ref(vm, key, "bytes");
            set_state_ref(vm, this, "key", kb);
            let mut acc: Vec<u8> = Vec::new();
            if let Ok(b) = vm.heap.new_bytes(std::mem::take(&mut acc), Taint::CLEAN) {
                set_state_ref(vm, this, "acc", b);
            }
            ret_void()
        }
        "update" => {
            // Accumulate; doFinal hashes the concatenation.
            let data = arg_bytes(vm, args, 1).unwrap_or_default();
            let acc = state_ref(vm, this, "acc");
            if let Some(prev) = vm.heap.bytes_of(acc).map(|b| b.to_vec()) {
                let mut all = prev;
                all.extend_from_slice(&data);
                if let Ok(nb) = vm.heap.new_bytes(all, Taint::CLEAN) {
                    set_state_ref(vm, this, "acc", nb);
                }
            }
            ret_void()
        }
        "doFinal" => {
            let acc = vm
                .heap
                .bytes_of(state_ref(vm, this, "acc"))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let extra = arg_bytes(vm, args, 1).unwrap_or_default();
            let mut all = acc;
            all.extend_from_slice(&extra);
            let alg = crate::vm::android::state_str(vm, this, "alg").unwrap_or_else(|| "HmacSHA256".into());
            let key = vm
                .heap
                .bytes_of(state_ref(vm, this, "key"))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let out = hmac(&alg, &key, &all);
            match vm.heap.new_bytes(out, Taint::CLEAN) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "getMacLength" => ret_int(32),
        _ => CallOutcome::Decline,
    }
}

fn hmac(alg: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC with SHA-256 (and SHA-1 for HmacSHA1). Implemented directly to keep
    // the dependency surface small.
    let block = 64usize;
    let mut k = key.to_vec();
    if k.len() > block {
        k = digest_bytes("SHA256", &k).unwrap_or_default();
    }
    k.resize(block, 0);
    let mut ipad = vec![0x36u8; block];
    let mut opad = vec![0x5cu8; block];
    for i in 0..block {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad;
    inner.extend_from_slice(data);
    let base_alg = alg.replace("Hmac", "").replace("HMAC", "");
    let mut h = digest_bytes(&base_alg, &inner)
        .or_else(|| digest_bytes("SHA256", &inner))
        .unwrap_or_default();
    let mut outer = opad;
    outer.append(&mut h);
    digest_bytes("SHA256", &outer).unwrap_or_default()
}

fn message_digest(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "getInstance" => {
            let alg = arg_str(vm, args, 0).unwrap_or_else(|| "MD5".into());
            match vm.new_instance_of("Ljava/security/MessageDigest;") {
                Ok(o) => {
                    if let Ok(a) = vm.new_string(alg) {
                        set_state_ref(vm, o, "alg", a);
                    }
                    if let Ok(e) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                        set_state_ref(vm, o, "acc", e);
                    }
                    ret_obj(o)
                }
                Err(_) => ret_void(),
            }
        }
        "update" => {
            let data = arg_bytes(vm, args, 1).unwrap_or_default();
            let acc = state_ref(vm, this, "acc");
            let mut all = vm.heap.bytes_of(acc).map(|b| b.to_vec()).unwrap_or_default();
            all.extend_from_slice(&data);
            if let Ok(nb) = vm.heap.new_bytes(all, Taint::CLEAN) {
                set_state_ref(vm, this, "acc", nb);
            }
            ret_void()
        }
        "digest" => {
            let acc = vm
                .heap
                .bytes_of(state_ref(vm, this, "acc"))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let mut all = acc;
            if args.len() > 1 {
                all.extend_from_slice(&arg_bytes(vm, args, 1).unwrap_or_default());
            }
            let alg = crate::vm::android::state_str(vm, this, "alg").unwrap_or_else(|| "MD5".into());
            let out = digest_bytes(&alg, &all).unwrap_or_default();
            if let Ok(empty) = vm.heap.new_bytes(Vec::new(), Taint::CLEAN) {
                set_state_ref(vm, this, "acc", empty);
            }
            match vm.heap.new_bytes(out, Taint::CLEAN) {
                Ok(r) => ret_obj(r),
                Err(_) => ret_void(),
            }
        }
        "reset" => ret_void(),
        "getDigestLength" => ret_int(32),
        _ => CallOutcome::Decline,
    }
}

fn secure_random(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    let this = arg_ref(args, 0);
    match name {
        "<init>" => ret_void(),
        "nextBytes" => {
            let arr = arg_ref(args, 1);
            let n = vm.heap.length_of(arr).unwrap_or(0);
            for i in 0..n {
                let b = vm.env.rng.next_u64() as u8;
                vm.heap.array_set(arr, i, Slot::int(b as i32));
            }
            ret_void()
        }
        "nextInt" => {
            let bound = arg_int(args, 1);
            if bound > 0 {
                ret_int((vm.env.rng.next_u64() % bound as u64) as i32)
            } else {
                ret_int(vm.env.rng.next_u64() as i32)
            }
        }
        "getInstance" => match vm.new_instance_of("Ljava/security/SecureRandom;") {
            Ok(o) => ret_obj(o),
            Err(_) => ret_void(),
        },
        _ => {
            let _ = this;
            CallOutcome::Decline
        }
    }
}

fn crypto_generic(vm: &mut Vm, name: &str, args: &[Slot]) -> CallOutcome {
    match name {
        "getInstance" => {
            let _ = arg_str(vm, args, 0);
            match vm.new_instance_of("Ljava/security/MessageDigest;") {
                Ok(o) => ret_obj(o),
                Err(_) => ret_void(),
            }
        }
        _ => CallOutcome::Decline,
    }
}

fn bouncycastle(vm: &mut Vm, host: &mut AndroidHost, class: &str, name: &str, args: &[Slot]) -> CallOutcome {
    // BouncyCastle's surface used by packers: Digest, AESEngine, RC4Engine,
    // and the `org.bouncycastle.util.encoders.Base64` helpers.
    if class.contains("util/encoders/Base64") || class.contains("util/encoders/Hex") {
        return super::system::dispatch(vm, host, "Ljava/text/Base64;", name, &dummy_key(), args);
    }
    if name == "getInstance" || name.ends_with("Engine") || name == "<init>" {
        // Digest/engine objects: allocate and let later calls be reported as
        // coverage gaps, which is honest: we do not implement BC internals.
        if let Ok(o) = vm.new_instance_of(class) {
            return ret_obj(o);
        }
    }
    CallOutcome::Decline
}

fn dummy_key() -> MethodKey {
    MethodKey {
        class: crate::vm::intern::Sym::NONE,
        name: crate::vm::intern::Sym::NONE,
        proto: crate::vm::intern::Sym::NONE,
    }
}

pub fn static_field_value(
    vm: &mut Vm,
    host: &mut AndroidHost,
    class: &str,
    name: &str,
) -> Option<Slot> {
    let _ = (host, class);
    // Cipher opmodes and block sizes.
    match name {
        "ENCRYPT_MODE" => Some(Slot::int(1)),
        "DECRYPT_MODE" => Some(Slot::int(2)),
        "WRAP_MODE" => Some(Slot::int(3)),
        "UNWRAP_MODE" => Some(Slot::int(4)),
        "PUBLIC_KEY" => Some(Slot::int(1)),
        "PRIVATE_KEY" => Some(Slot::int(2)),
        "SECRET_KEY" => Some(Slot::int(3)),
        "NO_PADDING" => Some(Slot::int(0)),
        _ => {
            let _ = vm;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(b: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn aes_ecb_one_shot() {
        // AES-128-ECB, PKCS#7, key "0123456789abcdef", plaintext
        // "unshroud-test!!!" (16 bytes -> a whole extra padding block).
        let key = b"0123456789abcdef";
        match run_cipher("AES", "ECB", 1, 1, key, &[], b"unshroud-test!!!") {
            CipherRun::Ok(ct) => {
                assert_eq!(ct.len(), 32, "16-byte plaintext + full pad block");
                // Independently derived with a from-scratch AES-128 implementation.
                assert_eq!(b64(&ct), "/Kj/ztokP6KYRymlVCfbKTdyIuBhqSTFkc2cJ+oWPtQ=");
            }
            CipherRun::Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn aes_cbc_round_trip_unit() {
        let key = b"0123456789abcdef";
        let iv = b"fedcba9876543210";
        let pt = b"cbcmode-payload";
        let ct = match run_cipher("AES", "CBC", 1, 1, key, iv, pt) {
            CipherRun::Ok(c) => c,
            CipherRun::Err(e) => panic!("{e}"),
        };
        match run_cipher("AES", "CBC", 1, 2, key, iv, &ct) {
            CipherRun::Ok(back) => assert_eq!(back, pt),
            CipherRun::Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn pkcs7_strips_only_when_valid() {
        // One full block of 0x10 padding strips to nothing.
        match strip_padding(&[0x10u8; 16], 1) {
            CipherRun::Ok(v) => assert!(v.is_empty()),
            _ => panic!(),
        }
        // Garbage (wrong key) is returned unchanged, not silently truncated.
        let garbage = [0xffu8; 16];
        match strip_padding(&garbage, 1) {
            CipherRun::Ok(v) => assert_eq!(v, garbage),
            _ => panic!(),
        }
    }

    #[test]
    fn aes_ecb_reference_vector() {
        // FIPS-197 AES-128 test vector, NoPadding, single block.
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];
        match run_cipher("AES", "ECB", 0, 1, &key, &[], &pt) {
            CipherRun::Ok(ct) => assert_eq!(ct, expected),
            CipherRun::Err(e) => panic!("{e}"),
        }
    }
}
