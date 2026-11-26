//! Crypto model correctness: decryption loops are where packers spend their
//! time and where a wrong implementation would produce a silently-wrong
//! payload. These check the model against known-answer vectors.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::vm::android::AndroidHost;
use unshroud::vm::env::{Environment, Persona};
use unshroud::vm::interp::Vm;
use unshroud::vm::registry::Registry;

fn vm_with(dex: Vec<u8>) -> Vm {
    let mut reg = Registry::new();
    reg.add_image(Arc::new(DexFile::parse("classes.dex", dex).unwrap()), false);
    Vm::new(reg, Environment::new(Persona::retail_default()), 5_000_000, 10_000)
}

/// Returns the string a static `String NAME()` method produces.
fn run_string(vm: &mut Vm, class: &str, method: &str) -> Option<String> {
    let mut host = AndroidHost::new();
    let entry = vm.find_method(class, method, "()Ljava/lang/String;")?;
    let r = vm.execute(&mut host, entry, vec![]).ok()?;
    vm.str_of_slot(r)
}

const SRC: &str = r#"
package com.example.crypto;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import android.util.Base64;

public class Crypto {
    static final byte[] KEY = "0123456789abcdef".getBytes();  // AES-128 key

    // AES-128/ECB/PKCS5 with a known key and plaintext.
    public static String aesEcb() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        byte[] ct = c.doFinal("unshroud-test!!!".getBytes("UTF-8"));
        return Base64.encodeToString(ct, Base64.NO_WRAP);
    }

    // AES-128/CBC/PKCS5, decrypting back to the known plaintext.
    public static String aesCbcRoundTrip() throws Exception {
        byte[] iv = "fedcba9876543210".getBytes();
        Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"),
                 new javax.crypto.spec.IvParameterSpec(iv));
        byte[] ct = enc.doFinal("cbcmode-payload".getBytes("UTF-8"));

        Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"),
                 new javax.crypto.spec.IvParameterSpec(iv));
        byte[] pt = dec.doFinal(ct);
        return new String(pt, "UTF-8");
    }

    public static String md5() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] h = md.digest("abc".getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    public static String sha256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest("abc".getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    public static String b64() {
        return Base64.encodeToString("hello, world".getBytes(), Base64.NO_WRAP);
    }

    public static String b64decode() {
        byte[] d = Base64.decode("aGVsbG8sIHdvcmxk", Base64.NO_WRAP);
        return new String(d);
    }

    public static String rc4() throws Exception {
        // RC4 is not in the JDK but packers implement it in Java; check the
        // model's RC4 against the well-known "Key"/"Plaintext" vector.
        byte[] key = "Key".getBytes();
        byte[] data = "Plaintext".getBytes();
        byte[] out = Arc4.run(key, data);
        StringBuilder sb = new StringBuilder();
        for (byte b : out) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
"#;

/// An in-sample RC4 so the test exercises a pure-Java loop as well as the
/// model; this is the shape packers use when they do not trust the platform.
const ARC4: &str = r#"
package com.example.crypto;
public class Arc4 {
    public static byte[] run(byte[] key, byte[] data) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xff)) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        int i = 0; j = 0;
        byte[] out = new byte[data.length];
        for (int k = 0; k < data.length; k++) {
            i = (i + 1) & 0xff;
            j = (j + s[i]) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            out[k] = (byte) (data[k] ^ s[(s[i] + s[j]) & 0xff]);
        }
        return out;
    }
}
"#;

#[test]
fn aes_ecb_known_answer() {
    let Some(dex) = compile_sources_to_dex(&[("Crypto", SRC), ("Arc4", ARC4)]) else { return };
    let mut vm = vm_with(dex);
    assert_eq!(run_string(&mut vm, "Lcom/example/crypto/Crypto;", "aesEcb").as_deref(),
        Some("/Kj/ztokP6KYRymlVCfbKTdyIuBhqSTFkc2cJ+oWPtQ="));
}

#[test]
fn aes_cbc_round_trip() {
    let Some(dex) = compile_sources_to_dex(&[("Crypto", SRC), ("Arc4", ARC4)]) else { return };
    let mut vm = vm_with(dex);
    assert_eq!(
        run_string(&mut vm, "Lcom/example/crypto/Crypto;", "aesCbcRoundTrip").as_deref(),
        Some("cbcmode-payload")
    );
}

#[test]
fn digests_match_known_vectors() {
    let Some(dex) = compile_sources_to_dex(&[("Crypto", SRC), ("Arc4", ARC4)]) else { return };
    let mut vm = vm_with(dex);
    assert_eq!(
        run_string(&mut vm, "Lcom/example/crypto/Crypto;", "md5").as_deref(),
        Some("900150983cd24fb0d6963f7d28e17f72")
    );
    assert_eq!(
        run_string(&mut vm, "Lcom/example/crypto/Crypto;", "sha256").as_deref(),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn base64_round_trip() {
    let Some(dex) = compile_sources_to_dex(&[("Crypto", SRC), ("Arc4", ARC4)]) else { return };
    let mut vm = vm_with(dex);
    assert_eq!(run_string(&mut vm, "Lcom/example/crypto/Crypto;", "b64").as_deref(), Some("aGVsbG8sIHdvcmxk"));
    assert_eq!(
        run_string(&mut vm, "Lcom/example/crypto/Crypto;", "b64decode").as_deref(),
        Some("hello, world")
    );
}

#[test]
fn java_rc4_matches_reference() {
    let Some(dex) = compile_sources_to_dex(&[("Crypto", SRC), ("Arc4", ARC4)]) else { return };
    let mut vm = vm_with(dex);
    // RC4("Key", "Plaintext") = BB F3 16 E8 D9 40 AF 0A D3
    assert_eq!(
        run_string(&mut vm, "Lcom/example/crypto/Crypto;", "rc4").as_deref(),
        Some("bbf316e8d940af0ad3")
    );
}
