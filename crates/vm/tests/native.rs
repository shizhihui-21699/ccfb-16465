//! Native emulation tests, driven by real compiler output.
//!
//! `fixtures/xor-decrypt-aarch64.o` is `fixtures/xor-decrypt.c` compiled with
//! clang for `--target=aarch64-linux-gnu -O1`. Using a real object file is the
//! point: it exercises the encodings a compiler actually emits (register
//! offset loads, `and` masks, `cbnz` loops) rather than ones we chose.

use unhusk_vm::native::aarch64::{Code, Machine};
use unhusk_vm::native::{NativeLimits, NativeOutcome};

/// Run the decryptor over `buf` with `key`, returning the in-place result.
fn run_decrypt(blob: &[u8], buf: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let code = Code::from_elf(blob)?;
    let mut m = Machine::new(NativeLimits::default());
    m.write_mem(m.mem_base, code.bytes);
    const BUF: u64 = 0x1010_0000;
    const KEY: u64 = 0x1011_0000;
    m.write_mem(BUF, buf);
    m.write_mem(KEY, key);
    m.regs[0] = BUF;
    m.regs[1] = buf.len() as u64;
    m.regs[2] = KEY;
    let out = m.run(m.mem_base + code.vaddr, &NativeLimits::default());
    assert!(
        matches!(out, NativeOutcome::Returned { .. }),
        "native run: {out:?}"
    );
    m.read_mem(BUF, buf.len()).map(|b| b.to_vec())
}

#[test]
fn runs_clang_compiled_xor_decryptor() {
    let blob = include_bytes!("fixtures/xor-decrypt-aarch64.o");
    let key = b"AK7Z";
    // The routine XORs in place, so feed it a buffer encrypted with the same key.
    let plain = b"the quick brown fox jumps over the lazy dog!";
    let mut enc = plain.to_vec();
    for (i, b) in enc.iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
    let out = run_decrypt(blob, &enc, key).expect("output buffer");
    assert_eq!(&out[..], &plain[..]);
}

#[test]
fn elf_parsing_rejects_non_aarch64() {
    assert!(Code::from_elf(b"not an elf at all").is_none());
    let mut fake = vec![0u8; 64];
    fake[0..4].copy_from_slice(b"\x7fELF");
    fake[4] = 2; // 64-bit
    fake[18] = 0x3E; // EM_X86_64
    assert!(Code::from_elf(&fake).is_none());
}
