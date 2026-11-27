//! Drive the AArch64 interpreter over a real compiled decryptor.
//!
//! Usage: cargo run -p unhusk-vm --example native -- <file.o|.so> <hexkey>

use unhusk_vm::native::aarch64::{Code, Machine};
use unhusk_vm::native::NativeLimits;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("path");
    let key = hex_decode(&args.next().expect("key"));
    let data = std::fs::read(&path).unwrap();
    let code = Code::from_elf(&data).expect("no executable segment");
    println!(
        "exec segment vaddr=0x{:x} size={} first={:08x}",
        code.vaddr,
        code.bytes.len(),
        code.first_word().unwrap_or(0)
    );

    let mut m = Machine::new(NativeLimits::default());
    // The machine's flat window starts at mem_base; code, buffer and key live
    // at distinct offsets inside it.
    m.write_mem(m.mem_base, code.bytes);
    // args: x0=buf, x1=len, x2=key
    const BUF: u64 = 0x1010_0000;
    const KEY: u64 = 0x1011_0000;
    let plain = b"the quick brown fox jumps over the lazy dog!";
    let mut enc = plain.to_vec();
    for i in 0..enc.len() {
        enc[i] ^= key[i & 3];
    }
    m.write_mem(BUF, &enc);
    m.write_mem(KEY, &key);
    m.regs[0] = BUF;
    m.regs[1] = plain.len() as u64;
    m.regs[2] = KEY;

    let out = m.run(m.mem_base + code.vaddr, &NativeLimits::default());
    println!("outcome: {out:?}");
    let restored = m
        .read_mem(BUF, plain.len())
        .map(|b| b.to_vec())
        .unwrap_or_default();
    println!("decrypted: {:?}", String::from_utf8_lossy(&restored));
    println!("matches  : {}", restored == plain);
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}
