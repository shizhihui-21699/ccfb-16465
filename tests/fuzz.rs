// Deterministic fuzz: mutate a valid DEX and confirm the parser never panics.
mod support;
use std::sync::Arc;
use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;

#[test]
fn dex_parser_never_panics_on_mutation() {
    let Some(base) = compile_sources_to_dex(&[("F", "package p; public class F { public static int g(int x){return x*2;} }")]) else { return };
    let mut x: u64 = 0x1234_5678_9abc_def0;
    let mut parsed = 0;
    let mut rejected = 0;
    for round in 0..3000 {
        let mut data = base.clone();
        // Corrupt a handful of bytes at random offsets (deterministic PRNG).
        let n = 1 + (x % 8) as usize;
        for _ in 0..n {
            x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
            let val = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
            if data.is_empty() { break; }
            let off = (val % data.len() as u64) as usize;
            data[off] = (val >> 32) as u8;
        }
        // Occasionally truncate.
        if round % 7 == 0 && data.len() > 16 {
            data.truncate(data.len() - (x % 16) as usize);
        }
        match DexFile::parse(format!("fuzz{round}"), data) {
            Ok(_) => parsed += 1,
            Err(_) => rejected += 1,
        }
    }
    eprintln!("parsed={parsed} rejected={rejected}");
    assert!(rejected > 0, "some mutations should be rejected");
    // The point of the test is that neither path panics.
    let _ = Arc::new(0);
}
