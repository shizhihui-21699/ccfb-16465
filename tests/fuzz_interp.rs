//! Fuzz the interpreter: mutate a valid method's bytecode and execute it. The
//! machine must return an error or a value, never panic — a panic in an
//! analysis tool is a denial of service against the whole triage queue.

mod support;

use std::sync::Arc;

use support::packed::compile_sources_to_dex;
use unshroud::dex::DexFile;
use unshroud::vm::android::AndroidHost;
use unshroud::vm::env::{Environment, Persona};
use unshroud::vm::interp::Vm;
use unshroud::vm::registry::Registry;
use unshroud::vm::value::Slot;

#[test]
fn mutated_bytecode_never_panics() {
    let src = r#"
package p;
public class Fuzz {
    public static int calc(int x) {
        int s = 0;
        for (int i = 0; i < x; i++) { s += i * 3 ^ (s >> 1); }
        if (s > 100) { s /= 2; } else { s *= 3; }
        try { return s / (x - 1); } catch (ArithmeticException e) { return -1; }
    }
}
"#;
    let Some(base) = compile_sources_to_dex(&[("Fuzz", src)]) else { return };
    let mut x: u64 = 0xdead_beef_cafe_0001;
    let mut runs = 0u32;
    let mut errors = 0u32;

    for _round in 0..400 {
        let mut data = base.clone();
        // Corrupt bytes inside the file, biased toward the code section.
        let n = 1 + (x % 6) as usize;
        for _ in 0..n {
            x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
            let val = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
            if data.is_empty() { break; }
            let off = (val % data.len() as u64) as usize;
            data[off] = (val >> 40) as u8;
        }
        let Ok(dex) = DexFile::parse("fuzz.dex", data) else { continue };
        let mut reg = Registry::new();
        reg.add_image(Arc::new(dex), false);
        let mut vm = Vm::new(reg, Environment::new(Persona::retail_default()), 50_000, 2_000);
        let Some(e) = vm.find_method("Lp/Fuzz;", "calc", "(I)I") else { continue };
        let mut host = AndroidHost::new();
        runs += 1;
        match vm.execute(&mut host, e, vec![Slot::int(7)]) {
            Ok(_) => {}
            Err(_) => errors += 1,
        }
    }
    eprintln!("runs={runs} errors={errors}");
    // Reaching here without a panic is the assertion; a mutation that broke
    // linking simply produced no method to run.
}
