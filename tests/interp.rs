//! End-to-end interpreter tests against real DEX bytecode produced by `d8`.

mod support;

use std::sync::Arc;

use support::javadex::compile_to_dex;
use unshroud::dex::DexFile;
use unshroud::vm::env::{Environment, Persona};
use unshroud::vm::heap::Heap;
use unshroud::vm::interp::{Host, Vm};
use unshroud::vm::registry::Registry;
use unshroud::vm::value::Slot;

/// A host that provides just enough of `java.lang.System`/`String` to run
/// arithmetic and string tests.
struct TestHost;

impl Host for TestHost {
    fn call(
        &mut self,
        vm: &mut Vm,
        key: &unshroud::vm::intern::MethodKey,
        _args: &[Slot],
    ) -> unshroud::vm::interp::CallOutcome {
        use unshroud::vm::interp::CallOutcome;
        let name = vm.sym_str(key.name).to_string();
        match name.as_str() {
            "exit" => CallOutcome::Value(Slot::default()),
            _ => CallOutcome::Decline,
        }
    }
    fn static_field(
        &mut self,
        vm: &mut Vm,
        key: &unshroud::vm::intern::FieldKey,
    ) -> unshroud::vm::interp::CallOutcome {
        let _ = vm;
        let _ = key;
        unshroud::vm::interp::CallOutcome::Decline
    }
    fn construct(
        &mut self,
        vm: &mut Vm,
        class: unshroud::vm::intern::Sym,
    ) -> unshroud::vm::interp::CallOutcome {
        let obj = vm.heap.new_instance(class).unwrap();
        unshroud::vm::interp::CallOutcome::Value(Slot::reference(obj))
    }
    fn native_call(
        &mut self,
        _vm: &mut Vm,
        _key: &unshroud::vm::intern::MethodKey,
        _args: &[Slot],
    ) -> unshroud::vm::interp::CallOutcome {
        unshroud::vm::interp::CallOutcome::Decline
    }
}

fn vm_for(dex_bytes: Vec<u8>) -> (Vm, TestHost) {
    let dex = DexFile::parse("classes.dex", dex_bytes).expect("parse dex");
    let mut registry = Registry::new();
    registry.add_image(Arc::new(dex), false);
    let env = Environment::new(Persona::retail_default());
    (Vm::new(registry, env, 5_000_000, 20_000), TestHost)
}

/// Run a static `int NAME()` method and return its integer result.
fn run_int(vm: &mut Vm, host: &mut TestHost, class: &str, method: &str) -> Option<i32> {
    let entry = vm.find_method(class, method, "()I")?;
    let slot = vm.execute(host, entry, Vec::new()).ok()?;
    Some(slot.v.as_int())
}

#[test]
fn interprets_arithmetic_and_loops() {
    let Some(dex) = compile_to_dex(
        "Arith",
        r#"
public class Arith {
    public static int sum(int n) {
        int s = 0;
        for (int i = 0; i < n; i++) {
            s += i;
        }
        return s;
    }
    public static int mix() {
        int a = 17, b = 5;
        int c = (a * b) + (a / b) + (a % b) - (a << 2) + (a >> 1) + (a >>> 1);
        c ^= (a | b) & (a ^ b);
        long l = (long) a * 1000000007L;
        return c + (int) (l % 13);
    }
    public static int branchy(int x) {
        int r;
        switch (x) {
            case 1: r = 10; break;
            case 2: r = 20; break;
            case 7: r = 70; break;
            default: r = -1;
        }
        if (r > 15 && x != 1) { r += 3; } else if (r < 0) { r = 42; }
        return r;
    }
}
"#,
    ) else {
        eprintln!("skipping: no d8/javac");
        return;
    };
    let (mut vm, mut host) = vm_for(dex);
    assert_eq!(run_int(&mut vm, &mut host, "LArith;", "sum"), None); // needs an int arg
    // sum takes an argument; call via a dedicated no-arg check instead.
    let entry = vm.find_method("LArith;", "sum", "(I)I").unwrap();
    let r = vm.execute(&mut host, entry, vec![Slot::int(100)]).unwrap();
    assert_eq!(r.v.as_int(), 4950);

    assert_eq!(run_int(&mut vm, &mut host, "LArith;", "mix"), Some(compute_mix()));
    assert_eq!(run_int(&mut vm, &mut host, "LArith;", "branchy"), None);
    let entry = vm.find_method("LArith;", "branchy", "(I)I").unwrap();
    for (x, want) in [(99, 42), (1, 10), (2, 23), (7, 73)] {
        let r = vm.execute(&mut host, entry, vec![Slot::int(x)]).unwrap();
        assert_eq!(r.v.as_int(), want, "branchy({x})");
    }
}

/// The same arithmetic spelled out in Rust, to check the interpreter's result.
fn compute_mix() -> i32 {
    let a: i32 = 17;
    let b: i32 = 5;
    let mut c = (a * b) + (a / b) + (a % b) - (a << 2) + (a >> 1) + ((a as u32) >> 1) as i32;
    c ^= (a | b) & (a ^ b);
    let l = (a as i64) * 1000000007i64;
    c.wrapping_add((l % 13) as i32)
}

#[test]
fn interprets_exceptions_and_catches() {
    let Some(dex) = compile_to_dex(
        "Thrower",
        r#"
public class Thrower {
    static int boom(int[] a, int i) {
        try {
            return a[i];
        } catch (ArrayIndexOutOfBoundsException e) {
            return -1;
        } catch (Exception e) {
            return -2;
        }
    }
    static int div(int x) {
        try {
            return 100 / x;
        } catch (ArithmeticException e) {
            return -3;
        }
    }
    static int nested(int depth) {
        if (depth == 0) throw new IllegalStateException("bottom");
        try {
            return nested(depth - 1);
        } catch (IllegalStateException e) {
            return depth * 10;
        }
    }
}
"#,
    ) else {
        return;
    };
    let (mut vm, mut host) = vm_for(dex);
    let mkarr = vm.new_array_of("I", 3).unwrap();
    let boom = vm.find_method("LThrower;", "boom", "([II)I").unwrap();
    let r = vm
        .execute(&mut host, boom, vec![Slot::reference(mkarr), Slot::int(1)])
        .unwrap();
    assert_eq!(r.v.as_int(), 0);
    let r = vm
        .execute(&mut host, boom, vec![Slot::reference(mkarr), Slot::int(9)])
        .unwrap();
    assert_eq!(r.v.as_int(), -1);

    let div = vm.find_method("LThrower;", "div", "(I)I").unwrap();
    let r = vm.execute(&mut host, div, vec![Slot::int(4)]).unwrap();
    assert_eq!(r.v.as_int(), 25);
    let r = vm.execute(&mut host, div, vec![Slot::int(0)]).unwrap();
    assert_eq!(r.v.as_int(), -3);

    let nested = vm.find_method("LThrower;", "nested", "(I)I").unwrap();
    let r = vm.execute(&mut host, nested, vec![Slot::int(3)]).unwrap();
    assert_eq!(r.v.as_int(), 10);
}

#[test]
fn interprets_fields_arrays_and_statics() {
    let Some(dex) = compile_to_dex(
        "State",
        r#"
public class State {
    static int counter;
    static final String TAG = "state";
    int value;
    long big;
    byte[] buf = new byte[8];

    static int bump() { return ++counter; }
    int acc(int x) { value += x; return value; }
    long accBig(long x) { big += x; return big; }
    int checksum() {
        int s = 0;
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (byte) (i * 7 + 1);
            s = (s * 31 + (buf[i] & 0xff)) & 0xffff;
        }
        return s;
    }
    String tag() { return TAG + value; }
}
"#,
    ) else {
        return;
    };
    let (mut vm, mut host) = vm_for(dex);
    let bump = vm.find_method("LState;", "bump", "()I").unwrap();
    assert_eq!(vm.execute(&mut host, bump, vec![]).unwrap().v.as_int(), 1);
    assert_eq!(vm.execute(&mut host, bump, vec![]).unwrap().v.as_int(), 2);

    let ctor = vm.find_method("LState;", "<init>", "()V").unwrap();
    let obj_slot = vm.new_instance_of("LState;").unwrap();
    vm.execute(&mut host, ctor, vec![Slot::reference(obj_slot)]).unwrap();

    let acc = vm.find_method("LState;", "acc", "(I)I").unwrap();
    let r = vm.execute(&mut host, acc, vec![Slot::reference(obj_slot), Slot::int(30)]).unwrap();
    assert_eq!(r.v.as_int(), 30);
    let r = vm.execute(&mut host, acc, vec![Slot::reference(obj_slot), Slot::int(12)]).unwrap();
    assert_eq!(r.v.as_int(), 42);

    let cks = vm.find_method("LState;", "checksum", "()I").unwrap();
    let r = vm.execute(&mut host, cks, vec![Slot::reference(obj_slot)]).unwrap();
    let mut expect: i32 = 0;
    for i in 0..8i32 {
        let b = (i * 7 + 1) as u8;
        expect = (expect * 31 + b as i32) & 0xffff;
    }
    assert_eq!(r.v.as_int(), expect);
}

/// `Heap` is re-exported here only so the helper above can name its type.
#[allow(dead_code)]
fn _typecheck(_h: &Heap) {}
