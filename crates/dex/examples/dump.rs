use std::time::Instant;
fn main() {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).unwrap();
        let t = Instant::now();
        match unhusk_dex::parse(&data) {
            Ok(dex) => {
                let methods: usize = dex.classes.iter().map(|c| c.data.direct_methods.len() + c.data.virtual_methods.len()).sum();
                let insns: usize = dex.all_methods().iter().filter_map(|m| m.code.as_ref()).map(|c| c.instructions.len()).sum();
                println!("{path}: v{:03} classes={} methods={} insns={} strings={} in {:?}",
                    dex.version, dex.classes.len(), methods, insns, dex.strings.len(), t.elapsed());
            }
            Err(e) => println!("{path}: ERROR {e}"),
        }
    }
}
