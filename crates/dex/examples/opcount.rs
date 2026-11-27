fn main() {
    let path = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&path).unwrap();
    let dex = unhusk_dex::parse(&data).unwrap();
    let mut counts = std::collections::BTreeMap::new();
    let mut total = 0u64;
    for m in dex.all_methods() {
        if let Some(c) = &m.code {
            for i in &c.instructions {
                if i.kind == unhusk_dex::insn::InsnKind::Real {
                    *counts.entry(i.mnemonic()).or_insert(0u64) += 1;
                    total += 1;
                }
            }
        }
    }
    println!("total real instructions: {total}");
    for (k, v) in counts.iter().filter(|(k, _)| {
        k.contains("custom")
            || k.contains("polymorphic")
            || k.contains("method-handle")
            || k.contains("method-type")
    }) {
        println!("  {k}: {v}");
    }
    // Show the top 8 most common
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    println!("top: {:?}", &v[..8.min(v.len())]);
}
