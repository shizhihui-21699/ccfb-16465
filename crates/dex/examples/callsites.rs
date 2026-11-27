//! Dump method handles and call sites (lambda bootstrap data).
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&path).unwrap();
    let dex = unhusk_dex::parse(&data).unwrap();
    println!(
        "handles: {}  call sites: {}",
        dex.method_handles.len(),
        dex.call_sites.len()
    );
    for (i, h) in dex.method_handles.iter().enumerate() {
        let member = if h.is_field() {
            dex.fields.get(h.member as usize).map(|f| f.signature())
        } else {
            dex.methods.get(h.member as usize).map(|m| m.signature())
        };
        println!("  #{i} kind={} {}", h.kind, member.unwrap_or_default());
    }
    for (i, c) in dex.call_sites.iter().enumerate() {
        println!("  site #{i} bootstrap={:?}", c.bootstrap);
        for a in &c.args {
            println!("    arg {}", a.render());
        }
    }
}
