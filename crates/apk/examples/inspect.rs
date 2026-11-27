use std::time::Instant;
fn main() {
    for path in std::env::args().skip(1) {
        let t = Instant::now();
        match unhusk_apk::Apk::open(std::path::Path::new(&path)) {
            Ok(apk) => {
                let m = &apk.manifest;
                println!("== {path}  ({} entries, {:.1} MiB uncompressed) in {:?}", apk.len(), apk.total_uncompressed() as f64/1048576.0, t.elapsed());
                println!("   package={} version={:?}/{:?} minSdk={:?} targetSdk={:?} debug={} app={:?} main={:?}",
                    m.package, m.version_name, m.version_code, m.min_sdk, m.target_sdk, m.debugabble, m.application_class, m.main_activity);
                if let Some(e) = &apk.manifest_error { println!("   manifest error: {e}"); }
                println!("   perms={} components={} (exported={})", m.permissions.len(), m.components.len(), m.components.iter().filter(|c| c.effectively_exported).count());
                println!("   dex={:?}", apk.dex_names());
                let libs: Vec<String> = apk.native_libs().into_iter().map(|(a,_)| a).collect();
                let mut uniq = libs.clone(); uniq.sort(); uniq.dedup();
                println!("   abis={:?}", uniq);
                for (name, dex) in apk.dex_files() {
                    match dex {
                        Ok(d) => println!("   {name}: classes={} methods={} strings={}", d.classes.len(), d.all_methods().len(), d.strings.len()),
                        Err(e) => println!("   {name}: ERROR {e}"),
                    }
                }
            }
            Err(e) => println!("== {path}: ERROR {e}"),
        }
    }
}
