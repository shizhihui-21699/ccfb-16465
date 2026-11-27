//! APK-level robustness.
//!
//! An analysis queue contains damaged, truncated and deliberately malformed
//! files every day. The contract is narrow and absolute: `Apk::from_bytes`
//! and the DEX parse either succeed or return an error — never panic, never
//! run for an unbounded time, never allocate proportional to a claimed count.

use std::io::Write;

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        for (name, data) in entries {
            z.start_file(*name, opts).unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

fn dex_header_with(patch: &[(usize, u32)]) -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    d[0..8].copy_from_slice(b"dex\n035\0");
    let size = d.len() as u32;
    d[0x20..0x24].copy_from_slice(&size.to_le_bytes());
    d[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
    d[0x28..0x2c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    for (off, v) in patch {
        d[*off..*off + 4].copy_from_slice(&v.to_le_bytes());
    }
    d
}

#[test]
fn not_a_zip_is_an_error_not_a_panic() {
    assert!(unhusk_apk::Apk::from_bytes(b"definitely not a zip".to_vec()).is_err());
    assert!(unhusk_apk::Apk::from_bytes(Vec::new()).is_err());
}

#[test]
fn empty_entries_are_tolerated() {
    let apk = zip_of(&[("classes.dex", b""), ("AndroidManifest.xml", b"")]);
    let a = unhusk_apk::Apk::from_bytes(apk).expect("empty entries are a valid, if useless, APK");
    assert!(a.manifest_error.is_some());
    assert!(a.dex_files().iter().all(|(_, d)| d.is_err()));
}

#[test]
fn absurd_dex_counts_do_not_allocate() {
    let dex = dex_header_with(&[(0x38, 0x7fff_ffff), (0x3c, 0x70)]);
    let apk = zip_of(&[("classes.dex", &dex)]);
    let started = std::time::Instant::now();
    let a = unhusk_apk::Apk::from_bytes(apk).unwrap();
    let _ = a.dex_files();
    assert!(
        started.elapsed().as_secs() < 10,
        "must fail fast rather than allocate on a claimed count"
    );
}

#[test]
fn malformed_manifest_does_not_stop_analysis() {
    let mut m = vec![0u8; 64];
    m[0..2].copy_from_slice(&3u16.to_le_bytes()); // RES_XML
    m[2..4].copy_from_slice(&8u16.to_le_bytes());
    m[4..8].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    let apk = zip_of(&[
        ("classes.dex", b"dex\n035\0rest"),
        ("AndroidManifest.xml", &m),
    ]);
    let a = unhusk_apk::Apk::from_bytes(apk).expect("container is still readable");
    assert!(a.manifest_error.is_some(), "the failure must be reported");
}

#[test]
fn many_entries_are_handled() {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..200 {
        entries.push((format!("assets/f{i}.bin"), vec![0u8; 16]));
    }
    entries.push(("classes.dex".into(), dex_header_with(&[])));
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let apk = unhusk_apk::Apk::from_bytes(zip_of(&refs)).unwrap();
    assert_eq!(apk.len(), 201);
    assert_eq!(apk.dex_names(), vec!["classes.dex".to_string()]);
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x1234_5678u64;
    for _ in 0..24 {
        let mut buf = vec![0u8; 512];
        for b in buf.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (state >> 33) as u8;
        }
        let _ = unhusk_apk::Apk::from_bytes(buf);
    }
}
