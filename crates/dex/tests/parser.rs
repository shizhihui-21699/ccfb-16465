//! Parser tests over hostile input.
//!
//! Every case here is something an analyst's queue could actually contain: a
//! truncated file, a header whose table offsets point past the end, absurd
//! counts. None may panic, hang, or allocate proportional to an attacker's
//! claim; each must become a typed error.

use unhusk_dex::{parse, ErrorKind};

fn dex_header() -> Vec<u8> {
    // Header layout from the DEX spec:
    //   0x00 magic(8) 0x08 checksum 0x0c signature(20) 0x20 file_size
    //   0x24 header_size 0x28 endian_tag 0x2c link_size 0x30 link_off
    //   0x34 map_off 0x38 string_ids_size 0x3c string_ids_off ...
    let mut d = vec![0u8; 0x70];
    d[0..8].copy_from_slice(b"dex\n035\0");
    d[0x20..0x24].copy_from_slice(&0x70u32.to_le_bytes()); // file_size
    d[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes()); // header_size
    d[0x28..0x2c].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian_tag
    d
}

fn set_string_table(d: &mut [u8], size: u32, off: u32) {
    d[0x38..0x3c].copy_from_slice(&size.to_le_bytes());
    d[0x3c..0x40].copy_from_slice(&off.to_le_bytes());
}

#[test]
fn rejects_non_dex() {
    assert_eq!(
        parse(b"this is not a dex file").unwrap_err().kind,
        ErrorKind::BadMagic
    );
}

#[test]
fn rejects_truncated_header() {
    assert!(matches!(
        parse(b"dex\n035\0").unwrap_err().kind,
        ErrorKind::Truncated
    ));
}

#[test]
fn rejects_bad_endian_tag() {
    let mut d = dex_header();
    d[0x28..0x2c].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    assert_eq!(parse(&d).unwrap_err().kind, ErrorKind::Unsupported);
}

#[test]
fn rejects_table_past_eof() {
    let mut d = dex_header();
    set_string_table(&mut d, 1, 0xffff_fff0);
    let e = parse(&d).unwrap_err();
    assert!(matches!(
        e.kind,
        ErrorKind::Truncated | ErrorKind::OutOfRange
    ));
}

#[test]
fn huge_declared_counts_fail_fast_without_allocating() {
    let mut d = dex_header();
    set_string_table(&mut d, 0x8000_0000, 0x70);
    let started = std::time::Instant::now();
    let e = parse(&d).unwrap_err();
    assert!(
        started.elapsed().as_secs() < 5,
        "must not allocate on a claimed count"
    );
    assert!(matches!(
        e.kind,
        ErrorKind::Truncated | ErrorKind::OutOfRange
    ));
}

#[test]
fn byte_mutations_never_panic() {
    let base = dex_header();
    for i in 0..base.len() {
        for delta in [0x01u8, 0x80, 0xff] {
            let mut d = base.clone();
            d[i] = d[i].wrapping_add(delta);
            let _ = parse(&d); // Ok or Err, but never a panic
        }
    }
}

#[test]
fn truncated_prefixes_never_panic() {
    let base = dex_header();
    for n in 0..base.len() {
        let _ = parse(&base[..n]);
    }
}
