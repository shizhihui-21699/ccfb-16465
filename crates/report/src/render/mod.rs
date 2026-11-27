//! Text and JSON rendering.

pub mod json;
pub mod text;

pub use json::to_json;
pub use text::render_text;

/// A safe preview of a byte body: printable ASCII, ellipsis when clipped.
pub fn preview(data: &[u8], max: usize) -> String {
    let shown = data.len().min(max);
    let mut s = String::with_capacity(shown + 8);
    for b in &data[..shown] {
        s.push(if (0x20..0x7f).contains(b) { *b as char } else { '.' });
    }
    if data.len() > shown {
        s.push('…');
    }
    s
}
