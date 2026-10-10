//! Renders the logo into the files the build needs:
//!
//!   cargo run -p deterium-gui --example make_icons
//!
//! Writes `crates/deterium-gui/assets/deterium.ico` (embedded into the .exe by
//! build.rs) and a few PNGs for the README and for looking at the design.
//! The drawing itself lives in `src/logo.rs`, the single source of the logo.

#[path = "../src/logo.rs"]
#[allow(dead_code)]
mod logo;

use std::fs;
use std::path::PathBuf;

fn png(size: u32, status: Option<logo::Status>) -> Vec<u8> {
    let rgba = logo::render(size, status);
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .and_then(|mut w| w.write_image_data(&rgba))
        .expect("encode png");
    out
}

/// A Windows icon holding one PNG-compressed image per size.
fn ico(sizes: &[u32]) -> Vec<u8> {
    let images: Vec<(u32, Vec<u8>)> = sizes.iter().map(|&s| (s, png(s, None))).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]); // reserved, type 1 = icon
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (size, data) in &images {
        out.push(if *size >= 256 { 0 } else { *size as u8 }); // width (0 = 256)
        out.push(if *size >= 256 { 0 } else { *size as u8 }); // height
        out.extend_from_slice(&[0, 0]); // palette, reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // colour planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += data.len() as u32;
    }
    for (_, data) in &images {
        out.extend_from_slice(data);
    }
    out
}

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
    fs::create_dir_all(&dir).expect("create assets");

    fs::write(
        dir.join("deterium.ico"),
        ico(&[16, 24, 32, 48, 64, 128, 256]),
    )
    .expect("write ico");
    fs::write(dir.join("logo-512.png"), png(512, None)).expect("write png");
    for (name, status) in [
        ("tray-idle.png", logo::Status::Idle),
        ("tray-connecting.png", logo::Status::Connecting),
        ("tray-connected.png", logo::Status::Connected),
        ("tray-warning.png", logo::Status::Warning),
    ] {
        fs::write(dir.join(name), png(128, Some(status))).expect("write png");
    }
    println!("wrote the logo files to {}", dir.display());
}
