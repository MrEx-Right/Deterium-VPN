//! Renders the README banner:
//!
//!   cargo run -p deterium-gui --example make_banner
//!
//! Writes `docs/banner.png`. The logo comes from `src/logo.rs`, the
//! "DETERIUM" lettering is geometric shapes drawn here (same stroke weight as
//! the logo's D, so it needs no font), and the small text uses the font that
//! ships with egui.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::redundant_closure
)]

#[path = "../src/logo.rs"]
#[allow(dead_code)]
mod logo;

use ab_glyph::{point, Font, FontRef, PxScale, ScaleFont};
use std::fs;
use std::path::PathBuf;

/// Design units; the image is rendered at `SCALE` times this for sharpness.
const W: f32 = 1280.0;
const H: f32 = 320.0;
const SCALE: f32 = 2.0;

type P = (f32, f32);

struct Canvas {
    w: usize,
    h: usize,
    rgb: Vec<f32>,
}

impl Canvas {
    fn new(w: usize, h: usize) -> Self {
        Self {
            w,
            h,
            rgb: vec![0.0; w * h * 3],
        }
    }

    fn blend(&mut self, x: usize, y: usize, colour: [f32; 3], alpha: f32) {
        if x >= self.w || y >= self.h || alpha <= 0.0 {
            return;
        }
        let i = (y * self.w + x) * 3;
        for c in 0..3 {
            self.rgb[i + c] = self.rgb[i + c] * (1.0 - alpha) + colour[c] * alpha;
        }
    }

    /// Fills every pixel with `f(x, y)` -> (colour, alpha), in design units.
    fn paint(&mut self, f: impl Fn(f32, f32) -> ([f32; 3], f32)) {
        for y in 0..self.h {
            for x in 0..self.w {
                let (c, a) = f(x as f32 / SCALE, y as f32 / SCALE);
                self.blend(x, y, c, a);
            }
        }
    }

    /// An anti-aliased shape given by a signed distance (negative = inside).
    fn shape(&mut self, bounds: (f32, f32, f32, f32), colour: [f32; 3], sdf: impl Fn(P) -> f32) {
        let (x0, y0, x1, y1) = bounds;
        let (px0, py0) = ((x0 * SCALE) as usize, (y0 * SCALE) as usize);
        let (px1, py1) = (
            ((x1 * SCALE).ceil() as usize).min(self.w),
            ((y1 * SCALE).ceil() as usize).min(self.h),
        );
        const N: u32 = 3;
        for y in py0..py1 {
            for x in px0..px1 {
                let mut inside = 0;
                for sy in 0..N {
                    for sx in 0..N {
                        let p = (
                            (x as f32 + (sx as f32 + 0.5) / N as f32) / SCALE,
                            (y as f32 + (sy as f32 + 0.5) / N as f32) / SCALE,
                        );
                        if sdf(p) <= 0.0 {
                            inside += 1;
                        }
                    }
                }
                self.blend(x, y, colour, inside as f32 / (N * N) as f32);
            }
        }
    }

    fn text(
        &mut self,
        font: &FontRef,
        text: &str,
        size: f32,
        at: P,
        spacing: f32,
        colour: [f32; 3],
        alpha: f32,
    ) -> f32 {
        let scaled = font.as_scaled(PxScale::from(size * SCALE));
        let mut caret = at.0 * SCALE;
        let baseline = at.1 * SCALE;
        let mut previous = None;
        for ch in text.chars() {
            let id = scaled.glyph_id(ch);
            if let Some(prev) = previous {
                caret += scaled.kern(prev, id);
            }
            let glyph = id.with_scale_and_position(scaled.scale(), point(caret, baseline));
            if let Some(outline) = font.outline_glyph(glyph) {
                let bounds = outline.px_bounds();
                outline.draw(|gx, gy, coverage| {
                    let x = bounds.min.x as i32 + gx as i32;
                    let y = bounds.min.y as i32 + gy as i32;
                    if x >= 0 && y >= 0 {
                        self.blend(x as usize, y as usize, colour, coverage * alpha);
                    }
                });
            }
            caret += scaled.h_advance(id) + spacing * SCALE;
            previous = Some(id);
        }
        caret / SCALE - at.0
    }

    fn text_width(font: &FontRef, text: &str, size: f32, spacing: f32) -> f32 {
        let scaled = font.as_scaled(PxScale::from(size * SCALE));
        let mut width = 0.0;
        for ch in text.chars() {
            width += scaled.h_advance(scaled.glyph_id(ch)) + spacing * SCALE;
        }
        width / SCALE
    }
}

// ---------------------------------------------------------------- shapes --

fn len(p: P) -> f32 {
    (p.0 * p.0 + p.1 * p.1).sqrt()
}

fn rect(p: P, x0: f32, y0: f32, x1: f32, y1: f32) -> f32 {
    let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
    let q = (
        (p.0 - cx).abs() - (x1 - x0) / 2.0,
        (p.1 - cy).abs() - (y1 - y0) / 2.0,
    );
    len((q.0.max(0.0), q.1.max(0.0))) + q.0.max(q.1).min(0.0)
}

fn rounded_rect(p: P, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> f32 {
    let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
    let q = (
        (p.0 - cx).abs() - (x1 - x0) / 2.0 + r,
        (p.1 - cy).abs() - (y1 - y0) / 2.0 + r,
    );
    len((q.0.max(0.0), q.1.max(0.0))) + q.0.max(q.1).min(0.0) - r
}

/// A flat-ended bar from `a` to `b`, `thickness` wide.
fn bar(p: P, a: P, b: P, thickness: f32) -> f32 {
    let d = (b.0 - a.0, b.1 - a.1);
    let l = len(d);
    let u = (d.0 / l, d.1 / l);
    let rel = (p.0 - a.0, p.1 - a.1);
    let along = rel.0 * u.0 + rel.1 * u.1;
    let across = -rel.0 * u.1 + rel.1 * u.0;
    let q = (
        (along - l / 2.0).abs() - l / 2.0,
        across.abs() - thickness / 2.0,
    );
    len((q.0.max(0.0), q.1.max(0.0))) + q.0.max(q.1).min(0.0)
}

fn ring(p: P, c: P, outer: f32, thickness: f32) -> f32 {
    (len((p.0 - c.0, p.1 - c.1)) - (outer - thickness / 2.0)).abs() - thickness / 2.0
}

/// One letter of the lettering: its width and its distance function for a
/// letter whose top-left corner is `(x, y)`, height `h`, stroke `s`.
fn letter(ch: char, x: f32, y: f32, h: f32, s: f32) -> (f32, Box<dyn Fn(P) -> f32>) {
    match ch {
        'D' => {
            let cx = x + 0.34 * h;
            let w = 0.34 * h + h / 2.0;
            (
                w,
                Box::new(move |p| {
                    let stem = rect(p, x, y, x + s, y + h);
                    let bowl = ring(p, (cx, y + h / 2.0), h / 2.0, s).max(cx - p.0);
                    let top = rect(p, x, y, cx + 0.02 * h, y + s);
                    let bottom = rect(p, x, y + h - s, cx + 0.02 * h, y + h);
                    stem.min(bowl).min(top).min(bottom)
                }),
            )
        }
        'E' => {
            let w = 0.56 * h;
            (
                w,
                Box::new(move |p| {
                    let stem = rect(p, x, y, x + s, y + h);
                    let top = rect(p, x, y, x + w, y + s);
                    let mid = rect(
                        p,
                        x,
                        y + h / 2.0 - s / 2.0,
                        x + w * 0.88,
                        y + h / 2.0 + s / 2.0,
                    );
                    let bottom = rect(p, x, y + h - s, x + w, y + h);
                    stem.min(top).min(mid).min(bottom)
                }),
            )
        }
        'T' => {
            let w = 0.66 * h;
            (
                w,
                Box::new(move |p| {
                    rect(p, x, y, x + w, y + s).min(rect(
                        p,
                        x + w / 2.0 - s / 2.0,
                        y,
                        x + w / 2.0 + s / 2.0,
                        y + h,
                    ))
                }),
            )
        }
        'R' => {
            let rb = 0.29 * h;
            let cx = x + 0.30 * h;
            let w = 0.30 * h + rb;
            let cy = y + rb;
            (
                w + 0.10 * h,
                Box::new(move |p| {
                    let stem = rect(p, x, y, x + s, y + h);
                    let bowl = ring(p, (cx, cy), rb, s).max(cx - p.0);
                    let top = rect(p, x, y, cx + 0.02 * h, y + s);
                    let mid = rect(p, x, y + 2.0 * rb - s, cx + 0.02 * h, y + 2.0 * rb);
                    let leg = bar(
                        p,
                        (cx - 0.05 * h, y + 2.0 * rb - s * 0.2),
                        (x + w + 0.07 * h, y + h),
                        s * 1.05,
                    );
                    let clip = p.1 - (y + h);
                    stem.min(bowl).min(top).min(mid).min(leg.max(clip))
                }),
            )
        }
        'I' => (s, Box::new(move |p| rect(p, x, y, x + s, y + h))),
        'U' => {
            let w = 0.62 * h;
            let r = w / 2.0;
            let cy = y + h - r;
            (
                w,
                Box::new(move |p| {
                    let left = rect(p, x, y, x + s, cy);
                    let right = rect(p, x + w - s, y, x + w, cy);
                    let bottom = ring(p, (x + r, cy), r, s).max(cy - p.1);
                    left.min(right).min(bottom)
                }),
            )
        }
        'M' => {
            let w = 0.92 * h;
            (
                w,
                Box::new(move |p| {
                    let left = rect(p, x, y, x + s, y + h);
                    let right = rect(p, x + w - s, y, x + w, y + h);
                    // Each diagonal runs a little past the middle and is cut off
                    // exactly on the centre line, so the two meet in a clean point.
                    let mid = x + w / 2.0;
                    let tip = (mid, y + 0.64 * h);
                    let beyond = |from: P| {
                        let d = (tip.0 - from.0, tip.1 - from.1);
                        let l = len(d);
                        (tip.0 + d.0 / l * s * 1.4, tip.1 + d.1 / l * s * 1.4)
                    };
                    let left_top = (x + s * 0.5, y + s * 0.3);
                    let right_top = (x + w - s * 0.5, y + s * 0.3);
                    let top_cut = y - p.1;
                    let a = bar(p, left_top, beyond(left_top), s)
                        .max(p.0 - mid)
                        .max(top_cut);
                    let b = bar(p, right_top, beyond(right_top), s)
                        .max(mid - p.0)
                        .max(top_cut);
                    left.min(right).min(a).min(b)
                }),
            )
        }
        _ => (0.0, Box::new(|_| 1.0e9)),
    }
}

fn lettering_width(text: &str, h: f32, s: f32, gap: f32) -> f32 {
    text.chars()
        .map(|c| letter(c, 0.0, 0.0, h, s).0)
        .sum::<f32>()
        + gap * (text.chars().count() as f32 - 1.0)
}

fn draw_lettering(
    canvas: &mut Canvas,
    text: &str,
    x: f32,
    y: f32,
    h: f32,
    s: f32,
    gap: f32,
    colour: [f32; 3],
) {
    let mut cursor = x;
    for ch in text.chars() {
        let (width, sdf) = letter(ch, cursor, y, h, s);
        canvas.shape(
            (cursor - 2.0, y - 2.0, cursor + width + 2.0, y + h + 2.0),
            colour,
            |p| sdf(p),
        );
        cursor += width + gap;
    }
}

fn main() {
    let (pw, ph) = ((W * SCALE) as usize, (H * SCALE) as usize);
    let mut canvas = Canvas::new(pw, ph);

    // Background: deep navy, two soft glows and the "tunnel" rings.
    canvas.paint(|_, y| {
        let t = (y / H).clamp(0.0, 1.0);
        let base = [
            14.0 + (8.0 - 14.0) * t,
            18.0 + (10.0 - 18.0) * t,
            36.0 + (18.0 - 36.0) * t,
        ];
        (base, 1.0)
    });
    canvas.paint(|x, y| {
        let blue = (1.0 - len((x - 190.0, y - 150.0)) / 430.0).clamp(0.0, 1.0);
        ([70.0, 120.0, 255.0], blue * blue * 0.30)
    });
    canvas.paint(|x, y| {
        let green = (1.0 - len((x - 1130.0, y - 250.0)) / 420.0).clamp(0.0, 1.0);
        ([30.0, 200.0, 160.0], green * green * 0.22)
    });
    canvas.paint(|x, y| {
        // Concentric rings around a point at the right edge, fading outwards.
        let d = len((x - 1180.0, y - 150.0));
        let band = (d % 46.0 - 23.0).abs();
        let line = (1.0 - band / 1.1).clamp(0.0, 1.0);
        let fade = (1.0 - (d - 60.0) / 520.0).clamp(0.0, 1.0);
        ([140.0, 180.0, 255.0], line * fade * 0.16)
    });

    // The logo mark.
    let mark = 196.0;
    let mark_px = (mark * SCALE) as u32;
    let rgba = logo::render(mark_px, None);
    let (mx, my) = (74.0f32, (H - mark) / 2.0);
    // A soft shadow under the tile.
    canvas.paint(|x, y| {
        let d = len((x - (mx + mark / 2.0), y - (my + mark / 2.0 + 14.0)));
        let a = (1.0 - d / (mark * 0.72)).clamp(0.0, 1.0);
        ([0.0, 0.0, 0.0], a * a * 0.35)
    });
    for y in 0..mark_px as usize {
        for x in 0..mark_px as usize {
            let i = (y * mark_px as usize + x) * 4;
            let a = rgba[i + 3] as f32 / 255.0;
            canvas.blend(
                (mx * SCALE) as usize + x,
                (my * SCALE) as usize + y,
                [rgba[i] as f32, rgba[i + 1] as f32, rgba[i + 2] as f32],
                a,
            );
        }
    }

    // Lettering, tagline and chips.
    let text_x = mx + mark + 56.0;
    let (lh, ls, gap) = (92.0, 15.0, 17.0);
    let lettering_y = 62.0;
    draw_lettering(
        &mut canvas,
        "DETERIUM",
        text_x,
        lettering_y,
        lh,
        ls,
        gap,
        [236.0, 240.0, 247.0],
    );
    let _ = lettering_width("DETERIUM", lh, ls, gap);

    let fonts = egui::FontDefinitions::default();
    let font_bytes = fonts
        .font_data
        .get("Ubuntu-Light")
        .expect("egui ships Ubuntu-Light")
        .font
        .clone();
    let font = FontRef::try_from_slice(&font_bytes).expect("parse font");

    canvas.text(
        &font,
        "Self-hosted VPN. Your server, your rules.",
        30.0,
        (text_x + 2.0, lettering_y + lh + 52.0),
        0.3,
        [190.0, 200.0, 220.0],
        1.0,
    );

    let mut chip_x = text_x + 2.0;
    let chip_y = lettering_y + lh + 76.0;
    for (label, dot) in [
        ("WireGuard", [86.0, 140.0, 255.0]),
        ("OpenVPN", [52.0, 211.0, 153.0]),
        ("Kill switch", [251.0, 191.0, 36.0]),
        ("Windows", [180.0, 190.0, 215.0]),
    ] {
        let size = 16.5;
        let text_w = Canvas::text_width(&font, label, size, 0.4);
        let chip_w = text_w + 46.0;
        let (x0, y0, x1, y1) = (chip_x, chip_y, chip_x + chip_w, chip_y + 32.0);
        canvas.shape(
            (x0 - 1.0, y0 - 1.0, x1 + 1.0, y1 + 1.0),
            [50.0, 60.0, 92.0],
            |p| rounded_rect(p, x0, y0, x1, y1, 16.0),
        );
        canvas.shape((x0, y0, x1, y1), [20.0, 25.0, 44.0], |p| {
            rounded_rect(p, x0 + 1.0, y0 + 1.0, x1 - 1.0, y1 - 1.0, 15.0)
        });
        canvas.shape((x0 + 10.0, y0 + 10.0, x0 + 22.0, y0 + 22.0), dot, |p| {
            len((p.0 - (x0 + 16.0), p.1 - (y0 + 16.0))) - 4.0
        });
        canvas.text(
            &font,
            label,
            size,
            (x0 + 28.0, y0 + 22.0),
            0.4,
            [226.0, 232.0, 245.0],
            1.0,
        );
        chip_x = x1 + 12.0;
    }

    // Write the PNG.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs");
    fs::create_dir_all(&dir).expect("create docs");
    let path = dir.join("banner.png");
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, pw as u32, ph as u32);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let data: Vec<u8> = canvas
        .rgb
        .iter()
        .map(|v| v.round().clamp(0.0, 255.0) as u8)
        .collect();
    encoder
        .write_header()
        .and_then(|mut w| w.write_image_data(&data))
        .expect("encode png");
    fs::write(&path, bytes).expect("write banner");
    println!("wrote {}", path.display());
}
