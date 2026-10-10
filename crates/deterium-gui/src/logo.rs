//! The Deterium logo, drawn in code so it is one definition used everywhere:
//! the executable's icon, the window and taskbar icon, the tray icon and the
//! mark in the app's header.
//!
//! The mark is a rounded tile in the app's blue-to-green gradient holding a
//! white "D" whose bowl is a ring around a small dot: the tunnel, and the one
//! server at its end that belongs to you.
//!
//! Everything is a signed-distance shape sampled several times per pixel, so
//! edges stay clean at every size from 16 px to 512 px.

/// What the small status dot (tray icon only) shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Idle,
    Connecting,
    Connected,
    Warning,
}

impl Status {
    fn rgb(self) -> [f32; 3] {
        match self {
            Status::Idle => [128.0, 136.0, 156.0],
            Status::Connecting => [86.0, 140.0, 255.0],
            Status::Connected => [52.0, 211.0, 153.0],
            Status::Warning => [251.0, 191.0, 36.0],
        }
    }
}

const BLUE: [f32; 3] = [78.0, 132.0, 255.0];
const GREEN: [f32; 3] = [34.0, 204.0, 166.0];
const OUTLINE: [f32; 3] = [10.0, 13.0, 24.0];

type P = (f32, f32);

fn len(p: P) -> f32 {
    (p.0 * p.0 + p.1 * p.1).sqrt()
}

/// Distance to a rounded box centred at `c` with half-size `h` and corner
/// radius `r` (negative inside).
fn rounded_box(p: P, c: P, h: P, r: f32) -> f32 {
    let q = ((p.0 - c.0).abs() - h.0 + r, (p.1 - c.1).abs() - h.1 + r);
    len((q.0.max(0.0), q.1.max(0.0))) + q.0.max(q.1).min(0.0) - r
}

fn rect(p: P, x0: f32, y0: f32, x1: f32, y1: f32) -> f32 {
    rounded_box(
        p,
        ((x0 + x1) / 2.0, (y0 + y1) / 2.0),
        ((x1 - x0) / 2.0, (y1 - y0) / 2.0),
        0.0,
    )
}

fn circle(p: P, c: P, r: f32) -> f32 {
    len((p.0 - c.0, p.1 - c.1)) - r
}

/// The white "D": a stem, a half ring for the bowl, and the dot inside it.
fn glyph(p: P) -> f32 {
    let (cx, cy) = (0.455, 0.50);
    let stem = rect(p, 0.285, 0.25, 0.385, 0.75);

    // Right half of a ring, joined to the stem by two bars.
    let ring = {
        let d = len((p.0 - cx, p.1 - cy));
        let band = (d - 0.20).abs() - 0.05; // outer 0.25, inner 0.15
                                            // Only the half to the right of the centre line.
        band.max(cx - p.0)
    };
    // The bars run a little into the ring so no seam shows where they meet.
    let top = rect(p, 0.35, 0.25, cx + 0.02, 0.35);
    let bottom = rect(p, 0.35, 0.65, cx + 0.02, 0.75);

    let dot = circle(p, (0.50, cy), 0.052);
    stem.min(ring).min(top).min(bottom).min(dot)
}

fn mix(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    [
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    ]
}

/// Straight-alpha RGBA pixels of the logo, `size` x `size`. With a `status`
/// a small coloured dot sits in the bottom-right corner (for the tray).
pub fn render(size: u32, status: Option<Status>) -> Vec<u8> {
    const SAMPLES: u32 = 4;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let step = 1.0 / size as f32;

    for y in 0..size {
        for x in 0..size {
            // Colour and coverage accumulated over the sub-samples, premultiplied.
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let p = (
                        (x as f32 + (sx as f32 + 0.5) / SAMPLES as f32) * step,
                        (y as f32 + (sy as f32 + 0.5) / SAMPLES as f32) * step,
                    );
                    let (colour, alpha) = sample(p, status);
                    r += colour[0] * alpha;
                    g += colour[1] * alpha;
                    b += colour[2] * alpha;
                    a += alpha;
                }
            }
            let n = (SAMPLES * SAMPLES) as f32;
            let i = ((y * size + x) * 4) as usize;
            if a > 0.0 {
                rgba[i] = (r / a).round().clamp(0.0, 255.0) as u8;
                rgba[i + 1] = (g / a).round().clamp(0.0, 255.0) as u8;
                rgba[i + 2] = (b / a).round().clamp(0.0, 255.0) as u8;
                rgba[i + 3] = (a / n * 255.0).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    rgba
}

/// Colour and opacity (0 or 1; the caller averages samples) at one point.
fn sample(p: P, status: Option<Status>) -> ([f32; 3], f32) {
    // The status dot sits on top of everything.
    if let Some(status) = status {
        let c = (0.775, 0.775);
        if circle(p, c, 0.19) <= 0.0 {
            return if circle(p, c, 0.14) <= 0.0 {
                (status.rgb(), 1.0)
            } else {
                (OUTLINE, 1.0)
            };
        }
    }

    // The tile.
    if rounded_box(p, (0.5, 0.5), (0.47, 0.47), 0.22) > 0.0 {
        return ([0.0; 3], 0.0);
    }
    if glyph(p) <= 0.0 {
        return ([255.0, 255.0, 255.0], 1.0);
    }
    // Diagonal gradient, with a soft lighter patch at the top left.
    let t = ((p.0 + p.1) / 2.0).clamp(0.0, 1.0);
    let base = mix(BLUE, GREEN, t * 1.15);
    let shine = (1.0 - len((p.0 - 0.18, p.1 - 0.12)) * 1.7).clamp(0.0, 1.0) * 0.22;
    (mix(base, [255.0, 255.0, 255.0], shine), 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(rgba: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * size + x) * 4) as usize;
        [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
    }

    #[test]
    fn the_logo_is_a_tile_with_transparent_corners_and_a_white_d() {
        let size = 128;
        let px = render(size, None);
        assert_eq!(px.len(), (size * size * 4) as usize);
        assert_eq!(pixel(&px, size, 0, 0)[3], 0, "corner is transparent");
        assert_eq!(pixel(&px, size, 127, 127)[3], 0);
        // On the tile, away from the letter: opaque and blue-ish.
        let tile = pixel(&px, size, 20, 64);
        assert_eq!(tile[3], 255);
        assert!(
            tile[2] > tile[0],
            "the left side of the tile is blue: {tile:?}"
        );
        // The D's stem is white.
        assert_eq!(
            pixel(&px, size, (0.335 * 128.0) as u32, 64),
            [255, 255, 255, 255]
        );
        // The dot in the bowl is white, the gap around it is not.
        assert_eq!(pixel(&px, size, 64, 64), [255, 255, 255, 255]);
        assert_ne!(pixel(&px, size, 77, 64)[..3], [255, 255, 255]);
    }

    #[test]
    fn the_status_dot_takes_the_colour_of_the_state() {
        let size = 64;
        let at = |s: Status| pixel(&render(size, Some(s)), size, 48, 48);
        assert_eq!(at(Status::Connected)[..3], [52, 211, 153]);
        assert_eq!(at(Status::Warning)[..3], [251, 191, 36]);
        assert_ne!(at(Status::Idle), at(Status::Connecting));
        // Without a status there is no dot there.
        assert_ne!(
            pixel(&render(size, None), size, 48, 48)[..3],
            [52, 211, 153]
        );
    }

    #[test]
    fn every_size_the_icon_needs_renders() {
        for size in [16, 24, 32, 48, 64, 128, 256] {
            let px = render(size, Some(Status::Connected));
            assert!(
                px.chunks(4).any(|p| p[3] == 255),
                "{size}px has opaque pixels"
            );
        }
    }
}
