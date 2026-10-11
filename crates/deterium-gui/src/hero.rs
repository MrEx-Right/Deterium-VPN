//! The connect screen's building blocks: the animated power button, stat
//! tiles and the details list. Pure drawing — state lives in `main.rs`.

use crate::theme::*;
use deterium_core::ServerProfile;
use eframe::egui::{self, pos2, vec2, Align2, Color32, FontId, RichText, Sense, Shape, Stroke};
use std::time::Duration;

pub struct StatusView {
    pub title: String,
    pub subtitle: String,
    pub subtitle_color: Color32,
    pub accent: Color32,
    pub spinning: bool,
    pub ripples: bool,
    /// Shown under the subtitle in small text (honest caveats).
    pub note: Option<&'static str>,
    /// A warning shown prominently under the subtitle (e.g. "not protected yet").
    pub warning: Option<&'static str>,
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn endpoint_of(profile: &ServerProfile) -> String {
    match (&profile.wireguard, &profile.openvpn) {
        (Some(wg), _) => wg.peer.endpoint.clone(),
        (None, Some(ovpn)) => ovpn
            .raw_config
            .lines()
            .find_map(|l| {
                let mut parts = l.split_whitespace();
                (parts.next() == Some("remote")).then(|| {
                    let host = parts.next().unwrap_or("");
                    match parts.next() {
                        Some(port) => format!("{host}:{port}"),
                        None => host.to_string(),
                    }
                })
            })
            .unwrap_or_else(|| "OpenVPN profile".into()),
        _ => String::new(),
    }
}

pub fn host_of(profile: &ServerProfile) -> String {
    let endpoint = endpoint_of(profile);
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(|c| c == '[' || c == ']').to_string())
        .unwrap_or(endpoint)
}

pub fn power_button(
    ui: &mut egui::Ui,
    view: &StatusView,
    enabled: bool,
    time: f64,
) -> egui::Response {
    // The glow/ripples need a big canvas, but only the button itself is
    // clickable — the empty corners must not trigger a connect.
    let (rect, _) = ui.allocate_exact_size(vec2(280.0, 280.0), Sense::hover());
    let radius = 64.0;
    let hit_rect = egui::Rect::from_center_size(
        rect.center(),
        vec2((radius + 8.0) * 2.0, (radius + 8.0) * 2.0),
    );
    let response = ui.interact(
        hit_rect,
        ui.id().with("power_button"),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let center = rect.center();
    let hovered = enabled && response.hovered();
    let color = if enabled { view.accent } else { DIM };
    let painter = ui.painter();

    radial_glow(
        painter,
        center,
        radius * 0.9,
        radius + 64.0,
        color,
        if hovered { 80 } else { 54 },
    );

    if view.ripples {
        for n in 0..3 {
            let phase = ((time * 0.45 + n as f64 / 3.0) % 1.0) as f32;
            painter.circle_stroke(
                center,
                radius + 10.0 + phase * 74.0,
                Stroke::new(2.0_f32, with_alpha(color, ((1.0 - phase) * 80.0) as u8)),
            );
        }
    }

    painter.circle_filled(center, radius, Color32::from_rgb(14, 18, 30));
    painter.circle_filled(
        center,
        radius - 3.0,
        with_alpha(color, if hovered { 46 } else { 26 }),
    );
    painter.circle_stroke(
        center,
        radius,
        Stroke::new(3.0_f32, with_alpha(color, if enabled { 255 } else { 90 })),
    );

    if view.spinning {
        let start = (time * 3.4).to_degrees() as f32;
        painter.circle_stroke(
            center,
            radius + 14.0,
            Stroke::new(1.0_f32, with_alpha(color, 50)),
        );
        painter.add(Shape::line(
            arc_points(center, radius + 14.0, start, start + 110.0, 36),
            Stroke::new(4.0_f32, color),
        ));
    }

    let icon_radius = radius * 0.42;
    let icon_stroke = Stroke::new(5.5_f32, color);
    painter.add(Shape::line(
        arc_points(center, icon_radius, -55.0, 235.0, 48),
        icon_stroke,
    ));
    let top = center + vec2(0.0, -icon_radius * 1.2);
    let bottom = center + vec2(0.0, -icon_radius * 0.1);
    painter.line_segment([top, bottom], icon_stroke);
    painter.circle_filled(top, 2.75, color);
    painter.circle_filled(bottom, 2.75, color);

    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A server row in the sidebar.
pub fn server_row(
    ui: &mut egui::Ui,
    profile: &ServerProfile,
    selected: bool,
    dot: Color32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 58.0), Sense::click());

    if ui.is_rect_visible(rect) {
        let fill = if selected {
            with_alpha(ACCENT, 40)
        } else if response.hovered() {
            Color32::from_rgba_unmultiplied(255, 255, 255, 10)
        } else {
            Color32::TRANSPARENT
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 12.0, fill);
        if selected {
            painter.rect_stroke(rect, 12.0, Stroke::new(1.0_f32, with_alpha(ACCENT, 120)));
        }

        painter.circle_filled(pos2(rect.left() + 18.0, rect.center().y), 5.0, dot);

        // Name gets the full row width; the protocol tag lives on the
        // endpoint line so a long server name is never cut by it.
        let name_clip = egui::Rect::from_min_max(
            pos2(rect.left() + 34.0, rect.top()),
            pos2(rect.right() - 10.0, rect.bottom()),
        );
        painter.with_clip_rect(name_clip).text(
            pos2(rect.left() + 34.0, rect.center().y - 9.0),
            Align2::LEFT_CENTER,
            &profile.name,
            FontId::proportional(15.0),
            TEXT,
        );

        let endpoint_clip = egui::Rect::from_min_max(
            pos2(rect.left() + 34.0, rect.top()),
            pos2(rect.right() - 44.0, rect.bottom()),
        );
        painter.with_clip_rect(endpoint_clip).text(
            pos2(rect.left() + 34.0, rect.center().y + 10.0),
            Align2::LEFT_CENTER,
            endpoint_of(profile),
            FontId::proportional(11.5),
            DIM,
        );

        painter.text(
            pos2(rect.right() - 12.0, rect.center().y + 10.0),
            Align2::RIGHT_CENTER,
            match profile.protocol {
                deterium_core::Protocol::Wireguard => "WG",
                deterium_core::Protocol::Openvpn => "OVPN",
            },
            FontId::proportional(11.0),
            DIM,
        );
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Dashed-looking "add" row at the end of the server list.
pub fn add_row(ui: &mut egui::Ui) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 44.0), Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let painter = ui.painter();
        painter.rect_filled(
            rect,
            12.0,
            if hovered {
                with_alpha(ACCENT, 30)
            } else {
                Color32::TRANSPARENT
            },
        );
        painter.rect_stroke(
            rect,
            12.0,
            Stroke::new(1.0_f32, with_alpha(ACCENT, if hovered { 170 } else { 80 })),
        );
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "+  Add server",
            FontId::proportional(14.5),
            ACCENT,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn detail_rows(ui: &mut egui::Ui, profile: &ServerProfile) {
    let row = |ui: &mut egui::Ui, key: &str, value: &str| {
        ui.label(RichText::new(key).size(13.0).color(DIM));
        ui.label(RichText::new(value).size(14.0).color(TEXT));
        ui.end_row();
    };

    egui::Grid::new("profile_details")
        .num_columns(2)
        .spacing([30.0, 10.0])
        .show(ui, |ui| {
            match (&profile.wireguard, &profile.openvpn) {
                (Some(wg), _) => {
                    row(ui, "Endpoint", &wg.peer.endpoint);
                    row(ui, "Tunnel address", &wg.interface.address.join(", "));
                    row(ui, "Routed networks", &wg.peer.allowed_ips.join(", "));
                    if let Some(dns) = &wg.interface.dns {
                        row(ui, "DNS", &dns.join(", "));
                    }
                    if let Some(mtu) = wg.interface.mtu {
                        row(ui, "MTU", &mtu.to_string());
                    }
                    if let Some(port) = wg.interface.listen_port {
                        row(ui, "Local port", &port.to_string());
                    }
                    row(
                        ui,
                        "Preshared key",
                        if wg.peer.preshared_key.is_some() {
                            "in use"
                        } else {
                            "none"
                        },
                    );
                    row(
                        ui,
                        "Keepalive",
                        &wg.peer
                            .persistent_keepalive
                            .map(|s| format!("{s}s"))
                            .unwrap_or_else(|| "off".into()),
                    );
                }
                (None, Some(ovpn)) => row(
                    ui,
                    "Config",
                    &format!("embedded .ovpn, {} lines", ovpn.raw_config.lines().count()),
                ),
                _ => {}
            }
            if !profile.tags.is_empty() {
                row(ui, "Tags", &profile.tags.join(", "));
            }
            if !profile.notes.is_empty() {
                row(ui, "Notes", &profile.notes);
            }
        });
}
