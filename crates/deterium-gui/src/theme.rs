//! Colors, painting helpers and small reusable widgets shared by every view.

use eframe::egui::{
    self, vec2, Align2, Color32, FontId, Margin, Pos2, RichText, Sense, Shape, Stroke,
};

pub const ACCENT: Color32 = Color32::from_rgb(86, 140, 255);
pub const GOOD: Color32 = Color32::from_rgb(52, 211, 153);
pub const WARN: Color32 = Color32::from_rgb(251, 191, 36);
pub const BAD: Color32 = Color32::from_rgb(248, 113, 113);
pub const TEXT: Color32 = Color32::from_rgb(236, 240, 247);
pub const DIM: Color32 = Color32::from_rgb(142, 152, 172);
pub const CARD: Color32 = Color32::from_rgb(24, 29, 44);
pub const BORDER: Color32 = Color32::from_rgb(40, 47, 68);
pub const BG_BOTTOM: Color32 = Color32::from_rgb(8, 10, 18);

pub fn with_alpha(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

pub fn arc_points(
    center: Pos2,
    radius: f32,
    start_deg: f32,
    end_deg: f32,
    steps: usize,
) -> Vec<Pos2> {
    (0..=steps)
        .map(|i| {
            let t = i as f32 / steps as f32;
            let angle = (start_deg + (end_deg - start_deg) * t).to_radians();
            center + radius * vec2(angle.cos(), angle.sin())
        })
        .collect()
}

/// Smooth radial glow: an annulus mesh fading from `alpha` at `inner` to
/// fully transparent at `outer` (no visible banding, unlike stacked circles).
pub fn radial_glow(
    painter: &egui::Painter,
    center: Pos2,
    inner: f32,
    outer: f32,
    color: Color32,
    alpha: u8,
) {
    const STEPS: u32 = 72;
    let near = with_alpha(color, alpha);
    let far = with_alpha(color, 0);

    let mut mesh = egui::Mesh::default();
    for i in 0..STEPS {
        let angle = i as f32 / STEPS as f32 * std::f32::consts::TAU;
        let dir = vec2(angle.cos(), angle.sin());
        mesh.colored_vertex(center + dir * inner, near);
        mesh.colored_vertex(center + dir * outer, far);
    }
    for i in 0..STEPS {
        let (a, b) = (i * 2, i * 2 + 1);
        let (c, d) = (((i + 1) % STEPS) * 2, ((i + 1) % STEPS) * 2 + 1);
        mesh.add_triangle(a, b, d);
        mesh.add_triangle(a, d, c);
    }
    painter.add(Shape::mesh(mesh));
}

fn animate_color(ctx: &egui::Context, id: &str, target: Color32) -> Color32 {
    let channel = |name: &str, value: u8| {
        ctx.animate_value_with_time(egui::Id::new((id, name)), value as f32, 0.7) as u8
    };
    Color32::from_rgb(
        channel("r", target.r()),
        channel("g", target.g()),
        channel("b", target.b()),
    )
}

/// Full-window vertical gradient; the top color eases toward the current
/// connection state's tint so the whole app "feels" connected.
pub fn paint_background(ctx: &egui::Context, top_target: Color32) {
    let top = animate_color(ctx, "bg_top", top_target);
    let rect = ctx.screen_rect();

    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), top);
    mesh.colored_vertex(rect.right_top(), top);
    mesh.colored_vertex(rect.right_bottom(), BG_BOTTOM);
    mesh.colored_vertex(rect.left_bottom(), BG_BOTTOM);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);

    ctx.layer_painter(egui::LayerId::background())
        .add(Shape::mesh(mesh));
}

pub fn apply_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::TRANSPARENT;
    visuals.window_fill = CARD;
    visuals.extreme_bg_color = Color32::from_rgb(14, 17, 28);
    visuals.faint_bg_color = CARD;
    // No override_text_color: egui derives placeholder (hint) text from the
    // normal text color, so overriding it makes hints look like real input.
    for state in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
    ] {
        state.fg_stroke.color = TEXT;
    }
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(30, 36, 54);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(38, 46, 70);
    visuals.selection.bg_fill = with_alpha(ACCENT, 90);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = vec2(8.0, 8.0);
    style.spacing.button_padding = vec2(14.0, 7.0);
    style.visuals.window_rounding = egui::Rounding::same(14.0);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(9.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(9.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(9.0);
    ctx.set_style(style);
}

pub fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(with_alpha(CARD, 215))
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(14.0)
        .inner_margin(Margin::symmetric(18.0, 16.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner
}

pub fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::none()
        .fill(with_alpha(color, 38))
        .rounding(7.0)
        .inner_margin(Margin::symmetric(9.0, 3.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.5).strong().color(color));
        });
}

pub fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).size(13.0).color(DIM)
}

pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(16.0).strong().color(TEXT));
    ui.add_space(4.0);
}

/// Filled accent button for the one main action on a screen.
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text)
            .size(14.5)
            .strong()
            .color(Color32::from_rgb(8, 14, 32)),
    )
    .fill(ACCENT)
    .stroke(Stroke::NONE)
    .min_size(vec2(110.0, 34.0))
    .rounding(9.0)
}

/// Quiet outlined button for secondary actions.
pub fn ghost_button(text: &str, color: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).size(13.5).color(color))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, with_alpha(color, 90)))
        .min_size(vec2(0.0, 30.0))
        .rounding(9.0)
}

/// A big clickable tile with a title and a wrapped description. Returns true
/// when clicked.
pub fn choice_card(ui: &mut egui::Ui, title: &str, description: &str, tag: &str) -> bool {
    let width = ui.available_width();
    let galley = ui.painter().layout(
        description.to_string(),
        FontId::proportional(13.0),
        DIM,
        width - 40.0,
    );
    let height = 22.0 + 24.0 + galley.size().y + 18.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());

    if ui.is_rect_visible(rect) {
        let hovered = response.hovered();
        let painter = ui.painter();
        painter.rect_filled(
            rect,
            14.0,
            if hovered {
                with_alpha(ACCENT, 34)
            } else {
                with_alpha(CARD, 215)
            },
        );
        painter.rect_stroke(
            rect,
            14.0,
            Stroke::new(
                1.0,
                if hovered {
                    with_alpha(ACCENT, 160)
                } else {
                    BORDER
                },
            ),
        );
        painter.text(
            rect.left_top() + vec2(20.0, 20.0),
            Align2::LEFT_TOP,
            title,
            FontId::proportional(16.5),
            TEXT,
        );
        if !tag.is_empty() {
            painter.text(
                rect.right_bottom() + vec2(-16.0, -12.0),
                Align2::RIGHT_BOTTOM,
                tag,
                FontId::proportional(11.0),
                ACCENT,
            );
        }
        painter.galley(rect.left_top() + vec2(20.0, 48.0), galley, DIM);
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

pub struct Toast {
    pub text: String,
    pub color: Color32,
    pub until: std::time::Instant,
}

pub fn toast(text: impl Into<String>, color: Color32) -> Toast {
    Toast {
        text: text.into(),
        color,
        until: std::time::Instant::now() + std::time::Duration::from_millis(3200),
    }
}

/// Draws the toast (bottom-right) while it's alive and drops it afterwards.
pub fn show_toast(ctx: &egui::Context, slot: &mut Option<Toast>) {
    let Some(current) = slot.as_ref() else {
        return;
    };
    let now = std::time::Instant::now();
    if now >= current.until {
        *slot = None;
        return;
    }

    egui::Area::new(egui::Id::new("toast"))
        .anchor(Align2::RIGHT_BOTTOM, vec2(-22.0, -22.0))
        .order(egui::Order::Tooltip)
        .show(ctx, |ui| {
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 25, 40))
                .stroke(Stroke::new(1.0, with_alpha(current.color, 140)))
                .rounding(12.0)
                .inner_margin(Margin::symmetric(16.0, 11.0))
                .show(ui, |ui| {
                    ui.label(RichText::new(&current.text).size(13.5).color(current.color));
                });
        });
    ctx.request_repaint_after(current.until - now);
}
