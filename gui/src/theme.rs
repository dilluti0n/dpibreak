// SPDX-License-Identifier: GPL-3.0-or-later

//! Colors, typography and small reusable widgets.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Shadow, Stroke, TextStyle,
    Vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x0a, 0x0c, 0x12);
pub const CARD: Color32 = Color32::from_rgb(0x13, 0x17, 0x21);
pub const CARD_ALT: Color32 = Color32::from_rgb(0x19, 0x1e, 0x2b);
pub const BORDER: Color32 = Color32::from_rgb(0x24, 0x2a, 0x3a);
pub const TEXT: Color32 = Color32::from_rgb(0xe8, 0xeb, 0xf2);
pub const MUTED: Color32 = Color32::from_rgb(0x86, 0x8f, 0xa3);
pub const FAINT: Color32 = Color32::from_rgb(0x3a, 0x41, 0x52);
pub const ACCENT: Color32 = Color32::from_rgb(0x7c, 0x6c, 0xff);
pub const ACCENT_2: Color32 = Color32::from_rgb(0x38, 0xbd, 0xf8);
pub const GREEN: Color32 = Color32::from_rgb(0x34, 0xd3, 0x99);
pub const YELLOW: Color32 = Color32::from_rgb(0xfb, 0xbf, 0x24);
pub const RED: Color32 = Color32::from_rgb(0xf8, 0x71, 0x71);

pub fn apply(ctx: &egui::Context) {
    // Always dark, regardless of the Windows theme.
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(18.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(13.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(12.5, FontFamily::Monospace),
            ),
            (
                TextStyle::Small,
                FontId::new(11.5, FontFamily::Proportional),
            ),
        ]
        .into();

        let s = &mut style.spacing;
        s.item_spacing = Vec2::new(8.0, 7.0);
        s.button_padding = Vec2::new(12.0, 5.0);
        s.interact_size.y = 26.0;
        s.slider_width = 90.0;

        let v = &mut style.visuals;
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.extreme_bg_color = Color32::from_rgb(0x0c, 0x0f, 0x16);
        v.faint_bg_color = CARD_ALT;
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = ACCENT.gamma_multiply(0.55);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.hyperlink_color = ACCENT_2;
        v.window_shadow = Shadow::NONE;
        v.popup_shadow = Shadow {
            offset: [0, 6],
            blur: 18,
            spread: 0,
            color: Color32::from_black_alpha(140),
        };

        let r = CornerRadius::same(8);
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.corner_radius = r;
        }
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        v.widgets.inactive.weak_bg_fill = CARD_ALT;
        v.widgets.inactive.bg_fill = CARD_ALT;
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x23, 0x29, 0x39);
        v.widgets.hovered.bg_fill = Color32::from_rgb(0x23, 0x29, 0x39);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.6));
        v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    });
}

/// A rounded, softly shadowed panel with a title row. `action` draws
/// right-aligned widgets on the title row.
pub fn card(
    ui: &mut egui::Ui,
    title: &str,
    subtitle: Option<&str>,
    action: impl FnOnce(&mut egui::Ui),
    body: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(14))
        .shadow(Shadow {
            offset: [0, 4],
            blur: 16,
            spread: 0,
            color: Color32::from_black_alpha(90),
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let width = ui.available_width();
            // Action on the right first, then the title block fills (and
            // wraps within) whatever width is left.
            ui.allocate_ui_with_layout(
                egui::vec2(width, 0.0),
                egui::Layout::right_to_left(egui::Align::Min),
                |ui| {
                    action(ui);
                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(RichText::new(title).size(15.0).strong());
                        if let Some(sub) = subtitle {
                            ui.add(
                                egui::Label::new(RichText::new(sub).color(MUTED).size(12.0)).wrap(),
                            );
                        }
                    });
                },
            );
            ui.add_space(4.0);
            body(ui);
        });
}

/// Inset area inside a card.
pub fn inset<R>(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD_ALT)
        .stroke(Stroke::new(1.0, BORDER.gamma_multiply(0.7)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            body(ui)
        })
        .inner
}

/// A small pill with a leading dot.
pub fn chip(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    // Painted by hand so it looks the same in left- and right-aligned rows.
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        FontId::new(12.0, FontFamily::Proportional),
        color,
    );
    let (pad_x, pad_y, dot_r, gap) = (9.0, 3.0, 3.0, 6.0);
    let size = Vec2::new(
        pad_x * 2.0 + dot_r * 2.0 + gap + galley.size().x,
        pad_y * 2.0 + galley.size().y.max(dot_r * 2.0),
    );
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        p.rect(
            rect,
            CornerRadius::same(255),
            color.gamma_multiply(0.13),
            Stroke::new(1.0, color.gamma_multiply(0.30)),
            egui::StrokeKind::Inside,
        );
        let dot_c = egui::pos2(rect.left() + pad_x + dot_r, rect.center().y);
        p.circle_filled(dot_c, dot_r, color);
        let text_pos = egui::pos2(
            dot_c.x + dot_r + gap,
            rect.center().y - galley.size().y / 2.0,
        );
        p.galley(text_pos, galley, color);
    }
    resp
}

pub fn dot(ui: &mut egui::Ui, color: Color32, radius: f32) -> egui::Response {
    let size = Vec2::splat(radius * 2.0 + 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), radius, color);
    resp
}

/// A status light with a soft glow around it.
pub fn glow_dot(ui: &mut egui::Ui, color: Color32, radius: f32) {
    let size = Vec2::splat(radius * 4.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let c = rect.center();
    let p = ui.painter();
    for (scale, alpha) in [(2.0, 0.06), (1.6, 0.12), (1.3, 0.22)] {
        p.circle_filled(c, radius * scale, color.gamma_multiply(alpha));
    }
    p.circle_filled(c, radius, color);
    p.circle_filled(
        c - Vec2::splat(radius * 0.3),
        radius * 0.35,
        Color32::from_white_alpha(70),
    );
}

/// App mark: a rounded square in the accent color with a light core.
pub fn logo(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same((size * 0.28) as u8), ACCENT);
    p.rect_filled(
        rect.shrink(size * 0.18)
            .translate(Vec2::new(size * 0.06, size * 0.06)),
        CornerRadius::same((size * 0.2) as u8),
        ACCENT_2.gamma_multiply(0.85),
    );
    p.circle_filled(rect.center(), size * 0.14, Color32::WHITE);
}

fn filled_button(text: &str, fill: Color32) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text.to_string())
            .strong()
            .color(Color32::WHITE),
    )
    .fill(fill)
    .stroke(Stroke::new(1.0, Color32::from_white_alpha(18)))
    .corner_radius(CornerRadius::same(9))
    .min_size(Vec2::new(0.0, 30.0))
}

pub fn primary(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(enabled, filled_button(text, ACCENT))
}

pub fn danger(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        filled_button(text, Color32::from_rgb(0xdc, 0x3d, 0x4b)),
    )
}

pub fn success(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        filled_button(text, Color32::from_rgb(0x10, 0xa3, 0x76)),
    )
}

pub fn secondary(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(text.to_string())
            .corner_radius(CornerRadius::same(9))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// Frameless muted text button.
pub fn link(ui: &mut egui::Ui, enabled: bool, text: &str, color: Color32) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).color(color).size(12.5)).frame(false),
    )
}

/// Label/value row used in forms.
pub fn field(ui: &mut egui::Ui, label: &str, value: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(LABEL_WIDTH, 22.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_min_width(LABEL_WIDTH);
                ui.label(RichText::new(label).color(MUTED));
            },
        );
        value(ui);
    });
}

pub const LABEL_WIDTH: f32 = 70.0;
