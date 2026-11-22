// SPDX-License-Identifier: GPL-3.0-or-later

//! Colors, typography and small reusable widgets.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Stroke, TextStyle, Vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x0f, 0x11, 0x15);
pub const CARD: Color32 = Color32::from_rgb(0x18, 0x1b, 0x22);
pub const CARD_ALT: Color32 = Color32::from_rgb(0x1f, 0x23, 0x2c);
pub const BORDER: Color32 = Color32::from_rgb(0x2a, 0x2f, 0x3a);
pub const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe9, 0xef);
pub const MUTED: Color32 = Color32::from_rgb(0x8b, 0x93, 0xa3);
pub const ACCENT: Color32 = Color32::from_rgb(0x3b, 0x82, 0xf6);
pub const GREEN: Color32 = Color32::from_rgb(0x22, 0xc5, 0x5e);
pub const YELLOW: Color32 = Color32::from_rgb(0xea, 0xb3, 0x08);
pub const RED: Color32 = Color32::from_rgb(0xef, 0x44, 0x44);

pub fn apply(ctx: &egui::Context) {
    // Always dark, regardless of the Windows theme.
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(22.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(14.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.5, FontFamily::Monospace),
            ),
            (
                TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            ),
        ]
        .into();

        let s = &mut style.spacing;
        s.item_spacing = Vec2::new(10.0, 10.0);
        s.button_padding = Vec2::new(14.0, 7.0);
        s.interact_size.y = 30.0;

        let v = &mut style.visuals;
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.extreme_bg_color = Color32::from_rgb(0x0b, 0x0d, 0x11);
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = ACCENT;
        v.hyperlink_color = ACCENT;

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
        v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x2a, 0x30, 0x3c);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x3a, 0x42, 0x52));
    });
}

/// A rounded panel with a title row. `action` draws right-aligned
/// widgets on the title row.
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
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(18))
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
                        ui.label(RichText::new(title).size(17.0).strong());
                        if let Some(sub) = subtitle {
                            ui.add(
                                egui::Label::new(RichText::new(sub).color(MUTED).size(13.0)).wrap(),
                            );
                        }
                    });
                },
            );
            ui.add_space(6.0);
            body(ui);
        });
}

/// A small colored pill.
pub fn chip(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).size(12.5).strong());
        })
        .response
}

pub fn dot(ui: &mut egui::Ui, color: Color32, radius: f32) {
    let size = Vec2::splat(radius * 2.0 + 4.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), radius, color);
}

fn filled_button(text: &str, fill: Color32) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text.to_string())
            .strong()
            .color(Color32::WHITE),
    )
    .fill(fill)
    .stroke(Stroke::NONE)
    .min_size(Vec2::new(0.0, 34.0))
}

pub fn primary(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(enabled, filled_button(text, ACCENT))
}

pub fn danger(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        filled_button(text, Color32::from_rgb(0xb9, 0x2c, 0x2c)),
    )
}

pub fn success(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        filled_button(text, Color32::from_rgb(0x16, 0xa3, 0x4a)),
    )
}

pub fn secondary(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(text.to_string()).min_size(Vec2::new(0.0, 34.0)),
    )
}

/// Label/value row used in detail lists.
pub fn field(ui: &mut egui::Ui, label: &str, value: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(LABEL_WIDTH, 24.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_min_width(LABEL_WIDTH);
                ui.label(RichText::new(label).color(MUTED));
            },
        );
        value(ui);
    });
}

pub const LABEL_WIDTH: f32 = 96.0;
