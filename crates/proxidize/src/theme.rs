//! The patch-panel look: graphite surfaces, three text roles, one teal accent,
//! coloured patch cables per proxy and square link lights for status. Every colour and font comes from here.

use std::sync::Arc;

use eframe::egui::{
    self, epaint::text::TextWrapping, text::LayoutJob, Align2, Color32, CornerRadius, FontData, FontDefinitions, FontFamily,
    FontId, Pos2, Rect, Stroke, StrokeKind, TextFormat, Vec2,
};
use proxidize_core::config::{Config, ProxyServer};
use proxidize_core::health::{HealthState, ProxyHealth};

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

// Graphite ramp.
pub const RACK: Color32 = hex(0x0F0F10); // navigation rail, deepest surface
pub const PAGE: Color32 = hex(0x141415); // page background
pub const CARD: Color32 = hex(0x19191B); // inputs, menus, dialogs
pub const RAISED: Color32 = hex(0x232325); // selection, hover, secondary buttons
pub const HAIRLINE: Color32 = hex(0x2A2A2D);
pub const HAIRLINE_STRONG: Color32 = hex(0x36363A);

pub const TEXT: Color32 = hex(0xEDEDED);
pub const TEXT_SECONDARY: Color32 = hex(0xA1A1A6);
pub const TEXT_MUTED: Color32 = hex(0x85858B);

/// Teal from the rack's status panels: selection marker and focus only.
pub const ACCENT: Color32 = hex(0x3FB9A9);

// Link lights.
pub const LIGHT_OK: Color32 = hex(0x4CC38A);
pub const LIGHT_FAULT: Color32 = hex(0xE5484D);
pub const LIGHT_CAUTION: Color32 = hex(0xE0A43A);
pub const LIGHT_OFF: Color32 = hex(0x4A4A4F);

/// Patch cable jackets, in the order new proxies get them.
pub const CABLES: [Color32; 12] = [
    hex(0x4C8DF6), // blue
    hex(0xF08C3A), // orange
    hex(0x3FB66B), // green
    hex(0xB07D52), // brown
    hex(0x9B7BEA), // violet
    hex(0xE5534B), // red
    hex(0xE3B341), // yellow
    hex(0x2BB3A6), // teal
    hex(0xE06C9F), // pink
    hex(0x8B949E), // grey
    hex(0x9CC43A), // lime
    hex(0xD8DEE4), // white
];

pub const CABLE_NAMES: [&str; 12] =
    ["Blue", "Orange", "Green", "Brown", "Violet", "Red", "Yellow", "Teal", "Pink", "Grey", "Lime", "White"];

// Spacing scale (4 px grid).
pub const S1: f32 = 4.0;
pub const S2: f32 = 8.0;
pub const S3: f32 = 12.0;
pub const S4: f32 = 16.0;
pub const S6: f32 = 24.0;
pub const S8: f32 = 32.0;

pub const RADIUS: u8 = 4;

fn family(name: &str) -> FontFamily {
    FontFamily::Name(name.into())
}

/// Segoe UI for interface text.
pub fn body() -> FontId {
    FontId::new(13.5, FontFamily::Proportional)
}

pub fn body_strong() -> FontId {
    FontId::new(13.5, family("strong"))
}

pub fn small() -> FontId {
    FontId::new(12.0, FontFamily::Proportional)
}

/// Bahnschrift for data: names, addresses, figures.
pub fn data() -> FontId {
    FontId::new(14.0, family("data"))
}

pub fn data_small() -> FontId {
    FontId::new(12.5, family("data"))
}

pub fn data_strong() -> FontId {
    FontId::new(14.0, family("data-strong"))
}

pub fn title() -> FontId {
    FontId::new(22.5, family("data"))
}

pub fn wordmark() -> FontId {
    FontId::new(17.5, family("data-strong"))
}

pub fn figure() -> FontId {
    FontId::new(19.5, family("data-strong"))
}

fn first_existing(candidates: &[&str]) -> Option<Vec<u8>> {
    candidates.iter().find_map(|p| std::fs::read(p).ok())
}

/// Installs fonts and the visual style.
pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    let win = |f: &str| format!(r"{windir}\Fonts\{f}");
    let ui = first_existing(&[
        &win("segoeui.ttf"),
        "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]);
    let strong = first_existing(&[
        &win("seguisb.ttf"),
        "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ]);
    let data = first_existing(&[
        &win("bahnschrift.ttf"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf",
        "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
    ]);
    let data_strong = first_existing(&[
        &win("seguisb.ttf"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf",
        "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf",
    ]);
    let mut add = |name: &str, bytes: Option<Vec<u8>>, families: &[FontFamily]| {
        let fallback: Vec<String> = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
        if let Some(bytes) = bytes {
            fonts.font_data.insert(name.into(), Arc::new(FontData::from_owned(bytes)));
        }
        for f in families {
            let list = fonts.families.entry(f.clone()).or_default();
            if fonts.font_data.contains_key(name) && !list.contains(&name.to_string()) {
                list.insert(0, name.into());
            }
            for fb in &fallback {
                if !list.contains(fb) {
                    list.push(fb.clone());
                }
            }
        }
    };
    add("ui", ui, &[FontFamily::Proportional]);
    add("strong", strong, &[family("strong")]);
    add("data", data, &[family("data")]);
    add("data-strong", data_strong, &[family("data-strong")]);
    ctx.set_fonts(fonts);

    ctx.global_style_mut(|style| {
        style.text_styles = [
            (egui::TextStyle::Small, small()),
            (egui::TextStyle::Body, body()),
            (egui::TextStyle::Button, body()),
            (egui::TextStyle::Heading, title()),
            (egui::TextStyle::Monospace, FontId::new(12.5, FontFamily::Monospace)),
        ]
        .into();
        style.spacing.item_spacing = Vec2::new(S2, S2);
        style.spacing.button_padding = Vec2::new(S3, 5.0);
        style.spacing.interact_size = Vec2::new(40.0, 28.0);
        style.spacing.scroll.bar_width = 6.0;
        style.spacing.scroll.floating = false;
        let v = &mut style.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = PAGE;
        v.window_fill = CARD;
        v.extreme_bg_color = CARD;
        v.faint_bg_color = RACK;
        v.code_bg_color = CARD;
        v.override_text_color = Some(TEXT);
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = ACCENT.linear_multiply(0.35);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.window_stroke = Stroke::new(1.0, HAIRLINE_STRONG);
        v.window_corner_radius = CornerRadius::same(6);
        v.menu_corner_radius = CornerRadius::same(RADIUS);
        v.popup_shadow = egui::epaint::Shadow { offset: [0, 4], blur: 16, spread: 0, color: Color32::from_black_alpha(120) };
        v.window_shadow = egui::epaint::Shadow { offset: [0, 8], blur: 28, spread: 0, color: Color32::from_black_alpha(140) };
        v.text_cursor.stroke = Stroke::new(1.5, TEXT);
        let radius = CornerRadius::same(RADIUS);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = PAGE;
        w.noninteractive.weak_bg_fill = PAGE;
        w.noninteractive.bg_stroke = Stroke::new(1.0, HAIRLINE);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_SECONDARY);
        w.inactive.bg_fill = CARD;
        w.inactive.weak_bg_fill = RAISED;
        w.inactive.bg_stroke = Stroke::new(1.0, HAIRLINE_STRONG);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.hovered.bg_fill = RAISED;
        w.hovered.weak_bg_fill = hex(0x2C2C2F);
        w.hovered.bg_stroke = Stroke::new(1.0, TEXT_MUTED);
        w.hovered.fg_stroke = Stroke::new(1.0, TEXT);
        w.active.bg_fill = RAISED;
        w.active.weak_bg_fill = hex(0x303033);
        w.active.bg_stroke = Stroke::new(1.0, ACCENT);
        w.active.fg_stroke = Stroke::new(1.0, TEXT);
        w.open = w.active;
        for s in [&mut w.noninteractive, &mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
            s.corner_radius = radius;
            s.expansion = 0.0;
        }
    });
}

pub fn parse_hex(text: &str) -> Option<Color32> {
    let t = text.trim().trim_start_matches('#');
    if t.len() != 6 {
        return None;
    }
    u32::from_str_radix(t, 16).ok().map(hex)
}

pub fn to_hex(c: Color32) -> String {
    format!("#{:02X}{:02X}{:02X}", c.r(), c.g(), c.b())
}

pub fn cable_of(proxy: &ProxyServer, config: &Config) -> Color32 {
    if let Some(c) = proxy.color.as_deref().and_then(parse_hex) {
        return c;
    }
    let index = config.proxies.iter().position(|p| p.id == proxy.id).unwrap_or(0);
    CABLES[index % CABLES.len()]
}

/// The next cable colour no proxy uses yet.
pub fn free_cable(config: &Config) -> Color32 {
    let used: Vec<Color32> = config.proxies.iter().map(|p| cable_of(p, config)).collect();
    CABLES.iter().copied().find(|c| !used.contains(c)).unwrap_or(CABLES[config.proxies.len() % CABLES.len()])
}

/// (colour, hollow) of a link light for a health result.
pub fn light_of(health: Option<&ProxyHealth>) -> (Color32, bool) {
    match health {
        None => (LIGHT_OFF, true),
        Some(h) => match h.state {
            HealthState::Ok => (LIGHT_OK, false),
            HealthState::SharedIp => (LIGHT_CAUTION, false),
            _ => (LIGHT_FAULT, false),
        },
    }
}

/// The signature: a small square link light, vertically centred on `y`. Unknown state is a hollow square.
pub fn light(p: &egui::Painter, x: f32, y: f32, color: Color32, hollow: bool) {
    let r = Rect::from_min_size(Pos2::new(x, (y - 4.0).round()), Vec2::splat(8.0));
    if hollow {
        p.rect_stroke(r.shrink(0.5), 0, Stroke::new(1.0, LIGHT_OFF), StrokeKind::Inside);
    } else {
        p.rect_filled(r, 0, color);
    }
}

/// A length of patch cable ending in its plug.
pub fn cable(p: &egui::Painter, from: Pos2, to: Pos2, color: Color32, dashed: bool) {
    let stroke = Stroke::new(3.0, color);
    let end = Pos2::new(to.x - 6.0, to.y);
    if dashed {
        p.extend(egui::Shape::dashed_line(&[from, end], stroke, 6.0, 4.0));
    } else {
        p.line_segment([from, end], stroke);
    }
    p.rect_filled(Rect::from_min_size(Pos2::new(to.x - 8.0, to.y - 4.0), Vec2::new(8.0, 8.0)), 0, color);
}

/// Single-line text clipped to `rect` with an ellipsis.
pub fn text(p: &egui::Painter, rect: Rect, text: &str, font: FontId, color: Color32, align: Align2) -> Rect {
    let mut job = LayoutJob::single_section(text.to_string(), TextFormat::simple(font, color));
    job.wrap =
        TextWrapping { max_width: rect.width().max(1.0), max_rows: 1, break_anywhere: true, overflow_character: Some('…') };
    let galley = p.layout_job(job);
    let pos = align.align_size_within_rect(galley.size(), rect).min;
    let r = Rect::from_min_size(pos, galley.size());
    p.galley(pos, galley, color);
    r
}

pub fn text_width(ctx: &egui::Context, text: &str, font: FontId) -> f32 {
    ctx.fonts_mut(|f| f.layout_no_wrap(text.to_string(), font, TEXT).size().x)
}

pub fn dim(c: Color32) -> Color32 {
    c.linear_multiply(0.45)
}
