//! Controls in the patch-panel style: buttons, the square check, search boxes, tables and form rows.

use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Pos2, Rect, Response, Sense, Stroke, StrokeKind, Ui, Vec2};

use crate::theme::{self, *};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The one main action on screen: light fill, dark text.
    Primary,
    /// Outlined.
    Secondary,
    /// Text only, for toolbars.
    Quiet,
    /// Destructive.
    Danger,
}

pub fn button(ui: &mut Ui, label: &str, kind: Kind) -> Response {
    button_enabled(ui, label, kind, true)
}

pub fn button_enabled(ui: &mut Ui, label: &str, kind: Kind, enabled: bool) -> Response {
    let font = body();
    let width = theme::text_width(ui.ctx(), label, font.clone()) + 2.0 * S4;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width.max(64.0), 30.0), if enabled { Sense::click() } else { Sense::hover() });
    let hovered = enabled && response.hovered();
    let pressed = enabled && response.is_pointer_button_down_on();
    let (fill, stroke, text) = match kind {
        Kind::Primary => (
            if pressed {
                Color32::from_gray(200)
            } else if hovered {
                Color32::WHITE
            } else {
                TEXT
            },
            Stroke::NONE,
            PAGE,
        ),
        Kind::Secondary => {
            (if hovered { RAISED } else { PAGE }, Stroke::new(1.0, if hovered { TEXT_MUTED } else { HAIRLINE_STRONG }), TEXT)
        }
        Kind::Quiet => (if hovered { RAISED } else { Color32::TRANSPARENT }, Stroke::NONE, TEXT),
        Kind::Danger => (
            if hovered { LIGHT_FAULT.linear_multiply(0.25) } else { PAGE },
            Stroke::new(1.0, LIGHT_FAULT.linear_multiply(0.6)),
            TEXT,
        ),
    };
    let (fill, stroke, text) = if enabled { (fill, stroke, text) } else { (PAGE, Stroke::new(1.0, HAIRLINE), TEXT_MUTED) };
    let p = ui.painter();
    p.rect(rect, CornerRadius::same(RADIUS), fill, stroke, StrokeKind::Inside);
    p.text(rect.center(), Align2::CENTER_CENTER, label, font, text);
    if response.has_focus() {
        p.rect_stroke(rect.expand(2.0), CornerRadius::same(RADIUS + 2), Stroke::new(1.0, ACCENT), StrokeKind::Outside);
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// The square check: a link light you can click. Returns true when it changed.
pub fn square_check(ui: &mut Ui, checked: &mut bool, label: &str) -> Response {
    let font = body();
    let width = 16.0 + S2 + theme::text_width(ui.ctx(), label, font.clone());
    let (rect, mut response) = ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::click());
    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    let p = ui.painter();
    let box_rect = Rect::from_min_size(Pos2::new(rect.left(), rect.center().y - 7.0), Vec2::splat(14.0));
    let stroke = if response.hovered() { TEXT_MUTED } else { HAIRLINE_STRONG };
    p.rect_stroke(box_rect, 2, Stroke::new(1.0, stroke), StrokeKind::Inside);
    if *checked {
        p.rect_filled(box_rect.shrink(3.0), 0, ACCENT);
    }
    p.text(Pos2::new(box_rect.right() + S2, rect.center().y), Align2::LEFT_CENTER, label, font, TEXT);
    response
}

/// An on/off square drawn inside a table row; returns true when clicked.
pub fn row_toggle(ui: &mut Ui, rect: Rect, id: egui::Id, on: bool) -> bool {
    let box_rect = Rect::from_center_size(rect.center(), Vec2::splat(14.0));
    let response = ui.interact(box_rect.expand(4.0), id, Sense::click());
    let p = ui.painter();
    p.rect_stroke(
        box_rect,
        2,
        Stroke::new(1.0, if response.hovered() { TEXT_MUTED } else { HAIRLINE_STRONG }),
        StrokeKind::Inside,
    );
    if on {
        p.rect_filled(box_rect.shrink(3.0), 0, ACCENT);
    }
    response.on_hover_text(if on { "On: click to turn off" } else { "Off: click to turn on" }).clicked()
}

pub fn search(ui: &mut Ui, text: &mut String, hint: &str, width: f32) -> Response {
    ui.add(egui::TextEdit::singleline(text).hint_text(hint).desired_width(width).margin(Vec2::new(S2, 6.0)))
}

/// A table column: a fixed width, or a share of what's left (`flex`).
#[derive(Clone, Copy)]
pub struct Col {
    pub title: &'static str,
    pub width: f32,
    pub flex: f32,
    pub right: bool,
}

pub const fn fixed(title: &'static str, width: f32) -> Col {
    Col { title, width, flex: 0.0, right: false }
}

pub const fn flex(title: &'static str, share: f32, min: f32) -> Col {
    Col { title, width: min, flex: share, right: false }
}

pub const fn right(title: &'static str, width: f32) -> Col {
    Col { title, width, flex: 0.0, right: true }
}

/// Cell rectangles for a row spanning `row`.
pub fn cells(row: Rect, cols: &[Col]) -> Vec<Rect> {
    let fixed: f32 = cols.iter().map(|c| c.width).sum();
    let shares: f32 = cols.iter().map(|c| c.flex).sum();
    let spare = (row.width() - fixed).max(0.0);
    let mut x = row.left();
    cols.iter()
        .map(|c| {
            let w = c.width + if shares > 0.0 { spare * c.flex / shares } else { 0.0 };
            let r = Rect::from_min_max(Pos2::new(x, row.top()), Pos2::new(x + w, row.bottom()));
            x += w;
            r.shrink2(Vec2::new(S2, 0.0))
        })
        .collect()
}

pub fn header(ui: &mut Ui, cols: &[Col]) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::hover());
    let p = ui.painter();
    for (c, r) in cols.iter().zip(cells(rect, cols)) {
        let align = if c.right { Align2::RIGHT_CENTER } else { Align2::LEFT_CENTER };
        theme::text(p, r, c.title, small(), TEXT_MUTED, align);
    }
    p.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, HAIRLINE));
}

/// One selectable table row. Returns the row response (click, double-click, context menu) and its rect.
pub fn row(ui: &mut Ui, height: f32, selected: bool, id: egui::Id) -> (Rect, Response) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let response = ui.interact(rect, id, Sense::click());
    let p = ui.painter();
    if selected {
        p.rect_filled(rect, 0, RAISED);
        p.rect_filled(Rect::from_min_size(rect.min, Vec2::new(2.0, rect.height())), 0, ACCENT);
    } else if response.hovered() {
        p.rect_filled(rect, 0, Color32::from_rgb(0x1B, 0x1B, 0x1D));
    }
    p.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, HAIRLINE));
    (rect, response)
}

/// Two lines in a cell: a strong first line and a quieter second one.
pub fn two_lines(
    p: &egui::Painter,
    r: Rect,
    first: &str,
    first_font: FontId,
    first_color: Color32,
    second: &str,
    second_color: Color32,
) {
    let mid = r.center().y;
    theme::text(
        p,
        Rect::from_min_max(Pos2::new(r.left(), mid - 18.0), Pos2::new(r.right(), mid)),
        first,
        first_font,
        first_color,
        Align2::LEFT_BOTTOM,
    );
    theme::text(
        p,
        Rect::from_min_max(Pos2::new(r.left(), mid + 1.0), Pos2::new(r.right(), mid + 18.0)),
        second,
        data_small(),
        second_color,
        Align2::LEFT_TOP,
    );
}

/// A labelled form row (label column + control).
pub fn form_row<R>(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(150.0, 28.0), Sense::hover());
        theme::text(ui.painter(), rect, label, body(), TEXT_SECONDARY, Align2::LEFT_CENTER);
        add(ui)
    })
    .inner
}

pub fn hint(ui: &mut Ui, text: &str) {
    ui.label(egui::RichText::new(text).font(small()).color(TEXT_MUTED));
}

pub fn section(ui: &mut Ui, title: &str) {
    ui.add_space(S4);
    ui.label(egui::RichText::new(title).font(data_strong()).color(TEXT));
    ui.add_space(S1);
}

/// A text field with a fixed width.
pub fn field(ui: &mut Ui, text: &mut String, width: f32) -> Response {
    ui.add(egui::TextEdit::singleline(text).desired_width(width).margin(Vec2::new(S2, 5.0)))
}

pub fn password(ui: &mut Ui, text: &mut String, width: f32) -> Response {
    ui.add(egui::TextEdit::singleline(text).password(true).desired_width(width).margin(Vec2::new(S2, 5.0)))
}

pub fn number<T: egui::emath::Numeric>(ui: &mut Ui, value: &mut T, range: std::ops::RangeInclusive<T>) -> Response {
    ui.add(egui::DragValue::new(value).range(range).speed(1.0))
}
