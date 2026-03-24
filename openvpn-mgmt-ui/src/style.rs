//! Gruvbox-themed style helpers.
//!
//! small functions derive colours from the active [`iced::Theme`] palette
//! so the UI stays consistent regardless of the concrete theme variant.

use iced::widget::{container, text};
use iced::{Border, Color, Theme};
use iced_aw::style::{Status as TabStatus, tab_bar};

// -------------------------------------------------------------------
// Tab bar
// -------------------------------------------------------------------

pub(crate) fn tab_style(theme: &Theme, status: TabStatus) -> tab_bar::Style {
    let pal = theme.extended_palette();
    let bg = pal.background.base.color;
    let fg = pal.background.base.text;

    let base = tab_bar::Style {
        background: None,
        border_color: None,
        border_width: 0.0,
        tab_label_background: Color::TRANSPARENT.into(),
        tab_label_border_color: Color::TRANSPARENT,
        tab_label_border_width: 0.0,
        icon_color: fg,
        icon_background: None,
        icon_border_radius: 0.0.into(),
        tab_border_radius: 0.0.into(),
        text_color: mix(fg, bg, 0.4),
    };

    match status {
        TabStatus::Active => tab_bar::Style {
            tab_label_background: mix(bg, fg, 0.08).into(),
            text_color: fg,
            ..base
        },
        TabStatus::Hovered => tab_bar::Style {
            tab_label_background: mix(bg, fg, 0.06).into(),
            text_color: mix(fg, bg, 0.15),
            ..base
        },
        _ => base,
    }
}

// -------------------------------------------------------------------
// Text styles
// -------------------------------------------------------------------

pub(crate) fn text_label(theme: &Theme) -> text::Style {
    let (fg, bg) = fg_bg(theme);
    text::Style {
        color: Some(mix(fg, bg, 0.4)),
    }
}

pub(crate) fn text_muted(theme: &Theme) -> text::Style {
    let (fg, bg) = fg_bg(theme);
    text::Style {
        color: Some(mix(fg, bg, 0.5)),
    }
}

pub(crate) fn text_warning(theme: &Theme) -> text::Style {
    let pal = theme.extended_palette();
    let danger = pal.danger.base.color;
    let success = pal.success.base.color;
    text::Style {
        color: Some(Color {
            r: danger.r * 0.67 + success.r * 0.33,
            g: danger.g * 0.33 + success.g * 0.67,
            b: (danger.b + success.b) * 0.25,
            a: 1.0,
        }),
    }
}

// -------------------------------------------------------------------
// Container styles
// -------------------------------------------------------------------

/// Code-block container with a subtle theme-aware background.
#[expect(dead_code, reason = "reserved for future response display")]
pub(crate) fn code_block() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let pal = theme.extended_palette();
        container::Style {
            background: Some(pal.background.weak.color.into()),
            border: Border {
                color: pal.background.strong.color,
                width: 1.0,
                radius: 4.0.into(),
            },
            text_color: Some(pal.background.weak.text),
            ..Default::default()
        }
    })
}

/// Selected log row — highlighted background.
pub(crate) fn log_row_selected() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let pal = theme.extended_palette();
        container::Style {
            background: Some(mix(pal.background.base.color, pal.primary.base.color, 0.15).into()),
            border: Border {
                radius: 2.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    })
}

/// Status card container — subtle raised surface.
pub(crate) fn card() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let pal = theme.extended_palette();
        container::Style {
            background: Some(mix(pal.background.base.color, pal.background.base.text, 0.04).into()),
            border: Border {
                color: mix(pal.background.base.color, pal.background.base.text, 0.10),
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        }
    })
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

fn fg_bg(theme: &Theme) -> (Color, Color) {
    let pal = theme.extended_palette();
    (pal.background.base.text, pal.background.base.color)
}

/// Linearly interpolate between two colours. `t = 0.0` → `a`, `t = 1.0` → `b`.
pub(crate) fn mix(a: Color, b: Color, t: f32) -> Color {
    Color {
        r: a.r + (b.r - a.r) * t,
        g: a.g + (b.g - a.g) * t,
        b: a.b + (b.b - a.b) * t,
        a: 1.0,
    }
}
