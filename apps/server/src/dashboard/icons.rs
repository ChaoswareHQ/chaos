//! The console's icons: Phosphor, vendored as markup and inlined into the page.
//!
//! # Why these are inlined and not `<img src>`
//!
//! Three reasons, in order of how much they matter:
//!
//! * `default-src 'none'; img-src 'self'` would need an extra request per icon,
//!   and a console that fires eight requests to draw a sidebar is a console that
//!   draws a sidebar eight times slower than it needs to.
//! * An `<img>` cannot inherit `currentColor`, so every icon would need its own
//!   colour rule and would go wrong the moment the palette changed. Inline, an
//!   icon is text: it tints with the thing it sits next to.
//! * Inline markup is part of the document, so the strict CSP does not have to be
//!   relaxed to have icons at all.
//!
//! # Why not the icon font, and why not npm
//!
//! An icon font is a webfont: a build step, a `font-src` directive, a flash of
//! wrong glyphs, and screen readers that read private-use codepoints. npm is the
//! dependency tree this console exists without. What is vendored here is the one
//! thing that is actually needed — the path data — and nothing else.
//!
//! # Provenance
//!
//! Source: [`@phosphor-icons/core`](https://github.com/phosphor-icons/core)
//! `2.1.1`, `assets/regular/<name>.svg`, MIT licensed. The regular weight is a
//! single `fill="currentColor"` path on a `256×256` viewBox, which is why the
//! wrapper below supplies only the box, the fill and the accessibility
//! attributes.
//!
//! To update, re-fetch the set and regenerate the table at the bottom of this
//! file:
//!
//! ```text
//! curl -sSL -o <name>.svg \
//!   https://unpkg.com/@phosphor-icons/core@2.1.1/assets/regular/<name>.svg
//! awk '/viewBox="0 0 256 256"/ {
//!   name = FILENAME; sub(/^.*\//, "", name); sub(/\.svg$/, "", name);
//!   body = $0; sub(/^.*viewBox="0 0 256 256"[^>]*>/, "", body); sub(/<\/svg>.*$/, "", body);
//!   printf "    (\"%s\", r#\"%s\"#),\n", name, body;
//! }' <name>.svg [...] >> icons.rs
//! ```

use std::fmt::Write as _;

/// The contents of `<svg>` for one icon, or `""` when the name is unknown.
///
/// Blank rather than a panic: a missing icon should cost a picture, not the page
/// it was going to be drawn on.
pub fn markup(name: &str) -> &'static str {
    VENDORED
        .iter()
        .find(|(icon, _)| *icon == name)
        .map(|(_, markup)| *markup)
        .unwrap_or("")
}

/// The icons the chrome draws. Paired with the vendored set by two tests, so the
/// two cannot drift: one says every name here is vendored, the other says nothing
/// else is.
#[cfg(test)]
const ASKED_FOR: &[&str] = &[
    "shield-check",
    "list-checks",
    "desktop",
    "crosshair",
    "pulse",
    "warning",
    "broadcast",
    "hard-drives",
    "database",
    "clock",
    "arrows-clockwise",
    "chart-bar",
    "funnel",
    "arrow-left",
    "magnifying-glass",
    "x",
];

/// One icon, as an `<svg>` that sizes itself like text.
///
/// `aria-hidden` is not optional: every icon here sits next to the word it
/// stands for, so a screen reader that announced both would say everything
/// twice. The label is the text, the icon is the decoration.
pub fn render(name: &str, class: &str) -> String {
    let mut html = String::with_capacity(markup(name).len() + 128);
    let _ = write!(
        html,
        "<svg class=\"{class}\" viewBox=\"0 0 256 256\" fill=\"currentColor\" \
         aria-hidden=\"true\" focusable=\"false\">{}</svg>",
        markup(name)
    );
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_vendored_icon_carries_a_path_and_a_unique_name() {
        assert!(VENDORED.len() >= 16, "the console's chrome needs its set");
        for (name, markup) in VENDORED {
            assert!(!name.is_empty());
            assert!(
                markup.starts_with("<path"),
                "{name} is not a path: {markup}"
            );
            assert!(markup.ends_with("/>"), "{name} is not self-closed");
        }
        let mut names: Vec<&str> = VENDORED.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "an icon is vendored twice");
    }

    /// The console's CSP forbids inline styles and script. Icons are inlined into
    /// every page, so this is the check that a re-vendor cannot smuggle either
    /// back in — a `style="fill:#fff"` in an icon would break the stylesheet-wide
    /// rule in exactly the place nobody would look.
    #[test]
    fn no_vendored_icon_carries_style_or_script() {
        for (name, markup) in VENDORED {
            let lowered = markup.to_ascii_lowercase();
            assert!(!lowered.contains("style="), "{name} carries a style=");
            assert!(!lowered.contains("<script"), "{name} carries script");
            assert!(!lowered.contains("onload"), "{name} carries a handler");
            assert!(!lowered.contains("href"), "{name} carries a link");
        }
    }

    #[test]
    fn an_unknown_icon_is_blank_rather_than_a_panic() {
        assert_eq!(markup("no-such-icon-9f3c1a"), "");
        let rendered = render("no-such-icon-9f3c1a", "ic");
        assert!(rendered.contains("<svg"));
        assert!(rendered.contains("</svg>"));
    }

    #[test]
    fn an_icon_takes_its_colour_from_the_text_around_it() {
        let rendered = render("desktop", "ic");
        assert!(rendered.contains("fill=\"currentColor\""), "{rendered}");
        assert!(rendered.contains("viewBox=\"0 0 256 256\""));
        assert!(rendered.contains("class=\"ic\""));
        assert!(
            rendered.contains("aria-hidden=\"true\""),
            "an icon next to its own label is decoration: {rendered}"
        );
        assert!(!rendered.contains("style="));
    }

    #[test]
    fn the_names_are_all_phosphor_names_the_chrome_asks_for() {
        // Adding an icon to a page without vendoring it is a blank square, and
        // this is what notices.
        for name in ASKED_FOR {
            assert!(!markup(name).is_empty(), "{name} is not vendored");
        }
    }

    #[test]
    fn nothing_is_vendored_that_the_chrome_does_not_draw() {
        // Eight kilobytes of path data nobody renders is the kind of thing that
        // accumulates. The icon set is exactly what the pages ask for.
        for (name, _) in VENDORED {
            assert!(
                ASKED_FOR.contains(name),
                "{name} is vendored but no view draws it"
            );
        }
    }
}

/// Every icon the console draws, keyed by its Phosphor name.
///
/// Generated from the upstream SVGs — see the module documentation. Keep it
/// last: it is the one part of this file that is not written by hand.
const VENDORED: &[(&str, &str)] = &[
    (
        "arrow-left",
        r#"<path d="M224,128a8,8,0,0,1-8,8H59.31l58.35,58.34a8,8,0,0,1-11.32,11.32l-72-72a8,8,0,0,1,0-11.32l72-72a8,8,0,0,1,11.32,11.32L59.31,120H216A8,8,0,0,1,224,128Z"/>"#,
    ),
    (
        "arrows-clockwise",
        r#"<path d="M224,48V96a8,8,0,0,1-8,8H168a8,8,0,0,1,0-16h28.69L182.06,73.37a79.56,79.56,0,0,0-56.13-23.43h-.45A79.52,79.52,0,0,0,69.59,72.71,8,8,0,0,1,58.41,61.27a96,96,0,0,1,135,.79L208,76.69V48a8,8,0,0,1,16,0ZM186.41,183.29a80,80,0,0,1-112.47-.66L59.31,168H88a8,8,0,0,0,0-16H40a8,8,0,0,0-8,8v48a8,8,0,0,0,16,0V179.31l14.63,14.63A95.43,95.43,0,0,0,130,222.06h.53a95.36,95.36,0,0,0,67.07-27.33,8,8,0,0,0-11.18-11.44Z"/>"#,
    ),
    (
        "broadcast",
        r#"<path d="M128,88a40,40,0,1,0,40,40A40,40,0,0,0,128,88Zm0,64a24,24,0,1,1,24-24A24,24,0,0,1,128,152Zm73.71,7.14a80,80,0,0,1-14.08,22.2,8,8,0,0,1-11.92-10.67,63.95,63.95,0,0,0,0-85.33,8,8,0,1,1,11.92-10.67,80.08,80.08,0,0,1,14.08,84.47ZM69,103.09a64,64,0,0,0,11.26,67.58,8,8,0,0,1-11.92,10.67,79.93,79.93,0,0,1,0-106.67A8,8,0,1,1,80.29,85.34,63.77,63.77,0,0,0,69,103.09ZM248,128a119.58,119.58,0,0,1-34.29,84,8,8,0,1,1-11.42-11.2,103.9,103.9,0,0,0,0-145.56A8,8,0,1,1,213.71,44,119.58,119.58,0,0,1,248,128ZM53.71,200.78A8,8,0,1,1,42.29,212a119.87,119.87,0,0,1,0-168,8,8,0,1,1,11.42,11.2,103.9,103.9,0,0,0,0,145.56Z"/>"#,
    ),
    (
        "chart-bar",
        r#"<path d="M224,200h-8V40a8,8,0,0,0-8-8H152a8,8,0,0,0-8,8V80H96a8,8,0,0,0-8,8v40H48a8,8,0,0,0-8,8v64H32a8,8,0,0,0,0,16H224a8,8,0,0,0,0-16ZM160,48h40V200H160ZM104,96h40V200H104ZM56,144H88v56H56Z"/>"#,
    ),
    (
        "clock",
        r#"<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,192a88,88,0,1,1,88-88A88.1,88.1,0,0,1,128,216Zm64-88a8,8,0,0,1-8,8H128a8,8,0,0,1-8-8V72a8,8,0,0,1,16,0v48h48A8,8,0,0,1,192,128Z"/>"#,
    ),
    (
        "crosshair",
        r#"<path d="M232,120h-8.34A96.14,96.14,0,0,0,136,32.34V24a8,8,0,0,0-16,0v8.34A96.14,96.14,0,0,0,32.34,120H24a8,8,0,0,0,0,16h8.34A96.14,96.14,0,0,0,120,223.66V232a8,8,0,0,0,16,0v-8.34A96.14,96.14,0,0,0,223.66,136H232a8,8,0,0,0,0-16Zm-96,87.6V200a8,8,0,0,0-16,0v7.6A80.15,80.15,0,0,1,48.4,136H56a8,8,0,0,0,0-16H48.4A80.15,80.15,0,0,1,120,48.4V56a8,8,0,0,0,16,0V48.4A80.15,80.15,0,0,1,207.6,120H200a8,8,0,0,0,0,16h7.6A80.15,80.15,0,0,1,136,207.6ZM128,88a40,40,0,1,0,40,40A40,40,0,0,0,128,88Zm0,64a24,24,0,1,1,24-24A24,24,0,0,1,128,152Z"/>"#,
    ),
    (
        "database",
        r#"<path d="M128,24C74.17,24,32,48.6,32,80v96c0,31.4,42.17,56,96,56s96-24.6,96-56V80C224,48.6,181.83,24,128,24Zm80,104c0,9.62-7.88,19.43-21.61,26.92C170.93,163.35,150.19,168,128,168s-42.93-4.65-58.39-13.08C55.88,147.43,48,137.62,48,128V111.36c17.06,15,46.23,24.64,80,24.64s62.94-9.68,80-24.64ZM69.61,53.08C85.07,44.65,105.81,40,128,40s42.93,4.65,58.39,13.08C200.12,60.57,208,70.38,208,80s-7.88,19.43-21.61,26.92C170.93,115.35,150.19,120,128,120s-42.93-4.65-58.39-13.08C55.88,99.43,48,89.62,48,80S55.88,60.57,69.61,53.08ZM186.39,202.92C170.93,211.35,150.19,216,128,216s-42.93-4.65-58.39-13.08C55.88,195.43,48,185.62,48,176V159.36c17.06,15,46.23,24.64,80,24.64s62.94-9.68,80-24.64V176C208,185.62,200.12,195.43,186.39,202.92Z"/>"#,
    ),
    (
        "desktop",
        r#"<path d="M208,40H48A24,24,0,0,0,24,64V176a24,24,0,0,0,24,24h72v16H96a8,8,0,0,0,0,16h64a8,8,0,0,0,0-16H136V200h72a24,24,0,0,0,24-24V64A24,24,0,0,0,208,40ZM48,56H208a8,8,0,0,1,8,8v80H40V64A8,8,0,0,1,48,56ZM208,184H48a8,8,0,0,1-8-8V160H216v16A8,8,0,0,1,208,184Z"/>"#,
    ),
    (
        "funnel",
        r#"<path d="M230.6,49.53A15.81,15.81,0,0,0,216,40H40A16,16,0,0,0,28.19,66.76l.08.09L96,139.17V216a16,16,0,0,0,24.87,13.32l32-21.34A16,16,0,0,0,160,194.66V139.17l67.74-72.32.08-.09A15.8,15.8,0,0,0,230.6,49.53ZM40,56h0Zm106.18,74.58A8,8,0,0,0,144,136v58.66L112,216V136a8,8,0,0,0-2.16-5.47L40,56H216Z"/>"#,
    ),
    (
        "hard-drives",
        r#"<path d="M208,136H48a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V152A16,16,0,0,0,208,136Zm0,64H48V152H208v48Zm0-160H48A16,16,0,0,0,32,56v48a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V56A16,16,0,0,0,208,40Zm0,64H48V56H208v48ZM192,80a12,12,0,1,1-12-12A12,12,0,0,1,192,80Zm0,96a12,12,0,1,1-12-12A12,12,0,0,1,192,176Z"/>"#,
    ),
    (
        "list-checks",
        r#"<path d="M224,128a8,8,0,0,1-8,8H128a8,8,0,0,1,0-16h88A8,8,0,0,1,224,128ZM128,72h88a8,8,0,0,0,0-16H128a8,8,0,0,0,0,16Zm88,112H128a8,8,0,0,0,0,16h88a8,8,0,0,0,0-16ZM82.34,42.34,56,68.69,45.66,58.34A8,8,0,0,0,34.34,69.66l16,16a8,8,0,0,0,11.32,0l32-32A8,8,0,0,0,82.34,42.34Zm0,64L56,132.69,45.66,122.34a8,8,0,0,0-11.32,11.32l16,16a8,8,0,0,0,11.32,0l32-32a8,8,0,0,0-11.32-11.32Zm0,64L56,196.69,45.66,186.34a8,8,0,0,0-11.32,11.32l16,16a8,8,0,0,0,11.32,0l32-32a8,8,0,0,0-11.32-11.32Z"/>"#,
    ),
    (
        "magnifying-glass",
        r#"<path d="M229.66,218.34l-50.07-50.06a88.11,88.11,0,1,0-11.31,11.31l50.06,50.07a8,8,0,0,0,11.32-11.32ZM40,112a72,72,0,1,1,72,72A72.08,72.08,0,0,1,40,112Z"/>"#,
    ),
    (
        "pulse",
        r#"<path d="M240,128a8,8,0,0,1-8,8H204.94l-37.78,75.58A8,8,0,0,1,160,216h-.4a8,8,0,0,1-7.08-5.14L95.35,60.76,63.28,131.31A8,8,0,0,1,56,136H24a8,8,0,0,1,0-16H50.85L88.72,36.69a8,8,0,0,1,14.76.46l57.51,151,31.85-63.71A8,8,0,0,1,200,120h32A8,8,0,0,1,240,128Z"/>"#,
    ),
    (
        "shield-check",
        r#"<path d="M208,40H48A16,16,0,0,0,32,56v56c0,52.72,25.52,84.67,46.93,102.19,23.06,18.86,46,25.26,47,25.53a8,8,0,0,0,4.2,0c1-.27,23.91-6.67,47-25.53C198.48,196.67,224,164.72,224,112V56A16,16,0,0,0,208,40Zm0,72c0,37.07-13.66,67.16-40.6,89.42A129.3,129.3,0,0,1,128,223.62a128.25,128.25,0,0,1-38.92-21.81C61.82,179.51,48,149.3,48,112l0-56,160,0ZM82.34,141.66a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32l-56,56a8,8,0,0,1-11.32,0Z"/>"#,
    ),
    (
        "warning",
        r#"<path d="M236.8,188.09,149.35,36.22h0a24.76,24.76,0,0,0-42.7,0L19.2,188.09a23.51,23.51,0,0,0,0,23.72A24.35,24.35,0,0,0,40.55,224h174.9a24.35,24.35,0,0,0,21.33-12.19A23.51,23.51,0,0,0,236.8,188.09ZM222.93,203.8a8.5,8.5,0,0,1-7.48,4.2H40.55a8.5,8.5,0,0,1-7.48-4.2,7.59,7.59,0,0,1,0-7.72L120.52,44.21a8.75,8.75,0,0,1,15,0l87.45,151.87A7.59,7.59,0,0,1,222.93,203.8ZM120,144V104a8,8,0,0,1,16,0v40a8,8,0,0,1-16,0Zm20,36a12,12,0,1,1-12-12A12,12,0,0,1,140,180Z"/>"#,
    ),
    (
        "x",
        r#"<path d="M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z"/>"#,
    ),
];
