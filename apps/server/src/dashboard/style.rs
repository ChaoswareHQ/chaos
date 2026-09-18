//! The console's look: a stylesheet, and the few components every view is built
//! from.
//!
//! # Deliberately plain
//!
//! This is a table application. Wazuh and Splunk both put an analyst in front of
//! one dense table with a handful of filters, and the console here started out
//! with six pages, four chart panels and a tile grid on top of that — most of
//! which restated what the table already said, and none of which told you
//! anything you could act on twice as fast.
//!
//! So: a header with the fleet's numbers, three tabs, a filter row, and the
//! table. Everything a chart would have shown is already a clickable count in
//! the filter row, which is the same information with an action attached.
//!
//! # No inline styles, ever
//!
//! `style-src 'self'` forbids `style=""` attributes, and a bare `width: 37%` on
//! a bar is the usual reason a console ends up relaxing that. With no charts
//! there is nothing to position per element, so the constraint costs nothing —
//! and the CSP stays as strict as it was.

use super::{Ctx, View};
use crate::dashboard::format::{escape, severity_class, thousands};
use model::Severity;
use std::fmt::Write as _;

/// How often the page reloads itself. No script, so this is a meta refresh.
pub const REFRESH_SECONDS: u32 = 10;

/// The tabs, in the order an analyst moves: the queue, then where it came from,
/// then what it was.
const TABS: &[(&str, View)] = &[
    ("Detections", View::Detections),
    ("Hosts", View::Hosts),
    ("Techniques", View::Techniques),
];

pub fn stylesheet() -> &'static str {
    BASE
}

const BASE: &str = r#"
:root {
  color-scheme: dark;
  --bg: #0e1116;      --panel: #141a22;   --line: #222a36;   --line-soft: #1b222c;
  --ink: #dbe3ef;     --ink-dim: #8b97a8; --ink-faint: #626d7d;
  --accent: #4aa8ff;  --accent-soft: rgba(74,168,255,.14);
  --sev-critical: #ff5d5d; --sev-high: #ff9f43; --sev-medium: #f5c542;
  --sev-low: #4aa8ff;      --sev-info: #626d7d;
  --sans: ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 13px/1.45 var(--sans); }
a { color: inherit; text-decoration: none; }
h1, h2 { margin: 0; font-size: .95rem; font-weight: 600; }

/* ---- header ---------------------------------------------------------- */
.top {
  display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
  padding: .5rem 1rem; background: var(--panel);
  border-bottom: 1px solid var(--line);
}
.top .brand { font: 600 .95rem/1 var(--mono); letter-spacing: .2em; }
.top .app { color: var(--ink-faint); font-size: .72rem; letter-spacing: .06em; }
.top .spacer { flex: 1; }
.top .stats { display: flex; align-items: baseline; gap: .9rem; flex-wrap: wrap; color: var(--ink-faint); font-size: .74rem; }
.top .stats b { color: var(--ink); font: 600 .8rem/1 var(--mono); font-variant-numeric: tabular-nums; }
.top .clock { color: var(--ink-faint); font: .72rem/1 var(--mono); }

/* ---- tabs ------------------------------------------------------------ */
.tabs { display: flex; gap: .1rem; padding: 0 1rem; background: var(--panel); border-bottom: 1px solid var(--line); }
.tabs a {
  padding: .45rem .7rem .4rem; color: var(--ink-dim); font-size: .8rem;
  border-bottom: 2px solid transparent;
}
.tabs a:hover { color: var(--ink); }
.tabs a.on { color: var(--ink); border-bottom-color: var(--accent); font-weight: 600; }
.tabs .n { margin-left: .35rem; color: var(--ink-faint); font: .72rem/1 var(--mono); font-variant-numeric: tabular-nums; }
.tabs a.on .n { color: var(--accent); }

/* ---- main ------------------------------------------------------------ */
main { padding: .9rem 1rem 2.5rem; }
.head { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; margin-bottom: .6rem; }
.head .meta { color: var(--ink-faint); font-size: .74rem; }
.crumbs { margin-bottom: .5rem; font-size: .75rem; color: var(--ink-dim); }
.crumbs a { color: var(--accent); }
footer { margin-top: 1.5rem; color: var(--ink-faint); font-size: .7rem; }

/* ---- filters --------------------------------------------------------- */
.filters {
  display: flex; align-items: center; gap: .35rem; flex-wrap: wrap;
  padding: .45rem 0; margin-bottom: .5rem; border-bottom: 1px solid var(--line);
}
.filters .label { color: var(--ink-faint); font-size: .68rem; letter-spacing: .07em; text-transform: uppercase; margin-right: .15rem; }
.facet {
  display: inline-flex; align-items: center; gap: .3rem; padding: .15rem .5rem;
  border: 1px solid var(--line); border-radius: 3px; font-size: .74rem; color: var(--ink-dim);
}
.facet:hover { border-color: var(--accent); color: var(--ink); }
.facet.on { background: var(--accent-soft); border-color: var(--accent); color: var(--ink); }
.facet .n { font: 500 .7rem/1 var(--mono); color: var(--ink-faint); font-variant-numeric: tabular-nums; }
.facet.on .n { color: var(--accent); }
.facet.clear { border-style: dashed; }

/* ---- tables ---------------------------------------------------------- */
table.data { border-collapse: collapse; width: 100%; }
table.data th, table.data td { text-align: left; padding: .32rem .55rem; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
table.data thead th {
  font-size: .66rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  color: var(--ink-faint); border-bottom: 1px solid var(--line); white-space: nowrap;
}
table.data tbody tr:hover { background: rgba(255,255,255,.03); }
table.data td.num { text-align: right; font-family: var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
table.data td.dim { color: var(--ink-faint); }
table.data .stamp { font-family: var(--mono); font-size: .74rem; white-space: nowrap; }
table.data .age { color: var(--ink-faint); font-size: .72rem; margin-left: .3rem; }
table.data tr.total td { border-top: 1px solid var(--line); border-bottom: none; color: var(--ink-dim); font-size: .74rem; }

/* Row rail: an inset shadow rather than a border, because a border on the first
   cell of a collapsed table draws over the row above it. */
table.data tr.sev-rail-critical td:first-child { box-shadow: inset 3px 0 0 var(--sev-critical); }
table.data tr.sev-rail-high td:first-child { box-shadow: inset 3px 0 0 var(--sev-high); }
table.data tr.sev-rail-medium td:first-child { box-shadow: inset 3px 0 0 var(--sev-medium); }
table.data tr.sev-rail-low td:first-child { box-shadow: inset 3px 0 0 var(--sev-low); }
table.data tr.sev-rail-info td:first-child { box-shadow: inset 3px 0 0 var(--sev-info); }

/* ---- chips and tags -------------------------------------------------- */
.chip { display: inline-block; padding: .05rem .4rem; border-radius: 3px; border: 1px solid var(--line); font-size: .68rem; }
.sev-chip-critical { color: var(--sev-critical); border-color: rgba(255,93,93,.34); }
.sev-chip-high { color: var(--sev-high); border-color: rgba(255,159,67,.34); }
.sev-chip-medium { color: var(--sev-medium); border-color: rgba(245,197,66,.34); }
.sev-chip-low { color: var(--sev-low); border-color: rgba(74,168,255,.34); }
.sev-chip-info { color: var(--sev-info); }
.tag { font-family: var(--mono); font-size: .74rem; color: var(--accent); }
a.tag:hover { text-decoration: underline; }

/* ---- detail ---------------------------------------------------------- */
.kv { display: grid; grid-template-columns: minmax(6.5rem, auto) 1fr; gap: .2rem .8rem; margin: 0; }
.kv dt { color: var(--ink-faint); font-size: .7rem; letter-spacing: .04em; text-transform: uppercase; }
.kv dd { margin: 0; font-size: .8rem; overflow-wrap: anywhere; }
.kv dd.mono { font-family: var(--mono); }
.body-note {
  margin: .5rem 0 0; padding: .5rem .6rem; background: var(--panel);
  border: 1px solid var(--line); border-radius: 4px;
  font: .74rem/1.6 var(--mono); color: var(--ink-dim); overflow-wrap: anywhere;
}
.empty { padding: .9rem .2rem; color: var(--ink-faint); font-size: .8rem; }
"#;

/// The `sev-rail-` class for a row.
pub fn row_class(severity: Severity) -> String {
    format!("sev-rail-{}", severity_class(severity))
}

/// A severity pill.
pub fn chip(severity: Severity) -> String {
    format!(
        "<span class=\"chip sev-chip-{}\">{}</span>",
        severity_class(severity),
        escape(severity.as_str())
    )
}

// ---------------------------------------------------------------------------
// chrome
// ---------------------------------------------------------------------------

/// A whole page: header, tabs, one view's content, footer.
pub fn document(ctx: &Ctx<'_>, title: &str, body: &str) -> String {
    let mut html = String::with_capacity(6000 + body.len());
    html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    html.push_str("<meta name=\"referrer\" content=\"no-referrer\">\n");
    let _ = write!(
        html,
        "<meta http-equiv=\"refresh\" content=\"{REFRESH_SECONDS}\">\n"
    );
    let _ = write!(html, "<title>{}</title>\n", escape(title));
    html.push_str("<link rel=\"stylesheet\" href=\"/static/app.css\">\n");
    html.push_str("</head>\n<body>\n");

    header(&mut html, ctx);
    tabs(&mut html, ctx);
    html.push_str("<main>\n");
    html.push_str(body);
    footer(&mut html, ctx);
    html.push_str("</main>\n</body>\n</html>\n");
    html
}

fn header(html: &mut String, ctx: &Ctx<'_>) {
    let snapshot = ctx.snapshot;
    let reporting = snapshot
        .hosts
        .iter()
        .filter(|host| host.is_reporting())
        .count();
    html.push_str("<header class=\"top\">\n");
    html.push_str("<span class=\"brand\">CHAOS</span>\n");
    html.push_str("<span class=\"app\">endpoint detection</span>\n");
    html.push_str("<span class=\"spacer\"></span>\n");
    html.push_str("<span class=\"stats\">\n");
    // The fleet's numbers, in one line. These used to be six cards and four
    // charts; the only ones anyone quotes are these, and they fit in a row.
    let _ = write!(
        html,
        "<span><b>{}</b> host{}{}</span>\n",
        snapshot.hosts.len(),
        if snapshot.hosts.len() == 1 { "" } else { "s" },
        if snapshot.hosts.len() > reporting {
            format!(", {} silent", snapshot.hosts.len() - reporting)
        } else {
            String::new()
        }
    );
    let _ = write!(
        html,
        "<span><b>{}</b> events</span>\n",
        thousands(snapshot.total_events)
    );
    let _ = write!(
        html,
        "<span><b>{}</b> detections</span>\n",
        thousands(ctx.stats.total as u64)
    );
    let _ = write!(
        html,
        "<span><b>{}</b> firings</span>\n",
        thousands(snapshot.total_firings)
    );
    if snapshot.duplicate_batches > 0 {
        let _ = write!(
            html,
            "<span><b>{}</b> retried</span>\n",
            thousands(snapshot.duplicate_batches)
        );
    }
    html.push_str("</span>\n");
    // Saying which clock these are on is not decoration. Telemetry is stored in
    // UTC, but the agent, the host's own event log and the analyst's watch are
    // all on local time, so an unlabelled timestamp is an invitation to misread
    // an incident timeline by the size of the offset.
    let _ = write!(
        html,
        "<span class=\"clock\">{} UTC</span>\n",
        escape(&ctx.now.format("%Y-%m-%d %H:%M:%S").to_string())
    );
    html.push_str("</header>\n");
}

fn tabs(html: &mut String, ctx: &Ctx<'_>) {
    html.push_str("<nav class=\"tabs\" aria-label=\"sections\">\n");
    for (label, view) in TABS {
        let active = if ctx.filters.view.tab() == *view {
            " class=\"on\""
        } else {
            ""
        };
        let count = match view {
            // The queue's count is what the filters leave visible, so narrowing
            // visibly narrows the number.
            View::Detections => Some(ctx.stats.visible as u64),
            View::Hosts => Some(ctx.snapshot.hosts.len() as u64),
            View::Techniques => Some(ctx.stats.by_technique.len() as u64),
            _ => None,
        };
        let count = match count {
            Some(count) => format!("<span class=\"n\">{}</span>", thousands(count)),
            None => String::new(),
        };
        let _ = write!(
            html,
            "<a href=\"{}\"{active}>{} {count}</a>\n",
            escape(&ctx.filters.to(*view)),
            escape(label)
        );
    }
    html.push_str("</nav>\n");
}

fn footer(html: &mut String, ctx: &Ctx<'_>) {
    // The retention story, in one line. The store is bounded, so "held" and
    // "received" diverge on a long-lived server, and that divergence is exactly
    // the thing an analyst would otherwise have to infer from a cap nobody
    // remembers.
    let _ = write!(
        html,
        "<footer>{} of {} alerts held &middot; {} shown &middot; timestamps UTC &middot; \
         fields may be redacted (A19)</footer>\n",
        thousands(ctx.snapshot.alerts.len() as u64),
        thousands(ctx.snapshot.total_alerts),
        thousands(ctx.stats.visible as u64)
    );
}

/// A page heading with an optional note on the right.
pub fn head(html: &mut String, title: &str, meta: &str) {
    heading(html, "h1", title, meta);
}

/// A section heading inside a page.
///
/// `h2`, not another `h1`: a details page has one title and several sections,
/// and a page whose every heading is top-level is one a screen reader announces
/// as a list of unrelated things.
pub fn section(html: &mut String, title: &str, meta: &str) {
    heading(html, "h2", title, meta);
}

fn heading(html: &mut String, tag: &str, title: &str, meta: &str) {
    html.push_str("<div class=\"head\">\n");
    let _ = write!(html, "<{tag}>{}</{tag}>\n", escape(title));
    if !meta.is_empty() {
        let _ = write!(html, "<span class=\"meta\">{}</span>\n", escape(meta));
    }
    html.push_str("</div>\n");
}

/// The filter row: severity facets, then whatever else is narrowing the queue.
///
/// This is the whole of the dashboard's "chart" story. The counts beside each
/// severity are the distribution a bar chart would draw, except these are also
/// the control that narrows to one.
pub fn filters(html: &mut String, ctx: &Ctx<'_>) {
    html.push_str("<div class=\"filters\">\n<span class=\"label\">severity</span>\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = ctx.stats.severity_count(severity);
        if count == 0 && ctx.filters.severity != Some(severity) {
            continue;
        }
        let on = if ctx.filters.severity == Some(severity) {
            " on"
        } else {
            ""
        };
        let _ = write!(
            html,
            "<a class=\"facet sev-chip-{}{on}\" href=\"{}\">{}<span class=\"n\">{count}</span></a>\n",
            severity_class(severity),
            escape(&ctx.filters.toggle_severity(Some(severity))),
            escape(severity.as_str())
        );
    }

    for (label, active) in [
        ("host", ctx.filters.host.as_deref()),
        ("technique", ctx.filters.technique.as_deref()),
    ] {
        let Some(value) = active else { continue };
        let href = if label == "host" {
            ctx.filters.toggle_host(value)
        } else {
            ctx.filters.toggle_technique(value)
        };
        let _ = write!(
            html,
            "<span class=\"label\">{}</span>\
             <a class=\"facet on\" href=\"{}\">{}<span class=\"n\">&times;</span></a>\n",
            escape(label),
            escape(&href),
            escape(value)
        );
    }

    if ctx.filters.is_filtered() {
        let _ = write!(
            html,
            "<a class=\"facet clear\" href=\"{}\">clear</a>\n",
            escape(&ctx.filters.cleared())
        );
    }
    html.push_str("</div>\n");
}

/// A block of explanatory text under a table.
pub fn empty(html: &mut String, text: &str) {
    let _ = write!(html, "<p class=\"empty\">{}</p>\n", escape(text));
}

/// The agent's own account of a finding, as a quoted block.
pub fn note(html: &mut String, text: &str) {
    let _ = write!(html, "<p class=\"body-note\">{}</p>\n", escape(text));
}
