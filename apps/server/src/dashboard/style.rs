//! The console's look: a stylesheet, and the components every view is built from.
//!
//! # What this is imitating, and what it is not
//!
//! The reference points are the tools an analyst already has open: Wazuh, Kibana
//! Discover, Grafana, Sentinel. What they share is not decoration — it is a fixed
//! left rail, one top bar that says where you are and how fresh it is, a row of
//! labelled counters, and then a dense table that takes the rest of the screen.
//! The table is the product. Everything above it is orientation.
//!
//! What is deliberately absent is the vocabulary of a marketing dashboard: no
//! cards floating on a gradient, no drop shadows, no rounded-everything, no
//! emoji standing in for an icon set, no hero number with nothing under it. A
//! counter here is one line tall, sits next to the label that explains it, and
//! carries a sub-line saying what it is made of.
//!
//! # Typography
//!
//! The system's own UI font, not a downloaded one. `Segoe UI` on Windows,
//! `system-ui` elsewhere, and a real monospace face for everything that is an
//! identifier or a count. A webfont would be a network dependency, a
//! `font-src` directive in the CSP, and a flash of unstyled text in the one place
//! an analyst is watching a live feed — for a typeface the operating system
//! already has and the operator is already used to.
//!
//! # No inline styles, ever
//!
//! `style-src 'self'` forbids `style=""` attributes, which is normally the first
//! thing a dashboard relaxes to draw a bar. Instead widths come from a fixed set
//! of classes ([`share`]), which is enough for a proportion bar and keeps the CSP
//! as strict as it was.
//!
//! # The severity distribution
//!
//! One thin proportion bar, and the facets below it are its legend *and* its
//! controls. This is not a chart: there is no axis, no scale, and no second
//! reading of the same number — it is the split between five values on one line,
//! which is the one thing a queue of two hundred rows cannot show you at a
//! glance.

use super::icons;
use super::{Ctx, View};
use crate::dashboard::format::{escape, severity_class, thousands};
use model::Severity;
use std::fmt::Write as _;

/// How often the page reloads itself. No script, so this is a meta refresh.
pub const REFRESH_SECONDS: u32 = 10;

/// The rail, in the order an analyst moves: the queue, then where it came from,
/// then what it was, then what the server itself is doing.
///
/// Icon, view. The label comes from [`View::label`] so the rail cannot drift from
/// the page it opens.
const TABS: &[(&str, View)] = &[
    ("list-checks", View::Detections),
    ("desktop", View::Hosts),
    ("crosshair", View::Techniques),
    ("pulse", View::Status),
];

pub fn stylesheet() -> &'static str {
    BASE
}

const BASE: &str = r#"
:root {
  color-scheme: dark;
  --bg: #0b0f14;        --panel: #101720;      --panel-2: #151d27;
  --line: #202a37;      --line-soft: #18202b;  --line-strong: #2b3746;
  --ink: #d8e0ec;       --ink-dim: #94a1b4;    --ink-faint: #6a7688;
  --accent: #3d9cf5;    --accent-soft: rgba(61,156,245,.13);
  --sev-critical: #f8656b; --sev-high: #ef9138; --sev-medium: #dfb63c;
  --sev-low: #4b9ff5;      --sev-info: #6a7688;
  --sans: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: "Cascadia Mono", Consolas, "SF Mono", Menlo, "Liberation Mono", monospace;
}
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 13px/1.5 var(--sans); }
a { color: inherit; text-decoration: none; }
h1, h2 { margin: 0; }
.icon { width: 15px; height: 15px; flex: none; vertical-align: -2px; }
.icon.lg { width: 20px; height: 20px; }
.icon.sm { width: 13px; height: 13px; }

/* ---- shell ----------------------------------------------------------- */
.shell { display: grid; grid-template-columns: 208px minmax(0, 1fr); min-height: 100vh; }
.side {
  display: flex; flex-direction: column; gap: 0; background: var(--panel);
  border-right: 1px solid var(--line); height: 100vh; position: sticky; top: 0;
}
.brand { display: flex; align-items: center; gap: .55rem; padding: .8rem .85rem .75rem; border-bottom: 1px solid var(--line); }
.brand .mark { color: var(--accent); }
.brand .name { font: 600 .85rem/1.1 var(--mono); letter-spacing: .16em; }
.brand .role { display: block; color: var(--ink-faint); font: .63rem/1.4 var(--sans); letter-spacing: .04em; }

.nav { padding: .4rem 0; flex: 1; }
.nav a {
  display: flex; align-items: center; gap: .55rem; padding: .42rem .85rem;
  color: var(--ink-dim); font-size: .8rem; border-left: 2px solid transparent;
}
.nav a:hover { background: rgba(255,255,255,.028); color: var(--ink); }
.nav a.on { color: var(--ink); background: var(--accent-soft); border-left-color: var(--accent); font-weight: 600; }
.nav a.on .icon { color: var(--accent); }
.nav .n {
  margin-left: auto; color: var(--ink-faint);
  font: .7rem/1 var(--mono); font-variant-numeric: tabular-nums;
}
.nav .n.zero { opacity: .45; }

.side-foot { border-top: 1px solid var(--line); padding: .6rem .85rem .7rem; display: grid; gap: .3rem; }
.side-foot .row { display: flex; align-items: center; gap: .45rem; color: var(--ink-faint); font-size: .7rem; }
.side-foot .row .icon { color: var(--ink-faint); }
.side-foot .row b { margin-left: auto; color: var(--ink-dim); font: 500 .7rem/1 var(--mono); font-variant-numeric: tabular-nums; }
.live { display: flex; align-items: center; gap: .4rem; margin-top: .35rem; color: var(--ink-faint); font-size: .68rem; }
.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--sev-low); flex: none; }

/* ---- top bar --------------------------------------------------------- */
.bar {
  display: flex; align-items: center; gap: .8rem; flex-wrap: wrap;
  padding: .55rem 1.1rem; background: var(--panel); border-bottom: 1px solid var(--line);
}
.bar h1 { font-size: .98rem; font-weight: 600; }
.bar .sub { color: var(--ink-faint); font-size: .74rem; }
.bar .right { margin-left: auto; display: flex; align-items: center; gap: .75rem; }
.bar .clock { color: var(--ink-dim); font: .72rem/1 var(--mono); }
.bar .refresh { display: flex; align-items: center; gap: .3rem; color: var(--ink-faint); font-size: .68rem; }

/* ---- counters -------------------------------------------------------- */
.stats { display: flex; flex-wrap: wrap; border-bottom: 1px solid var(--line); background: var(--panel-2); }
.stat { display: flex; align-items: center; gap: .55rem; padding: .5rem 1rem .5rem .9rem; border-right: 1px solid var(--line-soft); }
.stat .icon { color: var(--ink-faint); }
.stat .k { display: block; color: var(--ink-faint); font-size: .62rem; letter-spacing: .09em; text-transform: uppercase; }
.stat b { display: block; font: 600 1rem/1.25 var(--mono); font-variant-numeric: tabular-nums; }
.stat .s { display: block; color: var(--ink-faint); font-size: .67rem; }
.stat.alert b { color: var(--sev-critical); }

/* ---- main ------------------------------------------------------------ */
main { padding: .9rem 1.1rem 2.5rem; }
.sec { margin-top: 1.4rem; }
.head { display: flex; align-items: baseline; gap: .7rem; flex-wrap: wrap; margin-bottom: .55rem; }
.head h2 { font-size: .82rem; font-weight: 600; letter-spacing: .02em; }
.head .meta { color: var(--ink-faint); font-size: .72rem; }
.crumbs { margin-bottom: .5rem; font-size: .74rem; color: var(--ink-dim); display: flex; align-items: center; gap: .35rem; }
.crumbs a { color: var(--accent); }
footer {
  margin-top: 1.8rem; padding-top: .6rem; border-top: 1px solid var(--line-soft);
  color: var(--ink-faint); font-size: .69rem; display: flex; gap: .5rem; flex-wrap: wrap;
}

/* ---- distribution ---------------------------------------------------- */
.dist { display: flex; height: 6px; overflow: hidden; border-radius: 2px; background: var(--line-soft); margin: .1rem 0 .5rem; }
.dist span { height: 100%; }
.seg-critical { background: var(--sev-critical); }
.seg-high { background: var(--sev-high); }
.seg-medium { background: var(--sev-medium); }
.seg-low { background: var(--sev-low); }
.seg-info { background: var(--sev-info); }
.pc-0 { width: 0; }    .pc-5 { width: 5%; }   .pc-10 { width: 10%; }  .pc-15 { width: 15%; }
.pc-20 { width: 20%; } .pc-25 { width: 25%; } .pc-30 { width: 30%; }  .pc-35 { width: 35%; }
.pc-40 { width: 40%; } .pc-45 { width: 45%; } .pc-50 { width: 50%; }  .pc-55 { width: 55%; }
.pc-60 { width: 60%; } .pc-65 { width: 65%; } .pc-70 { width: 70%; }  .pc-75 { width: 75%; }
.pc-80 { width: 80%; } .pc-85 { width: 85%; } .pc-90 { width: 90%; }  .pc-95 { width: 95%; }
.pc-100 { width: 100%; }
/* A per-row proportion bar, for the tables that rank things. */
.mini { display: block; height: 3px; min-width: 24px; background: var(--line-soft); border-radius: 2px; overflow: hidden; }
.mini span { display: block; height: 100%; background: var(--accent); }

/* ---- filters --------------------------------------------------------- */
.filters {
  display: flex; align-items: center; gap: .35rem; flex-wrap: wrap;
  padding: .4rem 0 .5rem; border-bottom: 1px solid var(--line); margin-bottom: .5rem;
}
.filters .label {
  display: inline-flex; align-items: center; gap: .3rem; margin-right: .15rem;
  color: var(--ink-faint); font-size: .66rem; letter-spacing: .08em; text-transform: uppercase;
}
.facet {
  display: inline-flex; align-items: center; gap: .3rem; padding: .14rem .5rem;
  border: 1px solid var(--line); border-radius: 3px; font-size: .73rem; color: var(--ink-dim);
}
.facet:hover { border-color: var(--accent); color: var(--ink); }
.facet.on { background: var(--accent-soft); border-color: var(--accent); color: var(--ink); }
.facet .n { font: 500 .69rem/1 var(--mono); color: var(--ink-faint); font-variant-numeric: tabular-nums; }
.facet.on .n { color: var(--accent); }
.facet.clear { border-style: dashed; }

/* ---- tables ---------------------------------------------------------- */
table.data { border-collapse: collapse; width: 100%; }
table.data th, table.data td { text-align: left; padding: .3rem .55rem; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
table.data thead th {
  font-size: .64rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  color: var(--ink-faint); border-bottom: 1px solid var(--line); white-space: nowrap;
}
table.data tbody tr:hover { background: rgba(255,255,255,.03); }
table.data td.num { text-align: right; font-family: var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
table.data td.dim { color: var(--ink-faint); }
table.data .stamp { font-family: var(--mono); font-size: .73rem; white-space: nowrap; }
table.data .age { color: var(--ink-faint); font-size: .7rem; margin-left: .3rem; }
table.data tr.total td { border-top: 1px solid var(--line); border-bottom: none; color: var(--ink-dim); font-size: .73rem; }
table.data td .who { display: block; font-size: .72rem; }
table.data td .id { font: .72rem/1.3 var(--mono); color: var(--ink-faint); }
table.data td.stack > * + * { margin-top: .15rem; }

/* Row rail: an inset shadow rather than a border, because a border on the first
   cell of a collapsed table draws over the row above it. */
table.data tr.sev-rail-critical td:first-child { box-shadow: inset 3px 0 0 var(--sev-critical); }
table.data tr.sev-rail-high td:first-child { box-shadow: inset 3px 0 0 var(--sev-high); }
table.data tr.sev-rail-medium td:first-child { box-shadow: inset 3px 0 0 var(--sev-medium); }
table.data tr.sev-rail-low td:first-child { box-shadow: inset 3px 0 0 var(--sev-low); }
table.data tr.sev-rail-info td:first-child { box-shadow: inset 3px 0 0 var(--sev-info); }

/* ---- chips and tags -------------------------------------------------- */
.chip { display: inline-block; padding: .05rem .4rem; border-radius: 3px; border: 1px solid var(--line); font-size: .68rem; }
.sev-chip-critical { color: var(--sev-critical); border-color: rgba(248,101,107,.34); }
.sev-chip-high { color: var(--sev-high); border-color: rgba(239,145,56,.34); }
.sev-chip-medium { color: var(--sev-medium); border-color: rgba(223,182,60,.34); }
.sev-chip-low { color: var(--sev-low); border-color: rgba(75,159,245,.34); }
.sev-chip-info { color: var(--sev-info); }
.tag { font-family: var(--mono); font-size: .73rem; color: var(--accent); }
a.tag:hover { text-decoration: underline; }
.state { display: inline-flex; align-items: center; gap: .35rem; font-size: .73rem; }
.state .dot { background: var(--sev-low); }
.state.silent { color: var(--ink-faint); }
.state.silent .dot { background: var(--ink-faint); }

/* ---- detail ---------------------------------------------------------- */
.kv { display: grid; grid-template-columns: minmax(6.5rem, auto) 1fr; gap: .22rem .9rem; margin: 0; }
.kv dt { color: var(--ink-faint); font-size: .68rem; letter-spacing: .04em; text-transform: uppercase; }
.kv dd { margin: 0; font-size: .79rem; overflow-wrap: anywhere; }
.body-note {
  margin: .5rem 0 0; padding: .5rem .6rem; background: var(--panel);
  border: 1px solid var(--line); border-radius: 4px;
  font: .74rem/1.6 var(--mono); color: var(--ink-dim); overflow-wrap: anywhere;
}
.empty { padding: .9rem .2rem; color: var(--ink-faint); font-size: .8rem; }
.callout {
  display: flex; align-items: flex-start; gap: .5rem; margin: .5rem 0;
  padding: .5rem .65rem; border: 1px solid var(--line); border-left: 3px solid var(--sev-medium);
  border-radius: 3px; background: var(--panel); color: var(--ink-dim); font-size: .77rem;
}
.callout .icon { color: var(--sev-medium); margin-top: .1rem; }
.callout.ok { border-left-color: var(--accent); }
.callout.ok .icon { color: var(--accent); }

@media (max-width: 860px) {
  .shell { grid-template-columns: 1fr; }
  .side { height: auto; position: static; flex-direction: row; flex-wrap: wrap; align-items: center; border-right: none; border-bottom: 1px solid var(--line); }
  .brand { border-bottom: none; }
  .nav { display: flex; flex: 1; padding: 0; }
  .nav a { border-left: none; border-bottom: 2px solid transparent; }
  .nav a.on { border-left: none; border-bottom-color: var(--accent); }
  .side-foot { border-top: none; display: flex; gap: .8rem; }
  .side-foot .row b { margin-left: .3rem; }
}
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

/// A width class standing in for `part / whole`.
///
/// Discrete because `style-src 'self'` forbids setting a width per element. Five
/// percent is finer than anyone reads on a six-pixel bar, and a non-zero part
/// never rounds down to nothing — a severity with one detection in it must not
/// disappear from a distribution that claims to be complete.
pub fn share(part: u64, whole: u64) -> String {
    if part == 0 || whole == 0 {
        return "pc-0".to_string();
    }
    let percent = (part as f64 / whole as f64) * 100.0;
    let step = ((percent / 5.0).round() as u64).max(1).min(20) * 5;
    format!("pc-{step}")
}

/// The severity split, as one proportion bar.
///
/// Emitted even when the queue is empty (as a flat track) so the page does not
/// change height between "nothing has fired" and "something has".
pub fn distribution(html: &mut String, ctx: &Ctx<'_>) {
    html.push_str("<div class=\"dist\" role=\"img\" aria-label=\"detections by severity\">\n");
    let total = ctx.stats.total as u64;
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = u64::from(ctx.stats.severity_count(severity));
        if count == 0 {
            continue;
        }
        let _ = write!(
            html,
            "<span class=\"seg-{} {}\" title=\"{} {}\"></span>\n",
            severity_class(severity),
            share(count, total),
            escape(severity.as_str()),
            count
        );
    }
    html.push_str("</div>\n");
}

// ---------------------------------------------------------------------------
// chrome
// ---------------------------------------------------------------------------

/// A whole page: rail, top bar, counters, one view's content, footer.
///
/// `counters` is passed separately from `body` because it sits full-bleed under
/// the top bar rather than inside the padded content area — and because a view
/// that has nothing worth counting can pass an empty string and get no strip at
/// all, instead of an empty one.
pub fn document(ctx: &Ctx<'_>, title: &str, subtitle: &str, counters: &str, body: &str) -> String {
    let mut html = String::with_capacity(8000 + counters.len() + body.len());
    html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    html.push_str("<meta name=\"referrer\" content=\"no-referrer\">\n");
    let _ = write!(
        html,
        "<meta http-equiv=\"refresh\" content=\"{REFRESH_SECONDS}\">\n"
    );
    let _ = write!(
        html,
        "<title>{} · chaos</title>\n",
        escape(ctx.filters.view.label())
    );
    html.push_str("<link rel=\"stylesheet\" href=\"/static/app.css\">\n");
    html.push_str("</head>\n<body>\n<div class=\"shell\">\n");

    rail(&mut html, ctx);
    html.push_str("<div class=\"body\">\n");
    topbar(&mut html, ctx, title, subtitle);
    html.push_str(counters);
    html.push_str("<main>\n");
    html.push_str(body);
    footer(&mut html, ctx);
    html.push_str("</main>\n</div>\n</div>\n</body>\n</html>\n");
    html
}

fn rail(html: &mut String, ctx: &Ctx<'_>) {
    html.push_str("<aside class=\"side\">\n");
    html.push_str("<div class=\"brand\">\n");
    html.push_str(&icons::render("shield-check", "icon lg mark"));
    html.push_str(
        "<span><span class=\"name\">CHAOS</span>\
         <span class=\"role\">endpoint detection &amp; response</span></span>\n",
    );
    html.push_str("</div>\n");

    html.push_str("<nav class=\"nav\" aria-label=\"sections\">\n");
    for (icon, view) in TABS {
        let active = if ctx.filters.view.tab() == *view {
            " class=\"on\""
        } else {
            ""
        };
        // Each section's own number, so the rail doubles as the fleet's summary.
        // The queue's count is what the filters leave visible, which is what makes
        // narrowing visibly narrow the rail too.
        let (count, zero) = match view {
            View::Detections => (ctx.stats.visible as u64, ctx.stats.visible == 0),
            View::Hosts => (
                ctx.snapshot.hosts.len() as u64,
                ctx.snapshot.hosts.is_empty(),
            ),
            View::Techniques => (
                ctx.stats.by_technique.len() as u64,
                ctx.stats.by_technique.is_empty(),
            ),
            View::Status => (ctx.snapshot.total_events, ctx.snapshot.total_events == 0),
            // A detection opened from the queue is under Detections; the rail has
            // no entry of its own for it.
            View::Detection => (0, true),
        };
        let _ = write!(
            html,
            "<a href=\"{}\"{active}>{}<span>{}</span>{}</a>\n",
            escape(&ctx.filters.to(*view)),
            icons::render(icon, "icon"),
            escape(view.label()),
            if *view == View::Detection {
                String::new()
            } else {
                format!(
                    "<span class=\"n{}\">{}</span>",
                    if zero { " zero" } else { "" },
                    thousands(count)
                )
            }
        );
    }
    html.push_str("</nav>\n");

    // The server's own vitals, where an analyst's eye already is. A console that
    // shows you the fleet but not whether it is still receiving anything makes you
    // open a second terminal to answer the first question you have.
    html.push_str("<div class=\"side-foot\">\n");
    let _ = write!(
        html,
        "<div class=\"row\">{}<span>ingested</span><b>{}</b></div>\n",
        icons::render("broadcast", "icon sm"),
        thousands(ctx.snapshot.total_events)
    );
    let _ = write!(
        html,
        "<div class=\"row\">{}<span>alerts held</span><b>{} / {}</b></div>\n",
        icons::render("database", "icon sm"),
        thousands(ctx.snapshot.alerts.len() as u64),
        thousands(ctx.status.store_cap as u64)
    );
    let _ = write!(
        html,
        "<div class=\"row\">{}<span>journal</span><b>{}</b></div>\n",
        icons::render("hard-drives", "icon sm"),
        match &ctx.status.journal {
            Some(journal) => format!("{} seg", journal.segments),
            None => "off".to_string(),
        }
    );
    let _ = write!(
        html,
        "<div class=\"live\"><span class=\"dot\"></span>live &middot; reloads every {REFRESH_SECONDS}s</div>\n"
    );
    html.push_str("</div>\n</aside>\n");
}

fn topbar(html: &mut String, ctx: &Ctx<'_>, title: &str, subtitle: &str) {
    html.push_str("<header class=\"bar\">\n");
    let _ = write!(html, "<h1>{}</h1>\n", escape(title));
    if !subtitle.is_empty() {
        let _ = write!(html, "<span class=\"sub\">{}</span>\n", escape(subtitle));
    }
    html.push_str("<span class=\"right\">\n");
    let _ = write!(
        html,
        "<span class=\"refresh\">{}as of</span>\n",
        icons::render("clock", "icon sm")
    );
    // Saying which clock this is, is not decoration. Telemetry is stored in UTC,
    // while the agent, the host's own event log and the analyst's watch are all on
    // local time, so an unlabelled timestamp is an invitation to misread an
    // incident timeline by the size of the offset.
    let _ = write!(
        html,
        "<span class=\"clock\">{} UTC</span>\n",
        escape(&ctx.now.format("%Y-%m-%d %H:%M:%S").to_string())
    );
    html.push_str("</span>\n</header>\n");
}

/// One counter in the strip.
pub struct Stat {
    pub icon: &'static str,
    pub label: &'static str,
    pub value: String,
    pub sub: String,
    /// Draw the value in the alarm colour. For the one counter that is a problem.
    pub alert: bool,
}

impl Stat {
    pub fn new(
        icon: &'static str,
        label: &'static str,
        value: impl Into<String>,
        sub: impl Into<String>,
    ) -> Self {
        Self {
            icon,
            label,
            value: value.into(),
            sub: sub.into(),
            alert: false,
        }
    }
}

/// The counter strip, under the top bar.
///
/// One line tall, no cards: each entry is a label, a number, and a sub-line made
/// of the things that number is made of. A number with nothing under it is a
/// number an analyst has to go and verify.
pub fn stats(html: &mut String, stats: &[Stat]) {
    html.push_str("<div class=\"stats\">\n");
    for stat in stats {
        let _ = write!(
            html,
            "<div class=\"stat{}\">{}<span><span class=\"k\">{}</span><b>{}</b>\
             <span class=\"s\">{}</span></span></div>\n",
            if stat.alert { " alert" } else { "" },
            icons::render(stat.icon, "icon"),
            escape(stat.label),
            escape(&stat.value),
            escape(&stat.sub)
        );
    }
    html.push_str("</div>\n");
}

fn footer(html: &mut String, ctx: &Ctx<'_>) {
    // The retention story, in one line. The store is bounded, so "held" and
    // "received" diverge on a long-lived server, and that divergence is exactly
    // the thing an analyst would otherwise have to infer from a cap nobody
    // remembers.
    let _ = write!(
        html,
        "<footer><span>{} of {} alerts held</span><span>&middot;</span>\
         <span>{} shown</span><span>&middot;</span>\
         <span>timestamps UTC</span><span>&middot;</span>\
         <span>fields may be redacted (A19)</span></footer>\n",
        thousands(ctx.snapshot.alerts.len() as u64),
        thousands(ctx.snapshot.total_alerts),
        thousands(ctx.stats.visible as u64)
    );
}

/// A section heading inside a page.
///
/// `h2`, not another `h1`: the top bar owns the page's one title, and a page whose
/// every heading is top-level is one a screen reader announces as a list of
/// unrelated things.
pub fn section(html: &mut String, title: &str, meta: &str) {
    html.push_str("<div class=\"head\">\n");
    let _ = write!(html, "<h2>{}</h2>\n", escape(title));
    if !meta.is_empty() {
        let _ = write!(html, "<span class=\"meta\">{}</span>\n", escape(meta));
    }
    html.push_str("</div>\n");
}

/// The filter row: severity facets, then whatever else is narrowing the queue.
///
/// The facets are the distribution bar's legend and its controls at the same
/// time: the count beside each severity is that severity's share, and the link is
/// the way to narrow to it.
pub fn filters(html: &mut String, ctx: &Ctx<'_>) {
    html.push_str("<div class=\"filters\">\n");
    let _ = write!(
        html,
        "<span class=\"label\">{}severity</span>\n",
        icons::render("funnel", "icon sm")
    );
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

/// An inline remark that is not evidence, with an icon that says which kind.
pub fn callout(html: &mut String, icon: &str, ok: bool, text: &str) {
    let _ = write!(
        html,
        "<div class=\"callout{}\">{}<span>{}</span></div>\n",
        if ok { " ok" } else { "" },
        icons::render(icon, "icon"),
        escape(text)
    );
}
