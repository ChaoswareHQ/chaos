//! The pages.
//!
//! Each view is a function from a [`Ctx`] to a body, and [`render`] wraps it in
//! the chrome. That split is what keeps a view readable: nothing here builds a
//! `<head>`, a nav, or a stylesheet link.
//!
//! Four pages, in the order an analyst moves: the queue, the hosts it came from,
//! the techniques it maps to, and one detection opened out of it.

use super::format::{age, escape, stamp, thousands};
use super::style;
use super::{Ctx, Filters, QUEUE_PAGE, TITLES_PER_TECHNIQUE, TechniqueRollup, View};
use crate::store::{Snapshot, StoredAlert};
use std::fmt::Write as _;

pub fn render(ctx: &Ctx<'_>) -> String {
    let (title, body) = match ctx.filters.view {
        View::Detections => ("chaos · detections", detections(ctx)),
        View::Hosts => ("chaos · hosts", hosts(ctx)),
        View::Techniques => ("chaos · techniques", techniques(ctx)),
        View::Detection => ("chaos · detection", detection(ctx)),
    };
    style::document(ctx, title, &body)
}

// ---------------------------------------------------------------------------
// the queue
// ---------------------------------------------------------------------------

fn detections(ctx: &Ctx<'_>) -> String {
    let mut html = String::with_capacity(4000);
    style::head(
        &mut html,
        "Detections",
        &match ctx.stats.worst() {
            Some(worst) => format!(
                "{} of {} shown · highest open severity {}",
                ctx.stats.visible,
                ctx.stats.total,
                worst.as_str()
            ),
            None => "nothing has fired on this fleet yet".to_string(),
        },
    );
    style::filters(&mut html, ctx);
    queue_table(&mut html, ctx, QUEUE_PAGE);
    html
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

fn hosts(ctx: &Ctx<'_>) -> String {
    let snapshot = ctx.snapshot;
    let reporting = snapshot
        .hosts
        .iter()
        .filter(|host| host.is_reporting())
        .count();
    let mut html = String::with_capacity(3000);

    style::head(
        &mut html,
        "Hosts",
        &format!(
            "{} enrolled · {} reporting · {} silent",
            snapshot.hosts.len(),
            reporting,
            snapshot.hosts.len() - reporting
        ),
    );

    if snapshot.hosts.is_empty() {
        style::empty(&mut html, "No host has enrolled yet.");
        return html;
    }

    html.push_str("<table class=\"data\">\n<thead><tr>");
    html.push_str(
        "<th>host</th><th>name</th><th>os</th><th>events</th>\
         <th>detections</th><th>firings</th><th>highest</th>\
         <th>enrolled</th><th>last seen</th>",
    );
    html.push_str("</tr></thead>\n<tbody>\n");
    for host in &snapshot.hosts {
        let rollup = ctx
            .stats
            .by_host
            .iter()
            .find(|rollup| rollup.host_id == host.host_id);
        let highest = match rollup {
            Some(rollup) => style::chip(rollup.worst),
            None => "<span class=\"dim\">&mdash;</span>".to_string(),
        };
        let (detections, firings) = match rollup {
            Some(rollup) => (rollup.detections, rollup.firings),
            None => (0, 0),
        };
        let _ = write!(
            html,
            "<tr><td class=\"mono\"><a href=\"{queue}\">{host_id}</a></td>\
             <td>{name}</td><td class=\"dim\">{os}</td>\
             <td class=\"num\">{events}</td>\
             <td class=\"num\">{detections}</td><td class=\"num\">{firings}</td>\
             <td>{highest}</td>\
             <td class=\"stamp dim\">{enrolled}</td>\
             <td class=\"stamp\">{seen}<span class=\"age\">{age}</span></td></tr>\n",
            queue = escape(&ctx.filters.toggle_host(&host.host_id)),
            host_id = escape(&host.host_id),
            name = escape(&host.hostname),
            os = escape(&host.os),
            events = thousands(host.events),
            enrolled = escape(&stamp(&host.enrolled_at.to_rfc3339())),
            seen = escape(&stamp(&host.last_seen.to_rfc3339())),
            age = escape(&age(ctx.now, host.last_seen)),
        );
    }
    html.push_str("</tbody>\n</table>\n");
    html
}

// ---------------------------------------------------------------------------
// techniques
// ---------------------------------------------------------------------------

fn techniques(ctx: &Ctx<'_>) -> String {
    let mut html = String::with_capacity(3000);
    style::head(
        &mut html,
        "Techniques",
        &format!(
            "{} distinct across {} detections",
            ctx.stats.by_technique.len(),
            ctx.stats.total
        ),
    );

    if ctx.stats.by_technique.is_empty() {
        style::empty(&mut html, "No rule has fired on this fleet yet.");
        return html;
    }

    html.push_str("<table class=\"data\">\n<thead><tr>");
    html.push_str(
        "<th>technique</th><th>detections</th><th>hosts</th>\
         <th>firings</th><th>highest</th><th>what fired</th>",
    );
    html.push_str("</tr></thead>\n<tbody>\n");
    for rollup in &ctx.stats.by_technique {
        technique_row(&mut html, ctx, rollup);
    }
    html.push_str("</tbody>\n</table>\n");
    html
}

fn technique_row(html: &mut String, ctx: &Ctx<'_>, rollup: &TechniqueRollup) {
    // The titles behind the ATT&CK id. An id alone says which drawer to file it
    // in, not what happened; the titles are the sentence the analyst reads. The
    // matching detections are reachable by filtering, so this column names the
    // rules rather than repeating the whole queue.
    let what_fired: Vec<String> = ctx
        .snapshot
        .alerts
        .iter()
        .filter(|alert| alert.technique == rollup.technique)
        .map(|alert| alert.title.clone())
        .take(TITLES_PER_TECHNIQUE)
        .map(|title| escape(&title))
        .collect();
    let what_fired = if what_fired.is_empty() {
        "<span class=\"dim\">&mdash;</span>".to_string()
    } else {
        what_fired.join("<br>")
    };

    let _ = write!(
        html,
        "<tr><td><a class=\"tag\" href=\"{href}\">{technique}</a></td>\
         <td class=\"num\">{detections}</td><td class=\"num\">{hosts}</td>\
         <td class=\"num\">{firings}</td><td>{worst}</td>\
         <td class=\"dim\">{what_fired}</td></tr>\n",
        href = escape(&ctx.filters.toggle_technique(&rollup.technique)),
        technique = escape(&rollup.technique),
        detections = rollup.detections,
        hosts = rollup.hosts,
        firings = thousands(rollup.firings),
        worst = style::chip(rollup.worst),
    );
}

// ---------------------------------------------------------------------------
// one detection
// ---------------------------------------------------------------------------

fn detection(ctx: &Ctx<'_>) -> String {
    let mut html = String::with_capacity(3000);
    let _ = write!(
        html,
        "<div class=\"crumbs\"><a href=\"{}\">&larr; back to detections</a></div>\n",
        escape(&ctx.filters.cleared())
    );

    let Some(row) = find_row(ctx.snapshot, ctx.filters) else {
        style::head(&mut html, "Not found", "");
        style::empty(
            &mut html,
            "This detection is no longer in the queue. The store is in memory and bounded, \
             so an old row is dropped rather than kept forever.",
        );
        return html;
    };

    // The title leads. An analyst arriving from the queue or from a link needs to
    // confirm they are looking at the thing they clicked; the rule id below is
    // how it is filed, not what it is.
    style::head(
        &mut html,
        &row.title,
        &format!("{} on {}", row.rule_id, row.host_id),
    );

    html.push_str("<dl class=\"kv\">\n");
    kv(&mut html, "severity", &style::chip(row.severity));
    kv(&mut html, "technique", &escape(&row.technique));
    kv(&mut html, "host", &escape(&row.host_id));
    kv(&mut html, "firings", &thousands(row.firings));
    kv(&mut html, "alert objects", &format!("{}", row.occurrences));
    kv(&mut html, "first seen", &seen(ctx, row.first_seen));
    kv(&mut html, "last seen", &seen(ctx, row.last_seen));
    html.push_str("</dl>\n");

    html.push_str("<div class=\"head\"><h2>Evidence</h2>");
    html.push_str(
        "<span class=\"meta\">as the agent reported it, minimised on the host (A19)</span></div>\n",
    );
    if row.description.is_empty() {
        style::empty(&mut html, "No description was shipped with this alert.");
    } else {
        style::note(&mut html, &row.description);
    }

    // The pivot that makes a queue usable: what else fired on the same host.
    let related: Vec<&StoredAlert> = ctx
        .snapshot
        .alerts
        .iter()
        .filter(|other| other.host_id == row.host_id && other.rule_id != row.rule_id)
        .collect();
    style::section(
        &mut html,
        "Also on this host",
        &format!("{} other detections", related.len()),
    );
    if related.is_empty() {
        style::empty(
            &mut html,
            "Nothing else has fired here — this is the only detection on this host.",
        );
        return html;
    }
    html.push_str("<table class=\"data\">\n<thead><tr>");
    html.push_str(
        "<th>severity</th><th>technique</th><th>detection</th><th>firings</th><th>last seen</th>",
    );
    html.push_str("</tr></thead>\n<tbody>\n");
    for other in related {
        let _ = write!(
            html,
            "<tr class=\"{rail}\"><td>{chip}</td>\
             <td><a class=\"tag\" href=\"{technique}\">{technique_id}</a></td>\
             <td><a href=\"{open}\">{title}</a></td>\
             <td class=\"num\">{firings}</td>\
             <td class=\"stamp\">{seen}<span class=\"age\">{age}</span></td></tr>\n",
            rail = style::row_class(other.severity),
            chip = style::chip(other.severity),
            technique = escape(&ctx.filters.toggle_technique(&other.technique)),
            technique_id = escape(&other.technique),
            open = escape(&ctx.filters.detection(&other.host_id, &other.rule_id)),
            title = escape(&other.title),
            firings = thousands(other.firings),
            seen = escape(&stamp(&other.last_seen.to_rfc3339())),
            age = escape(&age(ctx.now, other.last_seen)),
        );
    }
    html.push_str("</tbody>\n</table>\n");

    html
}

fn kv(html: &mut String, key: &str, value_html: &str) {
    let _ = write!(html, "<dt>{}</dt><dd>{value_html}</dd>\n", escape(key));
}

fn seen(ctx: &Ctx<'_>, at: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{} <span class=\"age\">{}</span>",
        escape(&stamp(&at.to_rfc3339())),
        escape(&age(ctx.now, at))
    )
}

fn find_row<'a>(snapshot: &'a Snapshot, filters: &Filters) -> Option<&'a StoredAlert> {
    let host = filters.host.as_deref()?;
    let rule = filters.rule.as_deref()?;
    snapshot
        .alerts
        .iter()
        .find(|alert| alert.host_id == host && alert.rule_id == rule)
}

// ---------------------------------------------------------------------------
// the queue table
// ---------------------------------------------------------------------------

/// The queue, filtered and capped.
///
/// The store hands rows over most-recently-active first and filtering preserves
/// that order, so there is no sort here to disagree with the store about.
fn queue_table(html: &mut String, ctx: &Ctx<'_>, limit: usize) {
    let rows: Vec<&StoredAlert> = ctx
        .snapshot
        .alerts
        .iter()
        .filter(|alert| ctx.filters.matches(alert))
        .collect();

    if rows.is_empty() {
        let message = if ctx.stats.total == 0 {
            "Nothing has fired on this fleet yet. When the agent ships an alert it appears here."
        } else {
            "No detection matches these filters."
        };
        style::empty(html, message);
        return;
    }

    html.push_str("<table class=\"data\">\n<thead><tr>");
    html.push_str(
        "<th>severity</th><th>detection</th><th>host</th>\
         <th>firings</th><th>alerts</th><th>last seen</th>",
    );
    html.push_str("</tr></thead>\n<tbody>\n");

    let mut shown = 0usize;
    let mut firings_shown = 0u64;
    for row in rows.iter().take(limit) {
        shown += 1;
        firings_shown = firings_shown.saturating_add(row.firings);
        queue_row(html, ctx, row);
    }

    // A totals row, like a search result count: it is the number an analyst
    // quotes, and it is the check that the rows add up to the header.
    let _ = write!(
        html,
        "<tr class=\"total\"><td colspan=\"3\">{}{}</td>\
         <td class=\"num\">{}</td><td colspan=\"2\"></td></tr>\n",
        thousands(shown as u64),
        if rows.len() > shown {
            format!(" of {} matching rows", thousands(rows.len() as u64))
        } else {
            " rows".to_string()
        },
        thousands(firings_shown)
    );
    html.push_str("</tbody>\n</table>\n");
}

fn queue_row(html: &mut String, ctx: &Ctx<'_>, row: &StoredAlert) {
    let _ = write!(
        html,
        "<tr class=\"{rail}\">\
         <td>{chip}</td>\
         <td><a href=\"{open}\">{title}</a><br>\
             <a class=\"tag\" href=\"{technique}\">{technique_id}</a></td>\
         <td class=\"mono dim\"><a href=\"{host}\">{host_id}</a></td>\
         <td class=\"num\">{firings}</td>\
         <td class=\"num dim\">{occurrences}</td>\
         <td class=\"stamp\">{seen}<span class=\"age\">{age}</span></td></tr>\n",
        rail = style::row_class(row.severity),
        chip = style::chip(row.severity),
        open = escape(&ctx.filters.detection(&row.host_id, &row.rule_id)),
        title = escape(&row.title),
        technique = escape(&ctx.filters.toggle_technique(&row.technique)),
        technique_id = escape(&row.technique),
        host = escape(&ctx.filters.toggle_host(&row.host_id)),
        host_id = escape(&row.host_id),
        firings = thousands(row.firings),
        occurrences = row.occurrences,
        seen = escape(&stamp(&row.last_seen.to_rfc3339())),
        age = escape(&age(ctx.now, row.last_seen)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::{Filters, page};
    use crate::store::HostRecord;
    use chrono::Utc;
    use model::Severity;

    fn host(host_id: &str, hostname: &str) -> HostRecord {
        HostRecord {
            host_id: host_id.to_string(),
            hostname: hostname.to_string(),
            os: "windows".to_string(),
            secret_hash: [0u8; 32],
            enrolled_at: Utc::now(),
            last_seen: Utc::now(),
            events: 100,
            alerts: 2,
        }
    }

    fn row(host_id: &str, rule: &str, severity: Severity, title: &str) -> StoredAlert {
        StoredAlert {
            host_id: host_id.to_string(),
            rule_id: rule.to_string(),
            severity,
            title: title.to_string(),
            description: format!("isolate host (p=0.99, n=40) via {rule}"),
            technique: "T1059.001".to_string(),
            firings: 40,
            occurrences: 2,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            hosts: vec![host("a1b2", "DESKTOP-A"), host("c3d4", "DESKTOP-B")],
            alerts: vec![
                row(
                    "a1b2",
                    "run_key_persistence",
                    Severity::Critical,
                    "Persistence via a Run key",
                ),
                row(
                    "a1b2",
                    "encoded_powershell",
                    Severity::High,
                    "Encoded PowerShell command",
                ),
                row(
                    "c3d4",
                    "high_abuse_tld",
                    Severity::Low,
                    "Resolution in a high-abuse namespace",
                ),
            ],
            total_events: 2_600_000,
            total_alerts: 12,
            total_firings: 120,
            duplicate_batches: 0,
        }
    }

    fn at(view: &str) -> String {
        page(&snapshot(), &Filters::parse(view), Utc::now())
    }

    #[test]
    fn every_view_renders_a_whole_document() {
        for view in [
            "view=detections",
            "view=hosts",
            "view=techniques",
            "view=detection&host=a1b2&rule=run_key_persistence",
        ] {
            let html = at(view);
            assert!(html.starts_with("<!doctype html>"), "{view}");
            assert!(html.ends_with("</html>\n"), "{view}");
            assert!(html.contains("href=\"/static/app.css\""), "{view}");
        }
    }

    #[test]
    fn an_unknown_view_falls_back_to_the_queue() {
        // A hand-edited URL should show something, not an error page.
        assert!(at("view=nonsense").contains("Detections"));
    }

    #[test]
    fn the_landing_page_is_the_queue() {
        // Not an overview: an analyst opening the console wants the thing they
        // act on, not a page they have to click through.
        let html = at("");
        assert!(html.contains("<h1>Detections</h1>"));
        assert!(html.contains("Persistence via a Run key"));
    }

    #[test]
    fn there_are_three_tabs_and_no_charts() {
        let html = at("view=detections");
        assert!(html.contains(">Detections <span"));
        assert!(html.contains(">Hosts <span"));
        assert!(html.contains(">Techniques <span"));
        // The distribution is the filter row, not a chart. A second place to look
        // for one fact is what made this dashboard hard to read.
        assert!(html.contains("class=\"filters\""));
        assert!(!html.contains("class=\"barrow\""));
        assert!(!html.contains("class=\"strip\""));
        assert!(!html.contains("class=\"tile\""));
    }

    #[test]
    fn tags_injected_through_any_field_are_neutralised() {
        let payload = "</td></tr><script>fetch('//evil')</script>";
        let snapshot = Snapshot {
            hosts: vec![host("a1b2", payload)],
            alerts: vec![{
                let mut row = row("a1b2", payload, Severity::Critical, payload);
                row.technique = payload.to_string();
                row.description = payload.to_string();
                row
            }],
            ..Default::default()
        };

        for view in [
            "view=detections",
            "view=hosts",
            "view=techniques",
            &format!(
                "view=detection&host=a1b2&rule={}",
                crate::dashboard::format::encode(payload)
            ),
        ] {
            let html = page(&snapshot, &Filters::parse(view), Utc::now());
            assert!(html.contains("&lt;script&gt;"), "{view} lost the escape");
            assert!(!html.contains("<script"), "raw script tag in {view}");
        }
    }

    #[test]
    fn the_console_carries_no_script_and_no_inline_style() {
        // The load-bearing property of the design. Inline styles would mean
        // `style-src` had to be relaxed, and an inline style attribute is the
        // first step down that road.
        for view in [
            "view=detections",
            "view=hosts",
            "view=techniques",
            "view=detection&host=a1b2&rule=run_key_persistence",
        ] {
            let html = at(view);
            assert!(!html.contains("<script"), "{view}");
            assert!(!html.contains("onclick"), "{view}");
            assert!(!html.contains("onload"), "{view}");
            assert!(!html.contains("onmouseover"), "{view}");
            assert!(!html.contains("javascript:"), "{view}");
            assert!(
                !html.contains("style=\""),
                "{view} contains an inline style, which would force a looser CSP"
            );
        }
    }

    #[test]
    fn an_empty_fleet_renders_a_usable_page() {
        let snapshot = Snapshot::default();
        for view in ["view=detections", "view=hosts", "view=techniques"] {
            let html = page(&snapshot, &Filters::parse(view), Utc::now());
            assert!(html.starts_with("<!doctype html>"), "{view}");
            assert!(!html.contains(">NaN<"), "{view} divided by zero");
            assert!(!html.contains(">inf<"), "{view} divided by zero");
        }
    }

    #[test]
    fn a_facet_narrows_the_queue_to_matching_rows() {
        let all = at("view=detections");
        assert!(all.contains("Persistence via a Run key"));
        assert!(all.contains("Encoded PowerShell command"));
        assert!(all.contains("Resolution in a high-abuse namespace"));

        let critical = at("view=detections&severity=critical");
        assert!(critical.contains("Persistence via a Run key"));
        assert!(!critical.contains("Encoded PowerShell command"));

        let host = at("view=detections&host=c3d4");
        assert!(host.contains("Resolution in a high-abuse namespace"));
        assert!(!host.contains("Persistence via a Run key"));
    }

    #[test]
    fn the_filter_row_counts_match_the_queue() {
        let snapshot = snapshot();
        let filters = Filters::parse("view=detections");
        let stats = crate::dashboard::Stats::compute(&snapshot, &filters);
        let summed: u32 = stats.by_severity.values().copied().sum();
        assert_eq!(summed, snapshot.alerts.len() as u32);
        assert_eq!(stats.severity_count(Severity::Critical), 1);
        assert_eq!(stats.severity_count(Severity::Medium), 0);
        assert_eq!(stats.worst(), Some(Severity::Critical));
        assert_eq!(stats.visible, snapshot.alerts.len());
    }

    #[test]
    fn the_totals_row_agrees_with_the_rows_above_it() {
        let html = at("view=detections");
        // Three rows of forty firings each.
        assert!(html.contains(">120</td>"), "the totals row:\n{html}");
        assert!(html.contains("3 rows"));
    }

    #[test]
    fn big_counts_are_grouped_not_printed_raw() {
        let html = at("view=detections");
        assert!(html.contains("2,600,000"), "events in the header");
        assert!(!html.contains(">2600000<"));
    }

    #[test]
    fn a_technique_row_says_what_fired_not_only_which_id() {
        let html = at("view=techniques");
        assert!(html.contains("T1059.001"));
        assert!(
            html.contains("Persistence via a Run key"),
            "an ATT&CK id alone does not say what happened"
        );
    }

    #[test]
    fn opening_a_detection_shows_its_evidence_and_its_siblings() {
        let html = at("view=detection&host=a1b2&rule=run_key_persistence");
        assert!(
            html.contains("isolate host (p=0.99, n=40)"),
            "evidence body"
        );
        assert!(html.contains("run_key_persistence"), "the rule itself");
        assert!(html.contains("Encoded PowerShell command"), "sibling pivot");
        assert_eq!(html.matches("Persistence via a Run key").count(), 1);
        assert!(!html.contains("Resolution in a high-abuse namespace"));
    }

    #[test]
    fn a_detection_that_was_dropped_says_so_rather_than_erroring() {
        let html = at("view=detection&host=ffff&rule=gone");
        assert!(html.contains("Not found"));
        assert!(html.contains("bounded"), "say why it is gone");
    }

    #[test]
    fn the_page_has_one_title_and_sections_under_it() {
        // Three top-level headings on one page is a page a screen reader
        // announces as three unrelated things.
        let html = at("view=detection&host=a1b2&rule=run_key_persistence");
        assert_eq!(html.matches("<h1>").count(), 1, "one title");
        assert!(html.contains("<h2>Evidence</h2>"));
        assert!(html.contains("<h2>Also on this host</h2>"));
    }

    #[test]
    fn the_severity_rail_is_an_inset_shadow_not_a_border() {
        // A border on a collapsed table's first cell draws over the row above. If
        // this becomes a border, the queue grows stray horizontal lines.
        assert!(crate::dashboard::stylesheet().contains("tr.sev-rail-critical td:first-child"));
        assert!(crate::dashboard::stylesheet().contains("inset 3px 0 0"));
        let html = at("view=detections");
        assert!(html.contains("class=\"sev-rail-critical\""));
        assert!(html.contains("class=\"sev-rail-low\""));
    }
}
