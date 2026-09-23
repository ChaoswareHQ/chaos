//! The pages.
//!
//! Each view returns a [`Page`] — a title, a sub-line, a counter strip and a body
//! — and [`render`] wraps it in the chrome. That split is what keeps a view
//! readable: nothing here builds a `<head>`, a rail, or a stylesheet link.
//!
//! Five pages, in the order an analyst moves: the queue, the hosts it came from,
//! the techniques it maps to, what the server itself is doing, and one detection
//! opened out of the queue.
//!
//! The rule every view follows is that a number is never alone. A count with a
//! label and a sub-line made of the things it is made of can be acted on; a bare
//! number in a box moves the cost of understanding it onto the reader, which is
//! what makes a dashboard look busy and say nothing.

use super::format::{age, escape, stamp, thousands};
use super::style::{self, Stat, share};
use super::{Ctx, Filters, QUEUE_PAGE, TITLES_PER_TECHNIQUE, TechniqueRollup, View, icons};
use crate::store::{HostRecord, Snapshot, StoredAlert};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One page, in the pieces the chrome puts together.
struct Page {
    title: String,
    subtitle: String,
    counters: String,
    body: String,
}

impl Page {
    fn new(title: &str, subtitle: String) -> Self {
        Self {
            title: title.to_string(),
            subtitle,
            counters: String::new(),
            body: String::new(),
        }
    }

    fn counters(mut self, stats: &[Stat]) -> Self {
        style::stats(&mut self.counters, stats);
        self
    }
}

pub fn render(ctx: &Ctx<'_>) -> String {
    let page = match ctx.filters.view {
        View::Detections => detections(ctx),
        View::Hosts => hosts(ctx),
        View::Techniques => techniques(ctx),
        View::Status => status(ctx),
        View::Detection => detection(ctx),
    };
    style::document(ctx, &page.title, &page.subtitle, &page.counters, &page.body)
}

/// Hostnames by host id, built once per page rather than scanned per row.
fn host_names(snapshot: &Snapshot) -> BTreeMap<String, String> {
    snapshot
        .hosts
        .iter()
        .map(|host| (host.host_id.clone(), host.hostname.clone()))
        .collect()
}

fn reporting(snapshot: &Snapshot) -> usize {
    snapshot
        .hosts
        .iter()
        .filter(|host| host.is_reporting())
        .count()
}

fn silent(snapshot: &Snapshot) -> usize {
    snapshot.hosts.len() - reporting(snapshot)
}

/// A host cell: the id you filter by, with the name a person recognises under it.
fn host_cell(
    ctx: &Ctx<'_>,
    names: &BTreeMap<String, String>,
    host_id: &str,
    class: &str,
) -> String {
    let name = names.get(host_id).map(String::as_str).unwrap_or("");
    let _ = class;
    let mut html = format!(
        "<td class=\"{class}\"><a class=\"id\" href=\"{}\">{}</a>",
        escape(&ctx.filters.toggle_host(host_id)),
        escape(host_id)
    );
    if !name.is_empty() {
        let _ = write!(html, "<span class=\"who dim\">{}</span>", escape(name));
    }
    html.push_str("</td>");
    html
}

// ---------------------------------------------------------------------------
// the queue
// ---------------------------------------------------------------------------

fn detections(ctx: &Ctx<'_>) -> Page {
    let snapshot = ctx.snapshot;
    let subtitle = match ctx.stats.worst() {
        Some(worst) => format!(
            "{} of {} shown · {} rules have fired · highest open severity {}",
            ctx.stats.visible,
            ctx.stats.total,
            ctx.stats.by_rule.len(),
            worst.as_str()
        ),
        None => "nothing has fired on this fleet yet".to_string(),
    };
    let mut page = Page::new("Detections", subtitle);

    let critical = ctx.stats.severity_count(model::Severity::Critical);
    let high = ctx.stats.severity_count(model::Severity::High);
    page = page.counters(&[
        Stat::new(
            "desktop",
            "hosts",
            thousands(snapshot.hosts.len() as u64),
            format!(
                "{} reporting · {} silent",
                reporting(snapshot),
                silent(snapshot)
            ),
        ),
        Stat::new(
            "broadcast",
            "events in",
            thousands(snapshot.total_events),
            "accepted since start",
        ),
        {
            let mut stat = Stat::new(
                "warning",
                "open detections",
                thousands(ctx.stats.total as u64),
                format!("{} critical · {} high", critical, high),
            );
            stat.alert = critical > 0;
            stat
        },
        Stat::new(
            "chart-bar",
            "firings",
            thousands(snapshot.total_firings),
            format!("{} distinct rules", ctx.stats.by_rule.len()),
        ),
        Stat::new(
            "database",
            "alerts held",
            format!(
                "{} / {}",
                thousands(snapshot.alerts.len() as u64),
                thousands(ctx.status.store_cap as u64)
            ),
            "oldest dropped first",
        ),
    ]);

    style::distribution(&mut page.body, ctx);
    style::filters(&mut page.body, ctx);
    queue_table(&mut page.body, ctx, QUEUE_PAGE);
    page
}

/// The queue, filtered and capped.
///
/// The store hands rows over most-recently-active first and filtering preserves
/// that order, so there is no sort here to disagree with the store about.
fn queue_table(html: &mut String, ctx: &Ctx<'_>, limit: usize) {
    let names = host_names(ctx.snapshot);
    let rows: Vec<&StoredAlert> = ctx
        .snapshot
        .alerts
        .iter()
        .filter(|alert| ctx.filters.matches(alert))
        .collect();

    if rows.is_empty() {
        let message = if ctx.stats.total == 0 {
            "Nothing has fired on this fleet yet. When an agent ships an alert it appears here."
        } else {
            "No detection matches these filters."
        };
        style::empty(html, message);
        return;
    }

    html.push_str("<table class=\"data\">\n<thead><tr>");
    html.push_str(
        "<th>severity</th><th>detection</th><th>host</th><th>firings</th>\
         <th>alerts</th><th>first seen</th><th>last seen</th>",
    );
    html.push_str("</tr></thead>\n<tbody>\n");

    let mut shown = 0usize;
    let mut firings_shown = 0u64;
    for row in rows.iter().take(limit) {
        shown += 1;
        firings_shown = firings_shown.saturating_add(row.firings);
        queue_row(html, ctx, &names, row);
    }

    // A totals row, like a search result count: it is the number an analyst
    // quotes, and it is the check that the rows add up to the header.
    let _ = write!(
        html,
        "<tr class=\"total\"><td colspan=\"3\">{}{}</td>\
         <td class=\"num\">{}</td><td colspan=\"3\"></td></tr>\n",
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

fn queue_row(
    html: &mut String,
    ctx: &Ctx<'_>,
    names: &BTreeMap<String, String>,
    row: &StoredAlert,
) {
    let _ = write!(
        html,
        "<tr class=\"{rail}\">\
         <td>{chip}</td>\
         <td><a href=\"{open}\">{title}</a><br>\
             <a class=\"tag\" href=\"{technique}\">{technique_id}</a></td>",
        rail = style::row_class(row.severity),
        chip = style::chip(row.severity),
        open = escape(&ctx.filters.detection(&row.host_id, &row.rule_id)),
        title = escape(&row.title),
        technique = escape(&ctx.filters.toggle_technique(&row.technique)),
        technique_id = escape(&row.technique),
    );
    html.push_str(&host_cell(ctx, names, &row.host_id, "stack"));
    let _ = write!(
        html,
        "<td class=\"num\">{firings}</td>\
         <td class=\"num dim\">{occurrences}</td>\
         <td class=\"stamp dim\">{first}</td>\
         <td class=\"stamp\">{seen}<span class=\"age\">{age}</span></td></tr>\n",
        firings = thousands(row.firings),
        occurrences = row.occurrences,
        first = escape(&stamp(&row.first_seen.to_rfc3339())),
        seen = escape(&stamp(&row.last_seen.to_rfc3339())),
        age = escape(&age(ctx.now, row.last_seen)),
    );
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

fn hosts(ctx: &Ctx<'_>) -> Page {
    let snapshot = ctx.snapshot;
    let mut page = Page::new(
        "Hosts",
        format!(
            "{} enrolled · {} reporting · {} never sent anything",
            snapshot.hosts.len(),
            reporting(snapshot),
            silent(snapshot)
        ),
    );

    page = page.counters(&[
        Stat::new(
            "desktop",
            "enrolled",
            thousands(snapshot.hosts.len() as u64),
            format!("cap {}", thousands(ctx.status.host_cap as u64)),
        ),
        Stat::new(
            "pulse",
            "reporting",
            thousands(reporting(snapshot) as u64),
            // Not "recently": this counter means the host has shipped at least one
            // batch ever. Staleness is a different question and the last-seen
            // column is where it is answered.
            "has shipped a batch",
        ),
        Stat::new(
            "broadcast",
            "events in",
            thousands(snapshot.total_events),
            "across every host",
        ),
        Stat::new(
            "warning",
            "detections",
            thousands(ctx.stats.total as u64),
            format!("{} firings", thousands(snapshot.total_firings)),
        ),
    ]);

    if snapshot.hosts.is_empty() {
        style::empty(
            &mut page.body,
            "No host has enrolled yet. An agent enrolls with the bootstrap secret the server printed at startup.",
        );
        return page;
    }

    // Naming the hosts that have never sent anything is the thing a host table is
    // actually for: an agent that enrolled and then never reported is an incident,
    // and a table sorted by traffic hides it at the bottom. A host that stopped
    // reporting *later* is the last-seen column's job — this counter cannot see it,
    // because nothing here can know that a silent agent is not simply an idle one.
    let quiet: Vec<&HostRecord> = snapshot
        .hosts
        .iter()
        .filter(|host| !host.is_reporting())
        .collect();
    if quiet.is_empty() {
        style::callout(
            &mut page.body,
            "pulse",
            true,
            "Every enrolled host has shipped at least one batch.",
        );
    } else {
        style::callout(
            &mut page.body,
            "warning",
            false,
            &format!(
                "{} enrolled host{} never sent anything: {}",
                quiet.len(),
                if quiet.len() == 1 { " has" } else { "s have" },
                quiet
                    .iter()
                    .map(|host| host.hostname.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }

    html_hosts_table(&mut page.body, ctx);
    page
}

fn html_hosts_table(html: &mut String, ctx: &Ctx<'_>) {
    html.push_str("<table class=\"data\">\n<thead><tr>");
    html.push_str(
        "<th>state</th><th>host</th><th>os</th><th>events</th>\
         <th>detections</th><th>firings</th><th>highest</th>\
         <th>enrolled</th><th>last seen</th>",
    );
    html.push_str("</tr></thead>\n<tbody>\n");
    for host in &ctx.snapshot.hosts {
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
        let (state, state_class) = if host.is_reporting() {
            ("reporting", "state")
        } else {
            ("never sent", "state silent")
        };
        let _ = write!(
            html,
            "<tr><td><span class=\"{state_class}\"><span class=\"dot\"></span>{state}</span></td>\
             <td><a class=\"id\" href=\"{queue}\">{host_id}</a>\
                 <span class=\"who dim\">{name}</span></td>\
             <td class=\"dim\">{os}</td>\
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
}

// ---------------------------------------------------------------------------
// techniques
// ---------------------------------------------------------------------------

fn techniques(ctx: &Ctx<'_>) -> Page {
    let mut page = Page::new(
        "Techniques",
        format!(
            "{} distinct across {} detections",
            ctx.stats.by_technique.len(),
            ctx.stats.total
        ),
    );

    page = page.counters(&[
        Stat::new(
            "crosshair",
            "techniques",
            thousands(ctx.stats.by_technique.len() as u64),
            "seen on this fleet",
        ),
        Stat::new(
            "warning",
            "detections",
            thousands(ctx.stats.total as u64),
            format!("{} distinct rules", ctx.stats.by_rule.len()),
        ),
        Stat::new(
            "broadcast",
            "firings",
            thousands(ctx.snapshot.total_firings),
            "every firing counted",
        ),
        Stat::new(
            "desktop",
            "hosts touched",
            thousands(ctx.stats.by_host.len() as u64),
            format!("of {} enrolled", ctx.snapshot.hosts.len()),
        ),
    ]);

    if ctx.stats.by_technique.is_empty() {
        style::empty(&mut page.body, "No rule has fired on this fleet yet.");
        return page;
    }

    // Bars are relative to the loudest technique, so the column answers "how does
    // this compare" rather than "what fraction of everything is this", which the
    // firings column already says in numbers.
    let loudest = ctx
        .stats
        .by_technique
        .iter()
        .map(|rollup| rollup.firings)
        .max()
        .unwrap_or(1);

    page.body.push_str("<table class=\"data\">\n<thead><tr>");
    page.body.push_str(
        "<th>technique</th><th>detections</th><th>hosts</th>\
         <th>firings</th><th>highest</th><th>what fired</th>",
    );
    page.body.push_str("</tr></thead>\n<tbody>\n");
    for rollup in &ctx.stats.by_technique {
        technique_row(&mut page.body, ctx, rollup, loudest);
    }
    page.body.push_str("</tbody>\n</table>\n");
    page
}

fn technique_row(html: &mut String, ctx: &Ctx<'_>, rollup: &TechniqueRollup, loudest: u64) {
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
        firings = format!(
            "<span class=\"mini\"><span class=\"{}\"></span></span>{}",
            share(rollup.firings, loudest),
            thousands(rollup.firings)
        ),
        worst = style::chip(rollup.worst),
    );
}

// ---------------------------------------------------------------------------
// status: what the server itself is doing
// ---------------------------------------------------------------------------

fn status(ctx: &Ctx<'_>) -> Page {
    let snapshot = ctx.snapshot;
    let facts = &ctx.status;
    let up = age(ctx.now, facts.started);

    let mut page = Page::new(
        "Status",
        format!(
            "server up {} · started {} UTC · {}",
            up,
            facts.started.format("%Y-%m-%d %H:%M:%S"),
            match &facts.journal {
                Some(_) => "journal enabled",
                None => "in-memory only",
            }
        ),
    );

    page = page.counters(&[
        Stat::new(
            "clock",
            "uptime",
            up,
            format!("since {} UTC", facts.started.format("%H:%M:%S")),
        ),
        Stat::new(
            "broadcast",
            "events accepted",
            thousands(snapshot.total_events),
            "sum of every batch",
        ),
        Stat::new(
            "warning",
            "alert objects",
            thousands(snapshot.total_alerts),
            format!("{} firings", thousands(snapshot.total_firings)),
        ),
        Stat::new(
            "arrows-clockwise",
            "retried batches",
            thousands(snapshot.duplicate_batches),
            "accepted once, resent once",
        ),
        Stat::new(
            "hard-drives",
            "journal",
            match &facts.journal {
                Some(journal) => thousands(journal.replayed as u64),
                None => "off".to_string(),
            },
            match &facts.journal {
                Some(journal) => format!("{} segments, replayed at start", journal.segments),
                None => "nothing survives a restart".to_string(),
            },
        ),
    ]);

    // Retention, as three bars. This is the one page where a proportion is the
    // honest shape: "how full is it" is the question, and the answer is a
    // distance to a limit rather than a count.
    style::section(&mut page.body, "Retention", "how close each bound is");
    page.body.push_str("<table class=\"data\">\n<thead><tr>");
    page.body
        .push_str("<th>collection</th><th>held</th><th>limit</th><th>fill</th><th>what happens at the limit</th>");
    page.body.push_str("</tr></thead>\n<tbody>\n");
    retention_row(
        &mut page.body,
        "alert rows",
        snapshot.alerts.len() as u64,
        facts.store_cap as u64,
        "the least recently active row is dropped",
    );
    retention_row(
        &mut page.body,
        "batch ids",
        snapshot.duplicate_batches.min(0).max(0) as u64,
        facts.batch_cap as u64,
        "the oldest id is forgotten, so a very late retry could be counted twice",
    );
    retention_row(
        &mut page.body,
        "enrolled hosts",
        snapshot.hosts.len() as u64,
        facts.host_cap as u64,
        "further enrollment is refused rather than de-enrolling a host",
    );
    page.body.push_str("</tbody>\n</table>\n");

    // The journal, or the absence of one, in full. This is the paragraph an
    // operator needs before they trust a restart.
    style::section(&mut page.body, "Journal", "what survives a restart");
    match &facts.journal {
        Some(journal) => {
            page.body.push_str("<dl class=\"kv\">\n");
            kv(&mut page.body, "state", "enabled");
            kv(&mut page.body, "path", &escape(&journal.path));
            kv(
                &mut page.body,
                "segments",
                &format!("{} rotated files", journal.segments),
            );
            kv(
                &mut page.body,
                "records replayed",
                &format!(
                    "{} read back through the same code the live path runs",
                    thousands(journal.replayed as u64)
                ),
            );
            kv(
                &mut page.body,
                "torn records skipped",
                &format!(
                    "{} discarded from the end of a segment",
                    thousands(journal.skipped as u64)
                ),
            );
            kv(&mut page.body, "bytes", &thousands(journal.bytes));
            page.body.push_str("</dl>\n");
            style::callout(
                &mut page.body,
                "hard-drives",
                true,
                "Writes are flushed but not fsynced: the journal survives the process dying, not the machine losing power.",
            );
        }
        None => {
            style::callout(
                &mut page.body,
                "warning",
                false,
                "No journal is configured, so a restart forgets every enrolled host and every alert. Start the server with --data DIR to keep one.",
            );
        }
    }

    // Where the volume actually is. The queue groups by (host, rule) because that
    // is what you act on; this groups by rule, because that is what you turn off.
    style::section(
        &mut page.body,
        "Rules that fired",
        &format!("{} distinct, loudest first", ctx.stats.by_rule.len()),
    );
    if ctx.stats.by_rule.is_empty() {
        style::empty(&mut page.body, "No rule has fired yet.");
    } else {
        let loudest = ctx
            .stats
            .by_rule
            .iter()
            .map(|rollup| rollup.firings)
            .max()
            .unwrap_or(1);
        page.body.push_str("<table class=\"data\">\n<thead><tr>");
        page.body.push_str(
            "<th>rule</th><th>severity</th><th>technique</th>\
             <th>hosts</th><th>firings</th><th>detection</th>",
        );
        page.body.push_str("</tr></thead>\n<tbody>\n");
        for rollup in &ctx.stats.by_rule {
            let _ = write!(
                page.body,
                "<tr class=\"{rail}\"><td class=\"mono\">{rule}</td>\
                 <td>{chip}</td>\
                 <td><a class=\"tag\" href=\"{technique}\">{technique_id}</a></td>\
                 <td class=\"num\">{hosts}</td>\
                 <td class=\"num\">{firings}</td>\
                 <td class=\"dim\">{title}</td></tr>\n",
                rail = style::row_class(rollup.severity),
                rule = escape(&rollup.rule_id),
                chip = style::chip(rollup.severity),
                technique = escape(&ctx.filters.toggle_technique(&rollup.technique)),
                technique_id = escape(&rollup.technique),
                hosts = rollup.hosts,
                firings = format!(
                    "<span class=\"mini\"><span class=\"{}\"></span></span>{}",
                    share(rollup.firings, loudest),
                    thousands(rollup.firings)
                ),
                title = escape(&rollup.title),
            );
        }
        page.body.push_str("</tbody>\n</table>\n");
    }

    // What this page cannot know. Stated rather than implied, because an operator
    // reading a healthy-looking console should be told which half of the pipeline
    // it is describing.
    style::section(&mut page.body, "Scope", "what this page does not describe");
    style::note(
        &mut page.body,
        "These are the server's own counters. Whether the agent on a host is \
         collecting anything is a property of that host: its ETW providers, its \
         audit policy, and its queue depth are in the agent's run report, not here. \
         A host can be enrolled, reporting, and still be blind to a whole class of \
         events — process starts need an audit policy, script blocks need Script \
         Block Logging.",
    );

    page
}

fn retention_row(html: &mut String, what: &str, held: u64, limit: u64, at_limit: &str) {
    let _ = write!(
        html,
        "<tr><td>{what}</td><td class=\"num\">{held}</td><td class=\"num dim\">{limit}</td>\
         <td><span class=\"mini\"><span class=\"{share}\"></span></span></td>\
         <td class=\"dim\">{at_limit}</td></tr>\n",
        what = escape(what),
        held = thousands(held),
        limit = thousands(limit),
        share = share(held, limit),
        at_limit = escape(at_limit),
    );
}

fn kv(html: &mut String, key: &str, value_html: &str) {
    let _ = write!(html, "<dt>{}</dt><dd>{value_html}</dd>\n", escape(key));
}

// ---------------------------------------------------------------------------
// one detection
// ---------------------------------------------------------------------------

fn detection(ctx: &Ctx<'_>) -> Page {
    let Some(row) = find_row(ctx.snapshot, ctx.filters) else {
        let mut page = Page::new(
            "Not found",
            "this detection is no longer in the queue".into(),
        );
        page.body.push_str(&format!(
            "<div class=\"crumbs\">{}<a href=\"{}\">back to detections</a></div>\n",
            icons::render("arrow-left", "icon sm"),
            escape(&ctx.filters.cleared())
        ));
        style::empty(
            &mut page.body,
            "This detection is no longer in the queue. The store is in memory and bounded, \
             so an old row is dropped rather than kept forever.",
        );
        return page;
    };

    let names = host_names(ctx.snapshot);
    let hostname = names.get(&row.host_id).map(String::as_str).unwrap_or("");
    let mut page = Page::new(&row.title, format!("{} on {}", row.rule_id, row.host_id));
    page = page.counters(&[
        Stat::new(
            "warning",
            "severity",
            row.severity.as_str().to_string(),
            format!("via {}", row.rule_id),
        ),
        Stat::new(
            "desktop",
            "host",
            row.host_id.clone(),
            if hostname.is_empty() {
                "not enrolled".to_string()
            } else {
                hostname.to_string()
            },
        ),
        Stat::new(
            "chart-bar",
            "firings",
            thousands(row.firings),
            format!("{} alert objects", row.occurrences),
        ),
        Stat::new(
            "clock",
            "first seen",
            stamp(&row.first_seen.to_rfc3339()),
            format!("last seen {}", age(ctx.now, row.last_seen)),
        ),
    ]);

    let _ = write!(
        page.body,
        "<div class=\"crumbs\">{}<a href=\"{}\">back to detections</a></div>\n",
        icons::render("arrow-left", "icon sm"),
        escape(&ctx.filters.cleared())
    );

    // The title leads in the top bar; what follows is what you would write down.
    style::section(&mut page.body, "Properties", "as filed");
    page.body.push_str("<dl class=\"kv\">\n");
    kv(&mut page.body, "severity", &style::chip(row.severity));
    kv(&mut page.body, "rule", &escape(&row.rule_id));
    kv(
        &mut page.body,
        "technique",
        &format!(
            "<a class=\"tag\" href=\"{}\">{}</a>",
            escape(&ctx.filters.toggle_technique(&row.technique)),
            escape(&row.technique)
        ),
    );
    kv(
        &mut page.body,
        "host",
        &format!(
            "<a class=\"id\" href=\"{}\">{}</a>",
            escape(&ctx.filters.toggle_host(&row.host_id)),
            escape(&row.host_id)
        ),
    );
    kv(&mut page.body, "firings", &thousands(row.firings));
    kv(
        &mut page.body,
        "alert objects",
        &row.occurrences.to_string(),
    );
    kv(&mut page.body, "first seen", &seen(ctx, row.first_seen));
    kv(&mut page.body, "last seen", &seen(ctx, row.last_seen));
    page.body.push_str("</dl>\n");

    style::section(&mut page.body, "Evidence", "minimised on the host (A19)");
    if row.description.is_empty() {
        style::empty(
            &mut page.body,
            "No description was shipped with this alert.",
        );
    } else {
        style::note(&mut page.body, &row.description);
    }

    // The pivot that makes a queue usable: what else fired on the same host.
    let related: Vec<&StoredAlert> = ctx
        .snapshot
        .alerts
        .iter()
        .filter(|other| other.host_id == row.host_id && other.rule_id != row.rule_id)
        .collect();
    style::section(
        &mut page.body,
        "Also on this host",
        &format!("{} other detections", related.len()),
    );
    if related.is_empty() {
        style::empty(
            &mut page.body,
            "Nothing else has fired here — this is the only detection on this host.",
        );
        return page;
    }
    page.body.push_str("<table class=\"data\">\n<thead><tr>");
    page.body.push_str(
        "<th>severity</th><th>technique</th><th>detection</th><th>firings</th><th>last seen</th>",
    );
    page.body.push_str("</tr></thead>\n<tbody>\n");
    for other in related {
        let _ = write!(
            page.body,
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
    page.body.push_str("</tbody>\n</table>\n");

    page
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::{Filters, JournalFacts, Status, page};
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

    /// A host that enrolled and then never sent anything, which is what
    /// `is_reporting` actually means. It is deliberately not "last seen a while
    /// ago": a host that shipped a million events last week and nothing since is
    /// indistinguishable, from here, from one that is simply idle.
    fn quiet_host(host_id: &str, hostname: &str) -> HostRecord {
        HostRecord {
            events: 0,
            alerts: 0,
            ..host(host_id, hostname)
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
            duplicate_batches: 7,
        }
    }

    fn status() -> Status {
        Status {
            started: Utc::now() - chrono::Duration::minutes(42),
            store_cap: 10_000,
            batch_cap: 50_000,
            host_cap: 500,
            journal: Some(JournalFacts {
                path: "C:\\chaos-data".to_string(),
                segments: 3,
                replayed: 1_204,
                skipped: 1,
                bytes: 8_388_608,
            }),
        }
    }

    fn at(view: &str) -> String {
        page(&snapshot(), &status(), &Filters::parse(view), Utc::now())
    }

    /// Every page, including the one that takes no filters.
    const EVERY_VIEW: &[&str] = &[
        "view=detections",
        "view=hosts",
        "view=techniques",
        "view=status",
        "view=detection&host=a1b2&rule=run_key_persistence",
    ];

    #[test]
    fn every_view_renders_a_whole_document() {
        for view in EVERY_VIEW {
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
    fn the_rail_lists_every_section_and_marks_the_current_one() {
        let html = at("view=hosts");
        for label in ["Detections", "Hosts", "Techniques", "Status"] {
            assert!(html.contains(label), "the rail is missing {label}");
        }
        assert!(
            html.contains("href=\"/?view=hosts\"") && html.contains("class=\"on\""),
            "the current section is not marked"
        );
        // A detection opened from the queue stays under Detections rather than
        // going dark, which reads as having fallen out of the application.
        assert!(at("view=detection&host=a1b2&rule=run_key_persistence").contains(">Detections<"));
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
            "view=status",
            &format!(
                "view=detection&host=a1b2&rule={}",
                crate::dashboard::format::encode(payload)
            ),
        ] {
            let html = page(&snapshot, &status(), &Filters::parse(view), Utc::now());
            assert!(html.contains("&lt;script&gt;"), "{view} lost the escape");
            assert!(!html.contains("<script"), "raw script tag in {view}");
        }
    }

    /// The load-bearing property of the design. Inline styles would mean
    /// `style-src` had to be relaxed, and the width classes exist precisely so
    /// that the proportion bars never become the reason it is.
    #[test]
    fn the_console_carries_no_script_and_no_inline_style() {
        for view in EVERY_VIEW {
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
        for view in EVERY_VIEW {
            let html = page(
                &snapshot,
                &Status::default(),
                &Filters::parse(view),
                Utc::now(),
            );
            assert!(html.starts_with("<!doctype html>"), "{view}");
            assert!(!html.contains(">NaN<"), "{view} divided by zero");
            assert!(!html.contains(">inf<"), "{view} divided by zero");
            assert!(!html.contains("style=\""), "{view}");
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
        assert!(html.contains("2,600,000"), "events in the counters");
        assert!(!html.contains(">2600000<"));
    }

    /// The distribution is one line for information that would otherwise take a
    /// panel, and a severity with rows in it is never rounded out of the picture.
    #[test]
    fn the_distribution_shows_every_severity_that_has_rows() {
        let html = at("view=detections");
        assert!(html.contains("class=\"dist\""), "the proportion bar");
        assert!(html.contains("seg-critical"));
        assert!(html.contains("seg-high"));
        assert!(html.contains("seg-low"));
        // One row of a three-row queue is 33%, which lands on the 35% step.
        assert!(html.contains("pc-35"), "one of three rows");
    }

    #[test]
    fn a_share_never_rounds_a_real_count_away() {
        assert_eq!(share(0, 10), "pc-0");
        assert_eq!(
            share(1, 100_000),
            "pc-5",
            "one in a hundred thousand is still visible"
        );
        assert_eq!(share(1, 1), "pc-100");
        assert_eq!(share(1, 2), "pc-50");
        assert_eq!(share(5, 0), "pc-0", "an empty whole is not a division");
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
    fn the_hosts_page_names_the_hosts_that_never_reported() {
        // The one thing a host table is for: an agent that enrolled and then never
        // shipped anything is an incident, and a table sorted by traffic buries it
        // at the bottom.
        let snapshot = Snapshot {
            hosts: vec![host("a1b2", "DESKTOP-A"), quiet_host("c3d4", "DESKTOP-B")],
            ..Default::default()
        };
        let html = page(
            &snapshot,
            &Status::default(),
            &Filters::parse("view=hosts"),
            Utc::now(),
        );
        assert!(html.contains("never sent anything"), "{html}");
        assert!(html.contains("DESKTOP-B"), "the quiet host is named");
        assert!(html.contains("never sent"), "and marked in its own row");

        // And when nothing is wrong it says that instead of staying silent, which
        // is the difference between "no alert" and "not looked at".
        let healthy = at("view=hosts");
        assert!(healthy.contains("Every enrolled host has shipped"));
    }

    #[test]
    fn the_status_page_reports_what_survives_a_restart() {
        let html = at("view=status");
        assert!(html.contains("1,204"), "records replayed");
        assert!(html.contains("chaos-data"), "the journal path");
        assert!(
            html.contains("not fsynced"),
            "the durability claim is stated, not implied"
        );

        let without = page(
            &snapshot(),
            &Status::default(),
            &Filters::parse("view=status"),
            Utc::now(),
        );
        assert!(
            without.contains("--data DIR"),
            "with no journal the page says how to get one"
        );
    }

    #[test]
    fn the_status_page_shows_how_full_each_bound_is() {
        let html = at("view=status");
        assert!(html.contains("alert rows"));
        assert!(html.contains("10,000"), "the store cap");
        assert!(html.contains("50,000"), "the deduplication cap");
        assert!(html.contains("500"), "the enrollment cap");
        assert!(html.contains("class=\"mini\""), "a fill bar");
    }

    #[test]
    fn the_status_page_ranks_rules_by_volume() {
        // The queue groups by (host, rule) because that is what you act on; this
        // groups by rule, because that is what you turn off.
        let html = at("view=status");
        assert!(html.contains("run_key_persistence"));
        assert!(html.contains("encoded_powershell"));
        assert!(html.contains("high_abuse_tld"));
        assert!(html.contains("180"), "the three rules' firings, summed");
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
        // Several top-level headings on one page is a page a screen reader
        // announces as several unrelated things.
        let html = at("view=detection&host=a1b2&rule=run_key_persistence");
        assert_eq!(html.matches("<h1>").count(), 1, "one title");
        assert!(html.contains("<h2>Evidence</h2>"));
        assert!(html.contains("<h2>Also on this host</h2>"));
        for view in EVERY_VIEW {
            assert_eq!(
                at(view).matches("<h1>").count(),
                1,
                "{view} has more than one title"
            );
        }
    }

    #[test]
    fn every_counter_carries_a_label_and_a_sub_line() {
        // A number in a box with nothing under it moves the work of
        // understanding it onto the reader.
        let html = at("view=detections");
        assert!(html.contains("<span class=\"k\">open detections</span>"));
        assert!(
            html.contains("<span class=\"s\">1 critical"),
            "the sub-line says what the number is made of"
        );
    }

    #[test]
    fn icons_are_drawn_and_none_of_them_is_a_blank_square() {
        let html = at("view=detections");
        assert!(html.contains("<svg class=\"icon"), "the chrome draws icons");
        // A missing icon renders an empty `<svg>`, which is a blank square nobody
        // notices in review and everybody notices on the page.
        assert!(
            !html.contains("focusable=\"false\"></svg>"),
            "an icon rendered empty"
        );
        assert!(html.contains("aria-hidden=\"true\""));
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

    #[test]
    fn the_stylesheet_asks_for_nothing_off_the_machine() {
        // A webfont or a CDN icon would be a dependency, a `font-src` in the CSP,
        // and a flash of unstyled text on a live feed. Neither is here.
        let css = crate::dashboard::stylesheet();
        assert!(!css.contains("@import"), "the stylesheet imports nothing");
        assert!(!css.contains("url("), "and fetches nothing");
        assert!(css.contains("\"Segoe UI\""), "it names the system UI font");
        assert!(css.contains("Consolas"), "and a monospace the platform has");
    }
}
