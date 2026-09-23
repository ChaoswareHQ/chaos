//! The console: a server-rendered table application with no JavaScript.
//!
//! # Why no frontend framework
//!
//! A security console is a high-value target that a small team has to keep
//! secure for years. Every one of these is a liability on that timeline:
//!
//! * an npm dependency tree, where a transitive package can be compromised and
//!   your console starts exfiltrating the thing it exists to protect;
//! * a build step, which is another artifact to reproduce and another place for
//!   a difference between what was reviewed and what was deployed;
//! * client-side rendering, which means the browser is trusted to enforce
//!   access decisions the server should be making.
//!
//! Server-rendered HTML with a strict `Content-Security-Policy` and zero script
//! has none of those.
//!
//! # Why three tabs and no charts
//!
//! Three tabs — the queue, the hosts, the techniques — because that is the order
//! an analyst moves in, and because a console with six pages of which two are
//! restatements of the others is a console nobody remembers their way around.
//! There is a details page behind a row, and that is the whole navigation.
//!
//! The severity distribution lives in the filter row, not in a chart: the counts
//! beside each severity *are* the distribution, and each one is also the control
//! that narrows to it. A bar chart of the same numbers would be a second place to
//! look for one fact.
//!
//! # Why every control is a link
//!
//! With no scripting a filter cannot be applied in the browser, so it has to be
//! a request. [`Filters`] is therefore both the filter state and the URL, which
//! is what makes a filtered view something an analyst can bookmark or paste to a
//! colleague.
//!
//! # What is deliberately absent
//!
//! No acknowledge, close or assign action. `AlertStatus` exists on the wire, but
//! the console has no authentication, so a button that changes state would be an
//! unauthenticated write endpoint in the one interface an attacker would most
//! like to have one. Read-only until there is an identity to attribute writes to.

mod format;
mod icons;
mod style;
mod views;

pub use style::stylesheet;

use crate::store::{Snapshot, StoredAlert};
use chrono::{DateTime, Utc};
use model::Severity;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use format::{decode, encode};

/// Which page a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// The queue. The landing page, because it is the thing you came for.
    #[default]
    Detections,
    Hosts,
    Techniques,
    /// What the server itself is doing: ingest, retention, the journal.
    Status,
    /// One detection, opened from the queue.
    Detection,
}

impl View {
    fn slug(self) -> &'static str {
        match self {
            View::Detections => "detections",
            View::Hosts => "hosts",
            View::Techniques => "techniques",
            View::Status => "status",
            View::Detection => "detection",
        }
    }

    fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "detections" => Some(View::Detections),
            "hosts" => Some(View::Hosts),
            "techniques" => Some(View::Techniques),
            "status" => Some(View::Status),
            "detection" => Some(View::Detection),
            _ => None,
        }
    }

    /// Which tab lights up for this view.
    ///
    /// A detection opened from the queue belongs under Detections. Otherwise the
    /// whole nav goes dark exactly when an analyst has drilled in, which reads as
    /// having fallen out of the application.
    pub fn tab(self) -> Self {
        match self {
            View::Detection => View::Detections,
            other => other,
        }
    }

    /// The section's name in the rail, and the browser tab's label.
    ///
    /// The browser tab is labelled by section rather than by page title: a
    /// detection's `h1` is the alert's own title, and putting that in the tab
    /// strip too would make the same sentence appear twice in the document — once
    /// in chrome a person reads, once in chrome the browser draws.
    pub fn label(self) -> &'static str {
        match self {
            View::Detections => "Detections",
            View::Hosts => "Hosts",
            View::Techniques => "Techniques",
            View::Status => "Status",
            View::Detection => "Detection",
        }
    }
}

/// The console's filter state, which is also its URL.
///
/// `rule` only means anything on [`View::Detection`], where together with `host`
/// it names the row being opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    pub view: View,
    pub severity: Option<Severity>,
    pub host: Option<String>,
    pub technique: Option<String>,
    pub rule: Option<String>,
}

impl Filters {
    /// Parse a URL query string.
    ///
    /// Unknown keys and unparseable values are ignored rather than refused. A
    /// console that returns an error page because a URL was edited by hand is
    /// worse than one that shows slightly more than was asked for.
    pub fn parse(query: &str) -> Self {
        let mut filters = Filters::default();
        for pair in query.split('&') {
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, decode(value)),
                None => continue,
            };
            match key {
                "view" => {
                    if let Some(view) = View::from_slug(&value) {
                        filters.view = view;
                    }
                }
                "severity" => filters.severity = format::severity_from_str(&value),
                "host" if !value.is_empty() => filters.host = Some(value),
                "technique" if !value.is_empty() => filters.technique = Some(value),
                "rule" if !value.is_empty() => filters.rule = Some(value),
                _ => {}
            }
        }
        filters
    }

    /// The href for this filter set.
    pub fn href(&self) -> String {
        let mut query = format!("view={}", self.view.slug());
        if let Some(severity) = self.severity {
            let _ = write!(query, "&severity={}", format::severity_class(severity));
        }
        if let Some(host) = &self.host {
            let _ = write!(query, "&host={}", encode(host));
        }
        if let Some(technique) = &self.technique {
            let _ = write!(query, "&technique={}", encode(technique));
        }
        if let Some(rule) = &self.rule {
            let _ = write!(query, "&rule={}", encode(rule));
        }
        format!("/?{query}")
    }

    /// A tab link: change the page, drop the drill-down. Facets are kept so that
    /// moving between pages does not silently widen the analyst's filter.
    pub fn to(&self, view: View) -> String {
        Filters {
            view,
            rule: None,
            ..self.clone()
        }
        .href()
    }

    /// Toggle a severity facet. The active value clears it, which is what lets
    /// one link be both the filter and the way out of it.
    pub fn toggle_severity(&self, severity: Option<Severity>) -> String {
        let severity = match severity {
            Some(candidate) if self.severity == Some(candidate) => None,
            other => other,
        };
        Filters {
            view: View::Detections,
            severity,
            rule: None,
            ..self.clone()
        }
        .href()
    }

    /// Toggle a technique facet.
    pub fn toggle_technique(&self, technique: &str) -> String {
        let technique = match self.technique.as_deref() {
            Some(active) if active == technique => None,
            _ => Some(technique.to_string()),
        };
        Filters {
            view: View::Detections,
            technique,
            rule: None,
            ..self.clone()
        }
        .href()
    }

    /// Toggle a host facet.
    pub fn toggle_host(&self, host: &str) -> String {
        let host = match self.host.as_deref() {
            Some(active) if active == host => None,
            _ => Some(host.to_string()),
        };
        Filters {
            view: View::Detections,
            host,
            rule: None,
            ..self.clone()
        }
        .href()
    }

    /// Open one detection.
    pub fn detection(&self, host: &str, rule: &str) -> String {
        Filters {
            view: View::Detection,
            host: Some(host.to_string()),
            rule: Some(rule.to_string()),
            ..self.clone()
        }
        .href()
    }

    /// Drop every facet, back to the unfiltered queue.
    pub fn cleared(&self) -> String {
        Filters {
            view: View::Detections,
            severity: None,
            host: None,
            technique: None,
            rule: None,
        }
        .href()
    }

    /// Whether anything is filtered out.
    pub fn is_filtered(&self) -> bool {
        self.severity.is_some() || self.host.is_some() || self.technique.is_some()
    }

    /// Whether a row survives the current facets.
    pub fn matches(&self, alert: &StoredAlert) -> bool {
        if let Some(severity) = self.severity {
            if alert.severity != severity {
                return false;
            }
        }
        if let Some(host) = &self.host {
            if &alert.host_id != host {
                return false;
            }
        }
        if let Some(technique) = &self.technique {
            if &alert.technique != technique {
                return false;
            }
        }
        true
    }
}

/// Per-technique totals, for the Techniques tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueRollup {
    pub technique: String,
    pub detections: u32,
    pub firings: u64,
    pub worst: Severity,
    pub hosts: u32,
}

/// Per-rule totals.
///
/// The queue is one row per `(host, rule)`; this is the same firings gathered the
/// other way, which is the view that answers "which rule is doing this to my
/// day". Both exist because both questions are asked, and neither grouping
/// answers the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRollup {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub technique: String,
    pub firings: u64,
    pub hosts: u32,
}

/// Per-host totals, for the Hosts tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRollup {
    pub host_id: String,
    pub detections: u32,
    pub firings: u64,
    pub worst: Severity,
}

/// How many distinct titles a technique row shows.
///
/// Two, not all: the row is a summary of a technique, and the way to see every
/// detection under it is the link, which is already there.
pub const TITLES_PER_TECHNIQUE: usize = 2;

/// Totals the header, the filter row and the two summary tabs need.
///
/// Computed once per request. Six places want a rollup and each would otherwise
/// rescan the queue; more to the point, they must agree. Two panels disagreeing
/// about how many criticals there are is a bug an analyst would report as a
/// mystery.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Detections per severity. This is both the distribution and the filter
    /// counts, which is why there is no chart.
    pub by_severity: BTreeMap<Severity, u32>,
    pub by_technique: Vec<TechniqueRollup>,
    pub by_host: Vec<HostRollup>,
    pub by_rule: Vec<RuleRollup>,
    /// Detections matching the current facets.
    pub visible: usize,
    /// Detections in the queue at all.
    pub total: usize,
}

impl Stats {
    pub fn compute(snapshot: &Snapshot, filters: &Filters) -> Self {
        let mut stats = Stats {
            total: snapshot.alerts.len(),
            ..Default::default()
        };

        let mut techniques: BTreeMap<String, TechniqueRollup> = BTreeMap::new();
        let mut hosts: BTreeMap<String, HostRollup> = BTreeMap::new();
        let mut rules: BTreeMap<String, (RuleRollup, std::collections::BTreeSet<String>)> =
            BTreeMap::new();
        let mut hosts_per_technique: BTreeMap<String, std::collections::BTreeSet<String>> =
            BTreeMap::new();

        for alert in &snapshot.alerts {
            if filters.matches(alert) {
                stats.visible += 1;
            }

            let severity = stats.by_severity.entry(alert.severity).or_default();
            *severity = severity.saturating_add(1);

            let rule = rules.entry(alert.rule_id.clone()).or_insert_with(|| {
                (
                    RuleRollup {
                        rule_id: alert.rule_id.clone(),
                        title: alert.title.clone(),
                        severity: alert.severity,
                        technique: alert.technique.clone(),
                        firings: 0,
                        hosts: 0,
                    },
                    std::collections::BTreeSet::new(),
                )
            });
            rule.0.firings = rule.0.firings.saturating_add(alert.firings);
            rule.0.severity = rule.0.severity.max(alert.severity);
            rule.1.insert(alert.host_id.clone());

            let technique = techniques
                .entry(alert.technique.clone())
                .or_insert_with(|| TechniqueRollup {
                    technique: alert.technique.clone(),
                    detections: 0,
                    firings: 0,
                    worst: Severity::Info,
                    hosts: 0,
                });
            technique.detections = technique.detections.saturating_add(1);
            technique.firings = technique.firings.saturating_add(alert.firings);
            technique.worst = technique.worst.max(alert.severity);
            hosts_per_technique
                .entry(alert.technique.clone())
                .or_default()
                .insert(alert.host_id.clone());

            let host = hosts
                .entry(alert.host_id.clone())
                .or_insert_with(|| HostRollup {
                    host_id: alert.host_id.clone(),
                    detections: 0,
                    firings: 0,
                    worst: Severity::Info,
                });
            host.detections = host.detections.saturating_add(1);
            host.firings = host.firings.saturating_add(alert.firings);
            host.worst = host.worst.max(alert.severity);
        }

        for (technique, rolls) in &hosts_per_technique {
            if let Some(rollup) = techniques.get_mut(technique) {
                rollup.hosts = rolls.len() as u32;
            }
        }

        stats.by_technique = techniques.into_values().collect();
        // Loudest first, then by reach, then by name so the order cannot shuffle
        // between refreshes.
        stats.by_technique.sort_by(|a, b| {
            b.firings
                .cmp(&a.firings)
                .then_with(|| b.hosts.cmp(&a.hosts))
                .then_with(|| a.technique.cmp(&b.technique))
        });
        stats.by_host = hosts.into_values().collect();
        stats.by_host.sort_by(|a, b| {
            b.firings
                .cmp(&a.firings)
                .then_with(|| a.host_id.cmp(&b.host_id))
        });

        stats.by_rule = rules
            .into_values()
            .map(|(mut rollup, hosts)| {
                rollup.hosts = hosts.len() as u32;
                rollup
            })
            .collect();
        stats.by_rule.sort_by(|a, b| {
            b.firings
                .cmp(&a.firings)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        stats
    }

    /// Detections at one severity. Zero when nothing has fired at it.
    pub fn severity_count(&self, severity: Severity) -> u32 {
        self.by_severity.get(&severity).copied().unwrap_or(0)
    }

    /// The worst severity in the queue, if there is one.
    pub fn worst(&self) -> Option<Severity> {
        self.by_severity.keys().next_back().copied()
    }
}

/// How many rows a page renders. The store keeps more than this, and the footer
/// says how many were left out rather than letting the page imply it showed
/// everything.
pub const QUEUE_PAGE: usize = 200;

/// Everything a view needs to render.
pub struct Ctx<'a> {
    pub snapshot: &'a Snapshot,
    pub stats: &'a Stats,
    pub status: &'a Status,
    pub filters: &'a Filters,
    pub now: DateTime<Utc>,
}

/// What the server itself is doing, as opposed to what the fleet reported.
///
/// None of this is derivable from a [`Snapshot`]: it is properties of the
/// process — how long it has been up, what the journal has done, how close each
/// bounded collection is to the cap it will be trimmed at. The console is the
/// only place an operator can see them without a second terminal, which is the
/// whole reason the status page exists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// When this server started. The uptime on the status page is `now - this`.
    pub started: DateTime<Utc>,
    /// Alert rows kept before the least recently active are dropped.
    pub store_cap: usize,
    /// Batch ids remembered for deduplication.
    pub batch_cap: usize,
    /// Hosts this server will enroll.
    pub host_cap: usize,
    /// The journal, when the server was told to keep one.
    pub journal: Option<JournalFacts>,
}

/// The journal's own numbers, flattened.
///
/// Copied out of the journal's stats rather than borrowed, so that a view does
/// not hold a lock on the file while it renders a page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalFacts {
    pub path: String,
    pub segments: usize,
    /// Records read back at startup.
    pub replayed: usize,
    /// Torn records discarded from the end of a segment.
    pub skipped: usize,
    pub bytes: u64,
}

/// Render the page the filters ask for.
pub fn page(snapshot: &Snapshot, status: &Status, filters: &Filters, now: DateTime<Utc>) -> String {
    let stats = Stats::compute(snapshot, filters);
    let ctx = Ctx {
        snapshot,
        stats: &stats,
        status,
        filters,
        now,
    };
    views::render(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_url_is_the_queue() {
        let filters = Filters::parse("");
        assert_eq!(filters.view, View::Detections);
        assert!(!filters.is_filtered());
    }

    #[test]
    fn every_view_survives_a_round_trip_through_its_slug() {
        for view in [
            View::Detections,
            View::Hosts,
            View::Techniques,
            View::Detection,
        ] {
            let href = Filters {
                view,
                ..Default::default()
            }
            .href();
            assert_eq!(Filters::parse(&href[2..]).view, view, "{href}");
        }
    }

    #[test]
    fn unknown_keys_and_values_are_ignored_rather_than_refused() {
        let filters = Filters::parse("view=detections&severity=nonsense&host=&bogus=1");
        assert_eq!(filters.view, View::Detections);
        assert_eq!(filters.severity, None);
        assert_eq!(filters.host, None);
    }

    #[test]
    fn facets_round_trip_through_the_url() {
        let filters =
            Filters::parse("view=detections&severity=critical&host=a1b2&technique=T1059.001");
        assert_eq!(filters.severity, Some(Severity::Critical));
        assert_eq!(filters.host.as_deref(), Some("a1b2"));
        assert_eq!(filters.technique.as_deref(), Some("T1059.001"));
        assert!(filters.is_filtered());
        assert_eq!(
            Filters::parse(&filters.href()[2..]),
            filters,
            "URL is state"
        );
    }

    #[test]
    fn a_facet_link_toggles_itself_off() {
        // One link has to serve as both the filter and the way out of it,
        // because there is no script to add a second control.
        let filters = Filters::parse("view=detections&severity=high");
        assert_eq!(
            Filters::parse(&filters.toggle_severity(Some(Severity::High))[2..]).severity,
            None
        );
        assert_eq!(
            Filters::parse(&filters.toggle_severity(Some(Severity::Critical))[2..]).severity,
            Some(Severity::Critical)
        );
    }

    #[test]
    fn a_facet_link_keeps_the_other_facets() {
        let filters = Filters::parse("view=detections&host=a1b2&severity=high");
        let narrowed = Filters::parse(&filters.toggle_technique("T1059.001")[2..]);
        assert_eq!(narrowed.host.as_deref(), Some("a1b2"));
        assert_eq!(narrowed.severity, Some(Severity::High));
        assert_eq!(narrowed.technique.as_deref(), Some("T1059.001"));
    }

    #[test]
    fn opening_a_detection_carries_the_drill_down_key_only_there() {
        let filters = Filters::parse("view=detections&severity=high");
        let opened = Filters::parse(&filters.detection("a1b2", "R1")[2..]);
        assert_eq!(opened.view, View::Detection);
        assert_eq!(opened.rule.as_deref(), Some("R1"));
        assert_eq!(opened.severity, Some(Severity::High), "facets survive");
        // Navigating away drops it: a rule id is meaningless on the host list.
        assert_eq!(Filters::parse(&filters.to(View::Hosts)[2..]).rule, None);
    }

    #[test]
    fn clearing_drops_every_facet() {
        let filters = Filters::parse("view=detections&severity=high&host=a1b2");
        let cleared = Filters::parse(&filters.cleared()[2..]);
        assert_eq!(cleared.view, View::Detections);
        assert!(!cleared.is_filtered());
    }

    #[test]
    fn a_detection_opened_from_the_queue_still_lights_up_its_tab() {
        assert_eq!(View::Detection.tab(), View::Detections);
        assert_eq!(View::Hosts.tab(), View::Hosts);
    }

    #[test]
    fn matches_applies_every_active_facet() {
        let row = StoredAlert {
            host_id: "h1".into(),
            rule_id: "R1".into(),
            severity: Severity::High,
            title: "t".into(),
            description: "d".into(),
            technique: "T1059.001".into(),
            firings: 1,
            occurrences: 1,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };

        assert!(Filters::parse("view=detections").matches(&row));
        assert!(Filters::parse("view=detections&severity=high").matches(&row));
        assert!(!Filters::parse("view=detections&severity=low").matches(&row));
        assert!(Filters::parse("view=detections&host=h1").matches(&row));
        assert!(!Filters::parse("view=detections&host=h2").matches(&row));
        assert!(Filters::parse("view=detections&technique=T1059.001").matches(&row));
        assert!(!Filters::parse("view=detections&technique=T1218").matches(&row));
        assert!(
            Filters::parse("view=detections&host=h1&severity=high&technique=T1059.001")
                .matches(&row)
        );
        assert!(!Filters::parse("view=detections&host=h1&severity=low").matches(&row));
    }
}
