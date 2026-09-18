//! Host registry and received telemetry.
//!
//! In-memory, behind a trait, because the interesting decision here is not
//! which database to use — the config already names `sqlite` and `clickhouse` —
//! but what the ingest path is allowed to assume. Answering that with a `Store`
//! trait means the HTTP layer never sees a connection pool, and swapping in
//! ClickHouse later is additive.
//!
//! The store holds two credentials-adjacent things and treats them differently
//! on purpose: a host's **secret hash**, never its secret, and the set of
//! **batch ids** it has already accepted, which is what makes the client's
//! at-least-once retry safe to honour.
//!
//! # Why alerts are stored as aggregates
//!
//! One row per **`(host, rule)`**, not one row per alert.
//!
//! The agent already coalesces within a run (A8), so a rule firing two hundred
//! times in one run is one alert carrying `count = 200`. What that does not
//! cover is the run *after* it: a restarted agent, or a rule firing again once
//! the suppression window lapses, emits a fresh alert with a fresh id.
//! Appending those rebuilds the wall of near-identical rows this store exists
//! to prevent, and the wall grows with uptime — precisely when an analyst has
//! the least patience for it.
//!
//! Folding every alert about a detection into one row keeps the queue
//! proportional to how many *things were detected*, not to how long the server
//! has been running. A year-old server watching four detections shows four
//! rows.
//!
//! The subtlety is that one alert arrives more than once. The agent restates an
//! alert at the end of a run with its final count, and delivery is
//! at-least-once, so a batch can be redelivered. Both name an alert id the row
//! already holds, and both carry that alert's *running total* — so they
//! **replace** its contribution instead of adding to it. Adding would inflate
//! the count, which is the one direction this must never be wrong in: a count
//! that is too low hides firings an analyst needed to see.

use chrono::{DateTime, Utc};
use model::Severity;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

/// How many recent alert ids a row itemises, so that a restatement of one of
/// them is recognised as a restatement rather than counted as new.
///
/// One occurrence is one alert id. The agent mints a new one each time it runs
/// and again each time the suppression window lapses, so a rule firing
/// continuously produces about twelve an hour. Sixty-four covers five hours of
/// that — far beyond any plausible retry or flush delay — while keeping a row's
/// memory flat however long the server runs.
const MAX_ITEMISED_OCCURRENCES: usize = 64;

/// What the server remembers about one enrolled host.
#[derive(Debug, Clone)]
pub struct HostRecord {
    pub host_id: String,
    pub hostname: String,
    pub os: String,
    /// SHA-256 of the token's secret half. The secret itself is never stored.
    pub secret_hash: [u8; 32],
    pub enrolled_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub events: u64,
    pub alerts: u64,
}

impl HostRecord {
    /// Whether this host has ever sent anything.
    ///
    /// Not `events > 0`: a batch can carry alerts and no events — an agent's
    /// end-of-run restatement is exactly that — and a host whose detections are
    /// arriving is not silent. Counting it as silent is the kind of number an
    /// operator chases for an afternoon.
    pub fn is_reporting(&self) -> bool {
        self.events > 0 || self.alerts > 0
    }
}

/// An alert as it arrived, before it is folded into a row.
#[derive(Debug, Clone)]
pub struct IncomingAlert {
    /// The agent's alert id: unique per occurrence, stable across restatements
    /// of that same occurrence. This is what makes folding idempotent.
    pub alert_id: String,
    /// The detection that fired. Rows are keyed on this, so it has to be
    /// stable across runs — which is why the agent derives it from the rule and
    /// not, say, from a process id that changes every event.
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    /// The agent's own account of the finding, already minimised (A19).
    pub description: String,
    pub technique: String,
    /// Firings this alert stands for, from A8 coalescing on the agent.
    pub count: u32,
}

/// One row of the alert queue: a single detection on a single host.
#[derive(Debug, Clone)]
pub struct StoredAlert {
    pub host_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    /// The most recent occurrence's description. Kept so the console can show
    /// evidence rather than only a title, which is the difference between a
    /// row an analyst can triage and one they can only acknowledge.
    pub description: String,
    pub technique: String,
    /// Total rule firings this row stands for, summed over every occurrence.
    pub firings: u64,
    /// How many separate alerts have been folded in. Always at least one.
    pub occurrences: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Outcome of one ingest call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestOutcome {
    pub accepted_events: usize,
    /// Alerts the server counted. A restatement of an alert it already holds is
    /// not a new alert, so this can be smaller than the batch's alert list.
    pub accepted_alerts: usize,
    /// The batch id had been seen before, so this was a retry and nothing was
    /// counted twice.
    pub duplicate: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub hosts: Vec<HostRecord>,
    pub alerts: Vec<StoredAlert>,
    pub total_events: u64,
    /// Distinct alert occurrences received. Independent of the retention cap,
    /// because a total that shrinks when the console forgets a row is a total
    /// nobody can quote.
    pub total_alerts: u64,
    /// Rule firings those alerts stand for. This is the number that used to be
    /// the length of the alert list.
    pub total_firings: u64,
    pub duplicate_batches: u64,
}

pub trait Store: Send + Sync {
    fn enrollment_count(&self) -> usize;
    /// Returns false when the host id is already taken, which the caller must
    /// treat as a collision rather than an update.
    fn insert_host(&self, record: HostRecord) -> bool;
    fn secret_hash(&self, host_id: &str) -> Option<[u8; 32]>;
    fn record_ingest(
        &self,
        host_id: &str,
        batch_id: &str,
        events: usize,
        alerts: Vec<IncomingAlert>,
    ) -> IngestOutcome;
    fn snapshot(&self) -> Snapshot;
}

/// What folding one alert changed, so the running totals can stay exact even
/// though rows are pruned and evicted underneath them.
#[derive(Debug, Clone, Copy)]
struct Folded {
    /// The alert id was new for this row, so this is another occurrence rather
    /// than a restatement of one already counted.
    new_occurrence: bool,
    /// Firings this alert added. Zero when a restatement repeats a count the
    /// row has already taken, which is what at-least-once delivery produces.
    added_firings: u64,
}

/// The aggregate behind one `StoredAlert`.
#[derive(Debug)]
struct Aggregate {
    host_id: String,
    rule_id: String,
    severity: Severity,
    title: String,
    description: String,
    technique: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    /// The alert ids currently itemised, oldest first, each with the count it
    /// contributed.
    recent: VecDeque<(Box<str>, u32)>,
    /// Firings and occurrences that have aged out of `recent`, kept separately
    /// so that pruning the itemised list never moves the numbers the row
    /// reports.
    retired_firings: u64,
    retired_occurrences: u32,
}

impl Aggregate {
    fn firings(&self) -> u64 {
        // Saturating throughout: these are unbounded counters fed by a client,
        // and wrapping one is worse than pinning it at the ceiling.
        self.recent
            .iter()
            .fold(self.retired_firings, |total, (_, count)| {
                total.saturating_add(u64::from(*count))
            })
    }

    fn occurrences(&self) -> u32 {
        self.retired_occurrences + self.recent.len() as u32
    }

    fn materialise(&self) -> StoredAlert {
        StoredAlert {
            host_id: self.host_id.clone(),
            rule_id: self.rule_id.clone(),
            severity: self.severity,
            title: self.title.clone(),
            description: self.description.clone(),
            technique: self.technique.clone(),
            firings: self.firings(),
            occurrences: self.occurrences(),
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        }
    }

    /// Fold one alert in, reporting what it added.
    fn absorb(&mut self, alert: IncomingAlert, now: DateTime<Utc>) -> Folded {
        self.last_seen = now;

        // Title, description and technique are functions of the rule, so
        // occurrences agree on them; the latest wins rather than any attempt to
        // merge strings. The description is the one that moves: it names the
        // action and probability of *this* firing, so an older one would describe
        // a decision that has since changed.
        if !alert.title.is_empty() {
            self.title = alert.title.clone();
        }
        if !alert.description.is_empty() {
            self.description = alert.description.clone();
        }
        if !alert.technique.is_empty() {
            self.technique = alert.technique.clone();
        }
        // Severity only rises. A detection that has been critical is not made
        // less urgent by a later, quieter firing — nobody has necessarily looked
        // at it yet — and a row that faded from red to blue on its own would be
        // worse than useless for triage.
        if alert.severity > self.severity {
            self.severity = alert.severity;
        }

        let count = alert.count.max(1);

        if let Some(slot) = self
            .recent
            .iter_mut()
            .find(|(id, _)| &**id == alert.alert_id.as_str())
        {
            // A restatement carries the running total for this occurrence, so it
            // replaces that occurrence's contribution rather than adding to it.
            // Taking the maximum also makes this idempotent when a redelivered
            // batch arrives after a newer one.
            let previous = slot.1;
            slot.1 = slot.1.max(count);
            return Folded {
                new_occurrence: false,
                added_firings: u64::from(slot.1 - previous),
            };
        }

        self.recent
            .push_back((alert.alert_id.into_boxed_str(), count));
        if self.recent.len() > MAX_ITEMISED_OCCURRENCES {
            if let Some((_, retired)) = self.recent.pop_front() {
                self.retired_firings = self.retired_firings.saturating_add(u64::from(retired));
                self.retired_occurrences = self.retired_occurrences.saturating_add(1);
            }
        }

        Folded {
            new_occurrence: true,
            added_firings: u64::from(count),
        }
    }
}

#[derive(Default)]
struct Inner {
    hosts: HashMap<String, HostRecord>,
    alerts: VecDeque<Aggregate>,
    seen_batches: HashSet<String>,
    batch_order: VecDeque<String>,
    total_events: u64,
    total_alerts: u64,
    total_firings: u64,
    duplicate_batches: u64,
}

impl Inner {
    /// Fold an arriving alert into the row for its `(host, rule)`, creating the
    /// row if this is the first alert about that detection.
    ///
    /// Matched on `(host, rule)` rather than on the alert id, because the alert
    /// id is per-occurrence: matching on it is what turned one detection into
    /// one row per firing.
    ///
    /// The scan is linear. That is deliberate for now: the deque is bounded by
    /// the console's retention cap, a batch carries few alerts, and an index
    /// would be the first thing to get wrong when this moves to a real store —
    /// where the grouping becomes a `GROUP BY` and this function goes away.
    fn fold(&mut self, host_id: &str, alert: IncomingAlert, now: DateTime<Utc>) -> Folded {
        let position = self
            .alerts
            .iter()
            .position(|row| row.host_id == host_id && row.rule_id == alert.rule_id);

        match position {
            Some(index) => self.alerts[index].absorb(alert, now),
            None => {
                let count = alert.count.max(1);
                self.alerts.push_back(Aggregate {
                    host_id: host_id.to_string(),
                    rule_id: alert.rule_id,
                    severity: alert.severity,
                    title: alert.title,
                    description: alert.description,
                    technique: alert.technique,
                    first_seen: now,
                    last_seen: now,
                    recent: VecDeque::from([(alert.alert_id.into_boxed_str(), count)]),
                    retired_firings: 0,
                    retired_occurrences: 0,
                });
                Folded {
                    new_occurrence: true,
                    added_firings: u64::from(count),
                }
            }
        }
    }

    /// Drop rows until the queue fits, least recently active first.
    ///
    /// By `last_seen` rather than by position: a detection that is still firing
    /// must not be evicted ahead of one that fired once and stopped.
    fn enforce_retention(&mut self, max_alerts: usize) {
        while self.alerts.len() > max_alerts {
            let oldest = self
                .alerts
                .iter()
                .enumerate()
                .min_by_key(|(_, row)| row.last_seen)
                .map(|(index, _)| index);
            match oldest {
                Some(index) => {
                    self.alerts.remove(index);
                }
                None => break,
            }
        }
    }
}

/// Bounded, in-memory implementation.
pub struct MemoryStore {
    inner: RwLock<Inner>,
    /// Alert rows kept for the console. The least recently active are dropped
    /// first.
    max_alerts: usize,
    /// Batch ids remembered for deduplication. Bounded because an unbounded set
    /// is a memory exhaustion vector that any enrolled host can drive.
    max_batches: usize,
}

impl MemoryStore {
    pub fn new(max_alerts: usize, max_batches: usize) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            max_alerts: max_alerts.max(1),
            max_batches: max_batches.max(1),
        }
    }

    /// Recover from a poisoned lock rather than panicking.
    ///
    /// A panic while holding this lock means some request was aborted midway.
    /// The data may be inconsistent, but refusing every subsequent request
    /// turns a single bad batch into a dead server, which is strictly worse.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(10_000, 50_000)
    }
}

impl Store for MemoryStore {
    fn enrollment_count(&self) -> usize {
        self.read().hosts.len()
    }

    fn insert_host(&self, record: HostRecord) -> bool {
        let mut inner = self.write();
        if inner.hosts.contains_key(&record.host_id) {
            return false;
        }
        inner.hosts.insert(record.host_id.clone(), record);
        true
    }

    fn secret_hash(&self, host_id: &str) -> Option<[u8; 32]> {
        self.read().hosts.get(host_id).map(|h| h.secret_hash)
    }

    fn record_ingest(
        &self,
        host_id: &str,
        batch_id: &str,
        events: usize,
        alerts: Vec<IncomingAlert>,
    ) -> IngestOutcome {
        let mut inner = self.write();

        // The host must still exist: a host removed between authentication and
        // ingest must not be able to write.
        if !inner.hosts.contains_key(host_id) {
            return IngestOutcome {
                accepted_events: 0,
                accepted_alerts: 0,
                duplicate: false,
            };
        }

        if !inner.seen_batches.insert(batch_id.to_string()) {
            inner.duplicate_batches += 1;
            return IngestOutcome {
                accepted_events: 0,
                accepted_alerts: 0,
                duplicate: true,
            };
        }
        inner.batch_order.push_back(batch_id.to_string());
        while inner.batch_order.len() > self.max_batches {
            if let Some(oldest) = inner.batch_order.pop_front() {
                inner.seen_batches.remove(&oldest);
            }
        }

        let now = Utc::now();
        // Counted, not received. The agent restates an alert at the end of a run
        // so the server can pick up its final count, and that message is not
        // another alert: reporting it as one would contradict both the console's
        // alert total and the host's own row.
        let mut accepted_alerts = 0usize;
        for alert in alerts {
            let folded = inner.fold(host_id, alert, now);
            if folded.new_occurrence {
                accepted_alerts += 1;
                inner.total_alerts = inner.total_alerts.saturating_add(1);
            }
            inner.total_firings = inner.total_firings.saturating_add(folded.added_firings);
        }
        inner.enforce_retention(self.max_alerts);

        inner.total_events = inner.total_events.saturating_add(events as u64);

        if let Some(host) = inner.hosts.get_mut(host_id) {
            host.last_seen = now;
            host.events = host.events.saturating_add(events as u64);
            host.alerts = host.alerts.saturating_add(accepted_alerts as u64);
        }

        IngestOutcome {
            accepted_events: events,
            accepted_alerts,
            duplicate: false,
        }
    }

    fn snapshot(&self) -> Snapshot {
        let inner = self.read();

        let mut hosts: Vec<HostRecord> = inner.hosts.values().cloned().collect();
        // Most recently seen first: the console is for looking at what is
        // happening now, not at what happened when the service started.
        hosts.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.host_id.cmp(&b.host_id))
        });

        let mut alerts: Vec<StoredAlert> =
            inner.alerts.iter().map(Aggregate::materialise).collect();
        // Most recently active first, with a tie-break so two rows that fired in
        // the same instant cannot swap places between refreshes.
        alerts.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.host_id.cmp(&b.host_id))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        Snapshot {
            hosts,
            alerts,
            total_events: inner.total_events,
            total_alerts: inner.total_alerts,
            total_firings: inner.total_firings,
            duplicate_batches: inner.duplicate_batches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(host_id: &str) -> HostRecord {
        HostRecord {
            host_id: host_id.to_string(),
            hostname: format!("host-{host_id}"),
            os: "windows".to_string(),
            secret_hash: [7u8; 32],
            enrolled_at: Utc::now(),
            last_seen: Utc::now(),
            events: 0,
            alerts: 0,
        }
    }

    #[test]
    fn a_host_that_only_sent_alerts_is_still_reporting() {
        // A restatement carries alerts and no events, so keying "reporting" off
        // the event count calls an active host silent.
        let mut enrolled_only = record("a");
        assert!(!enrolled_only.is_reporting(), "enrolled but never sent");

        enrolled_only.alerts = 3;
        assert!(enrolled_only.is_reporting(), "alerts are reporting");

        let mut events_only = record("b");
        events_only.events = 1;
        assert!(events_only.is_reporting(), "events are reporting");
    }

    fn alert(rule: &str, id: &str) -> IncomingAlert {
        IncomingAlert {
            alert_id: id.to_string(),
            rule_id: rule.to_string(),
            severity: Severity::High,
            title: format!("title for {rule}"),
            description: format!("description for {rule}"),
            technique: "T1059.001".to_string(),
            count: 1,
        }
    }

    #[test]
    fn the_latest_occurrence_supplies_the_description() {
        // The description names the action and probability of one firing, so a
        // row that kept the first one would describe a decision that has since
        // changed. The console shows it as the evidence for the row.
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let mut first = alert("R1", "a-1");
        first.description = "raise alert (p=0.10, n=1)".into();
        store.record_ingest("a", "a-1", 0, vec![first]);

        let mut later = alert("R1", "a-2");
        later.description = "isolate host (p=0.99, n=40)".into();
        store.record_ingest("a", "a-2", 0, vec![later]);

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 1, "same detection, same row");
        assert_eq!(
            snapshot.alerts[0].description, "isolate host (p=0.99, n=40)",
            "the evidence must describe the most recent firing"
        );
    }

    #[test]
    fn host_ids_are_claimed_once() {
        let store = MemoryStore::default();
        assert!(store.insert_host(record("a")));
        assert!(
            !store.insert_host(record("a")),
            "the same id is not reusable"
        );
        assert_eq!(store.enrollment_count(), 1);
        assert!(store.insert_host(record("b")));
        assert_eq!(store.enrollment_count(), 2);
    }

    #[test]
    fn only_the_hash_is_retrievable() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));
        assert_eq!(store.secret_hash("a"), Some([7u8; 32]));
        assert_eq!(store.secret_hash("missing"), None);
    }

    #[test]
    fn ingest_counts_once_and_deduplicates_retries() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let first = store.record_ingest("a", "a-000000000001", 5, vec![alert("R1", "a-1")]);
        assert_eq!(
            first,
            IngestOutcome {
                accepted_events: 5,
                accepted_alerts: 1,
                duplicate: false
            }
        );

        // The client retried the same batch: nothing is counted twice.
        let retry = store.record_ingest("a", "a-000000000001", 5, vec![alert("R1", "a-1")]);
        assert!(retry.duplicate);
        assert_eq!(retry.accepted_events, 0);

        let snapshot = store.snapshot();
        assert_eq!(snapshot.total_events, 5, "the retry must not double-count");
        assert_eq!(snapshot.total_alerts, 1);
        assert_eq!(snapshot.total_firings, 1);
        assert_eq!(snapshot.duplicate_batches, 1);
        assert_eq!(snapshot.hosts[0].events, 5);
    }

    #[test]
    fn a_restatement_updates_its_row_rather_than_adding_one() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let mut first = alert("T1547.001", "run1-1");
        first.count = 1;
        let outcome = store.record_ingest("a", "a-1", 0, vec![first]);
        assert_eq!(outcome.accepted_alerts, 1);
        assert_eq!(store.snapshot().alerts.len(), 1);

        // The agent flushed: same id, larger count. It must update, not append,
        // and the count must be replaced rather than added to.
        let mut flushed = alert("T1547.001", "run1-1");
        flushed.count = 53;
        let succeeded = store.record_ingest("a", "a-2", 0, vec![flushed]);
        assert_eq!(
            succeeded.accepted_alerts, 0,
            "a restatement is not a new alert"
        );

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 1, "one row, not two");
        assert_eq!(
            snapshot.alerts[0].firings, 53,
            "a restatement is the running total, not an increment"
        );
        assert_eq!(
            snapshot.alerts[0].occurrences, 1,
            "a restatement is the same occurrence"
        );
        assert_eq!(snapshot.total_alerts, 1);
        assert_eq!(snapshot.total_firings, 53, "not 1 + 53");

        // The same restatement again, as at-least-once delivery allows. Neither
        // total may move, or a retrying agent would inflate the count.
        let mut again = alert("T1547.001", "run1-1");
        again.count = 53;
        store.record_ingest("a", "a-3", 0, vec![again]);
        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts[0].firings, 53);
        assert_eq!(snapshot.total_firings, 53);
    }

    #[test]
    fn the_same_detection_in_a_later_run_is_the_same_row_with_more_firings() {
        // The headline property. An agent restarted against the same activity
        // mints fresh alert ids, and the queue must not grow a row for each run
        // — that is the wall of duplicates, arriving slowly.
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let mut run_one = alert("T1547.001", "run1-7");
        run_one.count = 30;
        store.record_ingest("a", "a-1", 0, vec![run_one]);

        let mut run_two = alert("T1547.001", "run2-1");
        run_two.count = 30;
        store.record_ingest("a", "a-2", 0, vec![run_two]);

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 1, "one detection is one row");
        assert_eq!(snapshot.alerts[0].firings, 60, "firings accumulate");
        assert_eq!(
            snapshot.alerts[0].occurrences, 2,
            "but the row says it came from two alerts"
        );
        assert_eq!(snapshot.total_alerts, 2);
        assert_eq!(snapshot.total_firings, 60);
    }

    #[test]
    fn distinct_detections_stay_separate_rows() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));
        store.record_ingest("a", "a-1", 0, vec![alert("R1", "a-1")]);
        store.record_ingest("a", "a-2", 0, vec![alert("R2", "a-2")]);
        assert_eq!(store.snapshot().alerts.len(), 2);
    }

    #[test]
    fn the_same_detection_on_two_hosts_stays_two_rows() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));
        store.insert_host(record("b"));
        store.record_ingest("a", "a-1", 0, vec![alert("R1", "a-1")]);
        store.record_ingest("b", "b-1", 0, vec![alert("R1", "b-1")]);
        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 2, "rows are per host");
        assert_eq!(snapshot.total_firings, 2);
    }

    #[test]
    fn severity_only_rises_within_a_row() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let mut loud = alert("R1", "a-1");
        loud.severity = Severity::Critical;
        store.record_ingest("a", "a-1", 0, vec![loud]);

        // A later, quieter firing must not repaint a critical row as low: the
        // analyst may not have looked at it yet.
        let mut quiet = alert("R1", "a-2");
        quiet.severity = Severity::Low;
        store.record_ingest("a", "a-2", 0, vec![quiet]);

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 1);
        assert_eq!(snapshot.alerts[0].severity, Severity::Critical);
        assert_eq!(snapshot.alerts[0].occurrences, 2);
    }

    #[test]
    fn an_older_redelivery_cannot_lower_a_count() {
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let mut newer = alert("R1", "a-1");
        newer.count = 80;
        store.record_ingest("a", "a-1", 0, vec![newer]);

        // A batch held up in a retry queue arrives carrying its older, smaller
        // running total. It must not undo what is already known.
        let mut older = alert("R1", "a-1");
        older.count = 12;
        store.record_ingest("a", "a-2", 0, vec![older]);

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts[0].firings, 80);
        assert_eq!(snapshot.total_firings, 80);
    }

    #[test]
    fn an_unknown_host_cannot_write() {
        let store = MemoryStore::default();
        let outcome = store.record_ingest("ghost", "g-1", 10, vec![]);
        assert_eq!(outcome.accepted_events, 0);
        assert_eq!(store.snapshot().total_events, 0);
    }

    #[test]
    fn the_seen_batch_set_is_bounded() {
        let store = MemoryStore::new(16, 4);
        store.insert_host(record("a"));
        for i in 0..10 {
            store.record_ingest("a", &format!("a-{i}"), 1, vec![]);
        }
        // Only the most recent four ids are remembered, so the earliest is
        // treated as new again. That is the intended trade: bounded memory at
        // the cost of a very old retry being counted twice.
        let outcome = store.record_ingest("a", "a-0", 1, vec![]);
        assert!(!outcome.duplicate, "evicted ids are forgotten");
        // The newest is still remembered.
        let outcome = store.record_ingest("a", "a-9", 1, vec![]);
        assert!(outcome.duplicate);
    }

    #[test]
    fn rows_are_capped_and_evict_the_least_recently_active() {
        let store = MemoryStore::new(3, 64);
        store.insert_host(record("a"));
        for i in 0..6 {
            store.record_ingest(
                "a",
                &format!("a-{i}"),
                0,
                vec![alert(&format!("R{i}"), "x")],
            );
        }

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 3);
        assert_eq!(snapshot.alerts[0].rule_id, "R5", "newest activity first");
        assert_eq!(snapshot.alerts[2].rule_id, "R3");
        assert!(
            !snapshot.alerts.iter().any(|row| row.rule_id == "R0"),
            "the least recently active row is the one dropped"
        );
        // Retention bounds the console, not the ledger.
        assert_eq!(snapshot.total_alerts, 6);
        assert_eq!(snapshot.total_firings, 6);
    }

    #[test]
    fn a_row_keeps_reporting_firings_it_no_longer_itemises() {
        // The itemised occurrence list is pruned so that a long-lived row cannot
        // grow without bound. Pruning must move an occurrence into the row's
        // totals, not out of them: the firings happened either way.
        let store = MemoryStore::default();
        store.insert_host(record("a"));

        let mut first = alert("R1", "id-0");
        first.count = 5;
        store.record_ingest("a", "b-0", 0, vec![first]);

        // Enough further occurrences to push the first one out of the itemised
        // list and then keep going.
        let extra = MAX_ITEMISED_OCCURRENCES + 3;
        for i in 1..=extra {
            let alert = alert("R1", &format!("id-{i}"));
            store.record_ingest("a", &format!("b-{i}"), 0, vec![alert]);
        }

        let snapshot = store.snapshot();
        assert_eq!(snapshot.alerts.len(), 1, "still one detection");
        assert_eq!(
            snapshot.alerts[0].occurrences as usize,
            1 + extra,
            "every occurrence is still counted"
        );
        assert_eq!(
            snapshot.alerts[0].firings,
            5 + extra as u64,
            "a retired occurrence's firings survive its pruning"
        );

        let inner = store.read();
        assert_eq!(
            inner.alerts[0].recent.len(),
            MAX_ITEMISED_OCCURRENCES,
            "the itemised list is held at its cap"
        );
        assert_eq!(
            inner.alerts[0].retired_occurrences as usize,
            1 + extra - MAX_ITEMISED_OCCURRENCES,
            "the rest are retired, not discarded"
        );
    }

    #[test]
    fn hosts_are_listed_most_recently_seen_first() {
        let store = MemoryStore::default();
        let mut old = record("old");
        old.last_seen = Utc::now() - chrono::Duration::hours(2);
        let mut new = record("new");
        new.last_seen = Utc::now();
        store.insert_host(old);
        store.insert_host(new);

        let snapshot = store.snapshot();
        assert_eq!(snapshot.hosts[0].host_id, "new");
        assert_eq!(snapshot.hosts[1].host_id, "old");
    }
}
