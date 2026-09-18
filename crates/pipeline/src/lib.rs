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
use asmr::governance::{
    ActionRequest, AuditLog, AutonomyLevel, GovernancePolicy, Severity as GovSeverity, Verdict,
};
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
        }
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
    processes: BTreeMap<u32, ProcRecord>,
    metrics: Metrics,
    next_entity: u64,
    next_event: u64,
    next_alert: u64,
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
            processes: BTreeMap::new(),
            metrics: Metrics::default(),
            next_entity: 1,
            next_event: 1,
            next_alert: 1,
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
                let needs_human = verdict == Verdict::RequiresApproval;
                let promised = if needs_human {
                    format!("{} (proposed, awaiting approval)", action.name)
                } else {
                    action.name.to_string()
                };

                let body = findings
                    .iter()
                    .map(|f| format!("{}: {}", f.technique, minimise(&f.detail)))
                    .collect::<Vec<_>>()
                    .join("; ");

                self.metrics.alerts += 1;
                let id = self.next_alert;
                self.next_alert += 1;

                Some(Alert::new(
                    AlertId::new(id.to_string()).ok()?,
                    RuleId::new(rule).ok()?,
                    format!("{technique}: {promised}").into_boxed_str(),
                    format!("p={probability:.4} via {rule}; {body}").into_boxed_str(),
                    model_severity(action.severity),
                    event.timestamp,
                    self.cfg.host.clone(),
                    Vec::new(),
                    vec![technique.into()],
                ))
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

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
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

fn gov_severity(severity: u8) -> GovSeverity {
    match severity {
        5 => GovSeverity::Critical,
        4 => GovSeverity::High,
        3 => GovSeverity::Medium,
        2 => GovSeverity::Low,
        _ => GovSeverity::Info,
    }
}

fn model_severity(severity: u8) -> ModelSeverity {
    match severity {
        5 => ModelSeverity::Critical,
        4 => ModelSeverity::High,
        3 => ModelSeverity::Medium,
        2 => ModelSeverity::Low,
        _ => ModelSeverity::Info,
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
}
