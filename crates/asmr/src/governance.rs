//! Implements A12 (Governance and Policy).
//!
//! Formal objects: the autonomy lattice `Observe < Alert < Approve < Auto`, the
//! severity scale, action requests with reversibility and blast radius, the
//! policy `(max_auto, require_reversible)`, and the resulting verdict relation
//! `govern : ActionRequest x AutonomyLevel x Policy -> Verdict`.
//!
//! In a SIEM/XDR pipeline this crate is the brake: every response the detection
//! loop proposes passes through it before execution, disruptive actions are
//! escalated when they exceed policy or cannot be undone, and each verdict is
//! written to an append-only audit log with the exact reason it was reached.
#![forbid(unsafe_code)]

/// How much authority the deployment has granted the automated responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomyLevel {
    /// Passive collection only.
    Observe,
    /// May raise alerts, never disrupt.
    Alert,
    /// May propose disruptive actions for human sign-off.
    Approve,
    /// May execute disruptive actions within policy.
    Auto,
}

impl AutonomyLevel {
    /// Position on the autonomy lattice, `Observe = 0` through `Auto = 3`.
    pub fn rank(&self) -> u8 {
        match self {
            AutonomyLevel::Observe => 0,
            AutonomyLevel::Alert => 1,
            AutonomyLevel::Approve => 2,
            AutonomyLevel::Auto => 3,
        }
    }

    /// True when this level is at least as permissive as the required level.
    pub fn permits(&self, required: AutonomyLevel) -> bool {
        self.rank() >= required.rank()
    }
}

/// Impact scale used to bound what may run without a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Purely informational.
    Info,
    /// Minor impact.
    Low,
    /// Moderate impact.
    Medium,
    /// Significant impact on a host or user.
    High,
    /// Broad or destructive impact.
    Critical,
}

impl Severity {
    /// Position on the severity scale, `Info = 0` through `Critical = 4`.
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// Deployment policy bounding automatic disruptive action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernancePolicy {
    /// Highest severity the `Auto` level may execute unattended.
    pub max_auto: Severity,
    /// When true, only reversible actions may run unattended.
    pub require_reversible: bool,
}

impl Default for GovernancePolicy {
    fn default() -> Self {
        Self {
            max_auto: Severity::Medium,
            require_reversible: true,
        }
    }
}

/// Outcome of the governance check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Execute immediately.
    Auto,
    /// Escalate to a human operator.
    RequiresApproval,
    /// Refuse; the autonomy level does not allow this at all.
    Denied,
}

/// A proposed response action.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequest {
    /// Action identifier, e.g. `kill_process`.
    pub name: Box<str>,
    /// Estimated impact if it fires.
    pub severity: Severity,
    /// Whether the action can be undone.
    pub reversible: bool,
    /// Number of entities affected.
    pub blast_radius: u32,
    /// Whether the action interferes at all; enrichment never does.
    pub disruptive: bool,
}

/// Runs the A12 policy check and returns both verdict and the branch reason.
fn evaluate(
    req: &ActionRequest,
    level: AutonomyLevel,
    policy: &GovernancePolicy,
) -> (Verdict, &'static str) {
    if !req.disruptive {
        return (Verdict::Auto, "not disruptive");
    }
    match level {
        AutonomyLevel::Observe | AutonomyLevel::Alert => (Verdict::Denied, "observe-only autonomy"),
        AutonomyLevel::Approve => (Verdict::RequiresApproval, "approval autonomy level"),
        AutonomyLevel::Auto => {
            if req.severity.rank() > policy.max_auto.rank() {
                (Verdict::RequiresApproval, "exceeds max_auto severity")
            } else if policy.require_reversible && !req.reversible {
                (
                    Verdict::RequiresApproval,
                    "irreversible action requires approval",
                )
            } else {
                (Verdict::Auto, "within policy")
            }
        }
    }
}

/// Decides whether an action may run, be escalated, or be refused.
pub fn govern(req: &ActionRequest, level: AutonomyLevel, policy: &GovernancePolicy) -> Verdict {
    evaluate(req, level, policy).0
}

/// One immutable audit record of a governance decision.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    /// Decision time in nanoseconds since the epoch.
    pub ts_ns: i64,
    /// Name of the proposed action.
    pub action: Box<str>,
    /// Verdict that was issued.
    pub verdict: Verdict,
    /// The exact branch that produced the verdict.
    pub reason: &'static str,
}

/// Append-only record of governance decisions.
#[derive(Debug, Clone)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Creates an empty log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Evaluates a request and appends exactly one entry, returning the verdict.
    pub fn record(
        &mut self,
        ts_ns: i64,
        req: &ActionRequest,
        level: AutonomyLevel,
        policy: &GovernancePolicy,
    ) -> Verdict {
        let (verdict, reason) = evaluate(req, level, policy);
        self.entries.push(AuditEntry {
            ts_ns,
            action: req.name.clone(),
            verdict,
            reason,
        });
        verdict
    }

    /// All recorded entries in chronological insertion order.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Number of recorded decisions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(sev: Severity, reversible: bool, disruptive: bool) -> ActionRequest {
        ActionRequest {
            name: "kill_process".into(),
            severity: sev,
            reversible,
            blast_radius: 1,
            disruptive,
        }
    }

    #[test]
    fn ranks_are_totally_ordered_and_permits_is_monotone() {
        assert!(AutonomyLevel::Auto.rank() > AutonomyLevel::Approve.rank());
        assert!(AutonomyLevel::Approve.rank() > AutonomyLevel::Alert.rank());
        assert!(AutonomyLevel::Alert.rank() > AutonomyLevel::Observe.rank());
        assert!(AutonomyLevel::Auto.permits(AutonomyLevel::Observe));
        assert!(AutonomyLevel::Approve.permits(AutonomyLevel::Approve));
        assert!(!AutonomyLevel::Alert.permits(AutonomyLevel::Approve));
        assert_eq!(Severity::Info.rank(), 0);
        assert_eq!(Severity::Critical.rank(), 4);
        assert!(Severity::High.rank() > Severity::Medium.rank());
    }

    #[test]
    fn non_disruptive_actions_never_need_authority() {
        let p = GovernancePolicy::default();
        let r = req(Severity::Critical, false, false);
        assert_eq!(govern(&r, AutonomyLevel::Observe, &p), Verdict::Auto);
        assert_eq!(govern(&r, AutonomyLevel::Alert, &p), Verdict::Auto);
        assert_eq!(govern(&r, AutonomyLevel::Auto, &p), Verdict::Auto);
    }

    #[test]
    fn disruptive_actions_follow_the_autonomy_ladder() {
        let p = GovernancePolicy::default();
        let r = req(Severity::High, true, true);
        assert_eq!(govern(&r, AutonomyLevel::Observe, &p), Verdict::Denied);
        assert_eq!(govern(&r, AutonomyLevel::Alert, &p), Verdict::Denied);
        assert_eq!(
            govern(&r, AutonomyLevel::Approve, &p),
            Verdict::RequiresApproval
        );
        // High exceeds the default max_auto of Medium.
        assert_eq!(
            govern(&r, AutonomyLevel::Auto, &p),
            Verdict::RequiresApproval
        );
    }

    #[test]
    fn auto_level_gates_on_severity_then_reversibility() {
        let p = GovernancePolicy::default();
        assert_eq!(
            govern(&req(Severity::Medium, true, true), AutonomyLevel::Auto, &p),
            Verdict::Auto
        );
        assert_eq!(
            govern(&req(Severity::High, true, true), AutonomyLevel::Auto, &p),
            Verdict::RequiresApproval
        );
        assert_eq!(
            govern(&req(Severity::Low, false, true), AutonomyLevel::Auto, &p),
            Verdict::RequiresApproval
        );
        let lax = GovernancePolicy {
            max_auto: Severity::Critical,
            require_reversible: false,
        };
        assert_eq!(
            govern(
                &req(Severity::Critical, false, true),
                AutonomyLevel::Auto,
                &lax
            ),
            Verdict::Auto
        );
    }

    #[test]
    fn audit_log_appends_one_entry_per_call_with_branch_reason() {
        let p = GovernancePolicy::default();
        let mut log = AuditLog::new();
        assert!(log.is_empty());

        let benign = ActionRequest {
            name: "enrich_entity".into(),
            severity: Severity::Info,
            reversible: true,
            blast_radius: 0,
            disruptive: false,
        };
        assert_eq!(
            log.record(1, &benign, AutonomyLevel::Observe, &p),
            Verdict::Auto
        );
        assert_eq!(log.entries()[0].reason, "not disruptive");
        assert_eq!(log.entries()[0].action.as_ref(), "enrich_entity");

        assert_eq!(
            log.record(2, &req(Severity::High, true, true), AutonomyLevel::Auto, &p),
            Verdict::RequiresApproval
        );
        assert_eq!(log.entries()[1].reason, "exceeds max_auto severity");

        assert_eq!(
            log.record(3, &req(Severity::Low, false, true), AutonomyLevel::Auto, &p),
            Verdict::RequiresApproval
        );
        assert_eq!(
            log.entries()[2].reason,
            "irreversible action requires approval"
        );

        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[0].ts_ns, 1);
        assert_eq!(log.entries()[2].ts_ns, 3);
    }

    #[test]
    fn audit_log_keeps_denied_and_within_policy_reasons() {
        let p = GovernancePolicy::default();
        let mut log = AuditLog::new();
        let r = req(Severity::Low, true, true);
        log.record(5, &r, AutonomyLevel::Observe, &p);
        log.record(6, &r, AutonomyLevel::Auto, &p);
        assert_eq!(log.entries()[0].verdict, Verdict::Denied);
        assert_eq!(log.entries()[0].reason, "observe-only autonomy");
        assert_eq!(log.entries()[1].verdict, Verdict::Auto);
        assert_eq!(log.entries()[1].reason, "within policy");
    }
}
