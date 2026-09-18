//! Implements A6 (Actions), A27 (Compensating Controls) and A30 (Freeze and Isolate).
//!
//! The formal object is the *action space*: the set of interventions a defender
//! may apply to the state, each carrying a severity, a reversibility flag and a
//! blast radius. A detection pipeline needs this as a separate layer from
//! deciding whether something is malicious: finding an intrusion and being
//! allowed to isolate a production server are different questions, and a system
//! that conflates them will either under-respond or take down the business.
//!
//! A27 adds controls that compensate for a gap that has no patch yet. A30 is
//! the far end of the ladder: freeze, then isolate, both irreversible in
//! practice because they sever in-flight work.
#![forbid(unsafe_code)]

/// Identifies a registered action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId(pub u32);

/// What kind of intervention an action is, ordered by how far it escalates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Observe,
    Enrich,
    Alert,
    CompensatingControl,
    Freeze,
    Isolate,
    Rollback,
}

impl ActionKind {
    /// Position on the escalation ladder. Used to order the ladder, never to
    /// compare severity — a `Freeze` with severity 2 is still above an `Alert`
    /// with severity 5, because the ordering that matters is what it does to
    /// the state.
    pub fn rank(&self) -> u8 {
        match self {
            ActionKind::Observe => 0,
            ActionKind::Enrich => 1,
            ActionKind::Alert => 2,
            ActionKind::CompensatingControl => 3,
            ActionKind::Freeze => 4,
            ActionKind::Isolate => 5,
            ActionKind::Rollback => 6,
        }
    }

    /// Whether this kind changes the observed system. Alerting does not.
    pub fn disruptive(&self) -> bool {
        matches!(
            self,
            ActionKind::CompensatingControl
                | ActionKind::Freeze
                | ActionKind::Isolate
                | ActionKind::Rollback
        )
    }
}

/// One intervention available to the defender.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    pub id: ActionId,
    pub name: Box<str>,
    pub kind: ActionKind,
    pub severity: u8,
    pub reversible: bool,
    pub blast_radius: u32,
    pub duration_s: u64,
}

impl Action {
    pub fn new(
        id: ActionId,
        name: &str,
        kind: ActionKind,
        severity: u8,
        reversible: bool,
        blast_radius: u32,
        duration_s: u64,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            severity: severity.clamp(1, 5),
            reversible,
            blast_radius,
            duration_s,
        }
    }
}

/// The set of actions the defender may choose from.
#[derive(Debug, Clone, Default)]
pub struct ActionSpace {
    actions: Vec<Action>,
}

impl ActionSpace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, a: Action) -> ActionId {
        let id = a.id;
        self.actions.push(a);
        id
    }

    pub fn get(&self, id: ActionId) -> Option<&Action> {
        self.actions.iter().find(|a| a.id == id)
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Actions this environment is permitted to take: severity within the cap,
    /// and reversible if the caller cannot accept a one-way door.
    pub fn admissible(&self, max_severity: u8, require_reversible: bool) -> Vec<ActionId> {
        self.actions
            .iter()
            .filter(|a| a.severity <= max_severity && (!require_reversible || a.reversible))
            .map(|a| a.id)
            .collect()
    }

    /// A30: the ordered ladder from watching to isolating. Walking this list is
    /// how a response escalates without jumping straight to the most
    /// destructive option available.
    pub fn escalation_ladder(&self) -> Vec<ActionId> {
        let mut v: Vec<&Action> = self.actions.iter().collect();
        v.sort_by_key(|a| (a.kind.rank(), a.severity));
        v.iter().map(|a| a.id).collect()
    }
}

/// A27: a control that reduces exposure to a gap that cannot be patched yet.
#[derive(Debug, Clone, PartialEq)]
pub struct CompensatingControl {
    pub gap: Box<str>,
    pub control: Box<str>,
    pub coverage: f64,
}

impl CompensatingControl {
    pub fn new(gap: &str, control: &str, coverage: f64) -> Self {
        Self {
            gap: gap.into(),
            control: control.into(),
            coverage: coverage.clamp(0.0, 1.0),
        }
    }
}

/// A27: the exposure that survives the control. Note that coverage is a claim
/// about the control, not a measurement of it — treat it as an upper bound on
/// protection, which is why this floors at 0 rather than going negative.
pub fn residual_risk(gap_severity: f64, coverage: f64) -> f64 {
    gap_severity.max(0.0) * (1.0 - coverage.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space() -> ActionSpace {
        let mut s = ActionSpace::new();
        s.register(Action::new(
            ActionId(1),
            "observe",
            ActionKind::Observe,
            1,
            true,
            1,
            0,
        ));
        s.register(Action::new(
            ActionId(2),
            "alert",
            ActionKind::Alert,
            2,
            true,
            1,
            0,
        ));
        s.register(Action::new(
            ActionId(3),
            "block ip",
            ActionKind::CompensatingControl,
            3,
            true,
            5,
            60,
        ));
        s.register(Action::new(
            ActionId(4),
            "freeze process",
            ActionKind::Freeze,
            4,
            true,
            1,
            0,
        ));
        s.register(Action::new(
            ActionId(5),
            "isolate host",
            ActionKind::Isolate,
            5,
            false,
            500,
            900,
        ));
        s
    }

    #[test]
    fn severity_is_clamped_on_construction() {
        let a = Action::new(ActionId(1), "x", ActionKind::Isolate, 99, false, 1, 0);
        assert_eq!(a.severity, 5);
        let b = Action::new(ActionId(2), "y", ActionKind::Observe, 0, true, 1, 0);
        assert_eq!(b.severity, 1);
    }

    #[test]
    fn admissible_respects_severity_and_reversibility() {
        let s = space();
        assert_eq!(s.admissible(2, false), vec![ActionId(1), ActionId(2)]);
        // Isolate is severity 5 and irreversible, so either filter excludes it.
        assert!(!s.admissible(5, true).contains(&ActionId(5)));
        assert!(s.admissible(5, false).contains(&ActionId(5)));
    }

    #[test]
    fn escalation_ladder_is_ordered_by_kind_then_severity() {
        let s = space();
        assert_eq!(
            s.escalation_ladder(),
            vec![
                ActionId(1),
                ActionId(2),
                ActionId(3),
                ActionId(4),
                ActionId(5)
            ]
        );
    }

    #[test]
    fn disruptive_covers_exactly_the_state_changing_kinds() {
        assert!(!ActionKind::Observe.disruptive());
        assert!(!ActionKind::Enrich.disruptive());
        assert!(!ActionKind::Alert.disruptive());
        assert!(ActionKind::CompensatingControl.disruptive());
        assert!(ActionKind::Freeze.disruptive());
        assert!(ActionKind::Isolate.disruptive());
        assert!(ActionKind::Rollback.disruptive());
    }

    #[test]
    fn residual_risk_is_bounded_by_gap_severity() {
        assert_eq!(residual_risk(8.0, 1.0), 0.0);
        assert_eq!(residual_risk(8.0, 0.0), 8.0);
        assert_eq!(residual_risk(8.0, 0.75), 2.0);
        // Coverage claims beyond 100% must not create negative risk.
        assert_eq!(residual_risk(8.0, 2.0), 0.0);
        assert_eq!(residual_risk(-1.0, 0.5), 0.0);
    }

    #[test]
    fn control_coverage_is_clamped() {
        assert_eq!(CompensatingControl::new("g", "c", 2.0).coverage, 1.0);
        assert_eq!(CompensatingControl::new("g", "c", -1.0).coverage, 0.0);
    }
}
