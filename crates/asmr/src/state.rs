//! Implements A1 (State Space) and A21 (Open State Space).
//!
//! Formal objects: the state space `S` of typed entities, the projection
//! `pi : S -> Kind x Label`, its fibers `pi^-1(kind, label)`, and the residual
//! gap between the nominal universe and the observed subset.
//!
//! In a SIEM/XDR pipeline this is the entity inventory: the ETW sensor upserts
//! entities as they appear, detectors query them by kind, and A21 keeps the
//! universe explicitly open so an unseen entity is never assumed benign.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// Stable handle for an entity within the state space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityId(pub u64);

/// The A1 type tag; the first component of the projection's codomain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntityKind {
    /// Executing image or process instance.
    Process,
    /// File or directory object.
    File,
    /// Registry key, a common Windows persistence surface.
    RegistryKey,
    /// Local or remote network endpoint.
    NetworkEndpoint,
    /// Loaded module or driver.
    Module,
    /// User account, local or directory.
    User,
    /// Host machine.
    Host,
    /// Anything the sensor reports that does not fit above.
    Other,
}

/// A typed attribute value covering identifiers, text, and booleans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    /// Numeric attribute such as pid, size, or exit code.
    Int(i64),
    /// Free text attribute such as a path, SID, hash, or command line.
    Text(Box<str>),
    /// Boolean attribute such as `is_elevated`.
    Flag(bool),
}

/// One member of the A1 state space.
#[derive(Debug, Clone, PartialEq)]
pub struct Entity {
    /// Stable identity; the map key.
    pub id: EntityId,
    /// Type tag used by projections.
    pub kind: EntityKind,
    /// Human-readable label, e.g. `lsass.exe` or `HKLM\\...\\Run`.
    pub label: Box<str>,
    /// First observation time in nanoseconds since the epoch.
    pub first_seen_ns: i64,
    /// Most recent observation time in nanoseconds since the epoch.
    pub last_seen_ns: i64,
    /// Typed attributes; `BTreeMap` keeps iteration deterministic.
    pub attrs: BTreeMap<Box<str>, AttrValue>,
}

/// The A1 state space: a finite but open set of entities keyed by id.
#[derive(Debug, Clone)]
pub struct StateSpace {
    entities: BTreeMap<EntityId, Entity>,
}

impl StateSpace {
    /// Creates the empty state space.
    pub fn new() -> Self {
        Self {
            entities: BTreeMap::new(),
        }
    }

    /// Idempotent upsert. Refreshes `last_seen_ns` always; returns true only the
    /// first time this entity is seen (A21: the universe grows with observation).
    pub fn observe(&mut self, e: Entity) -> bool {
        match self.entities.get_mut(&e.id) {
            // `first_seen_ns` is deliberately preserved: history is immutable.
            Some(existing) => {
                existing.last_seen_ns = e.last_seen_ns;
                false
            }
            None => {
                self.entities.insert(e.id, e);
                true
            }
        }
    }

    /// Borrows an entity by id.
    pub fn get(&self, id: EntityId) -> Option<&Entity> {
        self.entities.get(&id)
    }

    /// Mutably borrows an entity by id.
    pub fn get_mut(&mut self, id: EntityId) -> Option<&mut Entity> {
        self.entities.get_mut(&id)
    }

    /// Number of known entities.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// True when nothing has been observed yet.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Ids of every entity of a given kind, in ascending id order.
    pub fn by_kind(&self, kind: EntityKind) -> Vec<EntityId> {
        self.entities
            .iter()
            .filter(|(_, e)| e.kind == kind)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Sets an attribute. Returns false when the entity is unknown, so callers
    /// can distinguish "attribute added" from "no such entity".
    pub fn set_attr(&mut self, id: EntityId, key: &str, v: AttrValue) -> bool {
        match self.entities.get_mut(&id) {
            Some(e) => {
                e.attrs.insert(key.into(), v);
                true
            }
            None => false,
        }
    }

    /// Reads an attribute, if both the entity and the key exist.
    pub fn attr(&self, id: EntityId, key: &str) -> Option<&AttrValue> {
        self.entities.get(&id)?.attrs.get(key)
    }
}

impl Default for StateSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// The A1 projection `pi` and the fibers it induces.
pub struct Projection;

impl Projection {
    /// The image `pi(s)` for a fixed kind.
    pub fn by_kind(s: &StateSpace, kind: EntityKind) -> BTreeSet<EntityId> {
        s.entities
            .iter()
            .filter(|(_, e)| e.kind == kind)
            .map(|(id, _)| *id)
            .collect()
    }

    /// The fiber `pi^-1(kind, label)`: every entity mapping to that pair.
    pub fn fiber(s: &StateSpace, kind: EntityKind, label: &str) -> BTreeSet<EntityId> {
        s.entities
            .iter()
            .filter(|(_, e)| e.kind == kind && &*e.label == label)
            .map(|(id, _)| *id)
            .collect()
    }
}

/// The A21 observation gap between nominal and observed universes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StateGap {
    /// Size of the nominal universe (what could exist).
    pub universe: usize,
    /// Size of the observed subset (what has been seen).
    pub observed: usize,
}

impl StateGap {
    /// Records a pair of universe sizes.
    pub fn new(universe: usize, observed: usize) -> Self {
        Self { universe, observed }
    }

    /// Entities that exist in the nominal universe but were never observed.
    pub fn gap(&self) -> usize {
        self.universe.saturating_sub(self.observed)
    }

    /// Observed fraction of the universe; 1.0 when the universe is empty.
    pub fn coverage(&self) -> f64 {
        if self.universe == 0 {
            1.0
        } else {
            (self.observed as f64 / self.universe as f64).clamp(0.0, 1.0)
        }
    }

    /// A21: the state space is never closed, however good coverage looks.
    pub fn is_open(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(id: u64, kind: EntityKind, label: &str, ts: i64) -> Entity {
        Entity {
            id: EntityId(id),
            kind,
            label: label.into(),
            first_seen_ns: ts,
            last_seen_ns: ts,
            attrs: BTreeMap::new(),
        }
    }

    #[test]
    fn observe_is_idempotent_and_preserves_first_seen() {
        let mut s = StateSpace::new();
        assert!(s.is_empty());
        assert!(s.observe(ent(1, EntityKind::Process, "cmd.exe", 10)));
        assert!(!s.observe(ent(1, EntityKind::Process, "cmd.exe", 20)));
        assert_eq!(s.len(), 1);
        let e = s.get(EntityId(1)).unwrap();
        assert_eq!(e.last_seen_ns, 20);
        assert_eq!(e.first_seen_ns, 10);
        assert!(s.get(EntityId(2)).is_none());
    }

    #[test]
    fn get_mut_mutates_in_place() {
        let mut s = StateSpace::new();
        s.observe(ent(7, EntityKind::User, "alice", 5));
        s.get_mut(EntityId(7)).unwrap().last_seen_ns = 99;
        assert_eq!(s.get(EntityId(7)).unwrap().last_seen_ns, 99);
        assert!(s.get_mut(EntityId(8)).is_none());
        assert_eq!(s.by_kind(EntityKind::User), vec![EntityId(7)]);
    }

    #[test]
    fn fibers_are_the_preimage_of_the_projection() {
        let mut s = StateSpace::new();
        s.observe(ent(1, EntityKind::Process, "cmd.exe", 1));
        s.observe(ent(2, EntityKind::Process, "cmd.exe", 1));
        s.observe(ent(3, EntityKind::File, "cmd.exe", 1));
        let procs = Projection::by_kind(&s, EntityKind::Process);
        assert_eq!(procs, BTreeSet::from([EntityId(1), EntityId(2)]));
        let fiber = Projection::fiber(&s, EntityKind::Process, "cmd.exe");
        assert_eq!(fiber, procs);
        assert!(Projection::fiber(&s, EntityKind::File, "cmd.exe").contains(&EntityId(3)));
        assert!(Projection::fiber(&s, EntityKind::Module, "cmd.exe").is_empty());
    }

    #[test]
    fn attributes_are_typed_and_scoped_to_known_entities() {
        let mut s = StateSpace::new();
        assert!(!s.set_attr(EntityId(9), "x", AttrValue::Flag(true)));
        s.observe(ent(1, EntityKind::Host, "ws01", 1));
        assert!(s.set_attr(EntityId(1), "domain", AttrValue::Text("corp".into())));
        assert!(s.set_attr(EntityId(1), "ports", AttrValue::Int(3)));
        assert_eq!(
            s.attr(EntityId(1), "domain"),
            Some(&AttrValue::Text("corp".into()))
        );
        assert_eq!(s.attr(EntityId(1), "ports"), Some(&AttrValue::Int(3)));
        assert_eq!(s.attr(EntityId(1), "missing"), None);
    }

    #[test]
    fn state_gap_is_saturating_and_never_closes() {
        let g = StateGap::new(10, 4);
        assert_eq!(g.gap(), 6);
        assert!((g.coverage() - 0.4).abs() < 1e-12);
        assert!(g.is_open());
        let over = StateGap::new(3, 9);
        assert_eq!(over.gap(), 0);
        assert_eq!(over.coverage(), 1.0);
        let empty = StateGap::new(0, 0);
        assert_eq!(empty.coverage(), 1.0);
        assert!(empty.is_open());
    }
}
