//! SIGMA's `detection` block: selections, the condition that combines them, and
//! the field modifiers.
//!
//! # The grammar, and the part of it this implements
//!
//! A SIGMA detection is a set of named *selections* plus a boolean `condition`
//! over their names. A selection is either a map of field tests (all of which
//! must match) or a list of such maps (any of which may), and a field test is a
//! `field|modifiers: value` whose value is a scalar or a list.
//!
//! This implements that, plus the modifiers in [`Modifier`]. It does **not**
//! implement everything: `re`, `base64`, `windash`, the UTF-16 variants and the
//! aggregation grammar (`| count() by ...`) are recognised and **rejected** at
//! load rather than silently ignored. A rule this engine cannot evaluate
//! correctly is worse than a rule it never loaded, because the first one is
//! quiet and looks healthy — the failure mode the whole crate exists to avoid.
//!
//! # Case, wildcards, and the defaults
//!
//! SIGMA string matching is case-insensitive unless a rule says `|cased`, and
//! `*`/`?` are wildcards in *every* string comparison, not only in `equals`.
//! Both are implemented here, and both are the kind of default that turns a
//! working ruleset into a broken one when they are missed.

use crate::view::{EventView, Value};
use saphyr::{MappingOwned, YamlOwned};
use std::cmp::Ordering;

/// How a field's value is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Whole-value match, wildcards allowed.
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    /// The value is an address inside a CIDR range.
    Cidr,
    Greater,
    GreaterEq,
    Less,
    LessEq,
    /// The value equals *another field's* value.
    FieldRef,
    /// The field is absent. A SIGMA `field: null`.
    Absent,
}

/// One `field|modifiers: value` test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldTest {
    pub field: String,
    pub op: Op,
    pub needles: Vec<String>,
    /// `|all`: every needle must match rather than any one of them.
    pub all: bool,
    /// `|cased`: match case-sensitively.
    pub case_sensitive: bool,
}

/// A list of field tests that must all match.
pub type Group = Vec<FieldTest>;

/// A selection: alternatives, of which any one may match.
pub type Selection = Vec<Group>;

/// The boolean condition over selection names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// One named selection.
    Selection(String),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
    /// `N of pattern*`, `all of them`, `1 of them` — all the same shape: at
    /// least `n` of the named selections must match.
    AtLeast(usize, Vec<String>),
}

/// A compiled `detection` block.
#[derive(Debug, Clone)]
pub struct Detection {
    pub selections: Vec<(String, Selection)>,
    pub condition: Condition,
}

impl Detection {
    /// Whether an event's view satisfies this detection.
    pub fn matches(&self, view: &EventView) -> bool {
        self.eval(&self.condition, view)
    }

    fn eval(&self, condition: &Condition, view: &EventView) -> bool {
        match condition {
            Condition::Selection(name) => self
                .selection(name)
                .is_some_and(|selection| selection_matches(selection, view)),
            Condition::And(a, b) => self.eval(a, view) && self.eval(b, view),
            Condition::Or(a, b) => self.eval(a, view) || self.eval(b, view),
            Condition::Not(inner) => !self.eval(inner, view),
            Condition::AtLeast(n, names) => {
                let matched = names
                    .iter()
                    .filter(|name| {
                        self.selection(name)
                            .is_some_and(|selection| selection_matches(selection, view))
                    })
                    .count();
                matched >= *n
            }
        }
    }

    fn selection(&self, name: &str) -> Option<&Selection> {
        self.selections
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s)
    }

    /// Every selection name, in document order.
    pub fn selection_names(&self) -> Vec<&str> {
        self.selections.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Every field name the detection reads.
    pub fn fields(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for (_, selection) in &self.selections {
            for group in selection {
                for test in group {
                    out.push(test.field.as_str());
                    if test.op == Op::FieldRef {
                        out.extend(test.needles.iter().map(|n| n.as_str()));
                    }
                }
            }
        }
        out
    }

    /// Whether any event could satisfy this detection, given a predicate for
    /// whether a field name can appear at all.
    ///
    /// The distinction this exists for is the shape of the condition. A field a
    /// sensor cannot produce inside a *conjunction* makes a rule unable to fire;
    /// the same field as one alternative of a *disjunction* only kills that
    /// alternative. A real rule that ORs `Image|endswith` with
    /// `OriginalFileName` still works on a sensor that has `Image`, and calling
    /// it dead would hide a live rule.
    pub fn satisfiable(&self, available: &dyn Fn(&str) -> bool) -> bool {
        self.condition_satisfiable(&self.condition, available)
    }

    fn condition_satisfiable(
        &self,
        condition: &Condition,
        available: &dyn Fn(&str) -> bool,
    ) -> bool {
        match condition {
            Condition::Selection(name) => self.selection_satisfiable(name, available),
            Condition::And(a, b) => {
                self.condition_satisfiable(a, available) && self.condition_satisfiable(b, available)
            }
            Condition::Or(a, b) => {
                self.condition_satisfiable(a, available) || self.condition_satisfiable(b, available)
            }
            // A negated selection is satisfiable whenever that selection is not
            // always true, which is the normal case; proving the exception needs
            // an "always true" analysis this does not have. Eroding toward "can
            // fire" is the safe direction — it never hides a working rule.
            Condition::Not(_) => true,
            Condition::AtLeast(n, names) => {
                names
                    .iter()
                    .filter(|name| self.selection_satisfiable(name, available))
                    .count()
                    >= *n
            }
        }
    }

    fn selection_satisfiable(&self, name: &str, available: &dyn Fn(&str) -> bool) -> bool {
        self.selection(name).is_some_and(|selection| {
            selection.iter().any(|group| {
                group.iter().all(|test| {
                    // "The field is absent" is satisfied by an event that does
                    // not carry it, which is every event if we never emit it.
                    if test.op == Op::Absent {
                        return true;
                    }
                    if !available(&test.field) {
                        return false;
                    }
                    if test.op == Op::FieldRef {
                        return test.needles.iter().all(|other| available(other));
                    }
                    true
                })
            })
        })
    }
}

fn selection_matches(selection: &Selection, view: &EventView) -> bool {
    selection
        .iter()
        .any(|group| group.iter().all(|test| test_matches(test, view)))
}

/// One field test against one view.
fn test_matches(test: &FieldTest, view: &EventView) -> bool {
    if test.op == Op::Absent {
        return view.get(&test.field).is_none();
    }

    let Some(value) = view.get(&test.field) else {
        // A field the event does not carry never matches a positive test. That
        // is SIGMA's semantics, and it is why a rule against a field we do not
        // collect is silent rather than wrong.
        return false;
    };

    // `fieldref` compares two fields of the same event, so it needs the view
    // rather than the value alone.
    if test.op == Op::FieldRef {
        return test.needles.iter().any(|other| {
            view.get(other).is_some_and(|right| {
                let (left, right) = (value.as_text(), right.as_text());
                if test.case_sensitive {
                    left == right
                } else {
                    left.to_lowercase() == right.to_lowercase()
                }
            })
        });
    }

    let matches = |needle: &String| test_one(test, value, needle);
    if test.all {
        test.needles.iter().all(matches)
    } else {
        test.needles.iter().any(matches)
    }
}

fn test_one(test: &FieldTest, value: &Value, needle: &str) -> bool {
    match test.op {
        // `fieldref` needs the whole view and is handled in `test_matches`.
        Op::FieldRef | Op::Absent => false,
        Op::Cidr => cidr_match(needle, &value.as_text()),
        Op::Greater => numeric(value, needle, Ordering::Greater),
        Op::GreaterEq => {
            numeric(value, needle, Ordering::Greater) || numeric(value, needle, Ordering::Equal)
        }
        Op::Less => numeric(value, needle, Ordering::Less),
        Op::LessEq => {
            numeric(value, needle, Ordering::Less) || numeric(value, needle, Ordering::Equal)
        }
        op => {
            let text = value.as_text();
            let pattern = match op {
                Op::Equals => needle.to_string(),
                Op::StartsWith => format!("{needle}*"),
                Op::EndsWith => format!("*{needle}"),
                Op::Contains => format!("*{needle}*"),
                _ => return false,
            };
            wildcard(&pattern, &text, test.case_sensitive)
        }
    }
}

fn numeric(value: &Value, needle: &str, want: Ordering) -> bool {
    let Some(left) = value_as_f64(value) else {
        return false;
    };
    let Ok(right) = needle.trim().parse::<f64>() else {
        return false;
    };
    left.partial_cmp(&right) == Some(want)
}

fn value_as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Int(i) => Some(*i as f64),
        Value::Text(s) => s.trim().parse().ok(),
        Value::Bool(_) => None,
    }
}

/// `*` and `?` against the whole of `text`, byte-wise.
///
/// The anchors are the caller's: `equals` passes the pattern through, `contains`
/// wraps it in `*...*`, and so on, which is why one matcher covers every string
/// modifier. SIGMA's wildcards are part of the *value*, not the operator.
///
/// Matching is over bytes with ASCII case folding when `case_sensitive` is false.
/// The paths and command lines these rules read are ASCII, so this is the same
/// answer as a character-wise match — without the lowercased copy and the
/// `Vec<char>` a comparison used to allocate. Non-ASCII bytes are compared
/// verbatim and `?` consumes one byte rather than one character.
fn wildcard(pattern: &str, text: &str, case_sensitive: bool) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let same = |a: u8, b: u8| {
        if case_sensitive {
            a == b
        } else {
            a.to_ascii_lowercase() == b.to_ascii_lowercase()
        }
    };

    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || same(p[pi], t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            // Backtrack: let the last `*` swallow one more character.
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Whether `text` is an address inside the CIDR `pattern`.
fn cidr_match(pattern: &str, text: &str) -> bool {
    use std::net::IpAddr;

    let (net, bits) = match pattern.split_once('/') {
        Some((addr, bits)) => match bits.trim().parse::<u8>() {
            Ok(bits) => (addr, Some(bits)),
            Err(_) => return false,
        },
        // No prefix: an exact host match. The width is the family's, so the
        // mask below is all-ones rather than an overflowed shift.
        None => (pattern, None),
    };
    let (Ok(net), Ok(ip)) = (net.trim().parse::<IpAddr>(), text.trim().parse::<IpAddr>()) else {
        return false;
    };

    match (net, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = bits.unwrap_or(32);
            if bits > 32 {
                return false;
            }
            let mask = mask32(bits);
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = bits.unwrap_or(128);
            if bits > 128 {
                return false;
            }
            let mask = mask128(bits);
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

fn mask32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(bits))
    }
}

fn mask128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - u128::from(bits))
    }
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/// What went wrong with one rule's `detection` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Modifiers this engine implements.
///
/// Anything outside this list is a compile error rather than a silent no-op:
/// see the module docs for why.
fn modifier(word: &str) -> Option<Modifier> {
    match word {
        "contains" => Some(Modifier::Contains),
        "startswith" => Some(Modifier::StartsWith),
        "endswith" => Some(Modifier::EndsWith),
        "all" => Some(Modifier::All),
        "cased" | "case_sensitive" => Some(Modifier::Cased),
        "cidr" => Some(Modifier::Cidr),
        "gt" => Some(Modifier::Gt),
        "gte" => Some(Modifier::Gte),
        "lt" => Some(Modifier::Lt),
        "lte" => Some(Modifier::Lte),
        "fieldref" => Some(Modifier::FieldRef),
        _ => None,
    }
}

enum Modifier {
    Contains,
    StartsWith,
    EndsWith,
    All,
    Cased,
    Cidr,
    Gt,
    Gte,
    Lt,
    Lte,
    FieldRef,
}

/// Compile a SIGMA `detection` mapping.
pub fn compile(detection: &YamlOwned) -> Result<Detection, CompileError> {
    let map = detection
        .as_mapping()
        .ok_or_else(|| CompileError("`detection` is not a mapping".to_string()))?;

    let mut selections = Vec::new();
    let mut condition = None;

    for (key, value) in map.iter() {
        let Some(name) = key.as_str() else {
            return Err(CompileError("a detection key is not a string".to_string()));
        };
        if name == "condition" {
            condition = Some(
                value
                    .as_str()
                    .ok_or_else(|| CompileError("`condition` is not a string".to_string()))?,
            );
            continue;
        }
        if name == "timeframe" {
            return Err(CompileError(
                "`timeframe` needs aggregation, which this engine does not implement".to_string(),
            ));
        }
        selections.push((name.to_string(), compile_selection(name, value)?));
    }

    if selections.is_empty() {
        return Err(CompileError("no selections".to_string()));
    }
    let Some(condition) = condition else {
        return Err(CompileError("no `condition`".to_string()));
    };
    let condition = parse_condition(condition, &selections)?;

    Ok(Detection {
        selections,
        condition,
    })
}

fn compile_selection(name: &str, value: &YamlOwned) -> Result<Selection, CompileError> {
    if let Some(sequence) = value.as_sequence() {
        let mut groups = Vec::new();
        for entry in sequence {
            let Some(map) = entry.as_mapping() else {
                return Err(CompileError(format!(
                    "selection `{name}` is a list containing something that is not a mapping"
                )));
            };
            groups.push(compile_group(name, map)?);
        }
        if groups.is_empty() {
            return Err(CompileError(format!("selection `{name}` is empty")));
        }
        return Ok(groups);
    }
    if let Some(map) = value.as_mapping() {
        return Ok(vec![compile_group(name, map)?]);
    }
    Err(CompileError(format!(
        "selection `{name}` is neither a mapping nor a list of mappings"
    )))
}

fn compile_group(name: &str, map: &MappingOwned) -> Result<Group, CompileError> {
    let mut group = Vec::new();
    for (key, value) in map.iter() {
        let Some(key) = key.as_str() else {
            return Err(CompileError(format!(
                "selection `{name}` has a field key that is not a string"
            )));
        };
        group.push(compile_test(name, key, value)?);
    }
    if group.is_empty() {
        return Err(CompileError(format!("selection `{name}` has no fields")));
    }
    Ok(group)
}

fn compile_test(selection: &str, key: &str, value: &YamlOwned) -> Result<FieldTest, CompileError> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default().to_string();
    if field.is_empty() {
        return Err(CompileError(format!(
            "selection `{selection}` has a test with no field name"
        )));
    }

    let mut op = Op::Equals;
    let mut all = false;
    let mut case_sensitive = false;
    for word in parts {
        match modifier(word).ok_or_else(|| {
            CompileError(format!(
                "field `{field}` uses the `|{word}` modifier, which this engine does not implement"
            ))
        })? {
            Modifier::Contains => op = Op::Contains,
            Modifier::StartsWith => op = Op::StartsWith,
            Modifier::EndsWith => op = Op::EndsWith,
            Modifier::Cidr => op = Op::Cidr,
            Modifier::Gt => op = Op::Greater,
            Modifier::Gte => op = Op::GreaterEq,
            Modifier::Lt => op = Op::Less,
            Modifier::Lte => op = Op::LessEq,
            Modifier::FieldRef => op = Op::FieldRef,
            Modifier::All => all = true,
            Modifier::Cased => case_sensitive = true,
        }
    }

    // `field: null` means "the field is not there", whatever modifiers say.
    if value.is_null() {
        return Ok(FieldTest {
            field,
            op: Op::Absent,
            needles: Vec::new(),
            all,
            case_sensitive,
        });
    }

    let mut needles = Vec::new();
    if let Some(sequence) = value.as_sequence() {
        for entry in sequence {
            needles.push(scalar(selection, &field, entry)?);
        }
    } else {
        needles.push(scalar(selection, &field, value)?);
    }
    if needles.is_empty() {
        return Err(CompileError(format!(
            "selection `{selection}` gives field `{field}` an empty list"
        )));
    }

    Ok(FieldTest {
        field,
        op,
        needles,
        all,
        case_sensitive,
    })
}

/// A scalar as the string a comparison works on.
fn scalar(selection: &str, field: &str, value: &YamlOwned) -> Result<String, CompileError> {
    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }
    if let Some(i) = value.as_integer() {
        return Ok(i.to_string());
    }
    if let Some(f) = value.as_floating_point() {
        return Ok(f.to_string());
    }
    if let Some(b) = value.as_bool() {
        return Ok(b.to_string());
    }
    Err(CompileError(format!(
        "selection `{selection}` gives field `{field}` a value that is not a scalar"
    )))
}

// ---------------------------------------------------------------------------
// The condition parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Open,
    Close,
}

fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for ch in source.chars() {
        match ch {
            '(' => {
                if !word.is_empty() {
                    tokens.push(Token::Word(std::mem::take(&mut word)));
                }
                tokens.push(Token::Open);
            }
            ')' => {
                if !word.is_empty() {
                    tokens.push(Token::Word(std::mem::take(&mut word)));
                }
                tokens.push(Token::Close);
            }
            c if c.is_whitespace() => {
                if !word.is_empty() {
                    tokens.push(Token::Word(std::mem::take(&mut word)));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        tokens.push(Token::Word(word));
    }
    tokens
}

/// Parse `and`/`or`/`not`, parentheses, and the quantifier forms.
///
/// Quantifiers (`all of them`, `1 of selection*`, `2 of filter*`) are resolved
/// here, at load, into [`Condition::AtLeast`] over concrete selection names, so
/// evaluation never has to re-resolve a pattern.
fn parse_condition(
    source: &str,
    selections: &[(String, Selection)],
) -> Result<Condition, CompileError> {
    let tokens = tokenize(source);
    if tokens.is_empty() {
        return Err(CompileError("`condition` is empty".to_string()));
    }
    let mut parser = Parser {
        tokens,
        at: 0,
        selections,
    };
    let condition = parser.or()?;
    if parser.at != parser.tokens.len() {
        return Err(CompileError(format!(
            "`condition` has trailing tokens starting at `{}`",
            parser.describe_rest()
        )));
    }
    Ok(condition)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    selections: &'a [(String, Selection)],
}

impl Parser<'_> {
    fn describe_rest(&self) -> String {
        match self.tokens.get(self.at) {
            Some(Token::Word(w)) => w.clone(),
            Some(Token::Open) => "(".to_string(),
            Some(Token::Close) => ")".to_string(),
            None => "<end>".to_string(),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn word(&self) -> Option<&str> {
        match self.peek() {
            Some(Token::Word(w)) => Some(w.as_str()),
            _ => None,
        }
    }

    fn eat_word(&mut self, want: &str) -> bool {
        if self.word() == Some(want) {
            self.at += 1;
            return true;
        }
        false
    }

    fn or(&mut self) -> Result<Condition, CompileError> {
        let mut left = self.and()?;
        while self.eat_word("or") {
            let right = self.and()?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Condition, CompileError> {
        let mut left = self.not()?;
        while self.eat_word("and") {
            let right = self.not()?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Condition, CompileError> {
        if self.eat_word("not") {
            return Ok(Condition::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Condition, CompileError> {
        if matches!(self.peek(), Some(Token::Open)) {
            self.at += 1;
            let inner = self.or()?;
            if !matches!(self.peek(), Some(Token::Close)) {
                return Err(CompileError("unbalanced `(` in `condition`".to_string()));
            }
            self.at += 1;
            return Ok(inner);
        }

        // A quantifier: `all of them`, `any of ...`, `1 of selection*`.
        if let Some(quantifier) = self.quantifier() {
            return self.quantified(quantifier);
        }

        match self.peek() {
            Some(Token::Word(name)) => {
                let name = name.clone();
                self.at += 1;
                self.resolve(&name)?;
                Ok(Condition::Selection(name))
            }
            _ => Err(CompileError(format!(
                "`condition` expected a selection name, found `{}`",
                self.describe_rest()
            ))),
        }
    }

    /// The count a quantifier asks for, or `None` if this is not one.
    fn quantifier(&self) -> Option<Quantifier> {
        match self.word()? {
            "all" => Some(Quantifier::All),
            "any" => Some(Quantifier::Any),
            word => {
                let mut it = word.chars();
                if it.next()?.is_ascii_digit() && word.chars().all(|c| c.is_ascii_digit()) {
                    word.parse::<usize>().ok().map(Quantifier::Count)
                } else {
                    None
                }
            }
        }
    }

    fn quantified(&mut self, quantifier: Quantifier) -> Result<Condition, CompileError> {
        self.at += 1; // the quantifier word
        if !self.eat_word("of") {
            return Err(CompileError(
                "a quantifier must be followed by `of`".to_string(),
            ));
        }
        let Some(target) = self.word().map(str::to_string) else {
            return Err(CompileError(
                "`of` must be followed by a selection name, a pattern, or `them`".to_string(),
            ));
        };
        self.at += 1;

        let names = self.select(quantifier, &target)?;
        let needed = match quantifier {
            Quantifier::All => names.len(),
            Quantifier::Any => 1,
            Quantifier::Count(n) => n,
        };
        if needed > names.len() {
            return Err(CompileError(format!(
                "`{target}` quantifies over {} selection(s), which cannot satisfy `{needed} of`",
                names.len()
            )));
        }
        Ok(Condition::AtLeast(needed, names))
    }

    /// Resolve a quantifier target to concrete selection names.
    fn select(&self, quantifier: Quantifier, target: &str) -> Result<Vec<String>, CompileError> {
        if target == "them" {
            // `them` is every selection, and `N of them` over an explicit count
            // is legal SIGMA. It is only ambiguous for `all`, which the caller
            // has already turned into `names.len()`.
            let _ = quantifier;
            return Ok(self.selections.iter().map(|(n, _)| n.clone()).collect());
        }
        if let Some(prefix) = target.strip_suffix('*') {
            let matched: Vec<String> = self
                .selections
                .iter()
                .filter(|(n, _)| n.starts_with(prefix))
                .map(|(n, _)| n.clone())
                .collect();
            if matched.is_empty() {
                return Err(CompileError(format!("`{target}` matches no selection")));
            }
            return Ok(matched);
        }
        self.resolve(target)?;
        Ok(vec![target.to_string()])
    }

    fn resolve(&self, name: &str) -> Result<(), CompileError> {
        if self.selections.iter().any(|(n, _)| n == name) {
            Ok(())
        } else {
            Err(CompileError(format!(
                "`condition` names the selection `{name}`, which the detection does not define"
            )))
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Quantifier {
    All,
    Any,
    Count(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{EventView, Value};
    use model::{
        EventId, EventKind, EventSource, HostId, Payload, ProcessId, ProcessStart, ProviderId,
        TelemetryEvent,
    };
    use saphyr::LoadableYamlNode;

    fn yaml(source: &str) -> YamlOwned {
        YamlOwned::load_from_str(source).expect("parses")[0].clone()
    }

    /// Compile one selection. `compile` requires a `condition`, and these tests
    /// are about comparison semantics rather than the grammar, so they go in at
    /// the selection level.
    fn selection(source: &str) -> Selection {
        compile_selection("test", &yaml(source)).expect("compiles")
    }

    fn process_with(image: &str, parent_image: &str) -> EventView {
        let event = TelemetryEvent::new(
            EventId::new(1),
            HostId::new("h").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            ProviderId::new("Microsoft-Windows-Kernel-Process"),
            1,
            42,
            42,
            4,
            EventKind::ProcessStart(ProcessStart {
                pid: ProcessId::new(42),
                parent_pid: Some(ProcessId::new(4)),
                executable: image.into(),
                command_line: None,
                user: None,
                working_directory: None,
                started_at: chrono::Utc::now(),
                image_hash: None,
                integrity_level: None,
                is_wow64: false,
                parent_image: Some(parent_image.into()),
            }),
            Payload::empty(),
        );
        EventView::of(&event).expect("mapped")
    }

    /// A view built from a real event, so the mapping is exercised too.
    fn powershell_view(cmd: &str) -> EventView {
        use model::*;
        let event = TelemetryEvent::new(
            EventId::new(1),
            HostId::new("h").unwrap(),
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
                executable: "C:\\Windows\\System32\\powershell.exe".into(),
                command_line: Some(cmd.into()),
                user: None,
                working_directory: None,
                started_at: chrono::Utc::now(),
                image_hash: None,
                integrity_level: None,
                is_wow64: false,
                parent_image: Some("C:\\Windows\\explorer.exe".into()),
            }),
            Payload::empty(),
        );
        EventView::of(&event).expect("mapped")
    }

    #[test]
    fn a_field_equals_selection_matches_case_insensitively() {
        let s = selection("Image: 'C:\\WINDOWS\\SYSTEM32\\POWERSHELL.EXE'\n");
        let view = powershell_view("powershell.exe -enc AAAA");
        assert!(selection_matches(&s, &view));
    }

    #[test]
    fn wildcards_are_part_of_the_value() {
        let view = powershell_view("powershell.exe -enc SQBFAFgA");
        assert!(selection_matches(
            &selection("CommandLine: '* -enc *'\n"),
            &view
        ));
        assert!(!selection_matches(
            &selection("CommandLine: '* -encoded *'\n"),
            &view
        ));
    }

    #[test]
    fn an_endswith_modifier_anchors_at_the_end() {
        let view = powershell_view("C:\\Windows\\System32\\powershell.exe -enc AAAA");
        assert!(selection_matches(
            &selection("Image|endswith: 'powershell.exe'\n"),
            &view
        ));
        // The same text in the middle must not satisfy an `endswith`.
        assert!(!selection_matches(
            &selection("CommandLine|endswith: 'powershell.exe'\n"),
            &view
        ));
    }

    #[test]
    fn a_null_value_means_the_field_is_absent() {
        let event = {
            use model::*;
            TelemetryEvent::new(
                EventId::new(1),
                HostId::new("h").unwrap(),
                chrono::Utc::now(),
                EventSource::WindowsEtw,
                ProviderId::new("p"),
                1,
                1,
                1,
                4,
                EventKind::ProcessStart(ProcessStart {
                    pid: ProcessId::new(1),
                    parent_pid: None,
                    executable: "C:\\a.exe".into(),
                    command_line: None,
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
        };
        let view = EventView::of(&event).expect("mapped");
        assert!(selection_matches(&selection("CommandLine: null\n"), &view));
    }

    #[test]
    fn a_list_of_maps_is_an_or_of_ands() {
        let s = selection(
            "- Image|endswith: 'cmd.exe'\n  CommandLine|contains: 'whoami'\n\
             - Image|endswith: 'powershell.exe'\n",
        );
        let view = powershell_view("powershell.exe");
        assert!(selection_matches(&s, &view));
    }

    #[test]
    fn a_condition_parses_quantifiers_into_concrete_selections() {
        let detection = compile(&yaml(
            "sel_a: {image|endswith: 'x'}\nsel_b: {image|endswith: 'y'}\n\
             filter: {image|endswith: 'z'}\ncondition: 1 of sel_* and not filter\n",
        ))
        .expect("compiles");
        assert_eq!(
            detection.condition,
            Condition::And(
                Box::new(Condition::AtLeast(
                    1,
                    vec!["sel_a".to_string(), "sel_b".to_string()]
                )),
                Box::new(Condition::Not(Box::new(Condition::Selection(
                    "filter".to_string()
                ))))
            )
        );
    }

    #[test]
    fn a_condition_naming_an_undefined_selection_is_rejected() {
        let error = compile(&yaml("sel: {image: 'x'}\ncondition: sel and missing\n"))
            .expect_err("must not compile");
        assert!(error.0.contains("missing"), "{}", error.0);
    }

    #[test]
    fn an_unimplemented_modifier_is_rejected_rather_than_ignored() {
        // The whole point: a rule we cannot evaluate must not load and go quiet.
        let error = compile(&yaml("cmd|re: '.*'\n")).expect_err("must not compile");
        assert!(error.0.contains("|re"), "{}", error.0);
    }

    #[test]
    fn an_aggregation_condition_is_rejected() {
        let error = compile(&yaml("sel: {image: 'x'}\ncondition: sel | count() > 5\n"))
            .expect_err("must not compile");
        assert!(error.0.contains("|"), "{}", error.0);
    }

    #[test]
    fn the_wildcard_matcher_folds_case_and_handles_star_and_question() {
        // The matcher is now byte-oriented; this is the contract every string
        // modifier depends on, so it is worth stating directly rather than only
        // through `selection_matches`.
        assert!(wildcard("*\\NMAP.EXE", "C:\\Tools\\nmap.exe", false));
        assert!(!wildcard("*\\NMAP.EXE", "C:\\Tools\\nmap.exe", true));
        // `?` is exactly one byte; `*` is any run of them.
        assert!(wildcard("*c?d.exe", "C:\\x\\cmd.exe", false));
        assert!(!wildcard("*c?d.exe", "C:\\x\\cd.exe", false));
        assert!(wildcard("*a*b", "xxayyb", false));
        assert!(wildcard(
            "C:\\*\\cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            false
        ));
        // A lone star matches the empty string rather than requiring a byte.
        assert!(wildcard("*", "", false));
    }

    #[test]
    fn cidr_matches_only_inside_the_range() {
        assert!(cidr_match("10.0.0.0/8", "10.1.2.3"));
        assert!(!cidr_match("10.0.0.0/8", "11.1.2.3"));
        assert!(cidr_match("192.168.0.0/16", "192.168.5.5"));
        assert!(cidr_match("2001:db8::/32", "2001:db8::1"));
        assert!(!cidr_match("2001:db8::/32", "2001:db9::1"));
        // A host address with no prefix is an exact match.
        assert!(cidr_match("8.8.8.8", "8.8.8.8"));
        assert!(!cidr_match("8.8.8.8", "8.8.8.9"));
    }

    #[test]
    fn numeric_modifiers_compare_as_numbers_not_strings() {
        // The trap: "9" > "10" as text and not as numbers.
        assert!(numeric(&Value::Int(10), "9", Ordering::Greater));
        assert!(!numeric(&Value::Int(9), "10", Ordering::Greater));
    }

    #[test]
    fn a_fieldref_compares_two_fields_of_the_same_event() {
        // `ParentImage|fieldref: Image` is a real SIGMA idiom for "this process
        // re-launched itself"; both sides are read from the same view.
        let s = selection("ParentImage|fieldref: Image\n");
        assert!(selection_matches(
            &s,
            &process_with("C:\\a.exe", "C:\\a.exe")
        ));
        assert!(!selection_matches(
            &s,
            &process_with("C:\\a.exe", "C:\\b.exe")
        ));
    }
}
