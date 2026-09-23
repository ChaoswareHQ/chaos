# `sigma`

A [SIGMA](https://sigmahq.io) rule engine, so the community ruleset can be
scored by this pipeline instead of only the hand-written rules in
`crates/pipeline/src/rules.rs`.

SIGMA is a vendor-neutral YAML detection format with a large community ruleset
written mostly against Sysmon and the Windows event log. This crate loads those
rules, evaluates them against our wire events, and produces the same
evidence-shaped result a native rule does — a likelihood pair, not a verdict —
so a SIGMA hit enters the A5/A8 decision the same way.

## The three caveats, up front

1. **SIGMA rules carry no false-positive rate.** `level` is a hand-assigned
   severity, so `Level::likelihood` *synthesises* the pair. A SIGMA rule's
   evidence is a guess about its miss rate where a native rule's is a reasoned
   claim. This augments the native rules; it does not replace them.

2. **A rule is only as good as its field mapping.** SIGMA rules are written
   against a log schema; our events are typed. `view` translates, and a field
   name it never emits is a rule that loads, looks healthy, and can never fire.
   Every rule reports `unmapped_fields` at load.

3. **Not every construct is implemented.** `re`, `base64`, `windash` and the
   UTF-16 modifiers are *rejected* at load rather than ignored, along with
   `timeframe`/aggregation. A rule this engine cannot evaluate is not loaded at
   all: a silent rule is worse than a missing one.

## What is not supported

- Aggregation: `timeframe`, `condition: selection | count() by X > N`.
- Service-based log sources (`service: security`, `service: sysmon`). A large
  share of the Windows ruleset is keyed this way; those rules are rejected with
  a reason and listed in `RuleSet::problems()`, so the loss is visible.
- WMI and scheduled-task shapes have no SIGMA category mapping, and are
  therefore invisible to SIGMA rules. Their native rules are the only readers.

## Using it

```rust
let rules = sigma::RuleSet::from_directory(std::path::Path::new("rules/"))?;
for rule in rules.rules_that_cannot_fire() {
    eprintln!("{} reads a field we never emit: {:?}", rule.title, rule.unmapped_fields);
}
for hit in rules.evaluate(&event) {
    // hit.likelihood, hit.technique(), hit.detail
}
```
