# `model`

The wire format. Everything the agent ships, everything the server stores, and
everything the console renders is a type from this crate.

It has no behaviour to speak of and no dependencies beyond `serde`, `chrono` and
`indexmap`. That is the point: this crate is the contract between a sensor that
produces bytes and an algebra that consumes numbers, and a contract that does
work is a contract you have to read before you can trust it.

## Why it is separate from `asmr`

`asmr` is mathematics — standard library only, no I/O, testable from a literal.
This crate is a serialisation format: it depends on `serde`, it is full of
`String`s and `Box<str>`, and it knows what a registry key is.

Neither may depend on the other. `pipeline` is where they meet, which is why it
is the only crate that imports both.

## The two halves

### Telemetry — what a host reports

`TelemetryEvent` is one observed thing:

```rust
pub struct TelemetryEvent {
    pub id: EventId,
    pub host: HostId,
    pub timestamp: DateTime<Utc>,
    pub received_at: Option<DateTime<Utc>>,
    pub schema_version: u16,
    pub source: EventSource,     // WindowsEtw | LinuxEbpf | MacOsEs
    pub provider: ProviderId,
    pub event_id: u16,
    pub pid: u32,
    pub tid: u32,
    pub level: u8,
    pub kind: EventKind,         // the typed payload
    pub payload: Payload,        // the raw fields, as came off the wire
}
```

`kind` and `payload` are both present on purpose. `kind` is the typed view the
pipeline scores, and it is `Option`-heavy because a sensor that cannot resolve a
field must say `None` rather than invent a value. `payload` is the provider's own
fields, preserved so an analyst can see what the sensor saw without replaying
the machine.

`EventKind` is a tagged enum over fourteen shapes — process start and exit,
network connect and disconnect, file create, write, delete and rename, registry
set and delete, DNS query, image load, script block, and `Unclassified`:

```rust
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind { ... }
```

It is tagged on the field name rather than the variant order, so a new event kind
does not renumber the existing ones. `Unclassified` is the `#[serde(other)]`
fallback and the `Default`: a newer agent talking to an older server must produce
one recognised event rather than a parse failure for the whole batch. That is what
makes adding a variant — `ScriptBlock` was the most recent — an additive change
that does not need a schema bump.

### Alerts — what the pipeline concluded

```rust
pub struct Alert {
    pub id: AlertId,
    pub rule_id: RuleId,
    pub title: Box<str>,
    pub description: Box<str>,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub host: HostId,
    pub events: Vec<EventId>,
    pub mitre_techniques: Vec<Box<str>>,
    pub count: u32,
    pub status: AlertStatus,
}
```

`count` is how many firings this one row stands for. Repeat detections of the
same rule are folded rather than re-emitted, so the row keeps the magnitude that
coalescing would otherwise hide. It defaults to 1 when absent, which is what an
older agent will send.

`status` is `New`, `Investigating`, `Closed` or `FalsePositive`. Nothing writes
anything but `New` today: the console has no authentication, so there is no
identity to attribute a close to. The field exists because retrofitting it after
the console has an acknowledge button is worse than carrying it from the start.

## Values

`Value` is the dynamic half of the format — the shape provider payloads arrive
in, and what an alert body is built from:

```rust
pub type Map = IndexMap<Box<str>, Value>;

pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(Box<str>),
    Array(Vec<Value>),
    Object(Map),
}
```

Two things about it are deliberate:

- **`Int` and `Uint` are distinct**, and a wide integer that does not fit is
  kept as one rather than forced through `f64`. ETW hands over plenty of
  `u64`s — a `TimeDateStamp`, a sequence key, a checksum — and `f64` has 53 bits
  of mantissa, so a single `Number` variant would silently round exactly the
  fields that are cheap to get right. Only `i128`/`u128` outside the 64-bit
  range degrade to `Float`, which is the honest answer for them.
- **`Map` is an `IndexMap`.** Insertion order is preserved, so a payload renders
  in the order the provider declared its fields rather than in a hash order that
  changes between runs — which is what makes a console row diffable against the
  same row a minute ago.

The `serde` implementations are hand-written rather than derived, because the
variant has to be chosen from the JSON *shape* on the way in: a bare number is
`Int`, `Uint` or `Float` depending on which visit the deserialiser calls, and
`null` is `Null` rather than an error.

### A positive integer comes back as `Uint`

JSON has one number type, so a decoded `7` has to be given a variant from the
number alone — non-negative goes through `visit_u64`, and `Uint` is what comes
back. `Int(7)` and `Uint(7)` are therefore the same event on the wire, and only
one of them survives a round trip. Negative values have a single representation
and survive exactly; so do values above `i64::MAX`, which only `Uint` can hold.

This matters when comparing a decoded payload against a hand-built one, which is
exactly what a test does. `Value::Int(-7)` round-trips; `Value::Int(7)` does not,
and the test in `event.rs` pins that rather than leaving it to be discovered.

## Sentinels, not strings

The identifiers are newtypes whose constructors are fallible, so an empty
identifier cannot be built and therefore cannot be serialised:

```rust
HostId::new("")     // Err(ModelError::EmptyField { field: "host_id" })
AlertId::new("")    // Err(ModelError::EmptyField { field: "alert_id" })
```

`HostId` and `ProviderId` hold an `Arc<str>`, not a `Box<str>`, because both are
cloned once per event on the sensor's hot path and a `Box` would make that a
malloc and a copy. The wire format cannot tell the difference: both serialise as
a plain JSON string.

`EventId` and `ProcessId` are `u64` and `u32` newtypes instead, because zero is a
legitimate value for both: pid 0 and pid 4 are real processes on Windows, and the
response guards single them out for refusal *because* they are real rather than
because the number is missing.

## Limits, enforced at construction

`MAX_PAYLOAD_SIZE` is 64 KiB, and `Payload::new` counts the serialised size as it
writes rather than serialising and measuring afterwards:

```rust
let payload = Payload::new(value)?;   // ModelError::PayloadTooLarge { size, max }
let empty = Payload::empty();         // Value::Null, no measuring at all
```

Measuring while writing means an oversized payload is rejected without ever
building the oversized buffer, which matters because the input is attacker
influenced.

`Payload` is `#[serde(transparent)]`, so the JSON is the value and nothing else.
It used to serialize as `{"value":...,"value_size":N}`; the size is a ceiling
being enforced rather than a fact worth shipping, so it cost about fifteen bytes
per event and bought nothing. Dropping it is why `CURRENT_SCHEMA_VERSION` is
**2**: a `1` event and a `2` event are not interchangeable. The version travels
on every event so a mixed fleet can be reasoned about later.

## Classification and redaction

`classification.rs` is a table from field name to `DataClass`:

| Class | Retained | Redacted | Dropped in cold storage | Export needs opt-in |
|---|---|---|---|---|
| `Public` | 365 days | no | no | no |
| `Internal` | 365 days | no | no | no |
| `Sensitive` | 90 days | yes | yes | yes |

`class_of` fails closed: a field the table has never heard of is `Sensitive`. That
is the right default and the wrong whole story, which is why `class_of_known`
exists to report ignorance *as* ignorance — `Some(Sensitive)` and `None` are
different facts and redaction has to tell them apart.

`redact.rs` then makes one deliberately asymmetric decision:

- a field whose name is **explicitly sensitive** is replaced wholesale;
- a field whose name is **unknown** and whose value is an object or array is
  recursed into, so its leaves are judged on their own;
- a field whose name is **unknown** and whose value is a scalar is replaced,
  because there is no later opportunity to catch it.

Without the middle rule redaction is unusable on real telemetry: provider
payloads are keyed by provider-specific names, so every top-level key is unknown
and a naive fail-closed pass replaces the entire event with one `[REDACTED]`.
The cost of the rule is that the *keys* of an unknown container survive, which is
a real leak channel when a map is keyed by user-controlled data — so
`strip_sensitive` removes rather than replaces, and callers who cannot accept
that leak use it instead.

Both have `_in_place` variants. Prefer them on the hot path: a telemetry payload
is walked once per event, and the copying version rebuilds the whole tree.

## Testing

```sh
cargo test -p model
```

The tests worth knowing about are the ones pinning decisions rather than
plumbing:

- `an_explicitly_sensitive_field_is_removed_whole_whatever_it_holds` — a
  known-sensitive name is not recursed into, so `command_line` holding an object
  does not smuggle its leaves past the table;
- `a_provider_payload_survives_redaction` — the container rule, on a payload
  whose every top-level key is a name the table has never seen;
- `strip_fails_closed_on_unknown_names` — the difference between `redact` and
  `strip_sensitive`, stated as a test rather than as a comment;
- `redact_in_place_matches_redact` — the two implementations agree, because an
  in-place walk that disagrees with the copying one is a leak that only shows up
  under load.
