//! Field-level redaction.
//!
//! The rule is deliberately asymmetric between containers and scalars, and the
//! asymmetry is the whole design:
//!
//! * A field whose name is **explicitly** classified sensitive is replaced
//!   wholesale, whatever it holds.
//! * A field whose name is **unknown** but whose value is an object or array is
//!   recursed into, so its leaves get classified on their own merits.
//! * A field whose name is **unknown** and whose value is a scalar is replaced,
//!   because there is no later opportunity to catch it.
//!
//! Without the middle rule redaction is unusable on real telemetry. Provider
//! payloads are keyed by provider-specific field names, so every top-level key
//! is unknown to the table and a naive fail-closed pass would replace the entire
//! event with a single `"[REDACTED]"` — technically safe, operationally
//! worthless, and silent about having done it.
//!
//! The cost is that the *keys* of an unknown container survive. That is a real
//! leak channel when a map is keyed by user-controlled data, so callers who
//! cannot accept it should use [`strip_sensitive`], which removes rather than
//! replaces and therefore keeps nothing of an unknown field.

use crate::classification::{REDACTED, class_of, class_of_known};
use crate::value::{Map, Value};

/// Replace sensitive leaves, preserving the shape of everything else.
pub fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => redact_object(map),
        Value::Array(arr) => Value::Array(arr.iter().map(redact).collect()),
        _ => value.clone(),
    }
}

/// In-place equivalent of [`redact`]. Prefer this on the hot path: it avoids
/// rebuilding the tree, and a telemetry payload is walked once per event.
pub fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                match class_of_known(key) {
                    Some(class) if class.requires_redaction() => {
                        *entry = Value::String(REDACTED.into());
                    }
                    Some(_) => redact_in_place(entry),
                    None if is_container(entry) => redact_in_place(entry),
                    None => *entry = Value::String(REDACTED.into()),
                }
            }
        }
        Value::Array(arr) => {
            for entry in arr.iter_mut() {
                redact_in_place(entry);
            }
        }
        _ => {}
    }
}

fn redact_object(map: &Map) -> Value {
    let mut out = Map::with_capacity(map.len());
    for (key, value) in map {
        out.insert(key.clone(), redact_field(key, value));
    }
    Value::Object(out)
}

fn redact_field(key: &str, value: &Value) -> Value {
    match class_of_known(key) {
        Some(class) if class.requires_redaction() => Value::String(REDACTED.into()),
        Some(_) => redact(value),
        None if is_container(value) => redact(value),
        None => Value::String(REDACTED.into()),
    }
}

fn is_container(value: &Value) -> bool {
    matches!(value, Value::Object(_) | Value::Array(_))
}

/// Remove sensitive fields entirely, rather than replacing them.
///
/// This keeps the fail-closed behaviour for unknown names — an unfamiliar field
/// is dropped rather than preserved — which is what makes it the right tool for
/// cold storage, where the goal is to retain as little as possible.
pub fn strip_sensitive(value: &Value) -> Value {
    match value {
        Value::Object(map) => strip_sensitive_object(map),
        Value::Array(arr) => Value::Array(arr.iter().map(strip_sensitive).collect()),
        _ => value.clone(),
    }
}

pub fn strip_sensitive_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|k, _| !class_of(k).stripped_in_cold_storage());
            for (_, v) in map.iter_mut() {
                strip_sensitive_in_place(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_sensitive_in_place(v);
            }
        }
        _ => {}
    }
}

fn strip_sensitive_object(map: &Map) -> Value {
    let mut out = Map::with_capacity(map.len());
    for (k, v) in map {
        if class_of(k).stripped_in_cold_storage() {
            continue;
        }
        out.insert(k.clone(), strip_sensitive(v));
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(entries: &[(&str, Value)]) -> Value {
        let mut m = Map::new();
        for (k, v) in entries {
            m.insert((*k).into(), v.clone());
        }
        Value::Object(m)
    }

    #[test]
    fn redacts_sensitive_fields() {
        let v = obj(&[
            ("pid", Value::Int(42)),
            ("command_line", Value::String("rm -rf /".into())),
            ("user", Value::String("alice".into())),
        ]);
        let r = redact(&v);
        assert_eq!(r.get_ref("pid").unwrap().as_i64(), Some(42));
        assert_eq!(r.get_ref("command_line").unwrap().as_str(), Some(REDACTED));
        assert_eq!(r.get_ref("user").unwrap().as_str(), Some(REDACTED));
    }

    #[test]
    fn preserves_internal_and_public() {
        let v = obj(&[
            ("pid", Value::Int(42)),
            ("source_ip", Value::String("10.0.0.1".into())),
            ("hostname", Value::String("HOST-42".into())),
        ]);
        let r = redact(&v);
        assert_eq!(r.get_ref("source_ip").unwrap().as_str(), Some("10.0.0.1"));
        assert_eq!(r.get_ref("hostname").unwrap().as_str(), Some("HOST-42"));
    }

    #[test]
    fn redacts_nested() {
        let v = obj(&[(
            "outer",
            obj(&[("path", Value::String("/home/alice/x".into()))]),
        )]);
        let r = redact(&v);
        assert_eq!(
            r.get_ref("outer")
                .unwrap()
                .get_ref("path")
                .unwrap()
                .as_str(),
            Some(REDACTED)
        );
    }

    #[test]
    fn a_provider_payload_survives_redaction() {
        // The case that motivates the container rule: every top-level key here
        // is a provider-specific name the classification table has never seen.
        // A naive fail-closed pass would delete the entire event.
        let v = obj(&[
            ("ProcessSequenceNumber", Value::Uint(7)),
            (
                "ImageName",
                Value::String("C:\\Windows\\System32\\svchost.exe".into()),
            ),
            (
                "Nested",
                obj(&[("Payload", Value::String("SECRET".into()))]),
            ),
        ]);

        let r = redact(&v);
        assert_eq!(
            r.get_ref("ImageName").unwrap().as_str(),
            Some(REDACTED),
            "unknown leaf must still be redacted"
        );
        assert_eq!(
            r.get_ref("ProcessSequenceNumber").unwrap().as_str(),
            Some(REDACTED),
            "unknown scalar is replaced, so it stops being a number"
        );
        assert_eq!(r.get_ref("ProcessSequenceNumber").unwrap().as_u64(), None);
        assert_eq!(
            r.get_ref("Nested")
                .unwrap()
                .get_ref("Payload")
                .unwrap()
                .as_str(),
            Some(REDACTED)
        );
        // The container itself survived, which is what makes the event usable.
        assert!(r.get_ref("Nested").unwrap().as_object().is_some());
    }

    #[test]
    fn an_explicitly_sensitive_field_is_removed_whole_whatever_it_holds() {
        let v = obj(&[(
            "command_line",
            obj(&[("nested", Value::String("x".into()))]),
        )]);
        let r = redact(&v);
        assert_eq!(
            r.get_ref("command_line").unwrap().as_str(),
            Some(REDACTED),
            "a known-sensitive name does not get recursed into"
        );
    }

    #[test]
    fn arrays_are_walked() {
        let v = obj(&[(
            "answers",
            Value::Array(vec![
                Value::String("1.2.3.4".into()),
                obj(&[("path", Value::String("/etc/passwd".into()))]),
            ]),
        )]);
        let r = redact(&v);
        // `answers` is itself classified sensitive, so the array goes wholesale
        // and no element survives.
        assert_eq!(r.get_ref("answers").unwrap().as_str(), Some(REDACTED));
    }

    #[test]
    fn strip_removes_sensitive_entirely() {
        let v = obj(&[
            ("pid", Value::Int(42)),
            ("command_line", Value::String("rm -rf /".into())),
        ]);
        let s = strip_sensitive(&v);
        assert!(s.get_ref("pid").is_some());
        assert!(s.get_ref("command_line").is_none());
    }

    #[test]
    fn strip_fails_closed_on_unknown_names() {
        // Unlike `redact`, stripping an unfamiliar field keeps nothing of it.
        let v = obj(&[("ProviderSpecificField", Value::String("x".into()))]);
        let s = strip_sensitive(&v);
        assert!(s.get_ref("ProviderSpecificField").is_none());
    }

    #[test]
    fn redact_in_place_matches_redact() {
        for value in [
            obj(&[("user", Value::String("alice".into()))]),
            obj(&[(
                "unknown_container",
                obj(&[("user", Value::String("alice".into()))]),
            )]),
            obj(&[("unknown_scalar", Value::String("x".into()))]),
            obj(&[(
                "outer",
                Value::Array(vec![obj(&[("path", Value::String("/a".into()))])]),
            )]),
        ] {
            let expected = redact(&value);
            let mut actual = value.clone();
            redact_in_place(&mut actual);
            assert_eq!(actual, expected);
        }
    }
}
