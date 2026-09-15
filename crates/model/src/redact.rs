use crate::classification::{REDACTED, class_of};
use crate::value::{Map, Value};

pub fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => redact_object(map),
        Value::Array(arr) => Value::Array(arr.iter().map(redact).collect()),
        _ => value.clone(),
    }
}

pub fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if class_of(k).requires_redaction() {
                    *v = Value::String(REDACTED.into());
                } else {
                    redact_in_place(v);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_in_place(v);
            }
        }
        _ => {}
    }
}

fn redact_object(map: &Map) -> Value {
    let mut out = Map::with_capacity(map.len());
    for (k, v) in map {
        if class_of(k).requires_redaction() {
            out.insert(k.clone(), Value::String(REDACTED.into()));
        } else {
            out.insert(k.clone(), redact(v));
        }
    }
    Value::Object(out)
}

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
    fn redact_in_place_matches_redact() {
        let mut a = obj(&[("user", Value::String("alice".into()))]);
        let b = redact(&a);
        redact_in_place(&mut a);
        assert_eq!(a, b);
    }
}
