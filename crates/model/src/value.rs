use indexmap::IndexMap;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub type Map = IndexMap<Box<str>, Value>;

#[derive(Debug, Clone, PartialEq)]
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

impl Value {
    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Uint(u) => i64::try_from(*u).ok(),
            _ => None,
        }
    }

    #[inline]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(u) => Some(*u),
            Value::Int(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            Value::Uint(u) => Some(*u as f64),
            _ => None,
        }
    }

    #[inline]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    #[inline]
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    #[inline]
    pub fn as_object(&self) -> Option<&Map> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    #[inline]
    pub fn as_object_mut(&mut self) -> Option<&mut Map> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    #[inline]
    pub fn get_ref(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }

    #[inline]
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.as_object_mut().and_then(|o| o.get_mut(key))
    }

    #[inline]
    pub fn get(&self, key: &str) -> Value {
        self.get_ref(key).cloned().unwrap_or(Value::Null)
    }

    #[inline]
    pub fn get_index(&self, index: usize) -> Value {
        self.as_array()
            .and_then(|a| a.get(index))
            .cloned()
            .unwrap_or(Value::Null)
    }

    #[inline]
    pub fn get_index_ref(&self, index: usize) -> Option<&Value> {
        self.as_array().and_then(|a| a.get(index))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
            Value::String(s) => s.is_empty(),
            Value::Null => true,
            _ => false,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Uint(_) => "uint",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

impl From<bool> for Value {
    #[inline]
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<i64> for Value {
    #[inline]
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}
impl From<i32> for Value {
    #[inline]
    fn from(v: i32) -> Self {
        Value::Int(v as i64)
    }
}
impl From<u64> for Value {
    #[inline]
    fn from(v: u64) -> Self {
        Value::Uint(v)
    }
}
impl From<u32> for Value {
    #[inline]
    fn from(v: u32) -> Self {
        Value::Uint(v as u64)
    }
}
impl From<usize> for Value {
    #[inline]
    fn from(v: usize) -> Self {
        Value::Uint(v as u64)
    }
}
impl From<f64> for Value {
    #[inline]
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}
impl From<f32> for Value {
    #[inline]
    fn from(v: f32) -> Self {
        Value::Float(v as f64)
    }
}
impl From<String> for Value {
    #[inline]
    fn from(v: String) -> Self {
        Value::String(v.into_boxed_str())
    }
}
impl From<&str> for Value {
    #[inline]
    fn from(v: &str) -> Self {
        Value::String(v.into())
    }
}
impl From<Box<str>> for Value {
    #[inline]
    fn from(v: Box<str>) -> Self {
        Value::String(v)
    }
}
impl From<Vec<Value>> for Value {
    #[inline]
    fn from(v: Vec<Value>) -> Self {
        Value::Array(v)
    }
}
impl From<Map> for Value {
    #[inline]
    fn from(v: Map) -> Self {
        Value::Object(v)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    #[inline]
    fn from(v: Option<T>) -> Self {
        match v {
            Some(x) => x.into(),
            None => Value::Null,
        }
    }
}

impl Default for Value {
    #[inline]
    fn default() -> Self {
        Value::Null
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Uint(u) => write!(f, "{u}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::String(s) => write!(f, "{s:?}"),
            Value::Array(a) => {
                f.write_str("[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Object(o) => {
                f.write_str("{")?;
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{k:?}:{v}")?;
                }
                f.write_str("}")
            }
        }
    }
}

impl Serialize for Value {
    #[inline]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Value::Null => s.serialize_unit(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(i) => s.serialize_i64(*i),
            Value::Uint(u) => s.serialize_u64(*u),
            Value::Float(f) => s.serialize_f64(*f),
            Value::String(st) => s.serialize_str(st),
            Value::Array(a) => a.serialize(s),
            Value::Object(o) => o.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any valid value")
            }

            #[inline]
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }

            #[inline]
            fn visit_i8<E>(self, v: i8) -> Result<Value, E> {
                Ok(Value::Int(v as i64))
            }
            #[inline]
            fn visit_i16<E>(self, v: i16) -> Result<Value, E> {
                Ok(Value::Int(v as i64))
            }
            #[inline]
            fn visit_i32<E>(self, v: i32) -> Result<Value, E> {
                Ok(Value::Int(v as i64))
            }
            #[inline]
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::Int(v))
            }
            #[inline]
            fn visit_i128<E>(self, v: i128) -> Result<Value, E> {
                match i64::try_from(v) {
                    Ok(i) => Ok(Value::Int(i)),
                    Err(_) => Ok(Value::Float(v as f64)),
                }
            }

            #[inline]
            fn visit_u8<E>(self, v: u8) -> Result<Value, E> {
                Ok(Value::Uint(v as u64))
            }
            #[inline]
            fn visit_u16<E>(self, v: u16) -> Result<Value, E> {
                Ok(Value::Uint(v as u64))
            }
            #[inline]
            fn visit_u32<E>(self, v: u32) -> Result<Value, E> {
                Ok(Value::Uint(v as u64))
            }
            #[inline]
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Uint(v))
            }
            #[inline]
            fn visit_u128<E>(self, v: u128) -> Result<Value, E> {
                match u64::try_from(v) {
                    Ok(u) => Ok(Value::Uint(u)),
                    Err(_) => Ok(Value::Float(v as f64)),
                }
            }

            #[inline]
            fn visit_f32<E>(self, v: f32) -> Result<Value, E> {
                Ok(Value::Float(v as f64))
            }
            #[inline]
            fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
                Ok(Value::Float(v))
            }

            #[inline]
            fn visit_char<E>(self, v: char) -> Result<Value, E> {
                let mut buf = [0u8; 4];
                Ok(Value::String(v.encode_utf8(&mut buf).into()))
            }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.into()))
            }
            #[inline]
            fn visit_string<E>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v.into_boxed_str()))
            }

            #[inline]
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Value, E>
            where
                E: de::Error,
            {
                match std::str::from_utf8(v) {
                    Ok(s) => Ok(Value::String(s.into())),
                    Err(e) => Err(E::custom(e)),
                }
            }
            #[inline]
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Value, E>
            where
                E: de::Error,
            {
                match String::from_utf8(v) {
                    Ok(s) => Ok(Value::String(s.into_boxed_str())),
                    Err(e) => Err(E::custom(e)),
                }
            }

            #[inline]
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            #[inline]
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            #[inline]
            fn visit_some<D>(self, d: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Value::deserialize(d)
            }

            fn visit_newtype_struct<D>(self, d: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Value::deserialize(d)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(elem) = seq.next_element()? {
                    v.push(elem);
                }
                Ok(Value::Array(v))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut obj = Map::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((k, val)) = map.next_entry::<Box<str>, Value>()? {
                    obj.insert(k, val);
                }
                Ok(Value::Object(obj))
            }
        }

        d.deserialize_any(ValueVisitor)
    }
}
