use crate::{Failure, Limits};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::fmt;

// Allocation-free lexical ceiling before serde allocates decoded strings. Raw
// escaped string bytes count toward the ceiling as well as decoded UTF-8 bytes.
pub(crate) fn parse(bytes: &[u8], limits: Limits) -> Result<Value, Failure> {
    let mut quoted = false;
    let mut escaped = false;
    let mut length = 0;
    for &byte in bytes {
        if quoted {
            if byte == b'"' && !escaped {
                quoted = false;
                continue;
            }
            length += 1;
            if length > limits.string_bytes {
                return Err(Failure::Capacity);
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            }
        } else if byte == b'"' {
            quoted = true;
            length = 0;
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let capacity = Cell::new(false);
    let value = Seed {
        limits,
        depth: 0,
        capacity: &capacity,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| {
        if capacity.get() {
            Failure::Capacity
        } else {
            Failure::Malformed
        }
    })?;
    deserializer.end().map_err(|_| Failure::Malformed)?;
    Ok(value)
}

#[derive(Clone, Copy)]
struct Seed<'a> {
    limits: Limits,
    depth: usize,
    capacity: &'a Cell<bool>,
}
struct RejectExcess<'a>(&'a Cell<bool>);
impl<'de> DeserializeSeed<'de> for RejectExcess<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        self.0.set(true);
        Err(de::Error::custom("capacity"))
    }
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.depth >= self.limits.json_depth {
            self.capacity.set(true);
            return Err(de::Error::custom("capacity"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("malformed"))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        let child = Seed {
            depth: self.depth + 1,
            ..self
        };
        while values.len() < self.limits.json_array_items {
            match seq.next_element_seed(child)? {
                Some(v) => {
                    values.reserve_exact(1);
                    values.push(v);
                }
                None => return Ok(Value::Array(values)),
            }
        }
        // SeqAccess checks for the closing bracket; an excess element is
        // rejected without invoking its deserializer or allocating nested data.
        seq.next_element_seed(RejectExcess(self.capacity))?;
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        let child = Seed {
            depth: self.depth + 1,
            ..self
        };
        while values.len() < self.limits.json_members {
            let Some(key) = map.next_key::<String>()? else {
                return Ok(Value::Object(values));
            };
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate"));
            }
            values.insert(key, map.next_value_seed(child)?);
        }
        if map.next_key::<de::IgnoredAny>()?.is_some() {
            self.capacity.set(true);
            return Err(de::Error::custom("capacity"));
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excess_array_element_is_rejected_without_parsing_nested_value() {
        let limits = Limits {
            json_array_items: 1,
            ..Limits::default()
        };
        assert_eq!(parse(b"[0]", limits), Ok(serde_json::json!([0])));

        let mut excess = format!("[0,{}", "[".repeat(4096));
        // Even an unfinished excess value must fail at admission, not while
        // traversing nested containers to discover the malformed suffix.
        assert_eq!(parse(excess.as_bytes(), limits), Err(Failure::Capacity));
        excess.push('0');
        excess.push_str(&"]".repeat(4097));
        assert_eq!(parse(excess.as_bytes(), limits), Err(Failure::Capacity));
    }
}
