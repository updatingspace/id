//! Portable YDB cache values written by the transition Python release.
//! Legacy pickle rows must be backfilled before Rust serves their flows.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::{Error, Result};

pub const MAGIC: &[u8] = b"USID-CACHE\x01\n";
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum CacheValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    ByteArray(Vec<u8>),
    List(Vec<Self>),
    Tuple(Vec<Self>),
    Map(BTreeMap<String, Self>),
}

pub fn is_portable(raw: &[u8]) -> bool {
    raw.starts_with(MAGIC)
}

pub fn decode(raw: &[u8]) -> Result<CacheValue> {
    let json = raw.strip_prefix(MAGIC).ok_or(Error::Unsupported)?;
    let document: Value = serde_json::from_slice(json).map_err(|_| Error::Invalid)?;
    let envelope = document.as_object().ok_or(Error::Invalid)?;
    if envelope.len() != 2 || envelope.get("version") != Some(&json!(1)) {
        return Err(Error::Invalid);
    }
    unpack(envelope.get("value").ok_or(Error::Invalid)?, 0)
}

pub fn encode(value: &CacheValue) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(&json!({"version": 1, "value": pack(value, 0)?}))
        .map_err(|_| Error::Invalid)?;
    let mut output = Vec::with_capacity(MAGIC.len() + json.len());
    output.extend_from_slice(MAGIC);
    output.extend(json);
    Ok(output)
}

fn pack(value: &CacheValue, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(Error::Limit);
    }
    Ok(match value {
        CacheValue::Null => json!({"t":"null"}),
        CacheValue::Bool(v) => json!({"t":"bool","v":v}),
        CacheValue::Int(v) => json!({"t":"int","v":v.to_string()}),
        CacheValue::Float(v) if v.is_finite() => json!({"t":"float","v":v}),
        CacheValue::Float(_) => return Err(Error::Invalid),
        CacheValue::String(v) => json!({"t":"str","v":v}),
        CacheValue::Bytes(v) => json!({"t":"bytes","v":STANDARD.encode(v)}),
        CacheValue::ByteArray(v) => json!({"t":"bytearray","v":STANDARD.encode(v)}),
        CacheValue::List(v) | CacheValue::Tuple(v) => {
            let tag = if matches!(value, CacheValue::Tuple(_)) {
                "tuple"
            } else {
                "list"
            };
            json!({"t":tag,"v":v.iter().map(|item|pack(item,depth+1)).collect::<Result<Vec<_>>>()?})
        }
        CacheValue::Map(v) => {
            let pairs = v
                .iter()
                .map(|(key, item)| Ok(json!([key, pack(item, depth + 1)?])))
                .collect::<Result<Vec<_>>>()?;
            json!({"t":"map","v":pairs})
        }
    })
}

fn unpack(node: &Value, depth: usize) -> Result<CacheValue> {
    if depth > MAX_DEPTH {
        return Err(Error::Limit);
    }
    let object = node.as_object().ok_or(Error::Invalid)?;
    let tag = object
        .get("t")
        .and_then(Value::as_str)
        .ok_or(Error::Invalid)?;
    if tag == "null" && object.len() == 1 {
        return Ok(CacheValue::Null);
    }
    if object.len() != 2 {
        return Err(Error::Invalid);
    }
    let v = object.get("v").ok_or(Error::Invalid)?;
    Ok(match tag {
        "bool" => CacheValue::Bool(v.as_bool().ok_or(Error::Invalid)?),
        "int" => {
            let text = v.as_str().ok_or(Error::Invalid)?;
            let parsed: i64 = text.parse().map_err(|_| Error::Invalid)?;
            if parsed.to_string() != text {
                return Err(Error::Invalid);
            }
            CacheValue::Int(parsed)
        }
        "float" => {
            if !v.is_f64() {
                return Err(Error::Invalid);
            }
            let parsed = v.as_f64().ok_or(Error::Invalid)?;
            if !parsed.is_finite() {
                return Err(Error::Invalid);
            }
            CacheValue::Float(parsed)
        }
        "str" => CacheValue::String(v.as_str().ok_or(Error::Invalid)?.to_owned()),
        "bytes" | "bytearray" => {
            let bytes = STANDARD
                .decode(v.as_str().ok_or(Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
            if tag == "bytes" {
                CacheValue::Bytes(bytes)
            } else {
                CacheValue::ByteArray(bytes)
            }
        }
        "list" | "tuple" => {
            let items = v
                .as_array()
                .ok_or(Error::Invalid)?
                .iter()
                .map(|item| unpack(item, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            if tag == "list" {
                CacheValue::List(items)
            } else {
                CacheValue::Tuple(items)
            }
        }
        "map" => {
            let mut map = BTreeMap::new();
            for pair in v.as_array().ok_or(Error::Invalid)? {
                let pair = pair.as_array().ok_or(Error::Invalid)?;
                if pair.len() != 2 {
                    return Err(Error::Invalid);
                }
                let key = pair[0].as_str().ok_or(Error::Invalid)?.to_owned();
                if map.insert(key, unpack(&pair[1], depth + 1)?).is_some() {
                    return Err(Error::Invalid);
                }
            }
            CacheValue::Map(map)
        }
        _ => return Err(Error::Invalid),
    })
}
