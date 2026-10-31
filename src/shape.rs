//! Strict parsing of run inputs.
//!
//! serde_json and derived structs are lenient in ways that can turn malformed
//! evidence into a pass: a duplicate key keeps only its last value, a struct
//! accepts a JSON array (fields by position), an enum accepts an object form,
//! and an optional field accepts `null`. Run inputs are security evidence, so
//! they are read with a parser that rejects duplicate keys at every depth,
//! then checked so every schema object is a JSON object, every enum is a
//! string, and a present line is an integer. Any other shape is an error.

use serde::de::{DeserializeOwned, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// A JSON value whose objects never contained a duplicate key.
struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_string())))
    }
    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Strict(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate key '{key}'")));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}

/// Parse JSON text, rejecting duplicate keys at every depth.
pub fn strict_json(text: &str) -> Result<Value, String> {
    serde_json::from_str::<Strict>(text)
        .map(|s| s.0)
        .map_err(|e| e.to_string())
}

/// A present enum field must be a plain string, never serde's object form.
fn enum_string(obj: &Map<String, Value>, key: &str, at: &str) -> Result<(), String> {
    match obj.get(key) {
        None => Ok(()),
        // null is how an absent optional enum serializes; a required enum
        // given null still fails deserialization.
        Some(Value::String(_)) | Some(Value::Null) => Ok(()),
        Some(_) => Err(format!("{at}.{key} must be a string")),
    }
}

fn object<'a>(v: &'a Value, at: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{at} must be a JSON object"))
}

fn objects<'a>(v: &'a Value, at: &str) -> Result<Vec<&'a Map<String, Value>>, String> {
    v.as_array()
        .ok_or_else(|| format!("{at} must be a JSON array"))?
        .iter()
        .enumerate()
        .map(|(i, item)| object(item, &format!("{at}[{i}]")))
        .collect()
}

/// A location object whose `line`, when present, is an integer (not null).
fn location(v: &Value, at: &str) -> Result<(), String> {
    let loc = object(v, at)?;
    if let Some(line) = loc.get("line") {
        if line.as_u64().is_none_or(|n| n < 1) {
            return Err(format!(
                "{at}.line must be a one-based integer when present"
            ));
        }
    }
    Ok(())
}

fn parse<T: DeserializeOwned>(
    text: &str,
    what: &str,
    check: impl Fn(&Value) -> Result<(), String>,
) -> Result<T, String> {
    let value = strict_json(text).map_err(|e| format!("{what}: {e}"))?;
    check(&value).map_err(|e| format!("{what}: {e}"))?;
    serde_json::from_value(value).map_err(|e| format!("{what}: {e}"))
}

/// Parse a findings file (`{"findings": [...]}`).
pub fn findings(text: &str) -> Result<crate::model::FindingsFile, String> {
    parse(text, "findings", |v| {
        let top = object(v, "document")?;
        let list = top.get("findings").ok_or("findings is required")?;
        for (i, f) in objects(list, "findings")?.into_iter().enumerate() {
            let at = format!("findings[{i}]");
            if let Some(v) = f.get("verification") {
                object(v, &format!("{at}.verification"))?;
            }
            for key in ["verdict", "proof_tier", "severity"] {
                enum_string(f, key, &at)?;
            }
            if let Some(l) = f.get("location") {
                location(l, &format!("findings[{i}].location"))?;
            }
            if let Some(trace) = f.get("trace") {
                for (j, step) in objects(trace, &format!("{at}.trace"))?
                    .into_iter()
                    .enumerate()
                {
                    if let Some(l) = step.get("location") {
                        location(l, &format!("{at}.trace[{j}].location"))?;
                    }
                }
            }
            if let Some(ls) = f.get("locations") {
                let arr = ls
                    .as_array()
                    .ok_or_else(|| format!("findings[{i}].locations must be a JSON array"))?;
                for (j, l) in arr.iter().enumerate() {
                    location(l, &format!("findings[{i}].locations[{j}]"))?;
                }
            }
        }
        Ok(())
    })
}

/// Parse a coverage ledger (`{"units": [...]}`).
pub fn ledger(text: &str) -> Result<crate::ledger::Ledger, String> {
    parse(text, "ledger", |v| {
        let top = object(v, "document")?;
        for (i, u) in objects(top.get("units").ok_or("units is required")?, "units")?
            .into_iter()
            .enumerate()
        {
            let at = format!("units[{i}]");
            enum_string(u, "status", &at)?;
            if u.get("note").is_some_and(|n| !n.is_string()) {
                return Err(format!("{at}.note must be a string when present"));
            }
        }
        Ok(())
    })
}

/// Parse a hunter candidates file (`{"candidates": [...]}`).
pub fn candidates(text: &str) -> Result<crate::critic::CandidatesFile, String> {
    parse(text, "candidates", |v| {
        let top = object(v, "document")?;
        let list = top.get("candidates").ok_or("candidates is required")?;
        for (i, c) in objects(list, "candidates")?.into_iter().enumerate() {
            if let Some(l) = c.get("location") {
                location(l, &format!("candidates[{i}].location"))?;
            }
        }
        Ok(())
    })
}

/// Parse a sensors summary (`{"tools_run": [...], "tools_unavailable": [...], "hits": [...]}`).
pub fn sensors(text: &str) -> Result<crate::sensors::SensorsReport, String> {
    let mut report: crate::sensors::SensorsReport = parse(text, "sensors", |v| {
        let top = object(v, "document")?;
        for key in ["tools_run", "tools_unavailable"] {
            let ok = top
                .get(key)
                .and_then(|l| l.as_array())
                .is_some_and(|l| l.iter().all(|t| t.is_string()));
            if !ok {
                return Err(format!("{key} must be an array of strings"));
            }
        }
        let hits = top.get("hits").ok_or("hits is required")?;
        objects(hits, "hits")?;
        for hit in hits.as_array().unwrap() {
            if hit.get("tool").and_then(|v| v.as_str()) != Some("osv-scanner")
                && !hit
                    .get("occurrence")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(
                    "sensor hit lacks occurrence identity; regenerate sensor artifacts".into(),
                );
            }
            if hit.get("tool").and_then(|v| v.as_str()) == Some("osv-scanner") {
                let package = hit
                    .get("package")
                    .and_then(|v| v.as_object())
                    .ok_or("OSV hit lacks package identity; regenerate sensor artifacts")?;
                for key in ["name", "version", "ecosystem"] {
                    if !package
                        .get(key)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.trim().is_empty())
                    {
                        return Err(
                            "OSV hit lacks package identity; regenerate sensor artifacts".into(),
                        );
                    }
                }
            }
        }
        Ok(())
    })?;
    crate::sensors::deduplicate_hits(&mut report.hits);
    Ok(report)
}

/// Proof records and every nested survivor must be objects, never positional arrays.
pub fn proof(text: &str) -> Result<crate::proof::ProofRecord, String> {
    parse(text, "proof", |v| {
        let top = object(v, "document")?;
        if top.get("schema").and_then(|s| s.as_str()) != Some(crate::proof::SCHEMA) {
            return Err(format!("proof record predates the current policy or has an unsupported schema; rerun omgs prove to create a {} record", crate::proof::SCHEMA));
        }
        object(
            top.get("contract").ok_or("contract is required")?,
            "contract",
        )?;
        objects(
            top.get("survivors").ok_or("survivors is required")?,
            "survivors",
        )?;
        Ok(())
    })
}
