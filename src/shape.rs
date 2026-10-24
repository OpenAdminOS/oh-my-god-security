//! Structural checks applied before deserializing run inputs.
//!
//! Serde's derived structs also accept a JSON array in place of an object
//! (fields by position) and `null` for an optional field. Run inputs are
//! security evidence, so every object the schemas declare must be a JSON
//! object, and an optional integer that is present must be an integer. Any
//! other shape is an error, never a silently empty or defaulted value.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

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
        if !line.is_u64() {
            return Err(format!("{at}.line must be a positive integer when present"));
        }
    }
    Ok(())
}

fn parse<T: DeserializeOwned>(
    text: &str,
    what: &str,
    check: impl Fn(&Value) -> Result<(), String>,
) -> Result<T, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("{what}: {e}"))?;
    check(&value).map_err(|e| format!("{what}: {e}"))?;
    serde_json::from_value(value).map_err(|e| format!("{what}: {e}"))
}

/// Parse a findings file (`{"findings": [...]}`).
pub fn findings(text: &str) -> Result<crate::model::FindingsFile, String> {
    parse(text, "findings", |v| {
        let top = object(v, "document")?;
        let list = top.get("findings").ok_or("findings is required")?;
        for (i, f) in objects(list, "findings")?.into_iter().enumerate() {
            if let Some(l) = f.get("location") {
                location(l, &format!("findings[{i}].location"))?;
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
        objects(top.get("units").ok_or("units is required")?, "units")?;
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
