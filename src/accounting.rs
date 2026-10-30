//! Host-supplied cumulative usage, never inferred from elapsed stage clocks.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_turn: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unreported: bool,
}

pub type Accounting = BTreeMap<String, Usage>;
pub const ROLES: [&str; 5] = [
    "host",
    "red-hunter",
    "blue-verifier",
    "evaluator",
    "green-fixer",
];

pub fn read(meta: &Map<String, Value>) -> Result<Accounting, String> {
    let mut values: Accounting = match meta.get("accounting") {
        Some(v) => {
            let roles = v.as_object().ok_or("accounting must be an object")?;
            if roles.values().any(|v| !v.is_object()) {
                return Err("accounting role usage must be an object".into());
            }
            serde_json::from_value(v.clone()).map_err(|e| format!("accounting: {e}"))?
        }
        None => BTreeMap::new(),
    };
    for (role, usage) in &values {
        check_role(role)?;
        if usage.cost_usd.is_some_and(|v| !v.is_finite() || v < 0.0) {
            return Err("accounting cost must be finite and non-negative".into());
        }
    }
    let turns = latest_turns(meta)?;
    for (role, usage) in &mut values {
        if let Some((_, id)) = role.split_once('@') {
            if let Some(turn) = turns.get(id) {
                usage.unreported = usage.covered_turn.as_ref() != Some(turn);
            }
        }
    }
    for role in ROLES {
        values.entry(role.into()).or_default();
    }
    Ok(values)
}

fn latest_turns(meta: &Map<String, Value>) -> Result<BTreeMap<String, String>, String> {
    let mut turns = BTreeMap::new();
    for record in crate::attempts::history(meta)? {
        if let crate::attempts::Event::Dispatch { id, turn, .. } = record.record {
            turns.insert(id, turn);
        }
    }
    Ok(turns)
}

/// Cumulative submissions cover the latest dispatched turn under the run lock.
pub fn submit(
    meta: &Map<String, Value>,
    values: &mut Accounting,
    supplied: Accounting,
) -> Result<(), String> {
    let turns = latest_turns(meta)?;
    for (role, mut usage) in supplied {
        usage.covered_turn = role
            .split_once('@')
            .and_then(|(_, id)| turns.get(id))
            .cloned();
        usage.unreported = false;
        values.insert(role, usage);
    }
    Ok(())
}

fn check_role(role: &str) -> Result<(), String> {
    let (base, attempt) = role
        .split_once('@')
        .map_or((role, None), |(r, id)| (r, Some(id)));
    if attempt.is_some_and(|id| id.trim().is_empty() || id.contains('@')) {
        return Err("accounting attempt id must not be blank or contain @".into());
    }
    if !ROLES.contains(&base) {
        return Err(format!(
            "accounting role must be one of {}",
            ROLES.join(", ")
        ));
    }
    Ok(())
}

/// Each entry replaces one role's cumulative totals. Empty fields and the
/// literal `unknown` both mean unavailable, including an explicit reset.
pub fn parse(entries: &[String]) -> Result<Accounting, String> {
    let mut out = BTreeMap::new();
    for entry in entries {
        let (role, fields) = entry
            .split_once('=')
            .ok_or("--accounting expects role=tokens,cost-usd,duration-ms")?;
        check_role(role)?;
        let fields: Vec<_> = fields.split(',').collect();
        if fields.len() != 3 {
            return Err("--accounting needs three comma-separated values".into());
        }
        let known = |s: &str| !s.is_empty() && s != "unknown";
        let integer = |s: &str| -> Result<Option<u64>, String> {
            if known(s) {
                Ok(Some(s.parse().map_err(|_| {
                    "accounting tokens and duration need non-negative integers"
                })?))
            } else {
                Ok(None)
            }
        };
        let cost_usd = if known(fields[1]) {
            let v: f64 = fields[1]
                .parse()
                .map_err(|_| "accounting cost needs a number")?;
            if !v.is_finite() || v < 0.0 {
                return Err("accounting cost must be finite and non-negative".into());
            }
            Some(v)
        } else {
            None
        };
        let usage = Usage {
            tokens: integer(fields[0])?,
            cost_usd,
            duration_ms: integer(fields[2])?,
            ..Default::default()
        };
        if out.insert(role.into(), usage).is_some() {
            return Err(format!("duplicate accounting role {role}"));
        }
    }
    Ok(out)
}

pub fn lines(values: &Accounting) -> Vec<String> {
    let mut all = Accounting::new();
    for role in ROLES {
        all.insert(role.into(), Usage::default());
    }
    all.extend(values.clone());
    for role in ROLES {
        let parts: Vec<_> = values
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{role}@")))
            .collect();
        if !parts.is_empty() {
            if let Some(legacy) = all
                .remove(role)
                .filter(|u| u.tokens.is_some() || u.cost_usd.is_some() || u.duration_ms.is_some())
            {
                all.insert(
                    format!("{role} (historical role total; excluded from attempt aggregate)"),
                    legacy,
                );
            }
        }
    }
    let mut lines: Vec<String> = all
        .iter()
        .map(|(role, u)| {
            let show =
                |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into());
            let cost = u
                .cost_usd
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into());
            format!(
                "{role}: tokens {}, cost USD {cost}, duration ms {}{}",
                show(u.tokens),
                show(u.duration_ms),
                if u.unreported {
                    "; later turn usage unknown"
                } else {
                    ""
                }
            )
        })
        .collect();
    for role in ROLES {
        let parts: Vec<_> = values
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{role}@")))
            .map(|(_, u)| u)
            .collect();
        if parts.is_empty() {
            continue;
        }
        let sum = |get: fn(&Usage) -> Option<u64>| {
            let total = parts
                .iter()
                .filter_map(|u| get(u))
                .try_fold(0u64, u64::checked_add);
            let unknown = parts
                .iter()
                .filter(|u| get(u).is_none() || u.unreported)
                .count();
            format!(
                "known subtotal {}, {unknown} unknown attempt(s)",
                total.map_or_else(|| "overflow".into(), |n| n.to_string())
            )
        };
        let cost: f64 = parts.iter().filter_map(|u| u.cost_usd).sum();
        let unknown_cost = parts
            .iter()
            .filter(|u| u.cost_usd.is_none() || u.unreported)
            .count();
        lines.push(format!("{role}: tokens {}; cost USD known subtotal {cost}, {unknown_cost} unknown attempt(s); duration ms {}. Aggregate {}", sum(|u| u.tokens), sum(|u| u.duration_ms), if parts.iter().all(|u| !u.unreported && u.tokens.is_some() && u.cost_usd.is_some() && u.duration_ms.is_some()) { "complete" } else { "incomplete" }));
    }
    lines
}

/// Sum cumulative entries once, preferring attempt totals over historical role
/// totals. Retain known subtotals when a continuation has unreported usage.
pub fn aggregate(meta: &Map<String, Value>) -> Result<Value, String> {
    let values = read(meta)?;
    let mut entries = Vec::new();
    for role in ROLES {
        let parts: Vec<_> = values
            .iter()
            .filter(|(key, _)| key.starts_with(&format!("{role}@")))
            .map(|(_, usage)| usage)
            .collect();
        if parts.is_empty() {
            if let Some(usage) = values.get(role) {
                // Host accounting is optional in historical runs.
                if role != "host"
                    || meta
                        .get("accounting")
                        .is_some_and(|v| v.get("host").is_some())
                {
                    entries.push(usage);
                }
            }
        } else {
            entries.extend(parts);
        }
    }
    let mut out = serde_json::json!({"tokens":null,"input_tokens":null,"output_tokens":null,"calls":null,"cost_usd":null,"duration_ms":null,"roles":values,"known_subtotals":{},"unknown_usage":{}});
    for field in ["tokens", "cost_usd", "duration_ms"] {
        let mut total = 0u64;
        let mut cost = 0.0;
        let mut unknown = 0;
        for usage in &entries {
            let known = match field {
                "cost_usd" => {
                    cost += usage.cost_usd.unwrap_or_default();
                    usage.cost_usd.is_some()
                }
                _ => {
                    let value = if field == "tokens" {
                        usage.tokens
                    } else {
                        usage.duration_ms
                    };
                    total = total
                        .checked_add(value.unwrap_or_default())
                        .ok_or("accounting integer overflow")?;
                    value.is_some()
                }
            };
            if !known || usage.unreported {
                unknown += 1;
            }
        }
        if !cost.is_finite() {
            return Err("accounting sum overflow".into());
        }
        let subtotal = if field == "cost_usd" {
            serde_json::json!(cost)
        } else {
            serde_json::json!(total)
        };
        out["known_subtotals"][field] = subtotal.clone();
        out["unknown_usage"][field] = serde_json::json!(unknown);
        if unknown == 0 {
            out[field] = subtotal;
        }
    }
    Ok(out)
}
