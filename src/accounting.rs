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
}

pub type Accounting = BTreeMap<String, Usage>;
pub const ROLES: [&str; 4] = ["red-hunter", "blue-verifier", "evaluator", "green-fixer"];

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
    for role in ROLES {
        values.entry(role.into()).or_default();
    }
    Ok(values)
}

fn check_role(role: &str) -> Result<(), String> {
    if !ROLES.contains(&role) {
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
    all.iter()
        .map(|(role, u)| {
            let show =
                |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into());
            let cost = u
                .cost_usd
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into());
            format!(
                "{role}: tokens {}, cost USD {cost}, duration ms {}",
                show(u.tokens),
                show(u.duration_ms)
            )
        })
        .collect()
}
