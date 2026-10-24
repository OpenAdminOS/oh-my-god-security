//! Coverage ledger: the record of which units of the target were examined,
//! with evidence links, and the transition rules that keep it honest.

use serde::{Deserialize, Serialize};

/// Every status a unit can hold.
pub const STATUSES: [&str; 6] = [
    "planned",
    "candidate",
    "covered",
    "deferred",
    "blocked",
    "out_of_scope",
];

/// Statuses that close a unit without examining it, so each needs a reason.
const NEEDS_NOTE: [&str; 3] = ["deferred", "blocked", "out_of_scope"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub units: Vec<Unit>,
    /// Fields this version does not know, kept so a rewrite never drops data.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Unit {
    pub id: String,
    #[serde(default)]
    pub surface: String,
    #[serde(default)]
    pub attack_classes: Vec<String>,
    #[serde(default = "planned")]
    pub status: String,
    /// What shows the unit was examined: finding fingerprints, candidate
    /// files, or repo paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Why a unit was deferred, blocked, or put out of scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn planned() -> String {
    "planned".into()
}

impl Unit {
    pub fn new(id: &str, surface: &str, attack_classes: &[&str], status: &str) -> Unit {
        Unit {
            id: id.into(),
            surface: surface.into(),
            attack_classes: attack_classes.iter().map(|s| s.to_string()).collect(),
            status: status.into(),
            ..Unit::default()
        }
    }

    fn has_note(&self) -> bool {
        self.note.as_deref().is_some_and(|n| !n.trim().is_empty())
    }
}

/// Rule violations for one unit, without the "units[i]" prefix.
fn unit_errors(u: &Unit) -> Vec<String> {
    let mut errors = Vec::new();
    if !STATUSES.contains(&u.status.as_str()) {
        errors.push(format!(
            "status '{}' is not one of {}",
            u.status,
            STATUSES.join(", ")
        ));
    }
    if u.status == "covered" && u.evidence.iter().all(|e| e.trim().is_empty()) {
        errors.push("covered requires at least one evidence reference".into());
    }
    if NEEDS_NOTE.contains(&u.status.as_str()) && !u.has_note() {
        errors.push(format!("{} requires a note giving the reason", u.status));
    }
    errors
}

/// Every structural and transition rule violation in the ledger.
pub fn validate_ledger(ledger: &Ledger) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (i, u) in ledger.units.iter().enumerate() {
        if u.id.trim().is_empty() {
            errors.push(format!("units[{i}]: id is empty"));
            continue;
        }
        if !seen.insert(u.id.as_str()) {
            errors.push(format!("units[{i}] '{}': duplicate unit id", u.id));
        }
        for e in unit_errors(u) {
            errors.push(format!("units[{i}] '{}': {e}", u.id));
        }
    }
    errors
}

/// Add a unit. Fails on a duplicate id or an unknown status.
pub fn add_unit(ledger: &mut Ledger, unit: Unit) -> Result<(), String> {
    if unit.id.trim().is_empty() {
        return Err("unit id is empty".into());
    }
    if ledger.units.iter().any(|u| u.id == unit.id) {
        return Err(format!("ledger unit already exists: {}", unit.id));
    }
    let errors = unit_errors(&unit);
    if !errors.is_empty() {
        return Err(format!("{}: {}", unit.id, errors.join("; ")));
    }
    ledger.units.push(unit);
    Ok(())
}

/// Move a unit to `status`, appending evidence and replacing the note when
/// given. The change is applied only if the resulting unit obeys the rules.
pub fn set_status(
    ledger: &mut Ledger,
    id: &str,
    status: &str,
    evidence: &[String],
    note: Option<&str>,
) -> Result<(), String> {
    let unit = ledger
        .units
        .iter_mut()
        .find(|u| u.id == id)
        .ok_or_else(|| format!("ledger unit not found: {id}"))?;
    let mut next = unit.clone();
    next.status = status.into();
    for e in evidence {
        let e = e.trim();
        if !e.is_empty() && !next.evidence.iter().any(|x| x == e) {
            next.evidence.push(e.to_string());
        }
    }
    if let Some(n) = note {
        next.note = Some(n.trim().to_string()).filter(|n| !n.is_empty());
    }
    let errors = unit_errors(&next);
    if !errors.is_empty() {
        return Err(format!("{id}: {}", errors.join("; ")));
    }
    *unit = next;
    Ok(())
}

/// One line per unit for reports, for example "covered: route:x (2 evidence)".
pub fn coverage_lines(ledger: &Ledger) -> Vec<String> {
    ledger
        .units
        .iter()
        .map(|u| {
            let mut line = format!("{}: {}", u.status, u.id);
            if !u.evidence.is_empty() {
                line.push_str(&format!(" ({} evidence)", u.evidence.len()));
            }
            if let Some(n) = u.note.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
                line.push_str(&format!(", note: {n}"));
            }
            line
        })
        .collect()
}
