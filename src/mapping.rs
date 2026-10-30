//! Source-only mapping checklists. No target syntax is evaluated or imported.
use crate::ledger::{Ledger, Unit};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn refs<'a>(u: &'a Unit, key: &str) -> Result<Vec<&'a str>, String> {
    let values = u
        .extra
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} requires an array of unit ids"))?;
    if values.is_empty() || values.len() > 256 {
        return Err(format!("{key} requires 1 to 256 references"));
    }
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|v| {
            let id = v
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| format!("{key} contains an invalid reference"))?;
            if id == u.id || !seen.insert(id) {
                return Err(format!("{key} contains a self or duplicate reference"));
            }
            Ok(id)
        })
        .collect()
}

pub fn unit_errors(u: &Unit) -> Vec<String> {
    let mut errors = Vec::new();
    let checklist = u.extra.get("checklist").and_then(Value::as_str);
    let broad = u.id.starts_with("stack:") || u.id.starts_with("project:");
    if ["covered", "out_of_scope"].contains(&u.status.as_str()) {
        if broad || checklist.is_some() {
            if let Err(e) = refs(u, "child_units") {
                errors.push(e);
            }
        }
        if checklist == Some("operations") {
            if u.extra.get("syntax_review").and_then(Value::as_str) != Some("complete") {
                errors.push("operation checklist requires complete source-only syntax_review; uncertain syntax remains blocked".into());
            }
            let operations = u.extra.get("operations").and_then(Value::as_object);
            if !operations.is_some_and(|ops| {
                !ops.is_empty()
                    && ops.len() <= 256
                    && ops.iter().all(|(op, id)| {
                        !op.trim().is_empty()
                            && id.as_str().is_some_and(|id| {
                                refs(u, "child_units").is_ok_and(|children| children.contains(&id))
                            })
                    })
            }) {
                errors.push(
                    "operations must map every source-reviewed method/operation to a child unit"
                        .into(),
                );
            }
        }
        if u.extra.get("partial").and_then(Value::as_bool) == Some(true) {
            if let Err(e) = refs(u, "residual_units") {
                errors.push(e);
            }
        }
    }
    if u.extra.get("partial").is_some_and(|v| !v.is_boolean()) {
        errors.push("partial must be boolean".into());
    }
    if u.extra
        .get("checklist")
        .is_some_and(|v| !matches!(v.as_str(), Some("partition" | "operations")))
    {
        errors.push("checklist must be partition or operations".into());
    }
    if let Some(value) = u.extra.get("scope_paths") {
        let paths = value.as_array();
        if !paths.is_some_and(|paths| {
            let mut seen = BTreeSet::new();
            !paths.is_empty()
                && paths.len() <= 256
                && paths.iter().all(|p| {
                    p.as_str().is_some_and(|p| {
                        !p.trim().is_empty()
                            && crate::paths::safe_relative(Path::new(p))
                            && seen.insert(p)
                    })
                })
        }) {
            errors.push("scope_paths requires 1 to 256 unique relative source scopes".into());
        }
    }
    if u.extra
        .get("syntax_review")
        .is_some_and(|v| !matches!(v.as_str(), Some("complete" | "uncertain")))
    {
        errors.push("syntax_review must be complete or uncertain".into());
    }
    errors
}

fn overlap(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with(['/', '#']))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with(['/', '#']))
}

/// Validate links even on open units, so a later transition cannot conceal an
/// invalid residual. Closed checklists require fully reconciled children.
pub fn partition_errors(ledger: &Ledger) -> Vec<String> {
    let mut errors = Vec::new();
    let index: BTreeMap<_, _> = ledger.units.iter().map(|u| (u.id.as_str(), u)).collect();
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut owners: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for u in &ledger.units {
        for key in ["child_units", "residual_units"] {
            if !u.extra.contains_key(key) {
                continue;
            }
            let ids = match refs(u, key) {
                Ok(ids) => ids,
                Err(e) => {
                    errors.push(format!("{}: {e}", u.id));
                    continue;
                }
            };
            for id in ids {
                edges.entry(&u.id).or_default().push(id);
                let Some(child) = index.get(id) else {
                    errors.push(format!("{}: {key} reference '{id}' is missing", u.id));
                    continue;
                };
                if key == "child_units" && ["covered", "out_of_scope"].contains(&u.status.as_str())
                {
                    if !["covered", "out_of_scope"].contains(&child.status.as_str()) {
                        errors.push(format!("{}: child '{id}' remains {}", u.id, child.status));
                    }
                    let scopes = child.extra.get("scope_paths").and_then(Value::as_array);
                    if !scopes.is_some_and(|s| {
                        !s.is_empty()
                            && s.len() <= 256
                            && s.iter().all(|v| {
                                v.as_str().is_some_and(|p| {
                                    !p.trim().is_empty()
                                        && crate::paths::safe_relative(Path::new(p))
                                })
                            })
                    }) {
                        errors.push(format!(
                            "{}: child '{id}' needs bounded relative scope_paths",
                            u.id
                        ));
                    }
                    if child.extra.contains_key("child_units") {
                        continue;
                    }
                    if child.attack_classes.is_empty() && !u.attack_classes.is_empty() {
                        errors.push(format!("{}: child '{id}' must name its attack class", u.id));
                    }
                    if let Some(scopes) = scopes {
                        for scope in scopes.iter().filter_map(Value::as_str) {
                            for class in &child.attack_classes {
                                for ((prior_scope, prior_class), prior_id) in &owners {
                                    if *prior_id != id
                                        && *prior_class == class
                                        && overlap(scope, prior_scope)
                                    {
                                        errors.push(format!("overlapping ownership: '{prior_id}' and '{id}' for {scope} class {class}"));
                                    }
                                }
                                owners.insert((scope, class), id);
                            }
                        }
                    }
                }
            }
        }
    }
    for start in edges.keys() {
        let mut pending = edges.get(start).cloned().unwrap_or_default();
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if id == *start {
                errors.push(format!("{start}: partition/residual cycle"));
                break;
            }
            if seen.insert(id) {
                pending.extend(edges.get(id).into_iter().flatten().copied());
            }
        }
    }
    errors
}

/// Conservative hints only. Every matching file remains a checklist until a
/// source review enumerates its operations. No inferred absence proves safety.
pub fn native_units(target: &Path, paths: &[PathBuf]) -> Vec<Unit> {
    let mut units = Vec::new();
    for path in paths
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "swift"))
    {
        if crate::paths::classify_file(target, path) != crate::paths::Class::Code {
            continue;
        }
        let Ok(bytes) = crate::platform::read_bounded_in(target, path, 1 << 20) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let rel = crate::paths::display(path);
        for (kind, class, found) in [
            (
                "listener-callers",
                "ipc_authorization",
                text.contains("NSXPC")
                    || text.contains("shouldAcceptNewConnection")
                    || text.contains("XPCListener"),
            ),
            (
                "credential-return",
                "secret_disclosure",
                [
                    "SecItemCopyMatching",
                    "kSecReturnData",
                    "password",
                    "credential",
                ]
                .iter()
                .any(|s| text.contains(s)),
            ),
        ] {
            if found {
                let mut unit =
                    Unit::new(&format!("native:{kind}:{rel}"), &rel, &[class], "planned");
                unit.extra
                    .insert("checklist".into(), Value::from("operations"));
                unit.note = Some("Source hint only: enumerate listener/caller checks or credential-return operations and split into bounded child units. Uncertain syntax remains blocked.".into());
                units.push(unit);
            }
        }
    }
    units
}

/// Merge only mapping metadata from a bounded JSON object. Callers hold the
/// ledger lock and publish only after transition and graph validation pass.
pub fn apply_metadata(unit: &mut Unit, text: &str) -> Result<(), String> {
    if text.len() > 65536 {
        return Err("mapping metadata exceeds 64 KiB".into());
    }
    let v = crate::shape::strict_json(text)?;
    let object = v.as_object().ok_or("mapping metadata must be an object")?;
    for key in object.keys() {
        if ![
            "child_units",
            "residual_units",
            "scope_paths",
            "partial",
            "checklist",
            "syntax_review",
            "operations",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unknown mapping field {key}"));
        }
    }
    for (key, value) in object {
        unit.extra.insert(key.clone(), value.clone());
    }
    Ok(())
}
