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

fn normalized_scope(scope: &str, root: Option<&Path>) -> Result<String, String> {
    let (path, operation) = scope.split_once('#').unwrap_or((scope, ""));
    let root = root.ok_or("closing partitions requires scope_root target context; migrate the legacy ledger before closure")?;
    let mut normalized = canonical_scope_path(root, Path::new(path))?;
    if scope.contains('#') {
        normalized.push('#');
        normalized.push_str(operation);
    }
    Ok(normalized)
}

// Resolve each component using the target filesystem, rather than realpath's
// caller-supplied casing on APFS. Exact names on case-sensitive volumes remain
// distinct. Directory scopes and operation suffixes retain their hierarchy.
fn canonical_scope_path(root: &Path, path: &Path) -> Result<String, String> {
    if !root.is_absolute() || !crate::paths::safe_relative(path) {
        return Err("scope target and relative path are invalid".into());
    }
    // Inspect the root itself before enumerating any target entries.
    reject_scope_link(root)?;
    let canonical_root =
        std::fs::canonicalize(root).map_err(|_| "scope target directory is unavailable")?;
    let mut current = canonical_root.clone();
    let mut relative = PathBuf::new();
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let requested = current.join(name);
        let entries: Vec<_> = std::fs::read_dir(&current)
            .map_err(|_| "scope target directory is unavailable")?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()
            .map_err(|_| "scope target entry is unavailable")?;
        let name = scope_component(name, &entries, |entry| {
            same_object(&requested, &current.join(entry))
        })
        .ok_or("scope path is absent from target")?;
        current.push(&name);
        reject_scope_link(&current)?;
        let resolved =
            std::fs::canonicalize(&current).map_err(|_| "scope path is absent from target")?;
        if !resolved.starts_with(&canonical_root) {
            return Err("scope path escapes target".into());
        }
        relative.push(name);
    }
    Ok(crate::paths::display(&relative))
}

fn reject_scope_link(path: &Path) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "scope path is absent from target")?;
    if crate::platform::is_link(&metadata) {
        return Err("scope paths must not contain symlinks or reparse points".into());
    }
    Ok(())
}

fn scope_component(
    requested: &std::ffi::OsStr,
    entries: &[std::ffi::OsString],
    equivalent: impl Fn(&std::ffi::OsStr) -> bool,
) -> Option<std::ffi::OsString> {
    entries
        .iter()
        .find(|entry| entry.as_os_str() == requested)
        .or_else(|| entries.iter().find(|entry| equivalent(entry)))
        .cloned()
}

fn same_object(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(windows)]
    {
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        a == b
    }
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
    let root = ledger
        .extra
        .get("scope_root")
        .and_then(Value::as_str)
        .map(Path::new);
    if ledger.extra.contains_key("scope_root") && root.is_none() {
        errors.push("scope_root must be an absolute target path".into());
    }
    let index: BTreeMap<_, _> = ledger.units.iter().map(|u| (u.id.as_str(), u)).collect();
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut owners: BTreeMap<(String, &str), &str> = BTreeMap::new();
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
            if key == "child_units" && ["covered", "out_of_scope"].contains(&u.status.as_str()) {
                if root.is_none() {
                    errors.push(format!("{}: closing partitions requires scope_root target context; migrate the legacy ledger before closure", u.id));
                }
                for class in &u.attack_classes {
                    if !ids.iter().any(|id| {
                        index.get(id).is_some_and(|child| {
                            child.attack_classes.contains(class)
                                && (child.status == "covered"
                                    || (child.status == "out_of_scope"
                                        && child
                                            .note
                                            .as_deref()
                                            .is_some_and(|n| !n.trim().is_empty())))
                        })
                    }) {
                        errors.push(format!("{}: parent class '{class}' is unaccounted for by examined children or reasoned exclusions", u.id));
                    }
                }
            }
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
                            let scope = match normalized_scope(scope, root) {
                                Ok(scope) => scope,
                                Err(e) => {
                                    errors.push(format!("{id}: {e}"));
                                    continue;
                                }
                            };
                            for class in &child.attack_classes {
                                for ((prior_scope, prior_class), prior_id) in &owners {
                                    if *prior_id != id
                                        && *prior_class == class
                                        && overlap(&scope, prior_scope)
                                    {
                                        errors.push(format!("overlapping ownership: '{prior_id}' and '{id}' for {scope} class {class}"));
                                    }
                                }
                                owners.insert((scope.clone(), class), id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_sensitive_comparison_preserves_distinct_inventory_names() {
        let entries = vec!["decision.ts".into(), "DECISION.ts".into()];
        for name in ["decision.ts", "DECISION.ts"] {
            let result = scope_component(std::ffi::OsStr::new(name), &entries, |entry| {
                entry == std::ffi::OsStr::new(name)
            });
            assert_eq!(result.unwrap(), std::ffi::OsStr::new(name));
        }
        let entries = vec!["decision.ts".into()];
        assert!(
            scope_component(std::ffi::OsStr::new("DECISION.ts"), &entries, |_| false).is_none()
        );
        assert_eq!(
            scope_component(std::ffi::OsStr::new("DECISION.ts"), &entries, |_| true).unwrap(),
            std::ffi::OsStr::new("decision.ts")
        );
    }
}
