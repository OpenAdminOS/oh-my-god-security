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
        if let Err(e) = parse_scopes(value) {
            errors.push(e);
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

// Keep path identity separate from operation identity, including after resolution.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Scope {
    path: String,
    operation: Option<String>,
}

fn valid_operation(operation: &str) -> bool {
    let mut bytes = operation.bytes();
    (1..=128).contains(&operation.len())
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn parse_scope(value: &Value) -> Result<Scope, String> {
    let (path, operation) = if let Some(legacy) = value.as_str() {
        if legacy.contains('#') {
            return Err("legacy scope_paths strings containing # are ambiguous: # may be part of the literal path or separate a path from an operation; migrate to objects, using {\"path\":\"dir/a#b\"} for a literal path or {\"path\":\"dir/a\",\"operation\":\"b\"} for an operation".into());
        }
        (legacy, None)
    } else {
        let object = value
            .as_object()
            .ok_or("scope_paths entries require path and optional operation")?;
        if object
            .keys()
            .any(|key| !["path", "operation"].contains(&key.as_str()))
        {
            return Err("scope_paths entries allow only path and operation".into());
        }
        let path = object
            .get("path")
            .and_then(Value::as_str)
            .ok_or("scope path must be a string")?;
        let operation = object
            .get("operation")
            .map(|v| {
                v.as_str()
                    .filter(|op| valid_operation(op))
                    .ok_or("scope operation must match [A-Za-z_][A-Za-z0-9_.:-]{0,127}")
            })
            .transpose()?;
        (path, operation)
    };
    if path.trim().is_empty() || !crate::paths::safe_relative(Path::new(path)) {
        return Err("scope path must be a nonempty relative source path".into());
    }
    Ok(Scope {
        path: path.into(),
        operation: operation.map(String::from),
    })
}

fn parse_scopes(value: &Value) -> Result<Vec<Scope>, String> {
    let values = value
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or("scope_paths requires 1 to 256 unique relative source scopes")?;
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|value| {
            let scope = parse_scope(value)?;
            if !seen.insert(scope.clone()) {
                return Err("scope_paths requires unique relative source scopes".into());
            }
            Ok(scope)
        })
        .collect()
}

fn normalized_scope(mut scope: Scope, root: Option<&Path>) -> Result<Scope, String> {
    let root = root.ok_or("closing partitions requires scope_root target context; run omgs ledger migrate --run <dir> before closure")?;
    scope.path = canonical_scope_path(root, Path::new(&scope.path))?;
    Ok(scope)
}

// Resolve each component using the target filesystem, rather than realpath's
// caller-supplied casing on APFS. Exact names on case-sensitive volumes remain
// distinct. Directory scopes retain their hierarchy; operations remain separate identifiers.
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

/// Bind editable mapping context to the target recorded by this run before
/// any scope paths are resolved. Legacy ledgers may remain open until migration.
pub fn validate_run_root(ledger: &Ledger, run: &Path) -> Result<(), String> {
    let Some(value) = ledger.extra.get("scope_root") else {
        return Ok(());
    };
    let root = value
        .as_str()
        .map(Path::new)
        .ok_or("scope_root must be an absolute target path")?;
    let target = run_target(run)?;
    if !root.is_absolute() || !same_object(root, &target) {
        return Err("scope_root must identify this run's target from run-metadata.json".into());
    }
    reject_scope_link(root)?;
    Ok(())
}

/// Migration accepts only the run's recorded, available target directory.
fn run_target(run: &Path) -> Result<PathBuf, String> {
    let meta = crate::runmeta::read(run)?;
    let target = meta
        .get("target")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or("run-metadata.json requires target")?;
    if !target.is_absolute() || !target.is_dir() {
        return Err("run target must be an available absolute directory".into());
    }
    reject_scope_link(&target)?;
    Ok(target)
}

pub fn migrate(ledger: &mut Ledger, run: &Path) -> Result<(), String> {
    validate_run_root(ledger, run)?;
    let target = run_target(run)?;
    let mut trial = ledger.clone();
    trial.extra.insert(
        "scope_root".into(),
        Value::from(target.to_str().ok_or("run target must be UTF-8")?),
    );
    let errors = crate::ledger::validate_ledger(&trial);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    *ledger = trial;
    Ok(())
}

fn overlap(a: &Scope, b: &Scope) -> bool {
    if a.path == b.path {
        return a.operation.is_none() || b.operation.is_none() || a.operation == b.operation;
    }
    // Only an entire directory scope owns descendant paths.
    (b.operation.is_none()
        && a.path
            .strip_prefix(&b.path)
            .is_some_and(|s| s.starts_with('/')))
        || (a.operation.is_none()
            && b.path
                .strip_prefix(&a.path)
                .is_some_and(|s| s.starts_with('/')))
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
    let mut owners: BTreeMap<(Scope, &str), &str> = BTreeMap::new();
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
                    errors.push(format!("{}: closing partitions requires scope_root target context; run omgs ledger migrate --run <dir> before closure", u.id));
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
                    // A reasoned exclusion (such as tests:excluded) claims no
                    // class and owns no scope, so it can be listed as a child
                    // without counting toward class coverage.
                    if child.status == "out_of_scope"
                        && child.attack_classes.is_empty()
                        && !child.extra.contains_key("scope_paths")
                        && !child.extra.contains_key("child_units")
                        && child.note.as_deref().is_some_and(|n| !n.trim().is_empty())
                    {
                        continue;
                    }
                    let scopes = child
                        .extra
                        .get("scope_paths")
                        .ok_or_else(|| "needs bounded relative scope_paths".to_string())
                        .and_then(parse_scopes);
                    if let Err(e) = &scopes {
                        errors.push(format!("{}: child '{id}' {e}", u.id));
                    }
                    if child.extra.contains_key("child_units") {
                        continue;
                    }
                    if child.attack_classes.is_empty() && !u.attack_classes.is_empty() {
                        errors.push(format!("{}: child '{id}' must name its attack class", u.id));
                    }
                    if let Ok(scopes) = scopes {
                        for scope in scopes {
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
                                        errors.push(format!("overlapping ownership: '{prior_id}' and '{id}' for {scope:?} class {class}"));
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
