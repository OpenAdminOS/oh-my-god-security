//! One cumulative allowance from disjoint per-run counters. Child usage is
//! never copied into its parent's counters.
use crate::runmeta;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct Allowance {
    pub budget_agent_calls: Option<u64>,
    pub budget_semantics: &'static str,
    pub calls_and_proofs_used: u64,
    pub remaining: Option<u64>,
    pub run_count: usize,
}

/// Resolve only the parent as the trusted runs directory. The run entry
/// itself is never canonicalized through a symlink or reparse point.
fn run_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let name = absolute
        .file_name()
        .ok_or("run path needs a directory name")?;
    if absolute
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("run path must not contain parent traversal".into());
    }
    crate::platform::safe_path(&absolute)
        .map_err(|e| format!("owner-private run storage {}: {e}", absolute.display()))?;
    let parent = std::fs::canonicalize(absolute.parent().ok_or("run path needs a parent")?)
        .map_err(|e| format!("runs directory {}: {e}", path.display()))?;
    let run = parent.join(name);
    let meta =
        std::fs::symlink_metadata(&run).map_err(|e| format!("run {}: {e}", run.display()))?;
    if crate::platform::is_link(&meta) || !meta.is_dir() {
        return Err(format!(
            "run {} must be a directory without symlinks or reparse points",
            run.display()
        ));
    }
    for dir in [&parent, &run] {
        crate::platform::check_private_dir(dir)
            .map_err(|e| format!("owner-private run storage {}: {e}", dir.display()))?;
    }
    Ok(run)
}

/// Open every component below the trusted directory without following links.
/// Unix uses openat(O_NOFOLLOW); Windows pins ancestors and rejects reparse
/// points on the opened handles, including run-metadata.json itself.
fn read_run(run: &Path) -> Result<Map<String, Value>, String> {
    let boundary = run.parent().ok_or("run path needs a parent")?;
    let relative = Path::new(run.file_name().ok_or("run path needs a name")?).join(runmeta::FILE);
    let bytes = crate::run_artifact::read(boundary, &relative, crate::run_artifact::METADATA_BYTES)
        .map_err(|e| {
            format!(
                "linked run {}: no-follow metadata read failed: {e}",
                run.display()
            )
        })?;
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let Value::Object(meta) = crate::shape::strict_json(text)? else {
        return Err("run metadata must be an object".into());
    };
    runmeta::check_numeric_fields(&meta)?;
    Ok(meta)
}

/// Proof setup must use the same no-follow reads as budget accounting.
pub fn metadata(run: &Path) -> Result<Map<String, Value>, String> {
    read_run(&run_path(run)?)
}

/// Refund only a validated family member. Broken links never redirect a
/// refund to external metadata or silently alter the remaining allowance.
pub fn release_proof(run: &Path) -> Result<(), String> {
    let run = run_path(run)?;
    let root = original(&run)?;
    runmeta::with_lock(&root, || {
        let update = || {
            allowance(&root)?;
            let mut meta = read_run(&run)?;
            if original(&run)? != root {
                return Err("linked run identity changed before refund".into());
            }
            let used = meta
                .get("proof_runs_used")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            meta.insert(
                "proof_runs_used".into(),
                Value::from(used.saturating_sub(1)),
            );
            runmeta::write_atomic(
                &run.join(runmeta::FILE),
                &serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
            )
        };
        if run == root {
            update()
        } else {
            runmeta::with_lock(&run, update)
        }
    })
}

fn run_id(meta: &Map<String, Value>) -> Result<&str, String> {
    meta.get("run_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| "linked run identity missing: run_id is required".into())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegisteredRun {
    path: PathBuf,
    run_id: String,
}

fn fix_runs(meta: &Map<String, Value>, boundary: &Path) -> Result<Vec<RegisteredRun>, String> {
    let Some(value) = meta.get("fix_runs") else {
        return Ok(Vec::new());
    };
    let runs: Vec<RegisteredRun> = serde_json::from_value(value.clone())
        .map_err(|e| format!("fix_runs must register paths and run identities: {e}"))?;
    for run in &runs {
        // Registration stores physical sibling paths. Reject alternate roots,
        // nested ancestors and traversal before any filesystem resolution.
        if run.path.parent() != Some(boundary)
            || !run.path.is_absolute()
            || run
                .path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("linked run is outside the trusted runs directory".into());
        }
        run_path(&run.path)?;
        if run.run_id.trim().is_empty() {
            return Err("registered run identity is empty".into());
        }
    }
    Ok(runs)
}

/// Resolve either the original run or a registered fix run to the same root.
pub fn original(run: &Path) -> Result<PathBuf, String> {
    let run = run_path(run)?;
    let meta = read_run(&run)?;
    let Some(parent) = meta.get("budget_parent") else {
        return Ok(run);
    };
    let parent = Path::new(parent.as_str().ok_or("budget_parent must be a path")?);
    if parent.parent() != run.parent() {
        return Err("budget_parent is outside the trusted runs directory".into());
    }
    let parent = run_path(parent)?;
    let root = read_run(&parent)?;
    if root.contains_key("budget_parent")
        || meta.get("budget_parent_id").and_then(Value::as_str) != Some(run_id(&root)?)
        || !fix_runs(&root, parent.parent().unwrap())?.iter().any(|r| {
            r.path == run && Some(r.run_id.as_str()) == meta.get("run_id").and_then(Value::as_str)
        })
    {
        return Err(
            "budget_parent must name the original run with this fix identity registered".into(),
        );
    }
    Ok(parent)
}

/// Caller holds the original run's lock. Missing or inconsistent links fail
/// closed instead of silently understating spent allowance.
pub fn allowance(root: &Path) -> Result<Allowance, String> {
    let root = run_path(root)?;
    let meta = read_run(&root)?;
    if meta.contains_key("budget_parent") {
        return Err("use the original run for cumulative accounting".into());
    }
    let cap = meta.get("budget_agent_calls").and_then(Value::as_u64);
    let linked = fix_runs(&meta, root.parent().unwrap())?;
    // Legacy standalone runs remain chargeable. Linked families require ids;
    // never infer an identity for an old registration that lacks one.
    let root_id = if linked.is_empty() {
        meta.get("run_id").and_then(Value::as_str).unwrap_or("")
    } else {
        run_id(&meta)?
    };
    let mut runs = vec![RegisteredRun {
        path: root.clone(),
        run_id: root_id.into(),
    }];
    runs.extend(linked);
    let mut seen = BTreeSet::new();
    let mut used = 0u64;
    for registered in &runs {
        let run = &registered.path;
        if !seen.insert(run) {
            return Err("duplicate run in cumulative budget".into());
        }
        let m = read_run(run)?;
        if m.get("run_id").and_then(Value::as_str).unwrap_or("") != registered.run_id {
            return Err(format!("linked run identity mismatch: {}", run.display()));
        }
        if run != &root {
            let parent = m
                .get("budget_parent")
                .and_then(Value::as_str)
                .ok_or("linked fix run has no budget_parent")?;
            if Path::new(parent) != root
                || m.get("budget_parent_id").and_then(Value::as_str) != Some(run_id(&meta)?)
                || !fix_runs(&m, root.parent().unwrap())?.is_empty()
            {
                return Err("fix run must link directly to its original run".into());
            }
        }
        for key in ["agent_calls_used", "proof_runs_used"] {
            used = used
                .checked_add(m.get(key).and_then(Value::as_u64).unwrap_or(0))
                .ok_or("cumulative budget usage overflow")?;
        }
    }
    Ok(Allowance {
        budget_agent_calls: cap,
        budget_semantics: "combined_calls_proofs_replays",
        calls_and_proofs_used: used,
        remaining: cap.map(|cap| cap.saturating_sub(used)),
        run_count: runs.len(),
    })
}

/// Serialize proof charging with fix registration and all other family proofs.
pub fn charge_proof(run: &Path) -> Result<(), String> {
    charge_proof_checked(run, || {})
}

fn charge_proof_checked(run: &Path, after_check: impl FnOnce()) -> Result<(), String> {
    let run = run_path(run)?;
    let root = original(&run)?;
    runmeta::with_lock(&root, || {
        let total = allowance(&root)?;
        if total.remaining == Some(0) {
            return Err(
                "run budget exhausted: cumulative original and fix allowance consumed".into(),
            );
        }
        after_check();
        let charge = |m: &mut Map<String, Value>| -> Result<(), String> {
            let calls = m
                .get("agent_calls_used")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let proofs = m
                .get("proof_runs_used")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if m.get("budget_agent_calls")
                .and_then(Value::as_u64)
                .is_some_and(|cap| u128::from(calls) + u128::from(proofs) >= u128::from(cap))
            {
                return Err("run budget exhausted: local run allowance consumed".into());
            }
            let next = proofs.checked_add(1).ok_or("proof_runs_used exhausted")?;
            m.insert("proof_runs_used".into(), Value::from(next));
            Ok(())
        };
        let expected_id = read_run(&run)?.get("run_id").cloned();
        let update = || {
            let mut meta = read_run(&run)?;
            if meta.get("run_id") != expected_id.as_ref() || original(&run)? != root {
                return Err("linked run identity changed before charging".into());
            }
            // Revalidate the whole family immediately before charging.
            if allowance(&root)?.remaining == Some(0) {
                return Err(
                    "run budget exhausted: cumulative original and fix allowance consumed".into(),
                );
            }
            charge(&mut meta)?;
            runmeta::write_atomic(
                &run.join(runmeta::FILE),
                &serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
            )
        };
        if run == root {
            update()
        } else {
            runmeta::with_lock(&run, update)
        }
    })
}

/// Initialize a fix with a computed cap and register it before returning it to
/// the caller. The original lock spans calculation, creation and registration.
pub fn init_fix(
    parent: &Path,
    family_cap: impl FnOnce(&Path) -> Result<Option<u64>, String>,
    init: impl FnOnce(&Path, &Map<String, Value>, Option<u64>) -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let root = original(parent)?;
    runmeta::with_lock(&root, || {
        let mut meta = read_run(&root)?;
        let cap = family_cap(&root)?;
        let used = allowance(&root)?.calls_and_proofs_used;
        let remaining = cap.map(|cap| cap.saturating_sub(used));
        run_id(&meta)?;
        let child = run_path(&init(&root, &meta, remaining)?)?;
        if child.parent() != root.parent() || child == root {
            return Err("fix run must be a distinct sibling in the trusted runs directory".into());
        }
        let child_id = run_id(&read_run(&child)?)?.to_string();
        runmeta::with_lock(&child, || {
            let mut m = read_run(&child)?;
            m.insert(
                "budget_parent".into(),
                Value::from(root.to_string_lossy().as_ref()),
            );
            m.insert("budget_parent_id".into(), Value::from(run_id(&meta)?));
            if run_id(&m)? != child_id {
                return Err("linked run identity changed during registration".into());
            }
            runmeta::write_atomic(
                &child.join(runmeta::FILE),
                &serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?,
            )
        })?;
        let mut runs = fix_runs(&meta, root.parent().unwrap())?;
        runs.push(RegisteredRun {
            path: child.clone(),
            run_id: child_id,
        });
        meta.insert(
            "fix_runs".into(),
            serde_json::to_value(runs).map_err(|e| e.to_string())?,
        );
        runmeta::write_atomic(
            &root.join(runmeta::FILE),
            &serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
        )?;
        Ok(child)
    })
}

/// Serialize metadata publications, including reported call counters, with
/// every proof and fix registration. Never acquire a parent after its child.
pub fn with_family_lock<T>(
    run: &Path,
    update: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let run = run_path(run)?;
    let root = original(&run)?;
    runmeta::with_lock(&root, || {
        if original(&run)? != root {
            return Err("linked run identity changed before publication".into());
        }
        if run == root {
            update()
        } else {
            runmeta::with_lock(&run, update)
        }
    })
}

/// Charge host-reported calls before dispatch, using the same family lock as proofs.
pub fn charge_calls(run: &Path, calls: u64) -> Result<(), String> {
    runmeta::update(run, |m| charge_calls_locked(run, m, calls))
}

/// Caller holds the family lock through the metadata transaction.
pub(crate) fn charge_calls_locked(
    run: &Path,
    m: &mut Map<String, Value>,
    calls: u64,
) -> Result<(), String> {
    let root = original(run)?;
    let total = allowance(&root)?;
    if total.remaining.is_some_and(|remaining| calls > remaining) {
        return Err("run budget exhausted: call charge exceeds remaining allowance".into());
    }
    let used = m
        .get("agent_calls_used")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    m.insert(
        "agent_calls_used".into(),
        Value::from(used.checked_add(calls).ok_or("call count overflow")?),
    );
    Ok(())
}

pub fn summary(run: &Path) -> Result<String, String> {
    let root = original(run)?;
    let a = runmeta::with_lock(&root, || allowance(&root))?;
    Ok(format!(
        "Cumulative budget: {} used of {}; {} remaining across {} run(s)",
        a.calls_and_proofs_used,
        a.budget_agent_calls
            .map_or("unlimited".into(), |n| n.to_string()),
        a.remaining.map_or("unlimited".into(), |n| n.to_string()),
        a.run_count
    ))
}

#[cfg(test)]
mod regressions {
    use super::*;
    use serde_json::json;
    use std::sync::mpsc;
    use std::time::Duration;

    fn family(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-budget-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::platform::create_private_dir(&dir).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let root = dir.join("original");
        let child = dir.join("child");
        for run in [&root, &child] {
            crate::platform::create_private_dir(run).unwrap();
        }
        runmeta::write_atomic(
            &root.join(runmeta::FILE),
            &json!({
                "run_id": "original", "budget_agent_calls": 2, "agent_calls_used": 1,
                "fix_runs": [{"path": child, "run_id": "child"}]
            })
            .to_string(),
        )
        .unwrap();
        runmeta::write_atomic(
            &child.join(runmeta::FILE),
            &json!({
                "run_id": "child", "budget_parent": root, "budget_parent_id": "original",
                "budget_agent_calls": 2, "agent_calls_used": 0
            })
            .to_string(),
        )
        .unwrap();
        (dir, root, child)
    }

    #[test]
    fn charge_rechecks_remaining_after_waiting_for_child_lock() {
        let (dir, root, child) = family("final-allowance");
        let (checked, observed) = mpsc::channel();
        let charging = runmeta::with_lock(&child, || {
            let run = child.clone();
            let charging = std::thread::spawn(move || {
                charge_proof_checked(&run, || {
                    checked.send(()).unwrap();
                })
            });
            // The first allowance check saw original usage 1 against cap 2.
            // Publish child usage 1 while charging waits for this child lock.
            observed.recv_timeout(Duration::from_secs(10)).unwrap();
            let mut meta = read_run(&child).unwrap();
            meta.insert("agent_calls_used".into(), json!(1));
            runmeta::write_atomic(
                &child.join(runmeta::FILE),
                &serde_json::to_string(&meta).unwrap(),
            )?;
            Ok(charging)
        })
        .unwrap();
        assert!(charging
            .join()
            .unwrap()
            .unwrap_err()
            .contains("budget exhausted"));
        assert_eq!(allowance(&root).unwrap().calls_and_proofs_used, 2);
        assert!(!read_run(&child).unwrap().contains_key("proof_runs_used"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn counter_publication_waits_for_root_before_child() {
        let (dir, root, child) = family("counter-lock-order");
        let (entered, observed) = mpsc::channel();
        let publishing = runmeta::with_lock(&root, || {
            let run = child.clone();
            let publishing = std::thread::spawn(move || {
                runmeta::update(&run, |m| {
                    entered.send(()).unwrap();
                    m.insert("agent_calls_used".into(), json!(1));
                    Ok(())
                })
            });
            assert!(observed.recv_timeout(Duration::from_millis(100)).is_err());
            // No child lock can be held while waiting for the root.
            runmeta::with_lock(&child, || Ok(()))?;
            Ok(publishing)
        })
        .unwrap();
        publishing.join().unwrap().unwrap();
        observed.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(allowance(&root).unwrap().calls_and_proofs_used, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
