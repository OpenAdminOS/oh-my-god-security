//! One cumulative allowance from disjoint per-run counters. Child usage is
//! never copied into its parent's counters.
use crate::runmeta;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct Allowance {
    pub budget_agent_calls: Option<u64>,
    pub calls_and_proofs_used: u64,
    pub remaining: Option<u64>,
    pub run_count: usize,
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(path).map_err(|e| format!("run {}: {e}", path.display()))
}

fn fix_runs(meta: &Map<String, Value>) -> Result<Vec<PathBuf>, String> {
    let Some(value) = meta.get("fix_runs") else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or("fix_runs must be an array")?
        .iter()
        .map(|v| {
            let path = v.as_str().ok_or("fix_runs entries must be paths")?;
            canonical(Path::new(path))
        })
        .collect()
}

/// Resolve either the original run or a registered fix run to the same root.
pub fn original(run: &Path) -> Result<PathBuf, String> {
    let run = canonical(run)?;
    let meta = runmeta::read(&run)?;
    let Some(parent) = meta.get("budget_parent") else {
        return Ok(run);
    };
    let parent = canonical(Path::new(
        parent.as_str().ok_or("budget_parent must be a path")?,
    ))?;
    let root = runmeta::read(&parent)?;
    if root.contains_key("budget_parent") || !fix_runs(&root)?.contains(&run) {
        return Err("budget_parent must name the original run with this fix registered".into());
    }
    Ok(parent)
}

/// Caller holds the original run's lock. Missing or inconsistent links fail
/// closed instead of silently understating spent allowance.
pub fn allowance(root: &Path) -> Result<Allowance, String> {
    let root = canonical(root)?;
    let meta = runmeta::read(&root)?;
    if meta.contains_key("budget_parent") {
        return Err("use the original run for cumulative accounting".into());
    }
    let cap = meta.get("budget_agent_calls").and_then(Value::as_u64);
    let mut runs = vec![root.clone()];
    runs.extend(fix_runs(&meta)?);
    let mut seen = BTreeSet::new();
    let mut used = 0u64;
    for run in &runs {
        if !seen.insert(run) {
            return Err("duplicate run in cumulative budget".into());
        }
        let m = runmeta::read(run)?;
        if run != &root {
            let parent = m
                .get("budget_parent")
                .and_then(Value::as_str)
                .ok_or("linked fix run has no budget_parent")?;
            if canonical(Path::new(parent))? != root || !fix_runs(&m)?.is_empty() {
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
        calls_and_proofs_used: used,
        remaining: cap.map(|cap| cap.saturating_sub(used)),
        run_count: runs.len(),
    })
}

/// Serialize proof charging with fix registration and all other family proofs.
pub fn charge_proof(run: &Path) -> Result<(), String> {
    let run = canonical(run)?;
    let root = original(&run)?;
    runmeta::with_lock(&root, || {
        let total = allowance(&root)?;
        if total.remaining == Some(0) {
            return Err(
                "run budget exhausted: cumulative original and fix allowance consumed".into(),
            );
        }
        let charge = |m: &mut Map<String, Value>| {
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
        if run == root {
            let mut meta = runmeta::read(&run)?;
            charge(&mut meta)?;
            runmeta::write_atomic(
                &run.join(runmeta::FILE),
                &serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
            )
        } else {
            runmeta::update(&run, charge)
        }
    })
}

/// Initialize a fix with a computed cap and register it before returning it to
/// the caller. The original lock spans calculation, creation and registration.
pub fn init_fix(
    parent: &Path,
    init: impl FnOnce(&Path, &Map<String, Value>, Option<u64>) -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let root = original(parent)?;
    runmeta::with_lock(&root, || {
        let mut meta = runmeta::read(&root)?;
        let remaining = allowance(&root)?.remaining;
        let child = canonical(&init(&root, &meta, remaining)?)?;
        runmeta::update(&child, |m| {
            m.insert(
                "budget_parent".into(),
                Value::from(root.to_string_lossy().as_ref()),
            );
            Ok(())
        })?;
        let mut runs = fix_runs(&meta)?;
        runs.push(child.clone());
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
