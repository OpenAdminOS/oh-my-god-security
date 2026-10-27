//! One-time human approval of tier 2 proofs per repository, kept in the
//! per-user data directory, never in the target or the run.

use std::io::BufRead;
use std::path::Path;

const FILE: &str = "tier2-approvals.json";

fn read(data: &Path) -> Result<Vec<serde_json::Value>, String> {
    let path = data.join(FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("approvals").and_then(|a| a.as_array()).cloned())
            .ok_or_else(|| format!("{} is malformed", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// `target` must already be canonical.
pub fn is_approved(data: &Path, target: &Path) -> Result<bool, String> {
    let key = target.to_string_lossy();
    Ok(read(data)?
        .iter()
        .any(|a| a.get("target").and_then(|t| t.as_str()) == Some(key.as_ref())))
}

pub fn approve(data: &Path, target: &Path) -> Result<(), String> {
    std::fs::create_dir_all(data).map_err(|e| format!("create {}: {e}", data.display()))?;
    crate::runmeta::with_lock_file(&data.join(format!(".{FILE}.lock")), || {
        let mut all = read(data)?;
        if !is_approved(data, target)? {
            all.push(serde_json::json!({
                "target": target.to_string_lossy(),
                "approved_at_ms": crate::runmeta::now_ms(),
            }));
        }
        let text = serde_json::to_string_pretty(&serde_json::json!({ "approvals": all }))
            .map_err(|e| e.to_string())?;
        crate::runmeta::write_atomic(&data.join(FILE), &format!("{text}\n"))
    })
}

/// Read one line from the controlling terminal rather than stdin, so a
/// piped or agent-driven invocation cannot answer the approval prompt.
pub fn read_from_terminal() -> Result<String, String> {
    let device = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
    let tty = std::fs::File::open(device).map_err(|_| {
        "approval needs an interactive terminal; a person has to run this command".to_string()
    })?;
    let mut line = String::new();
    std::io::BufReader::new(tty)
        .read_line(&mut line)
        .map_err(|e| format!("read terminal: {e}"))?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_per_canonical_target() {
        let data = std::env::temp_dir().join(format!("omgs-approval-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let a = Path::new("/work/a");
        assert!(!is_approved(&data, a).unwrap());
        approve(&data, a).unwrap();
        approve(&data, a).unwrap();
        assert!(is_approved(&data, a).unwrap());
        assert!(!is_approved(&data, Path::new("/work/b")).unwrap());
        assert_eq!(read(&data).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&data);
    }
}
