//! Skill placement and explicitly requested policy creation. Installs no tools.
use std::path::{Path, PathBuf};
pub const SKILL_NAME: &str = "omgs-security-review";

/// Agent roots are evidence of an installation. Never create an undetected root.
pub fn detected(home: &Path) -> Vec<PathBuf> {
    [
        ".claude",
        ".codex",
        ".agents",
        ".cursor",
        ".gemini",
        ".copilot",
        ".config/opencode",
        ".codeium/windsurf",
    ]
    .iter()
    .map(|root| home.join(root))
    .filter(|root| root.is_dir())
    .map(|root| root.join("skills").join(SKILL_NAME))
    .collect()
}

pub fn source(explicit: Option<PathBuf>, executable: &Path, cwd: &Path) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let bin = executable.parent().ok_or("executable has no parent")?;
    // Both direct binary + skill/ and bootstrap bin/omgs + ../skill/ layouts.
    [
        bin.join("skill"),
        bin.parent().unwrap_or(bin).join("skill"),
        cwd.join("skill"),
    ]
    .into_iter()
    .find(|p| p.join("SKILL.md").is_file())
    .ok_or_else(|| "skill not found beside binary; pass --from <skill-dir>".into())
}

fn unlinked(path: &Path) -> Result<(), String> {
    for parent in path.ancestors() {
        match std::fs::symlink_metadata(parent) {
            Ok(meta) if crate::platform::is_link(&meta) => {
                return Err(format!("refusing linked setup path {}", parent.display()))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
fn copy(src: &Path, dst: &Path) -> Result<(), String> {
    unlinked(src)?;
    unlinked(dst)?;
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for entry in std::fs::read_dir(src).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if crate::platform::is_link(&meta) {
            return Err("skill source contains a link".into());
        }
        let to = dst.join(entry.file_name());
        if meta.is_dir() {
            copy(&entry.path(), &to)?;
        } else if meta.is_file() {
            unlinked(&to)?;
            let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
            crate::runmeta::write_atomic_bytes(&to, &bytes).map_err(|e| e.to_string())?;
        } else {
            return Err("skill source contains a special file".into());
        }
    }
    Ok(())
}

pub fn install(from: &Path, targets: &[PathBuf]) -> Result<(), String> {
    let text = std::fs::read_to_string(from.join("SKILL.md")).map_err(|e| e.to_string())?;
    if !text.lines().any(|l| l == format!("name: {SKILL_NAME}")) {
        return Err("skill source has an unexpected name".into());
    }
    let from = std::fs::canonicalize(from).map_err(|e| e.to_string())?;
    for to in targets {
        if to == &from {
            println!("already installed: {}", to.display());
            continue;
        }
        // Physical ancestor identity also prevents copying a source into itself.
        if to.starts_with(&from) || from.starts_with(to) {
            return Err("skill source and destination overlap".into());
        }
        copy(&from, to)?;
        println!("installed: {}", to.display());
    }
    Ok(())
}

pub fn write_policy(repo: &Path, mode: crate::policy::Mode) -> Result<PathBuf, String> {
    let repo = std::fs::canonicalize(repo).map_err(|e| e.to_string())?;
    let path = repo.join(crate::policy::PATH);
    unlinked(&path)?;
    let policy = crate::policy::Policy {
        mode,
        ..Default::default()
    };
    let text = crate::policy::text(&policy)?;
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    unlinked(&path)?;
    use std::io::Write;
    // Never overwrite owner policy, including under --yes.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            format!(
                "create {} without replacing existing policy: {e}",
                path.display()
            )
        })?;
    file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path)
}
