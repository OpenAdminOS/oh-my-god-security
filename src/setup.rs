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

// The verified release binary carries the complete pack. No working-directory
// lookup is used for the default installation.
include!(concat!(env!("OUT_DIR"), "/skill.rs"));

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
fn manifest(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>, String> {
    fn walk(
        root: &Path,
        dir: &Path,
        out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), String> {
        unlinked(dir)?;
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if crate::platform::is_link(&meta) {
                return Err("skill tree contains a link".into());
            }
            let rel = entry.path().strip_prefix(root).unwrap().to_owned();
            if meta.is_dir() {
                walk(root, &entry.path(), out)?;
            } else if meta.is_file() {
                out.insert(
                    rel.clone(),
                    crate::platform::read_bounded_in(root, &rel, 16 << 20)
                        .map_err(|e| e.to_string())?,
                );
            } else {
                return Err("skill tree contains a special file".into());
            }
        }
        Ok(())
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

/// Stage a complete sibling tree, then rename. A replacement retains the old
/// tree as a named backup; failed final renames restore it without mixing files.
pub fn install(from: Option<&Path>, targets: &[PathBuf], replace: bool) -> Result<(), String> {
    let files = match from {
        Some(from) => manifest(from)?,
        None => BUNDLED
            .iter()
            .map(|(p, b)| (PathBuf::from(p), b.to_vec()))
            .collect(),
    };
    let text = std::str::from_utf8(
        files
            .get(Path::new("SKILL.md"))
            .ok_or("skill requires SKILL.md")?,
    )
    .map_err(|e| e.to_string())?;
    if !text.lines().any(|l| l == format!("name: {SKILL_NAME}")) {
        return Err("skill source has an unexpected name".into());
    }
    // Preflight every destination before writing any of them.
    let mut changed = Vec::new();
    for to in targets {
        unlinked(to)?;
        if to.exists() {
            let old = manifest(to)?;
            let differences: std::collections::BTreeSet<_> = old
                .keys()
                .chain(files.keys())
                .filter(|p| old.get(*p) != files.get(*p))
                .collect();
            if differences.is_empty() {
                println!("already installed: {}", to.display());
                continue;
            }
            if !replace {
                return Err(format!(
                    "skill files differ in {}: {}; use --replace to back up and replace",
                    to.display(),
                    differences
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        changed.push(to);
    }
    for to in changed {
        let parent = to.parent().ok_or("skill destination has no parent")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let nonce = crate::platform::random_nonce().map_err(|e| e.to_string())?;
        let staged = parent.join(format!(".{SKILL_NAME}.stage-{nonce}"));
        let backup = parent.join(format!("{SKILL_NAME}.backup-{nonce}"));
        std::fs::create_dir(&staged).map_err(|e| e.to_string())?;
        let stage = || -> Result<(), String> {
            for (rel, bytes) in &files {
                let file = staged.join(rel);
                std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
                std::fs::write(file, bytes).map_err(|e| e.to_string())?;
            }
            Ok(())
        };
        if let Err(e) = stage() {
            let _ = std::fs::remove_dir_all(&staged);
            return Err(e);
        }
        publish(&staged, to, &backup)?;
        println!("installed: {}", to.display());
    }
    Ok(())
}

fn publish(staged: &Path, to: &Path, backup: &Path) -> Result<(), String> {
    let had_old = to.exists();
    if had_old {
        if let Err(e) = std::fs::rename(to, backup) {
            let _ = std::fs::remove_dir_all(staged);
            return Err(e.to_string());
        }
    }
    if let Err(e) = std::fs::rename(staged, to) {
        let restored = !had_old || std::fs::rename(backup, to).is_ok();
        let _ = std::fs::remove_dir_all(staged);
        return Err(format!(
            "install rename failed: {e}; restored old tree: {restored}; backup {}",
            backup.display()
        ));
    }
    if had_old {
        println!("skill backup: {}", backup.display());
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

#[cfg(test)]
mod tests {
    #[test]
    fn failed_publish_restores_complete_original_tree() {
        let root = std::env::temp_dir().join(format!(
            "omgs-install-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let old = root.join("installed");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("original"), "owner content").unwrap();
        // A vanished staged tree makes the actual final rename fail after backup.
        let backup = root.join("backup");
        assert!(super::publish(&root.join("vanished-stage"), &old, &backup).is_err());
        assert_eq!(
            std::fs::read_to_string(old.join("original")).unwrap(),
            "owner content"
        );
        assert!(!backup.exists());
        assert_eq!(std::fs::read_dir(&old).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
