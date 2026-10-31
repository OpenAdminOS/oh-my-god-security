//! Skill placement and explicitly requested policy creation. Installs no tools.
use std::path::{Path, PathBuf};
#[path = "../bundle_path.rs"]
mod bundle_path;
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

/// SHA-256 over sorted UTF-8 relative paths and bytes, with u64 big-endian
/// lengths and a domain separator. Modes and timestamps do not affect identity.
fn digest<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> String {
    let mut files: Vec<_> = files.into_iter().collect();
    files.sort_by_key(|(path, _)| *path);
    let mut hash = crate::sha256::Sha256::new();
    hash.update(b"omgs-skill/1\0");
    for (path, bytes) in files {
        hash.update(&(path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    crate::sha256::hex(&hash.finish())
}

pub fn bundled_digest() -> String {
    digest(BUNDLED.iter().copied())
}

pub fn check_identity(root: &Path) -> Result<String, String> {
    let files = manifest(root)?;
    check_manifest_identity(root, &files)
}

fn check_manifest_identity(
    root: &Path,
    files: &std::collections::BTreeMap<PathBuf, Vec<u8>>,
) -> Result<String, String> {
    let names: Vec<_> = files
        .keys()
        .map(|p| {
            p.components()
                .map(|c| c.as_os_str().to_str().expect("validated UTF-8"))
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    let actual = digest(
        names
            .iter()
            .zip(files.values())
            .map(|(p, b)| (p.as_str(), b.as_slice())),
    );
    let expected = bundled_digest();
    if actual != expected {
        return Err(format!("skill identity mismatch at {}: selected sha256 {actual}, bundled sha256 {expected}, binary revision {}; stop and use matching release artifacts", root.display(), env!("OMGS_BUILD_REVISION")));
    }
    Ok(actual)
}

pub fn identity() -> serde_json::Value {
    let text = ARTIFACT_IDENTITY
        .strip_prefix("OMGS_IDENTITY_V1:")
        .unwrap()
        .strip_suffix(":OMGS_IDENTITY_END")
        .unwrap();
    serde_json::from_str(text).expect("build-generated identity")
}

/// Materialize the embedded bundle in admitted owner-private storage.
pub fn materialize(root: &Path) -> Result<PathBuf, String> {
    materialize_selected(root, None)
}

/// Snapshot an external selection before validation and publish only those
/// validated bytes. Never point a review at mutable external storage or replace
/// an existing cache tree: a changed cache is an identity error.
pub fn materialize_selected(root: &Path, from: Option<&Path>) -> Result<PathBuf, String> {
    let files = match from {
        Some(from) => {
            let files = manifest(from)?;
            check_manifest_identity(from, &files)?;
            files
        }
        None => BUNDLED
            .iter()
            .map(|(name, bytes)| (PathBuf::from(name), bytes.to_vec()))
            .collect(),
    };
    let parent = root.parent().ok_or("bundle cache needs a parent")?;
    crate::platform::create_private_tree(parent).map_err(|e| e.to_string())?;
    crate::runmeta::with_lock_file(&parent.join(".bundle.lock"), || {
        if !root.exists() {
            let nonce = crate::platform::random_nonce().map_err(|e| e.to_string())?;
            let staged = parent.join(format!(".bundle-stage-{nonce}"));
            crate::platform::create_private_dir_new(&staged).map_err(|e| e.to_string())?;
            let publish = || -> Result<(), String> {
                for (name, bytes) in &files {
                    let path = staged.join(name);
                    crate::platform::create_private_tree(path.parent().unwrap())
                        .map_err(|e| e.to_string())?;
                    crate::platform::write_private_new(&path, bytes).map_err(|e| e.to_string())?;
                }
                check_identity(&staged)?;
                std::fs::rename(&staged, root).map_err(|e| e.to_string())
            };
            if let Err(error) = publish() {
                let _ = std::fs::remove_dir_all(&staged);
                return Err(error);
            }
        }
        crate::platform::check_private_dir(root).map_err(|e| e.to_string())?;
        check_identity(root)?;
        std::fs::canonicalize(root).map_err(|e| e.to_string())
    })
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
            bundle_path::validate(
                entry
                    .file_name()
                    .to_str()
                    .ok_or("non-UTF-8 skill destination")?,
            )?;
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
            .map(|(p, b)| {
                bundle_path::validate(p)?;
                Ok((PathBuf::from(p), b.to_vec()))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?,
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
                crate::out::line(&format!("already installed: {}", to.display()));
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
        crate::out::line(&format!("installed: {}", to.display()));
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
        crate::out::line(&format!("skill backup: {}", backup.display()));
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
        let root = crate::platform::temp_root().unwrap().join(format!(
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
