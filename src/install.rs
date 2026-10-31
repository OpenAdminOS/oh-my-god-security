//! Publication entry point for an already verified bootstrap bundle.
use crate::platform;
use std::io::{Error, Result};
use std::path::{Path, PathBuf};

/// Publish only bytes read through the retained staging handle and matching
/// the checksums supplied by the bootstrap after signature verification.
pub fn install_self(
    to: &Path,
    staging: &Path,
    binary: (&Path, &str),
    mxc: Option<(&Path, &str)>,
    license: Option<(&Path, &str)>,
) -> Result<()> {
    let source = platform::StagingDir::open(staging)?;
    publish_verified(to, &source, binary, mxc, license)
}

fn install_tree(path: &Path) -> Result<()> {
    platform::safe_path(path)?;
    if std::fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        // Existing parents were admitted as ancestors above. Do not reclassify
        // a sticky/system-owned ancestor as a publication directory.
        if std::fs::symlink_metadata(parent).is_err() {
            install_tree(parent)?;
        }
    }
    platform::create_private_dir_new(path)
}

fn admit_leaf(path: &Path) -> Result<()> {
    let check = || -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if platform::is_link(&meta) || !meta.is_file() => {
                return Err(Error::other(
                    "destination must be a regular file without links or reparse points",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
            _ => {}
        }
        let file = platform::open_single_link(path)?
            .ok_or_else(|| Error::other("destination disappeared during admission"))?;
        platform::check_private_file(&file)
    };
    check().map_err(|e| Error::other(format!("installation destination {}: {e}", path.display())))
}

struct Staged(PathBuf);
impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn stage(
    source: &platform::StagingDir,
    name: &Path,
    expected: &str,
    destination: &Path,
    executable: bool,
) -> Result<Staged> {
    use std::io::Write;
    let bytes = source.read_verified(name, expected)?;
    let tmp = destination.with_file_name(format!(".omgs-{}", platform::random_nonce()?));
    #[cfg(windows)]
    let mut file = platform::open_private_write(&tmp, true)?;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if executable { 0o700 } else { 0o600 })
            .open(&tmp)?
    };
    #[cfg(not(unix))]
    let _ = executable;
    let staged = Staged(tmp);
    platform::check_private_file(&file)?;
    // Read only regular, bounded verified files. Compare the copied bytes before
    // any destination is replaced, including after write/sync/close.
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if std::fs::read(&staged.0)? != bytes {
        return Err(Error::other("staged copy differs from verified source"));
    }
    Ok(staged)
}

fn publish_verified(
    to: &Path,
    source_dir: &platform::StagingDir,
    binary: (&Path, &str),
    mxc: Option<(&Path, &str)>,
    license: Option<(&Path, &str)>,
) -> Result<()> {
    if !to.is_absolute() {
        return Err(Error::other("installation root must be absolute"));
    }
    if mxc.is_some() != license.is_some() {
        return Err(Error::other(
            "MXC executor and license must be supplied together",
        ));
    }
    let mut files = Vec::new();
    if let (Some(mxc), Some(license)) = (mxc, license) {
        let name = mxc
            .0
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let executor = include_str!("../skill/mxc-pins.txt")
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 4 && fields[2] == name)
                    .then(|| fields[1].rsplit('/').next().unwrap())
            })
            .ok_or_else(|| Error::other("unrecognized mirrored MXC asset name"))?;
        let dir = to.join("mxc").join(crate::sandbox::MXC_VERSION);
        files.push((mxc, dir.join(executor), true));
        files.push((license, dir.join("MXC-LICENSE.txt"), false));
    }
    files.push((
        binary,
        to.join("bin")
            .join(if cfg!(windows) { "omgs.exe" } else { "omgs" }),
        true,
    ));
    // Admit all directories and leaves before staging or replacing any file.
    for (_, destination, _) in &files {
        platform::safe_path(destination.parent().unwrap())?;
        admit_leaf(destination)?;
    }
    let mut staged = Vec::new();
    for (source, destination, executable) in &files {
        install_tree(destination.parent().unwrap())?;
        staged.push(stage(
            source_dir,
            source.0,
            source.1,
            destination,
            *executable,
        )?);
    }
    for ((_, destination, _), source) in files.iter().zip(&staged) {
        platform::safe_path(destination.parent().unwrap())?;
        admit_leaf(destination)?;
        // Unix rename and Windows MoveFileEx(REPLACE_EXISTING) target the exact
        // entry. Unlike File.Replace, the latter retains the new file's DACL.
        std::fs::rename(&source.0, destination).map_err(|e| Error::other(format!(
            "Publication failed for '{}'. A running omgs.exe or MXC executor may hold the file. Stop it and retry. The existing destination is preserved on a sharing violation. Earlier published files remain individually verified and complete, but the installation may contain a mix of old and new files until retry succeeds. Staged temporary files are cleaned up. Cause: {e}", destination.display()
        )))?;
        admit_leaf(destination)?;
    }
    for (_, destination, _) in files {
        if destination
            .file_name()
            .is_some_and(|n| n == "omgs" || n == "omgs.exe")
        {
            crate::out::line(&format!(
                "Installed omgs {}: {}",
                env!("CARGO_PKG_VERSION"),
                destination.display()
            ));
        } else if destination
            .file_name()
            .is_some_and(|n| n != "MXC-LICENSE.txt")
        {
            crate::out::line(&format!(
                "Installed MXC {}: {}",
                crate::sandbox::MXC_VERSION,
                destination.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn publish_bundle(
    to: &Path,
    binary: &Path,
    mxc: Option<&Path>,
    license: Option<&Path>,
) -> Result<()> {
    let hash = |p: &Path| crate::sha256::digest_file(p).unwrap_or_default();
    let binary_hash = hash(binary);
    let mxc_hash = mxc.map(hash);
    let license_hash = license.map(hash);
    install_self(
        to,
        binary.parent().unwrap(),
        (Path::new(binary.file_name().unwrap()), &binary_hash),
        mxc.map(|p| {
            (
                Path::new(p.file_name().unwrap()),
                mxc_hash.as_deref().unwrap(),
            )
        }),
        license.map(|p| {
            (
                Path::new(p.file_name().unwrap()),
                license_hash.as_deref().unwrap(),
            )
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::fs::canonicalize(crate::platform::temp_root().unwrap()).unwrap();
            let root = base.join(format!(
                "omgs-install-{}",
                platform::random_nonce().unwrap()
            ));
            platform::create_private_dir_new(&root).unwrap();
            Self(root)
        }
        fn binary(&self) -> PathBuf {
            let path = self.0.join("verified");
            std::fs::write(&path, b"verified binary").unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            #[cfg(target_os = "macos")]
            assert!(std::process::Command::new("/bin/chmod")
                .arg("-RN")
                .arg(&self.0)
                .status()
                .unwrap()
                .success());
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn destination(home: &Path) -> PathBuf {
        home.join("bin")
            .join(if cfg!(windows) { "omgs.exe" } else { "omgs" })
    }

    #[cfg(unix)]
    #[test]
    fn retained_staging_handle_never_reopens_swapped_ancestor() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        let stage = parent.join("stage");
        platform::create_private_tree(&stage).unwrap();
        std::fs::write(stage.join("binary"), b"verified").unwrap();
        let expected = crate::sha256::digest(b"verified");
        let held = platform::StagingDir::open(&stage).unwrap();
        let moved = fixture.0.join("moved");
        std::fs::rename(&parent, &moved).unwrap();
        platform::create_private_tree(&stage).unwrap();
        std::fs::write(stage.join("binary"), b"substituted").unwrap();
        assert_eq!(
            held.read_verified(Path::new("binary"), &expected).unwrap(),
            b"verified"
        );
        // Even a change inside the retained directory after verification must
        // fail before any destination is published.
        std::fs::write(moved.join("stage/binary"), b"changed in retained directory").unwrap();
        let home = fixture.0.join("home");
        assert!(
            publish_verified(&home, &held, (Path::new("binary"), &expected), None, None).is_err()
        );
        assert!(!destination(&home).exists());
        std::fs::remove_file(moved.join("stage/binary")).unwrap();
        std::os::unix::fs::symlink(stage.join("binary"), moved.join("stage/binary")).unwrap();
        assert!(held.read_verified(Path::new("binary"), &expected).is_err());
    }

    #[test]
    fn publication_replaces_complete_bytes_and_cleans_siblings() {
        let fixture = Fixture::new();
        let binary = fixture.binary();
        let home = fixture.0.join("home with spaces");
        for _ in 0..2 {
            publish_bundle(&home, &binary, None, None).unwrap();
            assert_eq!(
                std::fs::read(destination(&home)).unwrap(),
                b"verified binary"
            );
            assert_eq!(std::fs::read_dir(home.join("bin")).unwrap().count(), 1);
        }
    }

    #[test]
    fn failed_staging_preserves_every_previous_file_and_cleans_siblings() {
        let fixture = Fixture::new();
        let binary = fixture.binary();
        let home = fixture.0.join("home");
        let executor = fixture.0.join("mxc-1.0.1-windows-x64.exe");
        let license = fixture.0.join("MXC-LICENSE.txt");
        std::fs::write(&executor, b"verified executor").unwrap();
        std::fs::write(&license, b"verified license").unwrap();
        publish_bundle(&home, &binary, Some(&executor), Some(&license)).unwrap();
        let published = [
            destination(&home),
            home.join("mxc/1.0.1/wxc-exec.exe"),
            home.join("mxc/1.0.1/MXC-LICENSE.txt"),
        ];
        let previous: Vec<_> = published
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        std::fs::write(&executor, b"new executor").unwrap();
        // The final binary source fails after the executor and license copies
        // have staged. None of the three previous destinations may change.
        assert!(publish_bundle(
            &home,
            &fixture.0.join("missing"),
            Some(&executor),
            Some(&license)
        )
        .is_err());
        for (path, bytes) in published.iter().zip(previous) {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        assert_eq!(std::fs::read_dir(home.join("bin")).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_dir(home.join("mxc/1.0.1")).unwrap().count(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn sticky_publication_and_precreated_directory_or_symlink_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let binary = fixture.binary();
        for kind in ["sticky", "directory", "symlink"] {
            let home = fixture.0.join(kind);
            let bin = home.join("bin");
            install_tree(&bin).unwrap();
            let leaf = destination(&home);
            match kind {
                "sticky" => {
                    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o1777)).unwrap()
                }
                "directory" => std::fs::create_dir(&leaf).unwrap(),
                _ => symlink(&binary, &leaf).unwrap(),
            }
            let error = publish_bundle(&home, &binary, None, None)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(
                    &if kind == "sticky" { bin } else { leaf }
                        .display()
                        .to_string()
                ),
                "{error}"
            );
            assert_eq!(std::fs::read(&binary).unwrap(), b"verified binary");
        }
    }

    #[cfg(unix)]
    #[test]
    fn complete_chain_refuses_writable_shared_above_anchor_and_symlink_ancestor() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let binary = fixture.binary();
        let shared = fixture.0.join("shared");
        let anchor = shared.join("anchor");
        install_tree(&anchor).unwrap();
        // When run as root this anchor is root-owned. In either case the
        // traversal must continue above it and reject the writable parent.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = publish_bundle(&anchor.join("home"), &binary, None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&shared.display().to_string()), "{error}");
        assert!(platform::create_private_tree(&anchor.join("runs/run")).is_err());
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = fixture.0.join("alias");
        symlink(&anchor, &alias).unwrap();
        let error = publish_bundle(&alias.join("home"), &binary, None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&alias.display().to_string()), "{error}");
        assert!(platform::create_private_tree(&alias.join("runs/run")).is_err());
        // Ordinary protected parents and sticky ancestors remain supported.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        publish_bundle(&anchor.join("home"), &binary, None, None).unwrap();
        publish_bundle(&shared.join("direct-home"), &binary, None, None).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_destination_and_ancestor_mutation_acls_are_refused_without_repair() {
        let fixture = Fixture::new();
        let binary = fixture.binary();
        for leaf in [false, true] {
            let home = fixture.0.join(if leaf { "leaf" } else { "ancestor" });
            publish_bundle(&home, &binary, None, None).unwrap();
            let unsafe_path = if leaf {
                destination(&home)
            } else {
                home.clone()
            };
            assert!(std::process::Command::new("/bin/chmod")
                .arg("+a")
                .arg("everyone allow delete_child")
                .arg(&unsafe_path)
                .status()
                .unwrap()
                .success());
            let error = publish_bundle(&home, &binary, None, None)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&unsafe_path.display().to_string()),
                "{error}"
            );
            assert!(error.contains("ACL entry"), "{error}");
            assert!(publish_bundle(&home, &binary, None, None).is_err());
            assert_eq!(
                std::fs::read(destination(&home)).unwrap(),
                b"verified binary"
            );
        }
    }
}
