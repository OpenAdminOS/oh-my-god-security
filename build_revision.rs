//! Revision discovery also works for source archives without Git metadata.
use std::path::Path;
use std::process::{Command, Output};

fn git(root: &Path, args: &[&str]) -> Option<Output> {
    Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
}

fn exact(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("revision metadata must be a full 40-character commit SHA".into());
    }
    Ok(value.to_ascii_lowercase())
}

pub fn resolve(root: &Path, supplied: Option<String>) -> Result<String, String> {
    if let Some(value) = supplied {
        return exact(&value);
    }
    // Worktrees keep HEAD and refs outside the checkout. Do not accidentally
    // attribute an unpacked archive to an enclosing repository.
    let checkout = git(root, &["rev-parse", "--show-toplevel"])
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|path| std::fs::canonicalize(path.trim()).ok());
    if checkout == std::fs::canonicalize(root).ok() && checkout.is_some() {
        for name in ["HEAD", "index", "packed-refs", "refs"] {
            if let Some(out) = git(root, &["rev-parse", "--git-path", name]) {
                println!(
                    "cargo:rerun-if-changed={}",
                    String::from_utf8_lossy(&out.stdout).trim()
                );
            }
        }
        if let Some(out) = git(root, &["ls-files", "-z"]) {
            for name in out.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
                println!("cargo:rerun-if-changed={}", String::from_utf8_lossy(name));
            }
        }
        let head = git(root, &["rev-parse", "HEAD"]).ok_or("cannot resolve checkout revision")?;
        let head = exact(&String::from_utf8_lossy(&head.stdout))?;
        let status = git(root, &["status", "--porcelain", "--untracked-files=no"])
            .ok_or("cannot resolve checkout cleanliness")?;
        return Ok(format!(
            "{head}{}",
            if status.stdout.is_empty() {
                ""
            } else {
                "+dirty"
            }
        ));
    }
    match std::fs::read_to_string(root.join("BUILD-REVISION")) {
        Ok(value) => exact(&value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("unknown revision".into()),
        Err(error) => Err(error.to_string()),
    }
}
