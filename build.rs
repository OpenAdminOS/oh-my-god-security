use std::path::{Component, Path, PathBuf};
mod bundle_path;
#[allow(dead_code)]
#[path = "src/sha256.rs"]
mod sha256;
// File hashing is unused here; satisfy the shared module's runtime hooks.
mod supervise {
    pub fn check_interrupted() -> std::io::Result<()> {
        Ok(())
    }
}
mod platform {
    pub fn open_regular(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        std::fs::File::open(path)
    }
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    for entry in std::fs::read_dir(dir).expect("read skill bundle") {
        let entry = entry.expect("skill entry");
        let meta = entry.file_type().expect("skill file type");
        if meta.is_dir() {
            collect(root, &entry.path(), files);
        } else {
            assert!(meta.is_file(), "skill bundle must contain regular files");
            let original = entry.path();
            let relative = original.strip_prefix(root).unwrap();
            let components: Vec<_> = relative
                .components()
                .map(|c| {
                    let Component::Normal(c) = c else {
                        panic!("unsafe skill bundle component")
                    };
                    let c = c.to_str().expect("UTF-8 skill path");
                    assert!(!c.contains(['\\', ':']), "unsafe skill bundle component");
                    c
                })
                .collect();
            let destination = components.join("/");
            bundle_path::validate(&destination).expect("safe bundle destination");
            files.push((destination, original));
        }
    }
}
fn main() {
    // Worktrees store HEAD and refs outside the checkout. Track the actual paths.
    for name in ["HEAD", "index", "packed-refs", "refs"] {
        let output = std::process::Command::new("git")
            .args(["rev-parse", "--git-path", name])
            .output()
            .expect("git path");
        assert!(output.status.success(), "resolve build revision inputs");
        println!(
            "cargo:rerun-if-changed={}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .output()
        .expect("tracked build inputs");
    assert!(tracked.status.success(), "resolve tracked build inputs");
    for name in tracked.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        println!(
            "cargo:rerun-if-changed={}",
            std::str::from_utf8(name).expect("UTF-8 build path")
        );
    }
    let head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git revision");
    assert!(head.status.success(), "resolve build revision");
    let head = String::from_utf8(head.stdout).unwrap();
    let head = head.trim();
    assert!(
        head.len() == 40 && head.bytes().all(|b| b.is_ascii_hexdigit()),
        "full build revision"
    );
    let status = std::process::Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .expect("git status");
    assert!(status.status.success(), "resolve build cleanliness");
    let suffix = if status.stdout.is_empty() {
        ""
    } else {
        "+dirty"
    };
    println!("cargo:rustc-env=OMGS_BUILD_REVISION={head}{suffix}");
    println!("cargo:rerun-if-changed=skill");
    println!("cargo:rerun-if-changed=bundle_path.rs");
    let root =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("skill");
    let meta = std::fs::symlink_metadata(&root).expect("skill bundle root");
    assert!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "skill bundle root must be an unlinked directory"
    );
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    files.sort();
    let mut output = String::from("pub const BUNDLED: &[(&str, &[u8])] = &[\n");
    let mut hash = sha256::Sha256::new();
    hash.update(b"omgs-skill/1\0");
    for (file, original) in files {
        let bytes = std::fs::read(&original).expect("skill bytes");
        hash.update(&(file.len() as u64).to_be_bytes());
        hash.update(file.as_bytes());
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        output.push_str(&format!("({file:?}, include_bytes!({:?})),\n", original));
    }
    output.push_str("];\n");
    let digest = sha256::hex(&hash.finish());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    // A retained platform-neutral identity lets packaging inspect cross builds
    // without executing them. Runtime output consumes this exact same value.
    let identity = format!(
        r#"OMGS_IDENTITY_V1:{{"version":"{version}","build_revision":"{head}{suffix}","skill_digest_format":"omgs-skill/1","bundled_skill_sha256":"{digest}"}}:OMGS_IDENTITY_END"#
    );
    output.push_str(&format!(
        "pub const ARTIFACT_IDENTITY: &str = {identity:?};\n"
    ));
    std::fs::write(
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("skill.rs"),
        output,
    )
    .unwrap();
}
