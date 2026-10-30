use std::path::{Component, Path, PathBuf};
mod build_revision;
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
    println!("cargo:rerun-if-env-changed=OMGS_BUILD_REVISION");
    println!("cargo:rerun-if-changed=BUILD-REVISION");
    println!("cargo:rerun-if-changed=build_revision.rs");
    let source = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let revision = build_revision::resolve(&source, std::env::var("OMGS_BUILD_REVISION").ok())
        .expect("valid build revision metadata");
    println!("cargo:rustc-env=OMGS_BUILD_REVISION={revision}");
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
        r#"OMGS_IDENTITY_V1:{{"version":"{version}","build_revision":"{revision}","skill_digest_format":"omgs-skill/1","bundled_skill_sha256":"{digest}"}}:OMGS_IDENTITY_END"#
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
