use std::path::{Component, Path, PathBuf};
mod bundle_path;

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
    for (file, original) in files {
        output.push_str(&format!("({file:?}, include_bytes!({:?})),\n", original));
    }
    output.push_str("];\n");
    std::fs::write(
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("skill.rs"),
        output,
    )
    .unwrap();
}
