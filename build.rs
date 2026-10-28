use std::path::Path;

fn collect(root: &Path, dir: &Path, files: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read skill bundle") {
        let entry = entry.expect("skill entry");
        let meta = entry.file_type().expect("skill file type");
        if meta.is_dir() {
            collect(root, &entry.path(), files);
        } else {
            assert!(meta.is_file(), "skill bundle must contain regular files");
            files.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
            );
        }
    }
}
fn main() {
    println!("cargo:rerun-if-changed=skill");
    let root =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("skill");
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    files.sort();
    let mut output = String::from("pub const BUNDLED: &[(&str, &[u8])] = &[\n");
    for file in files {
        output.push_str(&format!(
            "({file:?}, include_bytes!({:?})),\n",
            root.join(&file)
        ));
    }
    output.push_str("];\n");
    std::fs::write(
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("skill.rs"),
        output,
    )
    .unwrap();
}
