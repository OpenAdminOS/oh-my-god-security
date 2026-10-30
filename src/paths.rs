//! Heuristic inventory priority. Every class remains accountable in the ledger.
//! Classification uses path conventions and file size, never execution.
use serde::Serialize;
use std::path::{Component, Path};

/// A physical overlap check without probe writes. Existing components use OS
/// identity, so case, normalization, symlinks and junctions cannot hide ancestry.
/// Missing components can alias only below the same existing directory. ASCII
/// spellings are folded there; non-ASCII spellings are conservatively ambiguous
/// without a filesystem-specific normalization oracle.
pub fn overlaps(left: &Path, right: &Path) -> Result<bool, String> {
    struct Location {
        ancestors: Vec<(u64, u64)>,
        missing: Vec<std::ffi::OsString>,
    }
    fn locate(path: &Path) -> Result<Location, String> {
        let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
        let mut existing = absolute.as_path();
        let mut missing = Vec::new();
        loop {
            match std::fs::metadata(existing) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let name = existing.file_name().ok_or_else(|| {
                        format!(
                            "cannot resolve {}; use a path without '..' after a missing directory",
                            path.display()
                        )
                    })?;
                    missing.push(name.to_os_string());
                    existing = existing.parent().ok_or("path has no existing ancestor")?;
                }
                Err(e) => return Err(format!("inspect {}: {e}", existing.display())),
            }
        }
        let existing = std::fs::canonicalize(existing).map_err(|e| e.to_string())?;
        if !missing.is_empty() && !existing.is_dir() {
            return Err(format!("{} is not a directory", existing.display()));
        }
        let ancestors = existing
            .ancestors()
            .map(identity)
            .collect::<Result<_, _>>()?;
        missing.reverse();
        Ok(Location { ancestors, missing })
    }
    fn identity(path: &Path) -> Result<(u64, u64), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
            Ok((meta.dev(), meta.ino()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x0200_0000)
                .open(path)
                .map_err(|e| e.to_string())?;
            crate::platform::windows_file_identity(&file)
                .map(|(volume, index)| (u64::from(volume), index))
                .map_err(|e| e.to_string())
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err("filesystem identity unavailable".into())
        }
    }
    let a = locate(left)?;
    let b = locate(right)?;
    if a.missing.is_empty() && b.ancestors.contains(&a.ancestors[0])
        || b.missing.is_empty() && a.ancestors.contains(&b.ancestors[0])
    {
        return Ok(true);
    }
    if a.ancestors[0] != b.ancestors[0] {
        // A missing entry cannot alias an entry that an OS lookup found.
        return Ok(false);
    }
    Ok(a.missing.iter().zip(&b.missing).all(|(a, b)| {
        let a = a.as_encoded_bytes();
        let b = b.as_encoded_bytes();
        a.eq_ignore_ascii_case(b) || !a.is_ascii() || !b.is_ascii()
    }))
}

/// Render native separators only. Escape literal backslashes and percent signs
/// in components so a Unix filename cannot become a different display path.
pub fn display(path: &Path) -> String {
    path.components()
        .map(|part| {
            part.as_os_str()
                .to_string_lossy()
                .replace('%', "%25")
                .replace('\\', "%5C")
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Code,
    Test,
    Docs,
    Data,
    Asset,
    Vendored,
}

/// Exhaustive mapping: adding a class requires choosing its accountable unit.
pub fn exclusion_group(class: Class) -> Option<(&'static str, &'static str)> {
    match class {
        Class::Code => None,
        Class::Test => Some(("tests:excluded", "test or fixture")),
        Class::Docs => Some(("docs:excluded", "documentation")),
        Class::Data => Some(("data:excluded", "large structured data")),
        Class::Asset => Some(("assets:excluded", "binary asset")),
        Class::Vendored => Some(("vendored:excluded", "vendored or generated")),
    }
}

/// Source recognition supplements exclusion disclosure, never accountability.
/// Unknown formats remain Code too.
pub fn is_source(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let file = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    let ext = file.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    [
        "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "cs", "cshtml", "razor", "csproj", "sln",
        "fs", "fsx", "vb", "swift", "ps1", "psm1", "psd1", "py", "pyi", "sh", "bash", "zsh", "ksh",
        "fish", "cmd", "bat", "bats", "html", "htm", "css", "scss", "sql", "go", "java", "kt",
        "rb", "php", "c", "h", "cpp", "hpp", "vue", "svelte", "astro", "ejs", "hbs", "pug",
        "jinja", "jinja2", "j2", "twig", "erb", "tmpl", "tpl", "liquid", "mustache",
    ]
    .contains(&ext)
        || executable_filename(file)
}

/// Conventional build and executable configuration names take priority over
/// docs and data suffixes. Container variants and Gradle Kotlin scripts count.
fn executable_filename(file: &str) -> bool {
    [
        "cmakelists.txt", "makefile", "gnumakefile", "dockerfile", "containerfile",
        "justfile", "rakefile", "gemfile", "jenkinsfile", "vagrantfile", "build",
        "build.bazel", "workspace", "workspace.bazel", "meson.build", "meson_options.txt",
        "sconstruct", "sconscript", "procfile", "brewfile", "taskfile.yml", "taskfile.yaml",
    ].contains(&file)
        || [".gradle", ".gradle.kts", ".cmake"].iter().any(|ext| file.ends_with(ext))
        || file.starts_with("dockerfile.")
        || file.starts_with("containerfile.")
        // Pip requirements are dependency configuration, not documentation.
        || (file.starts_with("requirements") && file.ends_with(".txt"))
}

fn notice_name(file: &str) -> bool {
    let stem = file.strip_suffix(".txt").unwrap_or(file);
    [
        "readme",
        "license",
        "licence",
        "notice",
        "changes",
        "changelog",
        "authors",
        "contributors",
        "contributing",
        "copying",
        "copyright",
        "thanks",
        "news",
    ]
    .contains(&stem)
}

/// Without file evidence a data-looking name still defaults to Code.
pub fn classify(path: &str) -> Class {
    classify_with_size(path, 0)
}

/// Exclusion requires a specific convention. Nested directory names cannot
/// turn production source into tests, docs, data or vendor.
pub fn classify_with_size(path: &str, size: u64) -> Class {
    let native_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let path = path.replace('\\', "/").to_ascii_lowercase();
    let parts: Vec<_> = path.split('/').collect();
    let file = parts.last().copied().unwrap_or("");
    let dirs = &parts[..parts.len().saturating_sub(1)];
    let ext = file.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    // Only inventory-root containers are conclusive. A nested tests/vendor
    // name may be part of runtime code, even in an unfamiliar framework.
    // Prefer extra hunting to guessing that a nested directory is excluded.
    if dirs
        .first()
        .is_some_and(|dir| ["node_modules", "vendor", "third_party", "thirdparty"].contains(dir))
    {
        return Class::Vendored;
    }
    if dirs
        .first()
        .is_some_and(|dir| ["tests", "test", "__tests__", "spec", "specs"].contains(dir))
    {
        return Class::Test;
    }
    if is_source(file)
        && ([".test.", ".spec.", "_test.", "_tests.", ".tests."]
            .iter()
            .any(|suffix| {
                file.rsplit_once('.')
                    .is_some_and(|(stem, _)| stem.ends_with(suffix.trim_end_matches('.')))
            })
            || (dirs.is_empty() && ext == "py" && file.starts_with("test_"))
            || conventional_test_suffix(native_name)
            || ext == "bats")
    {
        return Class::Test;
    }
    if is_source(file) {
        return Class::Code;
    }
    if [
        "png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "avif", "woff", "woff2", "ttf", "otf",
        "mp3", "mp4", "pdf",
    ]
    .contains(&ext)
    {
        return Class::Asset;
    }
    if executable_filename(file) {
        return Class::Code;
    }
    if ["md", "rst", "adoc"].contains(&ext) || notice_name(file) {
        return Class::Docs;
    }
    // SQL, HTML, MDX and templates can execute and are never data dumps.
    // Size and suffix prioritize likely data, never establish inertness. Its
    // exclusion unit still requires review. No content is executed or loaded.
    if size >= 1 << 20 && ["json", "jsonl", "ndjson", "csv", "tsv"].contains(&ext) {
        return Class::Data;
    }
    Class::Code
}

pub fn classify_file(target: &Path, relative: &Path) -> Class {
    let meta = std::fs::symlink_metadata(target.join(relative))
        .ok()
        .filter(|m| m.is_file());
    #[cfg(unix)]
    if meta.as_ref().is_some_and(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    }) && classify_with_size(&display(relative), 0) == Class::Asset
    {
        return Class::Code;
    }
    let size = meta.map_or(0, |m| m.len());
    classify_with_size(&display(relative), size)
}

fn conventional_test_suffix(file: &str) -> bool {
    let Some((stem, ext)) = file.rsplit_once('.') else {
        return false;
    };
    if !["cs", "java", "kt", "swift"].contains(&ext.to_ascii_lowercase().as_str()) {
        return false;
    }
    ["Test", "Tests", "test", "tests"].iter().any(|suffix| {
        stem.strip_suffix(suffix).is_some_and(|prefix| {
            prefix.is_empty()
                || prefix.ends_with(['_', '.', '-'])
                || (suffix.starts_with('T')
                    && prefix.chars().last().is_some_and(|c| c.is_lowercase()))
        })
    })
}

#[cfg(test)]
mod overlap_tests {
    use super::overlaps;
    use std::path::{Path, PathBuf};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = crate::platform::temp_root().unwrap().join(format!(
                "omgs-overlap-{}",
                crate::platform::random_nonce().unwrap()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn check(&self, a: &str, b: &str, expected: bool) {
            let a = self.0.join(a);
            let b = self.0.join(b);
            assert_eq!(overlaps(&a, &b).unwrap(), expected, "{a:?} {b:?}");
            assert_eq!(overlaps(&b, &a).unwrap(), expected, "{b:?} {a:?}");
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn missing_suffixes_compare_only_under_the_same_physical_parent() {
        let f = Fixture::new();
        for (a, b, expected) in [
            ("cache", "CACHE", true),
            ("cache/run", "CACHE", true),
            ("cache", "CACHE/run", true),
            ("cache", "cache-other", false),
            ("cache/a", "CACHE/b", false),
            ("Ä/a", "ä/A/run", true),
            ("é/run", "e\u{301}/RUN", true),
            ("é/a", "e\u{301}/b", false),
            ("cache/é", "elsewhere/é", false),
        ] {
            f.check(a, b, expected);
        }
        for name in ["left", "right"] {
            std::fs::create_dir(f.0.join(name)).unwrap();
        }
        f.check("left", "right", false);
        f.check("left/missing", "right/MISSING", false);
        std::fs::create_dir(f.0.join("cache")).unwrap();
        f.check("cache", "cache/run", true);
        f.check("cache/a", "cache/b", false);
        // Lookup found cache, so a genuinely missing sibling is not an alias.
        f.check("cache", "other", false);
        if !f.0.join("CACHE").exists() {
            f.check("cache", "CACHE/run", false);
            std::fs::create_dir(f.0.join("CACHE")).unwrap();
            f.check("cache", "CACHE", false);
            f.check("cache/run", "CACHE/run", false);
        }
    }

    #[test]
    fn existing_aliases_use_filesystem_identity_and_ancestor_chains() {
        let f = Fixture::new();
        for (name, alias) in [("Repo", "repo"), ("Ä", "ä"), ("é", "e\u{301}")] {
            let dir = f.0.join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::create_dir(dir.join("child")).unwrap();
            f.check(name, &format!("{name}/child/run"), true);
            if f.0.join(alias).exists() {
                f.check(name, alias, true);
                f.check(name, &format!("{alias}/child/run"), true);
                f.check(
                    &format!("{name}/missing"),
                    &format!("{alias}/MISSING/run"),
                    true,
                );
            }
        }
        std::fs::write(f.0.join("file"), "fixture").unwrap();
        std::fs::hard_link(f.0.join("file"), f.0.join("hardlink")).unwrap();
        f.check("file", "hardlink", true);
        assert!(overlaps(&f.0.join("file/child"), &f.0).is_err());
        // Unix refuses '..' after a missing directory. Win32 path parsing
        // removes it lexically before the filesystem sees it, which is exact
        // there because a missing component cannot be a link.
        #[cfg(unix)]
        assert!(overlaps(&f.0.join("missing/../other"), &f.0).is_err());
        #[cfg(windows)]
        assert!(overlaps(&f.0.join("missing/../other"), &f.0).unwrap());
    }

    #[test]
    fn linked_ancestors_resolve_before_missing_suffixes() {
        let f = Fixture::new();
        let real = f.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = f.0.join("alias");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .status()
            .unwrap()
            .success());
        f.check("alias", "real", true);
        f.check("alias/missing/run", "real/MISSING", true);
        f.check("alias/missing", "real/distinct", false);
        assert!(overlaps(Path::new(&link), &real).unwrap());
    }
}
