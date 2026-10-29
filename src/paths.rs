//! Heuristic inventory priority. Every class remains accountable in the ledger.
//! Classification uses path conventions and file size, never execution.
use serde::Serialize;
use std::path::{Component, Path};

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
    Vendored,
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
    let size = std::fs::symlink_metadata(target.join(relative))
        .ok()
        .filter(|m| m.is_file())
        .map_or(0, |m| m.len());
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
