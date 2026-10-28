//! Shared, path-only inventory policy. Classification never executes or reads
//! target content; data stays data regardless of its size.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Code,
    Test,
    Docs,
    Data,
    Vendored,
}

pub fn classify(path: &str) -> Class {
    let native_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let path = path.replace('\\', "/").to_lowercase();
    let parts: Vec<_> = path.split('/').collect();
    let file = parts.last().copied().unwrap_or("");
    let ext = file.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if parts.iter().any(|p| {
        [
            "vendor",
            "node_modules",
            "third_party",
            "thirdparty",
            "external",
            "monacoeditor",
            "dist",
            "build",
            "target",
            ".next",
            ".git",
        ]
        .contains(p)
    }) || [".min.js", ".min.css", ".dll", ".exe", ".pdb", ".map"]
        .iter()
        .any(|e| file.ends_with(e))
    {
        return Class::Vendored;
    }
    let source = [
        "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "cs", "cshtml", "csproj", "sln", "fs", "fsx",
        "vb", "swift", "ps1", "psm1", "psd1", "py", "pyi", "sh", "bash", "zsh", "ksh", "fish",
        "cmd", "bat", "html", "css", "scss", "sql", "go", "java", "kt", "rb", "php", "c", "h",
        "cpp", "hpp",
    ]
    .contains(&ext)
        || ["dockerfile", "makefile"].contains(&file);
    // Explicit fixture/test containers apply to manifests too. Broad "spec"
    // and "docs" hints cannot hide runtime app paths or named applications.
    let runtime = parts
        .iter()
        .any(|p| ["src", "app", "pages", "api", "server", "components"].contains(p));
    let test_dir = parts
        .iter()
        .any(|p| ["test", "tests", "__tests__", "fixtures", "__mocks__"].contains(p))
        || (!runtime && parts.first().is_some_and(|p| ["spec", "specs"].contains(p)));
    if test_dir
        || (source
            && ([".test.", ".spec.", "_test.", "_tests.", ".tests."]
                .iter()
                .any(|s| file.contains(s))
                || file.starts_with("test_")
                || file.starts_with("tests_")
                || conventional_test_suffix(native_name)))
        || ext == "bats"
    {
        return Class::Test;
    }
    let marker = [
        "package.json",
        "cargo.toml",
        "package.swift",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "go.mod",
        "manifest.json",
    ]
    .contains(&file)
        || ext == "csproj";
    if marker {
        return if source { Class::Code } else { Class::Data };
    }
    if ["md", "mdx", "rst", "txt", "adoc"].contains(&ext)
        || ["license", "notice", "readme"].contains(&file)
        || (!runtime
            && parts
                .first()
                .is_some_and(|p| ["docs", "doc", "documentation"].contains(p)))
    {
        return Class::Docs;
    }
    // SQL and HTML are code unless explicitly named or stored as dumps/exports.
    if ["sql", "html"].contains(&ext)
        && (parts.iter().any(|p| ["dumps", "exports"].contains(p))
            || ["dump.sql", "dump.html", "export.sql", "export.html"].contains(&file)
            || file.ends_with(".dump.sql")
            || file.ends_with(".dump.html"))
    {
        return Class::Data;
    }
    if source {
        Class::Code
    } else {
        Class::Data
    }
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
