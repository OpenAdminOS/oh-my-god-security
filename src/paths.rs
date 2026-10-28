//! Shared, path-only inventory policy. Classification never executes or reads
//! target content; data stays data regardless of its size.
use serde::Serialize;

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
    if ["md", "mdx", "rst", "txt", "adoc"].contains(&ext)
        || parts
            .iter()
            .any(|p| ["docs", "doc", "documentation"].contains(p))
        || ["license", "notice", "readme"].contains(&file)
    {
        return Class::Docs;
    }
    let source = [
        "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "cs", "cshtml", "csproj", "sln", "fs", "fsx",
        "vb", "swift", "ps1", "psm1", "psd1", "py", "pyi", "sh", "bash", "zsh", "ksh", "fish",
        "cmd", "bat", "html", "css", "scss", "sql", "go", "java", "kt", "rb", "php", "c", "h",
        "cpp", "hpp",
    ]
    .contains(&ext)
        || ["dockerfile", "makefile"].contains(&file);
    if source
        && (parts.iter().any(|p| {
            [
                "test",
                "tests",
                "__tests__",
                "spec",
                "specs",
                "fixtures",
                "__mocks__",
            ]
            .contains(p)
        }) || [".test.", ".spec.", "_test.", "_tests.", ".tests."]
            .iter()
            .any(|s| file.contains(s))
            || file.starts_with("test_")
            || file.starts_with("tests_")
            || file.ends_with("tests.swift")
            || file.ends_with("tests.cs")
            || file.ends_with("test.cs")
            || file.ends_with("test.java")
            || file.ends_with("test.kt")
            || file.ends_with(".bats"))
    {
        return Class::Test;
    }
    if ext == "bats" {
        return Class::Test;
    }
    if source {
        Class::Code
    } else {
        Class::Data
    }
}
