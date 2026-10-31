//! Stack inventory grouped by nearest project marker. Native paths are used
//! for reads; display paths are never converted back into filesystem paths.
use crate::paths::{classify_file, display, safe_relative, Class};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const INVENTORY_LIMIT: usize = 100_000;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Project {
    pub root: String,
    pub stacks: Vec<&'static str>,
}

pub fn detect(target: &Path, paths: &[PathBuf]) -> Vec<Project> {
    let eligible: Vec<_> = paths
        .iter()
        .take(INVENTORY_LIMIT)
        .filter(|p| {
            safe_relative(p)
                && !matches!(
                    classify_file(target, p),
                    Class::Vendored | Class::Docs | Class::Test | Class::Asset
                )
        })
        .collect();
    let mut roots = BTreeSet::new();
    let mut extensions = BTreeSet::new();
    for path in &eligible {
        let parent = path.parent().unwrap_or(Path::new("")).to_path_buf();
        let file = path.file_name().unwrap().to_string_lossy();
        let extension = file == "manifest.json"
            && crate::platform::read_bounded_in(target, path, 1 << 20)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .is_some_and(|v| {
                    matches!(
                        v.get("manifest_version").and_then(|v| v.as_u64()),
                        Some(2 | 3)
                    )
                });
        if extension {
            extensions.insert(parent.clone());
        }
        if extension
            || [
                "package.json",
                "Cargo.toml",
                "Package.swift",
                "pyproject.toml",
                "setup.py",
                "setup.cfg",
                "go.mod",
            ]
            .contains(&file.as_ref())
            || file.ends_with(".csproj")
        {
            roots.insert(parent);
        }
    }
    // Seed marker roots even if no supported stack can be inferred. Lookup
    // walks ancestors rather than scanning every root for every inventory path.
    let mut groups: BTreeMap<PathBuf, Vec<(String, Class)>> =
        roots.iter().map(|r| (r.clone(), Vec::new())).collect();
    for path in eligible {
        let root = path
            .parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .find(|p| roots.contains(*p))
            .unwrap_or(Path::new(""));
        groups
            .entry(root.to_path_buf())
            .or_default()
            .push((display(path), classify_file(target, path)));
    }
    groups
        .into_iter()
        .filter_map(|(root, paths)| {
            // Keep full paths for classification, including fixture ancestry.
            let mut stacks =
                crate::detect_stacks(&paths.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>());
            if extensions.contains(&root) {
                stacks.push("browser-extension");
            }
            (!stacks.is_empty()
                || roots.contains(&root)
                || paths.iter().any(|(_, class)| *class == Class::Code))
            .then(|| Project {
                root: if root.as_os_str().is_empty() {
                    ".".into()
                } else {
                    display(&root)
                },
                stacks,
            })
        })
        .collect()
}
