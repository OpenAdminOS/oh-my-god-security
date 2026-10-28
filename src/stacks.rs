//! Stack inventory grouped by nearest project marker. Nested packages never
//! leak their stack into a parent project. Manifest content is read as data.
use crate::paths::{classify, Class};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Project {
    pub root: String,
    pub stacks: Vec<&'static str>,
}

pub fn detect(target: &Path, paths: &[String]) -> Vec<Project> {
    let paths: Vec<String> = paths.iter().map(|p| p.replace('\\', "/")).collect();
    let mut roots = BTreeSet::from([String::new()]);
    let mut extensions = BTreeSet::new();
    for path in &paths {
        if matches!(classify(path), Class::Vendored | Class::Docs | Class::Test) {
            continue;
        }
        let (parent, file) = path.rsplit_once('/').unwrap_or(("", path));
        let extension = file == "manifest.json"
            && crate::platform::read_bounded(&target.join(path), 1 << 20)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .is_some_and(|v| {
                    matches!(
                        v.get("manifest_version").and_then(|v| v.as_u64()),
                        Some(2 | 3)
                    )
                });
        if extension {
            extensions.insert(parent.to_string());
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
            .contains(&file)
            || file.ends_with(".csproj")
        {
            roots.insert(parent.to_string());
        }
    }
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in &paths {
        let root = roots
            .iter()
            .filter(|r| r.is_empty() || path.starts_with(&format!("{r}/")))
            .max_by_key(|r| r.len())
            .unwrap();
        let rel = if root.is_empty() {
            path.as_str()
        } else {
            &path[root.len() + 1..]
        };
        groups.entry(root.clone()).or_default().push(rel.into());
    }
    groups
        .into_iter()
        .filter_map(|(root, paths)| {
            let mut stacks = crate::detect_stacks(&paths);
            if extensions.contains(&root) {
                stacks.push("browser-extension");
            }
            (!stacks.is_empty()).then(|| Project {
                root: if root.is_empty() { ".".into() } else { root },
                stacks,
            })
        })
        .collect()
}
