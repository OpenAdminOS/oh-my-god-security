//! Versioned, bounded identities for the bytes admitted to a proof workspace.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_MANIFEST_BYTES: u64 = 16 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub version: u32,
    pub paths: Vec<String>,
}

impl Selection {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION || self.paths.is_empty() || self.paths.len() > 256 {
            return Err("input selection needs version 1 and 1..=256 paths".into());
        }
        for (i, path) in self.paths.iter().enumerate() {
            safe_path(path)?;
            if self.paths[..i].iter().any(|p| overlaps(p, path)) {
                return Err(format!("overlapping input selection: {path}"));
            }
        }
        Ok(())
    }
}

pub fn read_selection(path: &Path) -> Result<Selection, String> {
    let file = crate::platform::open_regular(path).map_err(|e| e.to_string())?;
    let bytes = crate::platform::read_bounded_file(file, 65536).map_err(|e| e.to_string())?;
    let value = crate::shape::strict_json(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)?;
    if !value.is_object() {
        return Err("input selection must be an object".into());
    }
    let selection: Selection = serde_json::from_value(value).map_err(|e| e.to_string())?;
    selection.validate()?;
    Ok(selection)
}

pub fn safe_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains(['\\', ':', '\0'])
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || Path::new(path).is_absolute()
    {
        return Err("input paths must be canonical relative paths of at most 1024 bytes".into());
    }
    Ok(())
}

fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|p| p.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|p| p.starts_with('/'))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub kind: String,
    pub mode: u32,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub selection: Option<Selection>,
    pub entries: Vec<Entry>,
}

impl Manifest {
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err("execution input manifest exceeds 16 MiB; use --inputs-from".into());
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<String, String> {
        Ok(crate::sha256::digest(&self.bytes()?))
    }

    pub fn differences(&self, other: &Self) -> String {
        let old: std::collections::BTreeMap<_, _> =
            self.entries.iter().map(|e| (&e.path, e)).collect();
        let new: std::collections::BTreeMap<_, _> =
            other.entries.iter().map(|e| (&e.path, e)).collect();
        let paths: std::collections::BTreeSet<_> = old.keys().chain(new.keys()).collect();
        let changed: Vec<_> = paths
            .into_iter()
            .filter(|p| old.get(*p) != new.get(*p))
            .collect();
        let names: Vec<_> = changed
            .iter()
            .take(20)
            .map(|p| crate::platform::escape_controls(p))
            .collect();
        format!(
            "{} differing input path(s): {}",
            changed.len(),
            names.join(", ")
        )
    }
}

pub fn mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(windows)]
    {
        u32::from(meta.permissions().readonly())
    }
}

pub fn permissions(mode: u32, current: std::fs::Permissions) -> std::fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = current;
        std::fs::Permissions::from_mode(mode & 0o777)
    }
    #[cfg(windows)]
    {
        let mut p = current;
        p.set_readonly(mode != 0);
        p
    }
}

/// Hash normalized index bytes as well as all other Git state. The same index
/// normalization is applied to the disposable workspace before execution.
pub fn manifest(
    root: &Path,
    selection: Option<Selection>,
    normalize: bool,
) -> Result<Manifest, String> {
    if let Some(s) = &selection {
        s.validate()?;
    }
    let mut entries = Vec::new();
    walk(root, root, normalize, selection.as_ref(), &mut entries)?;
    let manifest = Manifest {
        version: VERSION,
        selection,
        entries,
    };
    manifest.bytes()?;
    Ok(manifest)
}

fn walk(
    root: &Path,
    dir: &Path,
    normalize: bool,
    selection: Option<&Selection>,
    out: &mut Vec<Entry>,
) -> Result<(), String> {
    let mut entries = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        crate::supervise::check_interrupted().map_err(|e| e.to_string())?;
        let path = entry.path();
        let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
        let name = rel
            .to_str()
            .ok_or("execution input paths must be UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if selection.is_some_and(|s| {
            name != ".git"
                && !name.starts_with(".git/")
                && !s.paths.iter().any(|p| overlaps(p, &name))
        }) {
            continue;
        }
        safe_path(&name)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if crate::platform::contentless(&meta) {
            continue;
        }
        if out.len() >= MAX_ENTRIES {
            return Err(
                "execution input manifest exceeds 100000 entries; use --inputs-from".into(),
            );
        }
        let (kind, digest) = if crate::platform::is_link(&meta) {
            let link = std::fs::canonicalize(&path)
                .ok()
                .and_then(|p| p.strip_prefix(root).ok().map(PathBuf::from))
                .map(|p| PathBuf::from("@workspace").join(p))
                .unwrap_or(std::fs::read_link(&path).map_err(|e| e.to_string())?);
            (
                "link",
                crate::sha256::digest(link.as_os_str().as_encoded_bytes()),
            )
        } else if meta.is_dir() {
            ("dir", crate::sha256::digest(b""))
        } else if meta.is_file() {
            if rel
                .file_name()
                .is_some_and(|s| s == "index" || s.to_string_lossy().starts_with("sharedindex."))
                && rel.components().any(|c| c.as_os_str() == ".git")
            {
                let bytes = crate::platform::read_bounded_in(root, rel, MAX_MANIFEST_BYTES)
                    .map_err(|e| e.to_string())?;
                let bytes = normalize_index(&bytes).map_err(|e| format!("{name}: {e}"))?;
                if normalize {
                    // Replace rather than modifying a possible hardlink to source.
                    crate::runmeta::write_atomic_bytes_with_permissions(
                        &path,
                        &bytes,
                        meta.permissions(),
                    )
                    .map_err(|e| e.to_string())?;
                }
                ("file", crate::sha256::digest(&bytes))
            } else {
                (
                    "file",
                    crate::sha256::digest_file(&path).map_err(|e| e.to_string())?,
                )
            }
        } else {
            return Err(format!("unsupported execution input: {name}"));
        };
        out.push(Entry {
            path: name,
            kind: kind.into(),
            mode: if kind == "link" { 0 } else { mode(&meta) },
            sha256: digest,
        });
        if meta.is_dir() && !crate::platform::is_link(&meta) {
            walk(root, &path, normalize, selection, out)?;
        }
    }
    Ok(())
}

/// Index v2/v3 with SHA-1 object IDs. Unknown formats fail closed. Preserve
/// modes, object IDs, paths, stages, flags and all non-cache extensions.
fn normalize_index(input: &[u8]) -> Result<Vec<u8>, String> {
    let invalid = || {
        "unsupported or malformed Git index; only SHA-1 index versions 2 and 3 are supported"
            .to_string()
    };
    if input.len() < 32 || &input[..4] != b"DIRC" {
        return Err(invalid());
    }
    let word = |at: usize| -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            input
                .get(at..at + 4)
                .ok_or_else(invalid)?
                .try_into()
                .unwrap(),
        ))
    };
    if ![2, 3].contains(&word(4)?) {
        return Err(invalid());
    }
    let end = input.len() - 20;
    if sha1(&input[..end]).as_slice() != &input[end..] {
        return Err(invalid());
    }
    let mut out = input[..12].to_vec();
    let mut at = 12;
    for _ in 0..word(8)? {
        let start = at;
        let entry = input
            .get(at..at + 62)
            .filter(|_| at + 62 <= end)
            .ok_or_else(invalid)?;
        let flags = u16::from_be_bytes([entry[60], entry[61]]);
        at += 62;
        if flags & 0x4000 != 0 {
            at += 2;
        }
        let tail = input.get(at..end).ok_or_else(invalid)?;
        at += tail.iter().position(|b| *b == 0).ok_or_else(invalid)? + 1;
        at = start + (at - start).div_ceil(8) * 8;
        let mut bytes = input
            .get(start..at)
            .filter(|_| at <= end)
            .ok_or_else(invalid)?
            .to_vec();
        // Stat data only: ctime, mtime, dev, ino, uid, gid and size.
        bytes[..24].fill(0);
        bytes[28..40].fill(0);
        out.extend(bytes);
    }
    while at < end {
        let header = input
            .get(at..at + 8)
            .filter(|_| at + 8 <= end)
            .ok_or_else(invalid)?;
        let size = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
        let next = at
            .checked_add(8)
            .and_then(|n| n.checked_add(size))
            .filter(|n| *n <= end)
            .ok_or_else(invalid)?;
        if &header[..4] == b"link" {
            return Err(
                "split Git indexes are unsupported execution inputs; use a standalone full index"
                    .into(),
            );
        }
        if ![b"TREE", b"UNTR", b"FSMN", b"EOIE", b"IEOT"].contains(&header[..4].try_into().unwrap())
        {
            out.extend_from_slice(&input[at..next]);
        }
        at = next;
    }
    let sum = sha1(&out);
    out.extend(sum);
    Ok(out)
}

// SHA-1 is used only for Git's existing index checksum, never proof identity.
fn sha1(input: &[u8]) -> [u8; 20] {
    let mut bytes = input.to_vec();
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&((input.len() as u64) * 8).to_be_bytes());
    let mut h = [
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    for block in bytes.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, b) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*b);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (v, add) in h.iter_mut().zip([a, b, c, d, e]) {
            *v = v.wrapping_add(add);
        }
    }
    let mut result = [0; 20];
    for (chunk, value) in result.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    result
}

/// Read a retained manifest only through the run artifact admission boundary.
pub fn retained(
    run: &Path,
    record: &crate::proof::ProofRecord,
) -> Result<Option<Manifest>, String> {
    let Some(identity) = &record.execution_inputs else {
        return if record.target.is_some() {
            Err("missing versioned execution input identity; rerun proof".into())
        } else {
            Ok(None)
        };
    };
    if identity.version != VERSION {
        return Err("unsupported execution input identity version; rerun proof".into());
    }
    let path = Path::new("proofs")
        .join(record.n.to_string())
        .join("input-manifest.json");
    let text = crate::run_artifact::text(run, &path, MAX_MANIFEST_BYTES)?;
    let value = crate::shape::strict_json(&text)?;
    if !value.is_object()
        || value
            .get("entries")
            .and_then(|v| v.as_array())
            .is_none_or(|entries| entries.iter().any(|e| !e.is_object()))
        || value
            .get("selection")
            .is_some_and(|v| !v.is_null() && !v.is_object())
    {
        return Err("execution input manifest and entries must be objects".into());
    }
    let manifest: Manifest = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if manifest.version != VERSION
        || manifest.entries.len() > MAX_ENTRIES
        || manifest.digest()? != identity.sha256
        || record.target_sha256.as_ref() != Some(&identity.sha256)
    {
        return Err("retained execution input manifest does not match record identity".into());
    }
    if let Some(s) = &manifest.selection {
        s.validate()?;
    }
    for e in &manifest.entries {
        safe_path(&e.path)?;
    }
    Ok(Some(manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> Vec<u8> {
        let mut data = b"DIRC\0\0\0\x02\0\0\0\x01".to_vec();
        let mut entry = vec![0; 72];
        entry[..40].fill(1);
        entry[24..28].copy_from_slice(&0o100644u32.to_be_bytes());
        entry[40..60].fill(7);
        entry[60..62].copy_from_slice(&5u16.to_be_bytes());
        entry[62..68].copy_from_slice(b"a.txt\0");
        data.extend(entry);
        checksum(&mut data);
        data
    }
    fn checksum(data: &mut Vec<u8>) {
        data.extend(sha1(data));
    }
    fn reseal(mut data: Vec<u8>) -> Vec<u8> {
        data.truncate(data.len() - 20);
        checksum(&mut data);
        data
    }

    #[test]
    fn index_refreshes_are_normalized_but_every_semantic_field_is_bound() {
        assert_eq!(
            crate::sha256::hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let data = index();
        let normalized = normalize_index(&data).unwrap();
        assert_eq!(normalize_index(&normalized).unwrap(), normalized);
        for at in (12..36).chain(40..52) {
            let mut changed = data.clone();
            changed[at] ^= 1;
            assert_eq!(
                normalize_index(&reseal(changed)).unwrap(),
                normalized,
                "stat byte {at}"
            );
        }
        for at in (36..40).chain(52..72).chain([72, 74]) {
            let mut changed = data.clone();
            changed[at] ^= 1;
            let result = normalize_index(&reseal(changed));
            assert!(
                result.is_err() || result.unwrap() != normalized,
                "semantic byte {at}"
            );
        }
        for signature in [b"TREE", b"UNTR", b"FSMN", b"EOIE", b"IEOT"] {
            let mut changed = data[..data.len() - 20].to_vec();
            changed.extend(signature);
            changed.extend(3u32.to_be_bytes());
            changed.extend(b"abc");
            checksum(&mut changed);
            assert_eq!(normalize_index(&changed).unwrap(), normalized);
        }
        let mut changed = data[..data.len() - 20].to_vec();
        changed.extend(b"TEST\0\0\0\x03abc");
        checksum(&mut changed);
        assert_ne!(normalize_index(&changed).unwrap(), normalized);
        let mut corrupt = data.clone();
        corrupt[20] ^= 1;
        assert!(normalize_index(&corrupt).is_err());
        let mut version4 = data;
        version4[7] = 4;
        assert!(normalize_index(&reseal(version4)).is_err());
    }

    #[test]
    fn versioned_manifest_binds_source_config_hooks_refs_objects_modes_and_index() {
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-inputs-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_tree(&d.join(".git/hooks")).unwrap();
        crate::platform::create_private_tree(&d.join(".git/refs/heads")).unwrap();
        crate::platform::create_private_tree(&d.join(".git/objects")).unwrap();
        let names = [
            "source",
            ".git/config",
            ".git/hooks/pre-commit",
            ".git/HEAD",
            ".git/refs/heads/main",
            ".git/objects/pack",
        ];
        for name in names {
            std::fs::write(d.join(name), b"original").unwrap();
        }
        crate::runmeta::write_atomic_bytes(&d.join(".git/index"), &index()).unwrap();
        let original = manifest(&d, None, false).unwrap();
        for name in names {
            std::fs::write(d.join(name), b"changed").unwrap();
            let next = manifest(&d, None, false).unwrap();
            assert_ne!(next.digest().unwrap(), original.digest().unwrap());
            assert!(original.differences(&next).contains(name));
            std::fs::write(d.join(name), b"original").unwrap();
        }
        let raw = index();
        let mut refreshed = raw.clone();
        refreshed[12] ^= 1;
        crate::runmeta::write_atomic_bytes(&d.join(".git/index"), &reseal(refreshed)).unwrap();
        assert_eq!(manifest(&d, None, false).unwrap(), original);
        assert_eq!(manifest(&d, None, true).unwrap(), original);
        assert_eq!(
            std::fs::read(d.join(".git/index")).unwrap(),
            normalize_index(&raw).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::metadata(d.join("source")).unwrap().permissions();
            std::fs::set_permissions(
                d.join("source"),
                std::fs::Permissions::from_mode(permissions.mode() ^ 0o100),
            )
            .unwrap();
            assert_ne!(manifest(&d, None, false).unwrap(), original);
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn scoped_manifest_omits_unselected_data_but_always_keeps_git() {
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-select-{}",
            crate::platform::random_nonce().unwrap()
        ));
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join(".git/config"), b"config").unwrap();
        std::fs::write(d.join("source"), b"source").unwrap();
        std::fs::write(d.join("asset"), b"asset").unwrap();
        let selection = Some(Selection {
            version: 1,
            paths: vec!["source".into()],
        });
        let first = manifest(&d, selection.clone(), false).unwrap();
        assert!(first.entries.iter().any(|e| e.path == ".git/config"));
        std::fs::write(d.join("asset"), b"changed").unwrap();
        assert_eq!(manifest(&d, selection.clone(), false).unwrap(), first);
        std::fs::write(d.join(".git/config"), b"changed").unwrap();
        assert_ne!(manifest(&d, selection, false).unwrap(), first);
        for paths in [
            vec!["../a"],
            vec!["a", "a/b"],
            vec!["/a"],
            vec!["a\\b"],
            vec!["a:b"],
            vec!["a/./b"],
        ] {
            assert!(Selection {
                version: 1,
                paths: paths.into_iter().map(String::from).collect()
            }
            .validate()
            .is_err());
        }
        assert!(Selection {
            version: 2,
            paths: vec!["a".into()]
        }
        .validate()
        .is_err());
        std::fs::remove_dir_all(d).unwrap();
    }
}
