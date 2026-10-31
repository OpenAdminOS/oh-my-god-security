//! Versioned, bounded identities for the bytes admitted to a proof workspace.
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const VERSION: u32 = 4;
const MAX_LINE_BYTES: usize = 6400;
const MAX_HEADER_BYTES: usize = 1 << 20;
// Shared with gate export policy. Six JSON bytes per path byte plus entry
// fields covers even maximally escaped canonical 1024-byte paths.
pub const MAX_ENTRIES: usize = crate::policy::GateLimits::MAX_ENTRIES;
pub const MAX_MANIFEST_BYTES: u64 = MAX_ENTRIES as u64 * 6400 + 65536;
pub(crate) const MAX_INDEX_BYTES: u64 = 16 << 20;

// Fixed preparation limits, independent of the later executor timeout.
pub(crate) const MAX_SOURCE_BYTES: u64 = 8 << 30;
const STAGING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
// Staging is synchronous. Nested manifest passes reuse the outer operation
// budget; the owning guard clears it on success, error or unwind. Standalone
// manifest generation gets the same bounds without changing its public API.
thread_local! {
    static STAGING: std::cell::RefCell<Option<(std::time::Instant, u64)>> = const { std::cell::RefCell::new(None) };
    #[cfg(test)]
    static ENUMERATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(crate) struct StagingGuard(bool);
impl StagingGuard {
    pub(crate) fn begin() -> Self {
        Self(STAGING.with(|state| {
            let mut state = state.borrow_mut();
            if state.is_some() {
                false
            } else {
                *state = Some((std::time::Instant::now() + STAGING_TIMEOUT, 0));
                true
            }
        }))
    }
}
impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.0 {
            STAGING.with(|state| *state.borrow_mut() = None);
        }
    }
}
#[cfg(test)]
pub(crate) fn expire_staging() {
    STAGING.with(|state| state.borrow_mut().as_mut().unwrap().0 = std::time::Instant::now());
}
pub(crate) fn check_staging() -> Result<(), String> {
    crate::supervise::check_interrupted().map_err(|e| e.to_string())?;
    STAGING.with(|state| {
        if state
            .borrow()
            .as_ref()
            .is_some_and(|(end, _)| std::time::Instant::now() >= *end)
        {
            Err("proof staging deadline exceeded (10 minutes)".into())
        } else {
            Ok(())
        }
    })
}

// Reserve the complete admitted size before any content read or destination write.
pub(crate) fn admitted_file(path: &Path) -> Result<AdmittedFile, String> {
    check_staging()?;
    let file = crate::platform::open_regular(path).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    STAGING.with(|state| {
        if let Some((_, used)) = state.borrow_mut().as_mut() {
            if size > MAX_SOURCE_BYTES - *used {
                return Err(
                    "proof staging aggregate source byte budget exceeded (8 GiB)".to_string(),
                );
            }
            *used += size;
        } else if size > MAX_SOURCE_BYTES {
            return Err("proof staging aggregate source byte budget exceeded (8 GiB)".to_string());
        }
        Ok(())
    })?;
    Ok(AdmittedFile {
        file,
        size,
        remaining: size,
    })
}
pub(crate) struct AdmittedFile {
    file: std::fs::File,
    size: u64,
    remaining: u64,
}
impl AdmittedFile {
    pub(crate) fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.file.metadata()
    }
}
impl std::io::Read for AdmittedFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Error;
        check_staging().map_err(Error::other)?;
        if buf.is_empty() {
            return Ok(0);
        }
        let changed = || Error::other("target changed during staging: file size changed");
        if self.file.metadata()?.len() != self.size {
            return Err(changed());
        }
        if self.remaining == 0 {
            if self.file.read(&mut [0u8; 1])? != 0 {
                return Err(changed());
            }
            return Ok(0);
        }
        let limit = self.remaining.min(buf.len() as u64) as usize;
        let n = self.file.read(&mut buf[..limit])?;
        if n == 0 {
            return Err(changed());
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}
pub(crate) fn read_index(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut file = admitted_file(path)?;
    if file.size > MAX_INDEX_BYTES {
        return Err("Git index exceeds byte limit".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn hash_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = admitted_file(path)?;
    let mut hash = crate::sha256::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(crate::sha256::hex(&hash.finish()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub version: u32,
    pub paths: Vec<String>,
}

impl Selection {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.paths.is_empty() || self.paths.len() > 256 {
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

/// A small identity descriptor, never an in-memory entry collection.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub selection: Option<Selection>,
    pub count: usize,
    root: std::path::PathBuf,
    sha256: String,
    retained: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

impl PartialEq for Manifest {
    fn eq(&self, other: &Self) -> bool {
        self.sha256 == other.sha256 && self.selection == other.selection
    }
}
impl Eq for Manifest {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    entries: usize,
    selection: Option<Selection>,
}

struct DigestWriter<W> {
    inner: W,
    hash: crate::sha256::Sha256,
    bytes: u64,
}
impl<W: std::io::Write> std::io::Write for DigestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES - self.bytes {
            return Err(std::io::Error::other(
                "execution input manifest exceeds serialized byte limit",
            ));
        }
        let n = self.inner.write(bytes)?;
        self.hash.update(&bytes[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn line(writer: &mut impl std::io::Write, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())
}

impl Manifest {
    pub fn digest(&self) -> Result<String, String> {
        Ok(self.sha256.clone())
    }

    fn stream(&self, writer: impl std::io::Write) -> Result<String, String> {
        let mut writer = DigestWriter {
            inner: writer,
            hash: crate::sha256::Sha256::new(),
            bytes: 0,
        };
        line(
            &mut writer,
            &Header {
                version: VERSION,
                entries: self.count,
                selection: self.selection.clone(),
            },
        )?;
        let mut count = 0;
        walk(
            &self.root,
            &self.root,
            self.selection.as_ref(),
            &mut count,
            &mut |entry| line(&mut writer, &entry),
        )?;
        if count != self.count {
            return Err("execution inputs changed while streaming manifest".into());
        }
        std::io::Write::flush(&mut writer).map_err(|e| e.to_string())?;
        Ok(crate::sha256::hex(&writer.hash.finish()))
    }

    pub fn write_to(&self, path: &Path) -> Result<(), String> {
        crate::runmeta::write_atomic_stream(path, None, |file| {
            let digest = self
                .stream(std::io::BufWriter::new(file))
                .map_err(std::io::Error::other)?;
            if digest != self.sha256 {
                return Err(std::io::Error::other(
                    "execution inputs changed before publication",
                ));
            }
            Ok(())
        })
        .map_err(|e| e.to_string())
    }

    pub fn differences(&self, other: &Self) -> String {
        let Some((run, path)) = &self.retained else {
            return "input identity mismatch".into();
        };
        let result = crate::run_artifact::with_reader(run, path, |file| {
            let mut reader = ManifestReader::new(std::io::BufReader::new(file))
                .map_err(std::io::Error::other)?;
            let mut difference = None;
            let mut count = 0;
            let comparison = walk(
                &other.root,
                &other.root,
                other.selection.as_ref(),
                &mut count,
                &mut |entry| {
                    let old = reader.next()?;
                    if old.as_ref() != Some(&entry) {
                        difference = Some(format!(
                            "differing input path(s): {}{}",
                            crate::platform::escape_controls(&entry.path),
                            old.filter(|e| e.path != entry.path)
                                .map(|e| format!(", {}", crate::platform::escape_controls(&e.path)))
                                .unwrap_or_default()
                        ));
                        return Err("stop at first divergence".into());
                    }
                    Ok(())
                },
            );
            if let Some(difference) = difference {
                return Ok(difference);
            }
            comparison.map_err(std::io::Error::other)?;
            if let Some(old) = reader.next().map_err(std::io::Error::other)? {
                return Ok(format!(
                    "differing input path(s): {}",
                    crate::platform::escape_controls(&old.path)
                ));
            }
            Ok("input header differs".into())
        });
        result.unwrap_or_else(|e| format!("input diagnostics unavailable: {e}"))
    }
}

fn read_line(reader: &mut impl std::io::BufRead, limit: usize) -> Result<Vec<u8>, String> {
    use std::io::{BufRead, Read};
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit || (!bytes.is_empty() && bytes.last() != Some(&b'\n')) {
        return Err("invalid or oversized execution input manifest line".into());
    }
    Ok(bytes)
}

fn strict_line<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let value = crate::shape::strict_json(std::str::from_utf8(bytes).map_err(|e| e.to_string())?)?;
    if !value.is_object() {
        return Err("manifest lines must be objects".into());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}

struct ManifestReader<R> {
    reader: R,
    remaining: usize,
    bytes: u64,
    previous: Option<String>,
}
impl<R: std::io::BufRead> ManifestReader<R> {
    fn new(mut reader: R) -> Result<Self, String> {
        let bytes = read_line(&mut reader, MAX_HEADER_BYTES)?;
        let header: Header = strict_line(&bytes)?;
        check_entry_count(header.entries)?;
        if header.version != VERSION {
            return Err("unsupported execution input manifest version; rerun proof".into());
        }
        if let Some(s) = &header.selection {
            s.validate()?;
        }
        Ok(Self {
            reader,
            remaining: header.entries,
            bytes: bytes.len() as u64,
            previous: None,
        })
    }
    fn next(&mut self) -> Result<Option<Entry>, String> {
        // Check the count before allocating or reading any additional line.
        if self.remaining == 0 {
            if !self
                .reader
                .fill_buf()
                .map_err(|e| e.to_string())?
                .is_empty()
            {
                return Err("execution input manifest exceeds declared entry count".into());
            }
            return Ok(None);
        }
        let bytes = read_line(&mut self.reader, MAX_LINE_BYTES)?;
        self.bytes += bytes.len() as u64;
        if self.bytes > MAX_MANIFEST_BYTES {
            return Err("execution input manifest exceeds serialized byte limit".into());
        }
        let entry: Entry = strict_line(&bytes)?;
        safe_path(&entry.path)?;
        if !["file", "dir", "link"].contains(&entry.kind.as_str())
            || entry.mode > if cfg!(windows) { 1 } else { 0o777 }
            || (entry.kind == "link" && entry.mode != 0)
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || (entry.kind == "dir" && entry.sha256 != crate::sha256::digest(b""))
            || self
                .previous
                .as_ref()
                .is_some_and(|p| path_order(p, &entry.path) != std::cmp::Ordering::Less)
        {
            return Err("invalid or unordered execution input entry".into());
        }
        self.previous = Some(entry.path.clone());
        self.remaining -= 1;
        Ok(Some(entry))
    }
}

fn path_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.split('/').cmp(b.split('/'))
}

fn check_entry_count(count: usize) -> Result<(), String> {
    if count > MAX_ENTRIES {
        return Err(format!(
            "execution input manifest exceeds {MAX_ENTRIES} entries; use --inputs-from"
        ));
    }
    Ok(())
}

pub(crate) fn admit_entry(count: &mut usize) -> Result<(), String> {
    check_entry_count(*count + 1)?;
    *count += 1;
    Ok(())
}

/// Windows reparse links cannot be materialized with portable exact semantics.
/// Use the same admission boundary for source validation and workspace staging.
pub(crate) fn admit_link(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        Err(format!("unsupported execution input link on Windows: {}; use a target without links or reparse points", path.display()))
    }
    #[cfg(unix)]
    {
        let _ = path;
        Ok(())
    }
}

pub fn mode(meta: &std::fs::Metadata) -> u32 {
    permission_mode(&meta.permissions())
}

pub(crate) fn permission_mode(permissions: &std::fs::Permissions) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.mode() & 0o777
    }
    #[cfg(windows)]
    {
        u32::from(permissions.readonly())
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
/// normalization is applied while freshly staging the disposable workspace.
pub fn manifest(root: &Path, selection: Option<Selection>) -> Result<Manifest, String> {
    let _budget = StagingGuard::begin();
    let mut manifest = descriptor(root, selection)?;
    manifest.sha256 = manifest.stream(std::io::sink())?;
    Ok(manifest)
}

/// Publish the staged identity in one content-hashing pass, before execution.
pub fn manifest_to(
    root: &Path,
    selection: Option<Selection>,
    path: &Path,
) -> Result<Manifest, String> {
    let _budget = StagingGuard::begin();
    let mut manifest = descriptor(root, selection)?;
    let mut digest = String::new();
    crate::runmeta::write_atomic_stream(path, None, |file| {
        digest = manifest
            .stream(std::io::BufWriter::new(file))
            .map_err(std::io::Error::other)?;
        Ok(())
    })
    .map_err(|e| e.to_string())?;
    manifest.sha256 = digest;
    Ok(manifest)
}

fn descriptor(root: &Path, selection: Option<Selection>) -> Result<Manifest, String> {
    if let Some(s) = &selection {
        s.validate()?;
        verify_selection(root, s)?;
    }
    let mut count = 0;
    // Count first so the canonical header precedes entries. No content is retained.
    count_paths(root, root, selection.as_ref(), &mut count)?;
    Ok(Manifest {
        selection,
        count,
        root: root.into(),
        sha256: String::new(),
        retained: None,
    })
}

/// Require the literal directory-entry spelling, never a filesystem alias.
/// Also used on the completed workspace: every selected component must occur
/// exactly once, and none may have become a link during materialization.
pub(crate) fn verify_selection(root: &Path, selection: &Selection) -> Result<(), String> {
    check_paths(
        root,
        &selection
            .paths
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        false,
    )
}

/// Group requested components by parent, retaining only requested names.
pub(crate) fn check_paths(root: &Path, paths: &[&str], harness: bool) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut parents: BTreeMap<String, BTreeMap<String, bool>> = BTreeMap::new();
    for path in paths {
        let mut parent = String::new();
        let parts: Vec<_> = path.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            parents
                .entry(parent.clone())
                .or_default()
                .insert((*part).into(), i + 1 == parts.len());
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(part);
        }
    }
    let mut missing = BTreeSet::new();
    let mut scanned = 0;
    for (parent, wanted) in parents {
        check_staging()?;
        if missing
            .iter()
            .any(|p: &String| parent == *p || parent.starts_with(&format!("{p}/")))
        {
            continue;
        }
        let dir = root.join(&parent);
        let lookup: BTreeMap<_, _> = wanted
            .iter()
            .map(|(part, leaf)| {
                (
                    if harness {
                        part.to_ascii_lowercase()
                    } else {
                        part.clone()
                    },
                    (part, leaf),
                )
            })
            .collect();
        let mut found = BTreeSet::new();
        #[cfg(test)]
        ENUMERATIONS.with(|n| n.set(n.get() + 1));
        for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
            check_staging()?;
            admit_entry(&mut scanned)?;
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            if harness && !name.to_str().is_some_and(str::is_ascii) {
                return Err("target has an ambiguous Unicode or non-UTF-8 harness sibling".into());
            }
            let Some(name) = name.to_str() else {
                continue;
            };
            let key = if harness {
                name.trim_end_matches([' ', '.']).to_ascii_lowercase()
            } else {
                name.to_owned()
            };
            if let Some((part, leaf)) = lookup.get(&key) {
                if harness && (name != *part || **leaf) {
                    return Err("harness destination collides with target entry".into());
                }
                let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
                if crate::platform::is_link(&meta)
                    || (!meta.is_dir() && (harness || !meta.is_file()))
                {
                    return Err(
                        "selected input or harness ancestor must not be a link or unsupported file"
                            .into(),
                    );
                }
                found.insert((*part).clone());
            }
        }
        for part in wanted.keys().filter(|part| !found.contains(*part)) {
            if !harness {
                return Err(
                    "selected input must match exactly one directory entry with exact spelling"
                        .into(),
                );
            }
            let relative = if parent.is_empty() {
                part.clone()
            } else {
                format!("{parent}/{part}")
            };
            match std::fs::symlink_metadata(root.join(&relative)) {
                Ok(_) => return Err("harness destination collides with target entry".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.insert(relative);
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    Ok(())
}

// Each directory is read once. Only selected candidates consume sort memory.
const MAX_DIRECTORY_NAMES: usize = 200_000;
const MAX_DIRECTORY_NAME_BYTES: usize = 32 << 20;

#[derive(Clone, Copy)]
struct DirectoryLimits {
    entries: usize,
    names: usize,
    bytes: usize,
}
const DIRECTORY_LIMITS: DirectoryLimits = DirectoryLimits {
    entries: MAX_ENTRIES,
    names: MAX_DIRECTORY_NAMES,
    bytes: MAX_DIRECTORY_NAME_BYTES,
};

pub(crate) fn children(
    dir: &Path,
    mut visit: impl FnMut(std::fs::DirEntry) -> Result<(), String>,
) -> Result<(), String> {
    sorted_children(dir, &mut 0, |_| true, |entry, _| visit(entry))
}

/// Charge every enumerated sibling, including omitted scoped inputs, to the
/// shared traversal budget before retaining or sorting selected candidates.
pub(crate) fn children_selected(
    root: &Path,
    dir: &Path,
    selection: Option<&Selection>,
    count: &mut usize,
    visit: impl FnMut(std::fs::DirEntry, &mut usize) -> Result<(), String>,
) -> Result<(), String> {
    let prefix = dir
        .strip_prefix(root)
        .map_err(|e| e.to_string())?
        .to_str()
        .ok_or("execution input paths must be UTF-8")?
        .replace(std::path::MAIN_SEPARATOR, "/");
    sorted_children(
        dir,
        count,
        |name| {
            let relative = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            selection.is_none_or(|s| {
                relative == ".git"
                    || relative.starts_with(".git/")
                    || s.paths.iter().any(|p| overlaps(p, &relative))
            })
        },
        visit,
    )
}

fn sorted_children(
    dir: &Path,
    count: &mut usize,
    include: impl FnMut(&str) -> bool,
    mut visit: impl FnMut(std::fs::DirEntry, &mut usize) -> Result<(), String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .map(|entry| {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "execution input paths must be UTF-8")?;
            Ok((name, entry))
        });
    for (_, entry) in sorted_names(dir, entries, count, DIRECTORY_LIMITS, include)? {
        visit(entry, count)?;
    }
    Ok(())
}

fn sorted_names<T>(
    dir: &Path,
    entries: impl IntoIterator<Item = Result<(String, T), String>>,
    count: &mut usize,
    limits: DirectoryLimits,
    mut include: impl FnMut(&str) -> bool,
) -> Result<Vec<(String, T)>, String> {
    let mut names = Vec::new();
    let mut bytes = 0;
    for (scanned, entry) in entries.into_iter().enumerate() {
        check_staging()?;
        if scanned >= limits.entries {
            return Err(format!(
                "execution input directory {} exceeds {} entries",
                dir.display(),
                limits.entries
            ));
        }
        admit_entry(count)?;
        let (name, entry) = entry?;
        if !include(&name) {
            continue;
        }
        if names.len() >= limits.names || name.len() > limits.bytes - bytes {
            return Err(format!("execution input directory {} exceeds sort memory budget ({} names or {} name bytes)", dir.display(), limits.names, limits.bytes));
        }
        bytes += name.len();
        names.push((name, entry));
    }
    names.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok(names)
}

fn count_paths(
    root: &Path,
    dir: &Path,
    selection: Option<&Selection>,
    count: &mut usize,
) -> Result<(), String> {
    count_paths_budgeted(root, dir, selection, count, &mut 0)
}

fn count_paths_budgeted(
    root: &Path,
    dir: &Path,
    selection: Option<&Selection>,
    count: &mut usize,
    scanned: &mut usize,
) -> Result<(), String> {
    children_selected(root, dir, selection, scanned, |entry, scanned| {
        let path = entry.path();
        let name = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("execution input paths must be UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        safe_path(&name)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if crate::platform::contentless(&meta) {
            return Ok(());
        }
        admit_entry(count)?;
        if meta.is_dir() && !crate::platform::is_link(&meta) {
            count_paths_budgeted(root, &path, selection, count, scanned)?;
        }
        Ok(())
    })
}

fn walk(
    root: &Path,
    dir: &Path,
    selection: Option<&Selection>,
    count: &mut usize,
    emit: &mut impl FnMut(Entry) -> Result<(), String>,
) -> Result<(), String> {
    walk_budgeted(root, dir, selection, count, &mut 0, emit)
}

fn walk_budgeted(
    root: &Path,
    dir: &Path,
    selection: Option<&Selection>,
    count: &mut usize,
    scanned: &mut usize,
    emit: &mut impl FnMut(Entry) -> Result<(), String>,
) -> Result<(), String> {
    children_selected(root, dir, selection, scanned, |entry, scanned| {
        check_staging()?;
        let path = entry.path();
        let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
        let name = rel
            .to_str()
            .ok_or("execution input paths must be UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        safe_path(&name)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if crate::platform::contentless(&meta) {
            return Ok(());
        }
        admit_entry(count)?;
        let (kind, digest) = if crate::platform::is_link(&meta) {
            admit_link(&path)?;
            let link = std::fs::read_link(&path).map_err(|e| e.to_string())?;
            (
                "link",
                crate::sha256::digest(link.as_os_str().as_encoded_bytes()),
            )
        } else if meta.is_dir() {
            ("dir", crate::sha256::digest(b""))
        } else if meta.is_file() {
            if canonical_git_index(rel) {
                let bytes = read_index(&path)?;
                let bytes = normalize_index(&bytes).map_err(|e| format!("{name}: {e}"))?;
                ("file", crate::sha256::digest(&bytes))
            } else {
                ("file", hash_file(&path)?)
            }
        } else {
            return Err(format!("unsupported execution input: {name}"));
        };
        emit(Entry {
            path: name,
            kind: kind.into(),
            mode: if kind == "link" { 0 } else { mode(&meta) },
            sha256: digest,
        })?;
        if meta.is_dir() && !crate::platform::is_link(&meta) {
            walk_budgeted(root, &path, selection, count, scanned, emit)?;
        }
        Ok(())
    })
}

/// Bounded canonical stamp stream, including the root and each traversed
/// directory itself so transient membership changes cannot disappear unnoticed.
/// This guards staging only; replay continues to bind normalized content.
pub(crate) fn source_stamps(
    root: &Path,
    selection: Option<&Selection>,
) -> Result<[u8; 32], String> {
    fn walk_stamps(
        root: &Path,
        path: &Path,
        selection: Option<&Selection>,
        count: &mut usize,
        hash: &mut crate::sha256::Sha256,
    ) -> Result<(), String> {
        check_staging()?;
        let rel = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("execution input paths must be UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !rel.is_empty() {
            safe_path(&rel)?;
        }
        hash.update(&(rel.len() as u64).to_le_bytes());
        hash.update(rel.as_bytes());
        for value in crate::platform::change_stamp(path).map_err(|e| e.to_string())? {
            hash.update(&value.to_le_bytes());
        }
        let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if meta.is_dir() && !crate::platform::is_link(&meta) {
            children_selected(root, path, selection, count, |entry, count| {
                walk_stamps(root, &entry.path(), selection, count, hash)
            })?;
        }
        Ok(())
    }
    let mut hash = crate::sha256::Sha256::new();
    walk_stamps(root, root, selection, &mut 0, &mut hash)?;
    Ok(hash.finish())
}

/// Reset copy-preserved access/write times after all hashing and staging, in
/// postorder so creating children cannot refresh a directory's write time.
/// Never follow links: outside and dangling links remain sandbox inputs.
pub(crate) fn normalize_timestamps(root: &Path) -> Result<(), String> {
    fn visit(path: &Path) -> std::io::Result<()> {
        check_staging().map_err(std::io::Error::other)?;
        let meta = std::fs::symlink_metadata(path)?;
        if meta.is_dir() && !crate::platform::is_link(&meta) {
            for entry in std::fs::read_dir(path)? {
                visit(&entry?.path())?;
            }
        }
        set_timestamp(path)
    }
    visit(root).map_err(|e| format!("cannot normalize workspace timestamps: {e}"))
}

// 2000-01-01 is representable on every supported filesystem.
#[cfg(unix)]
fn set_timestamp(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let times = [libc::timespec {
        tv_sec: 946684800,
        tv_nsec: 0,
    }; 2];
    #[cfg(target_os = "macos")]
    {
        let mut attrs = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_CRTIME,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        // SAFETY: attrs selects one timespec; times points to that initialized
        // buffer. FSOPT_NOFOLLOW applies the change to the link itself.
        if unsafe {
            libc::setattrlist(
                path.as_ptr(),
                (&mut attrs as *mut libc::attrlist).cast(),
                times.as_ptr().cast_mut().cast(),
                std::mem::size_of::<libc::timespec>(),
                libc::FSOPT_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    // SAFETY: path is NUL terminated and times has two initialized timespecs.
    // AT_SYMLINK_NOFOLLOW prevents any write through a target-controlled link.
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn set_timestamp(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::{FileTimesExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .access_mode(0x100) // FILE_WRITE_ATTRIBUTES, including read-only files
        .custom_flags(0x02000000 | 0x00200000) // backup semantics, open reparse point
        .open(path)?;
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946684800);
    file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(time)
            .set_modified(time)
            .set_created(time),
    )
}

// Git owns these names directly inside a .git directory. Hook data and
// auxiliary metadata remain byte-bound, even when a leaf is named index.
pub(crate) fn canonical_git_index(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|p| p == ".git")
        && path.file_name().is_some_and(|name| name == "index")
}

/// Index v2/v3 with SHA-1 object IDs. Unknown formats fail closed. Preserve
/// modes, object IDs, paths, stages, flags and supported semantic extensions.
pub(crate) fn normalize_index(input: &[u8]) -> Result<Vec<u8>, String> {
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
        match &header[..4] {
            // Derived caches are regenerated by Git, never execution inputs.
            b"TREE" | b"UNTR" | b"FSMN" | b"EOIE" | b"IEOT" => {}
            // Resolve-undo records carry staged object IDs and modes.
            b"REUC" => out.extend_from_slice(&input[at..next]),
            _ => return Err("unsupported Git index extension".into()),
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

/// Recover replay identity from the record without reading diagnostic entries.
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
    if record.target_sha256.as_ref() != Some(&identity.sha256)
        || identity.sha256.len() != 64
        || !identity
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("execution input identity does not match record".into());
    }
    if let Some(s) = &identity.selection {
        s.validate()?;
    }
    Ok(Some(Manifest {
        selection: identity.selection.clone(),
        count: 0,
        root: record
            .target
            .as_deref()
            .map(Path::new)
            .unwrap_or(Path::new(""))
            .into(),
        sha256: identity.sha256.clone(),
        retained: Some((
            run.into(),
            Path::new("proofs")
                .join(record.n.to_string())
                .join("input-manifest.json"),
        )),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_reads_refuse_growth_truncation_and_aggregate_overflow() {
        use std::io::Read;
        let d = scratch("bounded-reads");
        let path = d.join("input");
        let _budget = StagingGuard::begin();
        for size in [3, 1] {
            std::fs::write(&path, b"ab").unwrap();
            let mut reader = admitted_file(&path).unwrap();
            reader.read_exact(&mut [0u8; 1]).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(size)
                .unwrap();
            assert!(reader
                .read_to_end(&mut Vec::new())
                .unwrap_err()
                .to_string()
                .contains("target changed during staging"));
        }
        std::fs::write(&path, b"ab").unwrap();
        STAGING.with(|state| state.borrow_mut().as_mut().unwrap().1 = MAX_SOURCE_BYTES - 3);
        drop(admitted_file(&path).unwrap());
        assert!(admitted_file(&path)
            .err()
            .unwrap()
            .contains("aggregate source byte budget"));
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn staging_deadline_is_checked_between_chunks_and_directory_entries() {
        use std::io::Read;
        let d = scratch("deadline");
        std::fs::write(d.join("input"), b"ab").unwrap();
        let _budget = StagingGuard::begin();
        let mut reader = admitted_file(&d.join("input")).unwrap();
        STAGING.with(|state| state.borrow_mut().as_mut().unwrap().0 = std::time::Instant::now());
        assert!(reader
            .read(&mut [0u8; 1])
            .unwrap_err()
            .to_string()
            .contains("staging deadline exceeded"));
        assert!(check_paths(&d, &["input"], false)
            .unwrap_err()
            .contains("staging deadline exceeded"));
        drop(reader);
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn shared_ancestor_checks_enumerate_each_parent_once() {
        let d = scratch("shared-parents");
        std::fs::create_dir(d.join("wide")).unwrap();
        for i in 0..1024 {
            std::fs::write(d.join(format!("wide/file{i}")), b"").unwrap();
        }
        let selected: Vec<_> = (0..128).map(|i| format!("wide/file{i}")).collect();
        let paths: Vec<_> = selected.iter().map(String::as_str).collect();
        ENUMERATIONS.with(|n| n.set(0));
        check_paths(&d, &paths, false).unwrap();
        ENUMERATIONS.with(|n| assert_eq!(n.get(), 2));
        let harness: Vec<_> = (0..128).map(|i| format!("wide/new{i}")).collect();
        ENUMERATIONS.with(|n| n.set(0));
        crate::sandbox::preflight_harness(
            &d,
            &harness.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .unwrap();
        ENUMERATIONS.with(|n| assert_eq!(n.get(), 2));
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let base = crate::platform::temp_root().unwrap().join(format!(
            "omgs-input-fixtures-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_tree(&base).unwrap();
        let path = base.join(label);
        crate::platform::private_dir(&path).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn link_identity_binds_exact_text_including_dangling_namespace_and_dot_prefix() {
        let d = scratch("links");
        std::fs::write(d.join("source"), "source").unwrap();
        let mut identities = std::collections::BTreeSet::new();
        for text in ["source", "./source", "@workspace/source", "missing"] {
            std::os::unix::fs::symlink(text, d.join("selected")).unwrap();
            let identity = manifest(&d, None).unwrap();
            let mut found = false;
            walk(&d, &d, None, &mut 0, &mut |entry| {
                if entry.path == "selected" {
                    assert_eq!(entry.sha256, crate::sha256::digest(text.as_bytes()));
                    found = true;
                }
                Ok(())
            })
            .unwrap();
            assert!(found);
            assert!(identities.insert(identity.digest().unwrap()), "{text}");
            std::fs::remove_file(d.join("selected")).unwrap();
        }
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn workspace_times_are_normalized_for_files_directories_and_root() {
        let d = scratch("times");
        std::fs::create_dir(d.join("nested")).unwrap();
        std::fs::write(d.join("nested/source"), "bytes").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("missing", d.join("dangling")).unwrap();
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946684800);
        normalize_timestamps(&d).unwrap();
        for path in [&d, &d.join("nested"), &d.join("nested/source")] {
            let meta = std::fs::symlink_metadata(path).unwrap();
            assert_eq!(meta.modified().unwrap(), time);
            assert_eq!(meta.accessed().unwrap(), time);
            #[cfg(any(windows, target_os = "macos"))]
            assert_eq!(meta.created().unwrap(), time);
        }
        #[cfg(unix)]
        {
            let meta = std::fs::symlink_metadata(d.join("dangling")).unwrap();
            assert_eq!(meta.modified().unwrap(), time);
            assert_eq!(meta.accessed().unwrap(), time);
            assert!(!d.join("missing").exists());
        }
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn manifest_limits_reject_before_reading_entries() {
        let header = format!(
            "{{\"version\":4,\"entries\":{},\"selection\":null}}\n",
            MAX_ENTRIES + 1
        );
        let mut reader = std::io::Cursor::new(header.as_bytes());
        assert!(ManifestReader::new(&mut reader).is_err());
        assert_eq!(reader.position(), header.len() as u64);
        for count in [MAX_ENTRIES - 1, MAX_ENTRIES] {
            let header = format!("{{\"version\":4,\"entries\":{count},\"selection\":null}}\n");
            let parsed = ManifestReader::new(std::io::Cursor::new(header)).unwrap();
            assert_eq!(parsed.remaining, count);
        }
        // Exercise the production generation counter at the actual boundary,
        // using a lazy generator with no paths or entries retained.
        let mut count = 0;
        for () in std::iter::repeat_n((), MAX_ENTRIES - 1) {
            admit_entry(&mut count).unwrap();
        }
        assert_eq!(count, MAX_ENTRIES - 1);
        admit_entry(&mut count).unwrap();
        assert!(admit_entry(&mut count).is_err());
        assert_eq!(count, MAX_ENTRIES);
        check_entry_count(MAX_ENTRIES).unwrap();
        assert!(check_entry_count(MAX_ENTRIES + 1).is_err());
    }

    #[test]
    fn diagnostics_lines_are_strict_bounded_and_stop_at_declared_count() {
        let header = b"{\"version\":4,\"entries\":1,\"selection\":null}\n";
        let entry = Entry {
            path: "source".into(),
            kind: "file".into(),
            mode: 0,
            sha256: "f".repeat(64),
        };
        let mut bytes = header.to_vec();
        line(&mut bytes, &entry).unwrap();
        let end = bytes.len();
        bytes.extend(b"unread excess entry");
        let mut reader = ManifestReader::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(reader.next().unwrap(), Some(entry));
        assert!(reader.next().is_err());
        assert_eq!(reader.reader.position(), end as u64);
        for bad in [
            "{\"version\":4,\"version\":4,\"entries\":0,\"selection\":null}\n".to_string(),
            "{\"version\":3,\"entries\":0,\"selection\":null}\n".to_string(),
            "{\"version\":4,\"entries\":0,\"selection\":null,\"extra\":0}\n".to_string(),
            "x".repeat(MAX_HEADER_BYTES + 1),
        ] {
            assert!(ManifestReader::new(std::io::Cursor::new(bad)).is_err());
        }
        for bad in [
            "{\"path\":\"a\",\"path\":\"b\",\"kind\":\"file\",\"mode\":0,\"sha256\":\"f\"}\n"
                .to_string(),
            "x".repeat(MAX_LINE_BYTES + 1),
        ] {
            let mut bytes = header.to_vec();
            bytes.extend(bad.as_bytes());
            assert!(ManifestReader::new(std::io::Cursor::new(bytes))
                .unwrap()
                .next()
                .is_err());
        }
    }

    #[test]
    fn streamed_manifest_bytes_match_digest_and_diagnostics_report_first_difference() {
        let d = scratch("stream");
        let target = d.join("target");
        crate::platform::private_dir(&target).unwrap();
        std::fs::write(target.join("a"), "before").unwrap();
        std::fs::write(target.join("b"), "before").unwrap();
        let mut original = manifest(&target, None).unwrap();
        original.write_to(&d.join("manifest")).unwrap();
        assert_eq!(
            crate::sha256::digest_file(&d.join("manifest")).unwrap(),
            original.digest().unwrap()
        );
        original.retained = Some((d.clone(), "manifest".into()));
        std::fs::write(target.join("b"), "after").unwrap();
        assert!(original
            .differences(&manifest(&target, None).unwrap())
            .contains("b"));
        std::fs::write(target.join("a"), "after").unwrap();
        assert_eq!(
            original.differences(&manifest(&target, None).unwrap()),
            "differing input path(s): a"
        );
        assert!(original.write_to(&d.join("manifest")).is_err());
        assert_eq!(
            crate::sha256::digest_file(&d.join("manifest")).unwrap(),
            original.digest().unwrap()
        );
        assert!(!std::fs::read_dir(&d).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn directory_scan_budget_is_checked_before_visiting_or_retaining_all_names() {
        let d = scratch("scan-budget");
        for i in 0..257 {
            std::fs::write(d.join(format!("p{i:04}")), b"").unwrap();
        }
        let entries = || {
            std::fs::read_dir(&d).unwrap().map(|entry| {
                let entry = entry.unwrap();
                Ok((entry.file_name().into_string().unwrap(), entry))
            })
        };
        let error = sorted_names(
            &d,
            entries(),
            &mut 0,
            DirectoryLimits {
                entries: 256,
                ..DIRECTORY_LIMITS
            },
            |_| true,
        )
        .unwrap_err();
        assert!(error.contains("exceeds 256 entries"));
        let mut count = 0;
        let names = sorted_names(&d, entries(), &mut count, DIRECTORY_LIMITS, |_| true).unwrap();
        assert_eq!(names.len(), 257);
        assert_eq!(count, 257, "one enumeration charges each sibling once");
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn wide_directory_sort_limits_and_scoped_filter_are_bounded() {
        let dir = Path::new("synthetic-wide-directory");
        let entries = |n| (0..n).rev().map(|i| Ok((format!("p{i:06}"), ())));
        let mut count = 0;
        let names = sorted_names(
            dir,
            entries(MAX_DIRECTORY_NAMES),
            &mut count,
            DIRECTORY_LIMITS,
            |_| true,
        )
        .unwrap();
        assert_eq!(count, MAX_DIRECTORY_NAMES);
        assert_eq!(names.len(), MAX_DIRECTORY_NAMES);
        assert_eq!(names.first().unwrap().0, "p000000");
        assert_eq!(names.last().unwrap().0, "p199999");
        let error = sorted_names(
            dir,
            entries(MAX_DIRECTORY_NAMES + 1),
            &mut 0,
            DIRECTORY_LIMITS,
            |_| true,
        )
        .unwrap_err();
        assert!(error.contains("synthetic-wide-directory") && error.contains("sort memory budget"));
        let error = sorted_names(
            dir,
            entries(2),
            &mut 0,
            DirectoryLimits {
                bytes: 13,
                ..DIRECTORY_LIMITS
            },
            |_| true,
        )
        .unwrap_err();
        assert!(error.contains("13 name bytes"));
        let names = sorted_names(
            dir,
            entries(2),
            &mut 0,
            DirectoryLimits {
                bytes: 14,
                ..DIRECTORY_LIMITS
            },
            |_| true,
        )
        .unwrap();
        assert_eq!(names.len(), 2);
        let mut count = 0;
        let names = sorted_names(
            dir,
            entries(MAX_DIRECTORY_NAMES + 1),
            &mut count,
            DirectoryLimits {
                names: 1,
                bytes: 7,
                ..DIRECTORY_LIMITS
            },
            |name| name == "p000001",
        )
        .unwrap();
        assert_eq!(
            names.len(),
            1,
            "unselected siblings never consume sort memory"
        );
        assert_eq!(count, MAX_DIRECTORY_NAMES + 1);
        let error = sorted_names(
            dir,
            entries(2),
            &mut (MAX_ENTRIES - 1),
            DIRECTORY_LIMITS,
            |_| false,
        )
        .unwrap_err();
        assert!(error.contains("exceeds 2000000 entries"), "{error}");
    }

    #[test]
    fn scoped_walk_and_copy_filter_a_wide_directory_before_sorting() {
        let d = scratch("scoped-wide");
        let target = d.join("target");
        std::fs::create_dir_all(target.join("selected")).unwrap();
        std::fs::write(target.join("selected/input"), b"synthetic").unwrap();
        for i in 0..1024 {
            std::fs::write(target.join(format!("omitted{i:04}")), b"").unwrap();
        }
        let selection = Selection {
            version: 1,
            paths: vec!["selected/input".into()],
        };
        let mut count = 0;
        let mut visited = Vec::new();
        children_selected(
            &target,
            &target,
            Some(&selection),
            &mut count,
            |entry, _| {
                visited.push(entry.file_name());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 1025);
        assert_eq!(visited, [std::ffi::OsString::from("selected")]);
        let identity = manifest(&target, Some(selection.clone())).unwrap();
        assert_eq!(identity.count, 2);
        // Exercise the same copy filter through staging without executing code.
        let copied = d.join("copy");
        crate::sandbox::copy_selected(&target, &copied, &selection).unwrap();
        assert_eq!(identity, manifest(&copied, Some(selection)).unwrap());
        assert_eq!(std::fs::read_dir(&copied).unwrap().count(), 1);
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn selection_checks_exact_components_and_missing_materialized_paths() {
        let d = scratch("selection-spelling");
        std::fs::create_dir(d.join("Source")).unwrap();
        std::fs::write(d.join("Source/Entry"), b"synthetic").unwrap();
        for path in ["source/Entry", "Source/entry", "Source/missing"] {
            let selection = Selection {
                version: 1,
                paths: vec![path.into()],
            };
            let error = manifest(&d, Some(selection)).unwrap_err();
            assert!(
                error.contains("exactly one directory entry with exact spelling"),
                "{error}"
            );
        }
        let selection = Selection {
            version: 1,
            paths: vec!["Source/Entry".into()],
        };
        let copy = d.join("copy");
        std::fs::create_dir_all(copy.join("Source")).unwrap();
        assert!(verify_selection(&copy, &selection).is_err());
        std::fs::write(copy.join("Source/Entry"), b"synthetic").unwrap();
        verify_selection(&copy, &selection).unwrap();
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn wide_directory_stream_is_component_sorted() {
        let d = scratch("wide");
        let target = d.join("target");
        crate::platform::private_dir(&target).unwrap();
        for i in (0..300).rev() {
            std::fs::write(target.join(format!("p{i:04}")), b"").unwrap();
        }
        std::fs::create_dir(target.join("a")).unwrap();
        for name in ["a/child", "a!", "z", "é", "𐀀"] {
            std::fs::write(target.join(name), b"").unwrap();
        }
        let identity = manifest_to(&target, None, &d.join("manifest")).unwrap();
        assert_eq!(identity, manifest(&target, None).unwrap());
        assert_eq!(
            identity.digest().unwrap(),
            crate::sha256::digest_file(&d.join("manifest")).unwrap()
        );
        let mut reader = ManifestReader::new(std::io::BufReader::new(
            std::fs::File::open(d.join("manifest")).unwrap(),
        ))
        .unwrap();
        assert_eq!(reader.next().unwrap().unwrap().path, "a");
        assert_eq!(reader.next().unwrap().unwrap().path, "a/child");
        assert_eq!(reader.next().unwrap().unwrap().path, "a!");
        let mut count = 3;
        while reader.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, identity.count);
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_index_is_normalized_during_fresh_staging() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("shared-index");
        let src = root.join("source");
        let dst = root.join("copy");
        std::fs::create_dir_all(src.join(".git")).unwrap();
        let raw = index();
        std::fs::write(src.join(".git/index"), &raw).unwrap();
        std::fs::set_permissions(
            src.join(".git/index"),
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let before = manifest(&src, None).unwrap();
        crate::sandbox::copy_tree(&src, &dst).unwrap();
        assert_eq!(manifest(&dst, None).unwrap(), before);
        assert_eq!(std::fs::read(src.join(".git/index")).unwrap(), raw);
        assert_eq!(
            std::fs::read(dst.join(".git/index")).unwrap(),
            normalize_index(&raw).unwrap()
        );
        assert_eq!(
            mode(&std::fs::metadata(dst.join(".git/index")).unwrap()),
            0o664
        );
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

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
        assert!(canonical_git_index(Path::new(".git/index")));
        assert!(canonical_git_index(Path::new("nested/.git/index")));
        for path in [
            ".git/hooks/index",
            ".git/modules/module/index",
            ".git/worktrees/other/index",
            ".git/sharedindex.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!canonical_git_index(Path::new(path)), "{path}");
        }
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
        assert!(normalize_index(&changed).is_err());
        for signature in [b"REUC", b"link", b"sdir", b"test"] {
            changed[84..88].copy_from_slice(signature);
            changed = reseal(changed);
            if signature == b"REUC" {
                assert_ne!(normalize_index(&changed).unwrap(), normalized);
            } else {
                assert!(normalize_index(&changed).is_err());
            }
        }
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
            ".git/hooks/index",
            ".git/hooks/sharedindex.fixture",
            ".git/sharedindex.fixture",
            ".git/HEAD",
            ".git/refs/heads/main",
            ".git/objects/pack",
        ];
        for name in names {
            std::fs::write(d.join(name), b"original").unwrap();
        }
        crate::runmeta::write_atomic_bytes(&d.join(".git/index"), &index()).unwrap();
        let original = manifest(&d, None).unwrap();
        for name in names {
            std::fs::write(d.join(name), b"changed").unwrap();
            let next = manifest(&d, None).unwrap();
            assert_ne!(next.digest().unwrap(), original.digest().unwrap());

            if name.contains("hooks/") || name.ends_with("sharedindex.fixture") {
                assert_eq!(manifest(&d, None).unwrap(), next);
                assert_eq!(std::fs::read(d.join(name)).unwrap(), b"changed");
            }
            std::fs::write(d.join(name), b"original").unwrap();
        }
        let raw = index();
        let mut refreshed = raw.clone();
        refreshed[12] ^= 1;
        let refreshed = reseal(refreshed);
        crate::runmeta::write_atomic_bytes(&d.join(".git/index"), &refreshed).unwrap();
        assert_eq!(manifest(&d, None).unwrap(), original);
        assert_eq!(std::fs::read(d.join(".git/index")).unwrap(), refreshed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::metadata(d.join("source")).unwrap().permissions();
            std::fs::set_permissions(
                d.join("source"),
                std::fs::Permissions::from_mode(permissions.mode() ^ 0o100),
            )
            .unwrap();
            assert_ne!(manifest(&d, None).unwrap(), original);
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
        let first = manifest(&d, selection.clone()).unwrap();
        assert!(first.count >= 3);
        std::fs::write(d.join("asset"), b"changed").unwrap();
        assert_eq!(manifest(&d, selection.clone()).unwrap(), first);
        std::fs::write(d.join(".git/config"), b"changed").unwrap();
        assert_ne!(manifest(&d, selection).unwrap(), first);
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
