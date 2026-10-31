//! Run evidence has one admission boundary, distinct from checkout content.
use std::path::Path;

pub const DASHBOARD_STATUS_BYTES: u64 = 1 << 20;
pub const STATUS_BYTES: u64 = 16 << 20;
pub const FINDINGS_BYTES: u64 = 16 << 20;
pub const LEDGER_BYTES: u64 = 16 << 20;
pub const CANDIDATES_BYTES: u64 = 16 << 20;
pub const SENSORS_BYTES: u64 = 16 << 20;
pub const SENSOR_HITS_BYTES: u64 = 16 << 20;
pub const ARCHITECTURE_BYTES: u64 = 16 << 20;
pub const PROOF_BYTES: u64 = 2 << 20;
pub const COMMAND_BYTES: u64 = 1 << 20;
pub const CONFIG_BYTES: u64 = 2 << 20;
pub const DRAFT_BYTES: u64 = 16 << 20;
pub const METADATA_BYTES: u64 = 16 << 20;
pub const EVALUATION_BYTES: u64 = 8 << 20;
pub const DISPOSITIONS_BYTES: u64 = 16 << 20;
pub const ANSWERS_BYTES: u64 = 1 << 20;
pub const CLAIM_BYTES: u64 = 64;
pub const BENCHMARK_BYTES: u64 = 16 << 20;

/// Read relative to a trusted run directory. Every descendant component is
/// opened without following links; the opened leaf must be an owner-held regular
/// file with no hardlink aliases or shared write grants. Privacy is guaranteed
/// by the admitted owner-private run root, not by normalizing nested modes.
/// Bounds apply both before and during reading.
/// Validation uses the opened descriptor, never an earlier path inspection.
/// Only NotFound from this contained traversal denotes genuine absence.
pub fn read(run: &Path, relative: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    read_with_permissions(run, relative, limit).map(|(bytes, _)| bytes)
}

/// Retained draft staging also needs the mode from the admitted descriptor.
pub fn read_with_permissions(
    run: &Path,
    relative: &Path,
    limit: u64,
) -> std::io::Result<(Vec<u8>, std::fs::Permissions)> {
    let result = if cfg!(windows) && has_windows_stream_syntax(relative) {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "artifact filename components must not contain Windows stream syntax",
        ))
    } else {
        crate::platform::read_private_bounded_with_permissions_in(run, relative, limit)
    };
    result.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("read run artifact {}: {e}", run.join(relative).display()),
        )
    })
}

/// Stream from the admitted descriptor without materializing the artifact.
pub fn with_reader<T>(
    run: &Path,
    relative: &Path,
    read: impl FnOnce(std::fs::File) -> std::io::Result<T>,
) -> std::io::Result<T> {
    if cfg!(windows) && has_windows_stream_syntax(relative) {
        return Err(std::io::Error::other(
            "artifact filename contains Windows stream syntax",
        ));
    }
    crate::platform::with_file_in(run, relative, |file| {
        crate::platform::check_private_file(&file)?;
        read(file)
    })
}

fn has_windows_stream_syntax(relative: &Path) -> bool {
    relative
        .components()
        .any(|c| c.as_os_str().as_encoded_bytes().contains(&b':'))
}

/// Explicit privacy preflight for role-written output. Never repairs permissions.
pub fn check_containment(run: &Path, relative: &Path) -> Result<(), String> {
    crate::platform::check_private_dir(run).map_err(|e| e.to_string())?;
    read(run, relative, DRAFT_BYTES).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn text(run: &Path, relative: &Path, limit: u64) -> Result<String, String> {
    String::from_utf8(read(run, relative, limit).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", run.join(relative).display()))
}

pub fn optional_text(run: &Path, relative: &Path, limit: u64) -> Result<Option<String>, String> {
    match read(run, relative, limit) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|e| format!("{}: {e}", run.join(relative).display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// CLI artifact arguments may have arbitrary filenames. Their parent is the
/// trusted run boundary and their leaf is still admitted by the same reader.
pub fn text_path(path: &Path, limit: u64) -> Result<String, String> {
    let run = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    text(
        run,
        Path::new(path.file_name().ok_or("artifact needs a filename")?),
        limit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_stream_syntax_is_detected_in_every_component() {
        for name in [
            "findings.json:alternate",
            "findings.json:alternate:$DATA",
            "findings.json::$DATA",
            "findings.json::$data",
            "proofs/1.json:alternate",
            "proofs/1.json::$DATA",
            "proofs:alternate/1.json",
            "proofs::$INDEX_ALLOCATION/1.json",
        ] {
            assert!(has_windows_stream_syntax(Path::new(name)), "{name}");
        }
        for name in ["findings.json", "proofs/1.json", "proofs/1/command.txt"] {
            assert!(!has_windows_stream_syntax(Path::new(name)), "{name}");
        }
    }
}
