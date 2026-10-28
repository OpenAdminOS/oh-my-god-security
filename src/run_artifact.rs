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
/// opened without following links; the opened leaf must be a private regular
/// file with no hardlink aliases. Bounds apply both before and during reading.
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
    crate::platform::read_private_bounded_with_permissions_in(run, relative, limit).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("read run artifact {}: {e}", run.join(relative).display()),
        )
    })
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
