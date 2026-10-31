//! Opt-in proof screenshots. A headless browser already installed on this
//! machine renders a page inside the same MXC sandbox as the proof, at a fixed
//! small viewport. The runner keeps only small PNG files it can parse, hashes
//! them into the proof record, and the report embeds verified copies inline.
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const WIDTH: u32 = 800;
pub const HEIGHT: u32 = 600;
pub const MAX_FILES: usize = 4;
pub const MAX_BYTES: u64 = 512 * 1024;
/// Longest a single capture may run before the helper stops the browser.
pub const CAPTURE_SECONDS: u32 = 20;
/// Directory name under the sandbox scratch and under the proof directory.
pub const DIR: &str = "screenshots";
/// Environment variable naming the capture helper inside the sandbox.
pub const ENV: &str = "OMGS_SCREENSHOT";
/// Host override naming a headless browser executable.
pub const BROWSER_ENV: &str = "OMGS_BROWSER";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shot {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub width: u32,
    pub height: u32,
}

/// What a proof run requested and kept. `blocker` names why no browser was
/// available; `skipped` names files the runner refused to keep.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Screenshots {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    #[serde(default)]
    pub files: Vec<Shot>,
    #[serde(default)]
    pub skipped: Vec<String>,
}

/// A screenshot name: 1 to 64 ASCII letters, digits, `-` or `_`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Relative path of a kept screenshot inside its proof directory.
pub fn relative(name: &str) -> PathBuf {
    Path::new(DIR).join(format!("{name}.png"))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Width and height of a structurally complete PNG: signature, a valid IHDR
/// first, checksummed chunks with letter types, only known critical chunks,
/// a palette exactly where the colour type needs one and before the image
/// data, one run of consecutive IDAT chunks, and IEND as the last bytes.
/// Pixel data is not decoded.
pub fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), String> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    if bytes.len() < 8 || bytes[..8] != SIGNATURE {
        return Err("not a PNG file".into());
    }
    let word =
        |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let mut at = 8;
    let mut dimensions = None;
    let mut color = 0u8;
    let mut depth = 0u8;
    let mut palette = false;
    let mut image_data = false;
    let mut image_data_ended = false;
    loop {
        if at + 12 > bytes.len() {
            return Err("truncated PNG".into());
        }
        let length = word(at) as usize;
        let kind = &bytes[at + 4..at + 8];
        let end = at
            .checked_add(8)
            .and_then(|v| v.checked_add(length))
            .filter(|end| end + 4 <= bytes.len())
            .ok_or("truncated PNG chunk")?;
        if crc32(&bytes[at + 4..end]) != word(end) {
            return Err("PNG chunk checksum mismatch".into());
        }
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            return Err("PNG chunk type is not four letters".into());
        }
        if image_data && kind != b"IDAT" {
            image_data_ended = true;
        }
        match (dimensions.is_none(), kind) {
            (true, b"IHDR") if length == 13 => {
                let (width, height) = (word(at + 8), word(at + 12));
                depth = bytes[at + 16];
                color = bytes[at + 17];
                let valid = match color {
                    0 => [1, 2, 4, 8, 16].contains(&depth),
                    3 => [1, 2, 4, 8].contains(&depth),
                    2 | 4 | 6 => [8, 16].contains(&depth),
                    _ => false,
                };
                if !valid || bytes[at + 18] != 0 || bytes[at + 19] != 0 || bytes[at + 20] > 1 {
                    return Err("PNG header has unsupported values".into());
                }
                if width == 0 || height == 0 {
                    return Err("PNG has an empty dimension".into());
                }
                dimensions = Some((width, height));
            }
            (true, _) | (false, b"IHDR") => {
                return Err("PNG does not start with one IHDR chunk".into())
            }
            (false, b"PLTE") => {
                if palette || image_data || matches!(color, 0 | 4) {
                    return Err("PNG palette is misplaced or not allowed".into());
                }
                let limit = if color == 3 { 3usize << depth } else { 768 };
                if length == 0 || length > limit || !length.is_multiple_of(3) {
                    return Err("PNG palette has an invalid length".into());
                }
                palette = true;
            }
            (false, b"IDAT") => {
                if image_data_ended {
                    return Err("PNG image data is not consecutive".into());
                }
                if color == 3 && !palette {
                    return Err("indexed PNG has no palette".into());
                }
                image_data = true;
            }
            (false, b"IEND") => {
                if length != 0 || end + 4 != bytes.len() {
                    return Err("PNG has data after its end".into());
                }
                if !image_data {
                    return Err("PNG has no image data".into());
                }
                return dimensions.ok_or_else(|| "PNG has no header".into());
            }
            // Unknown critical chunks (uppercase first letter) cannot be skipped.
            (false, kind) if kind[0].is_ascii_uppercase() => {
                return Err("PNG has an unknown critical chunk".into());
            }
            _ => {}
        }
        at = end + 4;
    }
}

/// Checks a candidate file's bytes against every limit and returns its
/// dimensions.
pub fn admit(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(format!("larger than {MAX_BYTES} bytes"));
    }
    let (width, height) = png_dimensions(bytes)?;
    if width > WIDTH || height > HEIGHT {
        return Err(format!(
            "{width}x{height} exceeds the fixed {WIDTH}x{HEIGHT} viewport"
        ));
    }
    Ok((width, height))
}

fn default_browsers(os: &str) -> &'static [&'static str] {
    match os {
        "linux" => &[
            "/opt/google/chrome/chrome",
            "/opt/microsoft/msedge/msedge",
            "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser",
        ],
        "windows" => &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ],
        _ => &[],
    }
}

/// The headless browser for this run, or the exact reason there is none.
/// `OMGS_BROWSER` overrides discovery and must name an executable file.
pub fn browser(os: &str, explicit: Option<OsString>) -> Result<PathBuf, String> {
    if let Some(raw) = explicit.filter(|v| !v.is_empty()) {
        let path = PathBuf::from(&raw);
        if !path.is_absolute() {
            return Err(format!("{BROWSER_ENV} must be an absolute path"));
        }
        let path = std::fs::canonicalize(&path)
            .map_err(|e| format!("{BROWSER_ENV} {}: {e}", path.display()))?;
        if !executable(&path) {
            return Err(format!(
                "{BROWSER_ENV} {} is not an executable file",
                path.display()
            ));
        }
        return Ok(path);
    }
    if os == "macos" {
        return Err(format!("no screenshot browser on macOS by default: Chrome, Edge and Chromium app bundles abort inside the sandbox because they must register with the window server, which OMGS keeps closed. Set {BROWSER_ENV} to a chrome-headless-shell executable outside protected folders"));
    }
    default_browsers(os)
        .iter()
        .map(PathBuf::from)
        .find(|p| executable(p))
        .ok_or_else(|| {
            format!(
                "no headless browser found at {}; install Chrome, Edge or Chromium there or set {BROWSER_ENV}",
                default_browsers(os).join(", ")
            )
        })
}

fn executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

/// The directory granted read access so the browser can load its files,
/// computed from the recorded text with `os` path rules, never the host's.
pub fn browser_root(os: &str, browser: &str) -> String {
    let path = if os == "windows" {
        crate::platform::mxc_path(Path::new(browser))
    } else {
        browser.to_string()
    };
    let separators: &[char] = if os == "windows" {
        &['\\', '/']
    } else {
        &['/']
    };
    match path.rfind(separators) {
        Some(0) => path[..1].to_string(),
        Some(i) if os == "windows" && path[..i].ends_with(':') => path[..=i].to_string(),
        Some(i) => path[..i].to_string(),
        None => path,
    }
}

fn flags(os: &str) -> Vec<String> {
    let mut flags: Vec<String> = [
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "--disable-breakpad",
        "--no-first-run",
        "--no-default-browser-check",
        "--hide-scrollbars",
        // Chrome stops waiting for the page before the helper's watchdog.
        "--timeout=15000",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // The macOS headless shell cannot register its multi-process rendezvous
    // service inside the sandbox; one process needs no rendezvous.
    if os == "macos" {
        flags.push("--single-process".into());
    }
    flags.push(format!("--window-size={WIDTH},{HEIGHT}"));
    flags
}

/// File name and text of the capture helper written into scratch. Callers run
/// it as `"$OMGS_SCREENSHOT" <name> <url>` (`call "%OMGS_SCREENSHOT%" <name>
/// <url>` on Windows). Names are checked again when files are collected.
pub fn helper(os: &str, browser: &Path, scratch: &Path) -> Result<(String, String), String> {
    let separator = if os == "windows" { "\\" } else { "/" };
    let scratch = scratch.to_string_lossy();
    let profile = PathBuf::from(format!("{scratch}{separator}browser-profile"));
    let out = PathBuf::from(format!("{scratch}{separator}{DIR}"));
    if os == "windows" {
        let quoted = |p: &Path| -> Result<String, String> {
            let s = p.to_string_lossy();
            if s.contains(['"', '%', '\r', '\n']) {
                return Err(format!("unsupported character in {s}"));
            }
            Ok(s.into_owned())
        };
        let out = quoted(&out)?;
        let text = format!(
            "@echo off\r\n\"{}\" {} \"--user-data-dir={}\" \"--screenshot={out}\\%~1.png\" \"%~2\"\r\nset omgs_status=%errorlevel%\r\nif not \"%omgs_status%\"==\"0\" (echo %omgs_status%)> \"{out}\\%~1.failed\"\r\nexit /b 0\r\n",
            quoted(browser)?,
            flags(os).join(" "),
            quoted(&profile)?,
        );
        return Ok((helper_name(os).into(), text));
    }
    let quoted = |p: &Path| -> Result<String, String> {
        let s = p.to_string_lossy();
        if s.contains(['\'', '\n', '\r']) {
            return Err(format!("unsupported character in {s}"));
        }
        Ok(format!("'{s}'"))
    };
    let out = quoted(&out)?;
    // Chrome binds a singleton socket under TMPDIR; a socket path must fit in
    // about 107 bytes, so the browser runs from a scratch directory with a
    // relative TMPDIR instead of the long absolute scratch path.
    let tmp = quoted(&PathBuf::from(format!("{scratch}{separator}browser-tmp")))?;
    let text = format!(
        "#!/bin/sh\ncase \"$1\" in ''|*[!A-Za-z0-9_-]*) echo 'omgs-screenshot: name must be 1 to 64 letters, digits, - or _' >&2; exit 0;; esac\nmkdir -p {tmp} && cd {tmp} || exit 0\nTMPDIR=. {} {} --user-data-dir={} --screenshot={out}/\"$1\".png \"$2\" &\nbrowser=$!\n(i=0; while kill -0 \"$browser\" 2>/dev/null; do if [ \"$i\" -ge {CAPTURE_SECONDS} ]; then : > {out}/\"$1\".timeout; kill -9 \"$browser\" 2>/dev/null; break; fi; sleep 1; i=$((i + 1)); done) &\nwatchdog=$!\nwait \"$browser\"\nstatus=$?\nwait \"$watchdog\"\n[ -f {out}/\"$1\".timeout ] || [ \"$status\" -eq 0 ] || echo \"$status\" > {out}/\"$1\".failed\nexit 0\n",
        quoted(browser)?,
        flags(os).join(" "),
        quoted(&profile)?,
    );
    Ok((helper_name(os).into(), text))
}

/// File name of the capture helper inside scratch.
pub fn helper_name(os: &str) -> &'static str {
    if os == "windows" {
        "omgs-screenshot.cmd"
    } else {
        "omgs-screenshot"
    }
}

/// Keeps admissible PNG files from the sandbox's `scratch/screenshots` in
/// `to`, in name order, and names every file it refused. Sandboxed code owned
/// that directory, so nothing in it is followed: a linked directory is refused
/// before listing and every file is opened beneath `scratch` without
/// traversing links, as a single-link regular file.
pub fn collect(scratch: &Path, to: &Path) -> (Vec<Shot>, Vec<String>) {
    let mut kept = Vec::new();
    let mut skipped = Vec::new();
    let dir = scratch.join(DIR);
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (kept, skipped),
        Err(e) => {
            skipped.push(format!("cannot inspect the screenshot directory: {e}"));
            return (kept, skipped);
        }
        Ok(meta) if crate::platform::is_link(&meta) || !meta.is_dir() => {
            skipped.push("the screenshot directory is not a plain directory".into());
            return (kept, skipped);
        }
        Ok(_) => {}
    }
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(e) => {
            skipped.push(format!("cannot read the screenshot directory: {e}"));
            return (kept, skipped);
        }
    };
    names.sort();
    for file in names {
        let shown = crate::platform::escape_controls(&file);
        if let Some(name) = file.strip_suffix(".timeout").filter(|n| valid_name(n)) {
            skipped.push(format!(
                "{name}: capture timed out after {CAPTURE_SECONDS} s and the browser was stopped"
            ));
            continue;
        }
        if let Some(name) = file.strip_suffix(".failed").filter(|n| valid_name(n)) {
            let status = crate::platform::read_bounded_in(scratch, &Path::new(DIR).join(&file), 64)
                .ok()
                .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
                .unwrap_or_else(|| "unknown".into());
            skipped.push(format!("{name}: the browser exited with status {status}"));
            continue;
        }
        let name = match file.strip_suffix(".png").filter(|n| valid_name(n)) {
            Some(n) => n.to_string(),
            None => {
                skipped.push(format!(
                    "{shown}: name must be 1 to 64 letters, digits, - or _ with a .png extension"
                ));
                continue;
            }
        };
        match crate::platform::read_bounded_in(scratch, &Path::new(DIR).join(&file), MAX_BYTES)
            .map_err(|e| match e.to_string().as_str() {
                "file exceeds byte limit" => format!("larger than {MAX_BYTES} bytes"),
                other => format!("not a single-link regular file: {other}"),
            })
            .and_then(|bytes| {
                let (width, height) = admit(&bytes)?;
                if kept.len() == MAX_FILES {
                    return Err(format!("more than {MAX_FILES} screenshots"));
                }
                crate::platform::private_dir(to)
                    .and_then(|_| {
                        crate::runmeta::write_atomic_bytes(&to.join(format!("{name}.png")), &bytes)
                    })
                    .map_err(|e| format!("cannot keep it: {e}"))?;
                Ok(Shot {
                    name: name.clone(),
                    sha256: crate::sha256::digest(&bytes),
                    bytes: bytes.len() as u64,
                    width,
                    height,
                })
            }) {
            Ok(shot) => kept.push(shot),
            Err(reason) => skipped.push(format!("{shown}: {reason}")),
        }
    }
    (kept, skipped)
}

/// Standard base64 for data URIs.
pub fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let start = out.len();
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let crc = crc32(&out[start..]);
        out.extend_from_slice(&crc.to_be_bytes());
    }

    /// A structurally complete PNG with `extra` bytes of image data.
    pub(crate) fn png(width: u32, height: u32, extra: usize) -> Vec<u8> {
        let mut b = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        let mut header = Vec::new();
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[8, 6, 0, 0, 0]);
        chunk(&mut b, b"IHDR", &header);
        chunk(&mut b, b"IDAT", &vec![0u8; extra.max(1)]);
        chunk(&mut b, b"IEND", &[]);
        b
    }

    #[test]
    fn names_are_short_and_plain() {
        for ok in ["login", "after-fix", "a_1", &"x".repeat(64)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "../x", "a b", "a.png", "ü", &"x".repeat(65)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn png_limits_hold() {
        assert_eq!(admit(&png(800, 600, 9)).unwrap(), (800, 600));
        assert_eq!(admit(&png(1, 1, 0)).unwrap(), (1, 1));
        assert!(admit(&png(801, 600, 0)).unwrap_err().contains("viewport"));
        assert!(admit(&png(800, 601, 0)).unwrap_err().contains("viewport"));
        assert!(admit(&png(0, 10, 0)).unwrap_err().contains("empty"));
        assert!(admit(b"GIF89a not a png file at all")
            .unwrap_err()
            .contains("not a PNG"));
        // A bare signature and header prefix is not an image.
        let whole = png(10, 10, 0);
        for cut in [20, 24, 33, whole.len() - 1] {
            assert!(
                admit(&whole[..cut]).unwrap_err().contains("truncated"),
                "{cut}"
            );
        }
        let mut wrong = png(10, 10, 0);
        wrong[12..16].copy_from_slice(b"tEXt");
        assert!(admit(&wrong).unwrap_err().contains("checksum"));
        let mut corrupt = png(10, 10, 4);
        corrupt[40] ^= 1;
        assert!(admit(&corrupt).unwrap_err().contains("checksum"));
        let mut trailing = png(10, 10, 0);
        trailing.push(0);
        assert!(admit(&trailing).unwrap_err().contains("after its end"));
        let mut no_data = whole[..33].to_vec();
        no_data.extend_from_slice(&whole[whole.len() - 12..]);
        assert!(admit(&no_data).unwrap_err().contains("no image data"));
        let mut depth = png(10, 10, 0);
        depth[24] = 3;
        let crc = crc32(&depth[12..29]);
        depth[29..33].copy_from_slice(&crc.to_be_bytes());
        assert!(admit(&depth).unwrap_err().contains("unsupported"));
        // Structural rules beyond checksums.
        let build = |color: u8, chunks: &[(&[u8; 4], Vec<u8>)]| {
            let mut b = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
            let mut header = Vec::new();
            header.extend_from_slice(&10u32.to_be_bytes());
            header.extend_from_slice(&10u32.to_be_bytes());
            header.extend_from_slice(&[8, color, 0, 0, 0]);
            chunk(&mut b, b"IHDR", &header);
            for (kind, data) in chunks {
                chunk(&mut b, kind, data);
            }
            chunk(&mut b, b"IEND", &[]);
            b
        };
        let idat = || (b"IDAT", vec![0u8; 4]);
        let plte = || (b"PLTE", vec![0u8; 3]);
        assert!(admit(&build(3, &[idat()]))
            .unwrap_err()
            .contains("no palette"));
        assert_eq!(admit(&build(3, &[plte(), idat()])).unwrap(), (10, 10));
        // An indexed palette holds at most 2^depth entries.
        let indexed = |depth: u8, entries: usize| {
            let mut b = build(3, &[(b"PLTE", vec![0u8; entries * 3]), idat()]);
            b[24] = depth;
            let crc = crc32(&b[12..29]);
            b[29..33].copy_from_slice(&crc.to_be_bytes());
            admit(&b)
        };
        assert!(indexed(1, 2).is_ok());
        assert!(indexed(1, 3).unwrap_err().contains("invalid length"));
        assert!(indexed(8, 256).is_ok());
        assert!(indexed(8, 257).unwrap_err().contains("invalid length"));
        assert!(admit(&build(2, &[idat(), plte(), idat()]))
            .unwrap_err()
            .contains("misplaced"));
        assert!(admit(&build(0, &[plte(), idat()]))
            .unwrap_err()
            .contains("misplaced"));
        assert!(admit(&build(2, &[(b"PLTE", vec![0u8; 4]), idat()]))
            .unwrap_err()
            .contains("invalid length"));
        assert!(admit(&build(6, &[idat(), (b"tEXt", vec![b'a']), idat()]))
            .unwrap_err()
            .contains("not consecutive"));
        assert!(admit(&build(6, &[(b"ZZZZ", vec![]), idat()]))
            .unwrap_err()
            .contains("unknown critical"));
        assert!(admit(&build(6, &[(b"zz1z", vec![]), idat()]))
            .unwrap_err()
            .contains("four letters"));
        assert_eq!(
            admit(&build(6, &[(b"tEXt", vec![b'a']), idat(), idat()])).unwrap(),
            (10, 10)
        );
        assert!(admit(&png(10, 10, MAX_BYTES as usize))
            .unwrap_err()
            .contains("larger"));
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, out) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), out);
        }
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn browser_roots_follow_the_recorded_os() {
        assert_eq!(
            browser_root(
                "windows",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            ),
            r"C:\Program Files\Google\Chrome\Application"
        );
        assert_eq!(
            browser_root("windows", r"\\?\C:\Tools\chrome-headless-shell.exe"),
            r"C:\Tools"
        );
        assert_eq!(browser_root("windows", r"C:\chrome.exe"), r"C:\");
        assert_eq!(
            browser_root("linux", "/opt/google/chrome/chrome"),
            "/opt/google/chrome"
        );
        assert_eq!(browser_root("macos", "/chs"), "/");
    }

    #[cfg(unix)]
    #[test]
    fn a_non_executable_override_is_a_blocker() {
        let base = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-shots-exec-{}", std::process::id()));
        crate::platform::private_dir(&base).unwrap();
        let file = base.join("chrome");
        std::fs::write(&file, "not a browser").unwrap();
        let err = browser("linux", Some(file.clone().into_os_string())).unwrap_err();
        assert!(err.contains("not an executable file"), "{err}");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn macos_needs_an_explicit_headless_shell() {
        let err = browser("macos", None).unwrap_err();
        assert!(
            err.contains("window server") && err.contains(BROWSER_ENV),
            "{err}"
        );
        assert!(browser("linux", Some("relative/chrome".into()))
            .unwrap_err()
            .contains("absolute"));
    }

    #[test]
    fn helpers_quote_paths_and_fix_the_viewport() {
        let (name, text) =
            helper("linux", Path::new("/opt/c/chrome"), Path::new("/r/scratch")).unwrap();
        assert_eq!(name, "omgs-screenshot");
        assert!(text.contains("mkdir -p '/r/scratch/browser-tmp' && cd '/r/scratch/browser-tmp' || exit 0\nTMPDIR=. '/opt/c/chrome' --headless"));
        assert!(text.contains("--window-size=800,600"));
        assert!(text.contains("--screenshot='/r/scratch/screenshots'/\"$1\".png \"$2\""));
        assert!(!text.contains("--single-process"));
        assert!(text.contains(
            "[ \"$status\" -eq 0 ] || echo \"$status\" > '/r/scratch/screenshots'/\"$1\".failed"
        ));
        let (_, mac) = helper(
            "macos",
            Path::new("/a/chrome-headless-shell"),
            Path::new("/r/s"),
        )
        .unwrap();
        assert!(mac.contains("--single-process"));
        assert!(helper("linux", Path::new("/o'x/chrome"), Path::new("/r")).is_err());
        let (win, text) = helper(
            "windows",
            Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Path::new(r"C:\r\scratch"),
        )
        .unwrap();
        assert_eq!(win, "omgs-screenshot.cmd");
        assert!(text.contains(r#""--screenshot=C:\r\scratch\screenshots\%~1.png" "%~2""#));
        assert!(text.contains(r#"(echo %omgs_status%)> "C:\r\scratch\screenshots\%~1.failed""#));
        assert!(helper("windows", Path::new(r"C:\a%b\c.exe"), Path::new(r"C:\r")).is_err());
    }

    #[test]
    fn collect_keeps_valid_files_and_names_every_refusal() {
        let base = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-shots-{}", std::process::id()))
            .join("case");
        let _ = std::fs::remove_dir_all(&base);
        crate::platform::private_dir(&base).unwrap();
        let scratch = base.join("scratch");
        let from = scratch.join(DIR);
        let to = base.join("to");
        std::fs::create_dir_all(&from).unwrap();
        std::fs::write(from.join("a.png"), png(800, 600, 4)).unwrap();
        std::fs::write(from.join("b.png"), png(900, 600, 0)).unwrap();
        std::fs::write(from.join("bad name.png"), png(10, 10, 0)).unwrap();
        std::fs::write(from.join("c.txt"), "x").unwrap();
        std::fs::write(from.join("broken.failed"), "133\n").unwrap();
        std::fs::write(from.join("slow.timeout"), "").unwrap();
        for n in ["d", "e", "f", "g"] {
            std::fs::write(from.join(format!("{n}.png")), png(10, 10, 0)).unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(from.join("a.png"), from.join("link.png")).unwrap();
        #[cfg(unix)]
        {
            std::fs::write(base.join("outside.png"), png(10, 10, 0)).unwrap();
            std::fs::hard_link(base.join("outside.png"), from.join("hard.png")).unwrap();
        }
        let (kept, skipped) = collect(&scratch, &to);
        let names: Vec<_> = kept.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "d", "e", "f"]);
        assert_eq!(kept[0].sha256, crate::sha256::digest(&png(800, 600, 4)));
        assert_eq!(std::fs::read(to.join("a.png")).unwrap(), png(800, 600, 4));
        let joined = skipped.join("\n");
        for needle in [
            "broken: the browser exited with status 133",
            "slow: capture timed out after 20 s",
            "b.png: 900x600",
            "bad name.png: name",
            "c.txt: name",
            "g.png: more than 4",
        ] {
            assert!(joined.contains(needle), "{needle}: {joined}");
        }
        #[cfg(unix)]
        for refused in ["link.png: not a single-link", "hard.png: not a single-link"] {
            assert!(joined.contains(refused), "{refused}: {joined}");
        }
        assert_eq!(collect(&base.join("missing"), &to), (vec![], vec![]));
        // A screenshot directory replaced by a link to host storage is never listed.
        #[cfg(unix)]
        {
            let linked = base.join("linked");
            std::fs::create_dir_all(&linked).unwrap();
            std::os::unix::fs::symlink(&from, linked.join(DIR)).unwrap();
            let (kept, skipped) = collect(&linked, &base.join("to2"));
            assert!(kept.is_empty());
            assert_eq!(
                skipped,
                ["the screenshot directory is not a plain directory"]
            );
        }
        std::fs::remove_dir_all(base.parent().unwrap()).unwrap();
    }
}
