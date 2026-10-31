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

/// Width and height from a PNG signature and its leading IHDR chunk.
pub fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), String> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    if bytes.len() < 24 || bytes[..8] != SIGNATURE {
        return Err("not a PNG file".into());
    }
    if bytes[8..12] != [0, 0, 0, 13] || &bytes[12..16] != b"IHDR" {
        return Err("PNG does not start with an IHDR chunk".into());
    }
    let word =
        |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let (width, height) = (word(16), word(20));
    if width == 0 || height == 0 {
        return Err("PNG has an empty dimension".into());
    }
    Ok((width, height))
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
        if !path.is_file() {
            return Err(format!("{BROWSER_ENV} {} is not a file", path.display()));
        }
        return Ok(path);
    }
    if os == "macos" {
        return Err(format!("no screenshot browser on macOS by default: Chrome, Edge and Chromium app bundles abort inside the sandbox because they must register with the window server, which OMGS keeps closed. Set {BROWSER_ENV} to a chrome-headless-shell executable outside protected folders"));
    }
    default_browsers(os)
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or_else(|| {
            format!(
                "no headless browser found at {}; install Chrome, Edge or Chromium there or set {BROWSER_ENV}",
                default_browsers(os).join(", ")
            )
        })
}

/// The directory to grant read access to so the browser can load its files.
pub fn browser_root(browser: &Path) -> PathBuf {
    browser
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| browser.to_path_buf())
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
        let text = format!(
            "@echo off\r\n\"{}\" {} \"--user-data-dir={}\" \"--screenshot={}\\%~1.png\" \"%~2\"\r\nexit /b %errorlevel%\r\n",
            quoted(browser)?,
            flags(os).join(" "),
            quoted(&profile)?,
            quoted(&out)?
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
    let text = format!(
        "#!/bin/sh\ncase \"$1\" in ''|*[!A-Za-z0-9_-]*) echo 'omgs-screenshot: name must be 1 to 64 letters, digits, - or _' >&2; exit 2;; esac\n{} {} --user-data-dir={} --screenshot={}/\"$1\".png \"$2\"\n",
        quoted(browser)?,
        flags(os).join(" "),
        quoted(&profile)?,
        quoted(&out)?
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

/// Keeps admissible PNG files from `from` (the sandbox's output directory) in
/// `to`, in name order, and names every file it refused.
pub fn collect(from: &Path, to: &Path) -> (Vec<Shot>, Vec<String>) {
    let mut kept = Vec::new();
    let mut skipped = Vec::new();
    let mut entries: Vec<_> = match std::fs::read_dir(from) {
        Ok(dir) => dir.filter_map(Result::ok).map(|e| e.path()).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (kept, skipped),
        Err(e) => {
            skipped.push(format!("cannot read the screenshot directory: {e}"));
            return (kept, skipped);
        }
    };
    entries.sort();
    for path in entries {
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let shown = crate::platform::escape_controls(&file);
        let name = match file.strip_suffix(".png").filter(|n| valid_name(n)) {
            Some(n) => n.to_string(),
            None => {
                skipped.push(format!(
                    "{shown}: name must be 1 to 64 letters, digits, - or _ with a .png extension"
                ));
                continue;
            }
        };
        match read_regular(&path).and_then(|bytes| {
            let (width, height) = admit(&bytes)?;
            if kept.len() == MAX_FILES {
                return Err(format!("more than {MAX_FILES} screenshots"));
            }
            let target = to.join(format!("{name}.png"));
            crate::platform::private_dir(to)
                .and_then(|_| crate::runmeta::write_atomic_bytes(&target, &bytes))
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

/// Reads a regular, unlinked file, refusing anything above the byte cap.
fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() || crate::platform::is_link(&meta) {
        return Err("not a regular file".into());
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
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

    pub(crate) fn png(width: u32, height: u32, extra: usize) -> Vec<u8> {
        let mut b = vec![
            0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 13,
        ];
        b.extend_from_slice(b"IHDR");
        b.extend_from_slice(&width.to_be_bytes());
        b.extend_from_slice(&height.to_be_bytes());
        b.extend(std::iter::repeat_n(0u8, extra));
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
        assert!(admit(&png(10, 10, 0)[..20]).is_err());
        let mut wrong = png(10, 10, 0);
        wrong[12..16].copy_from_slice(b"tEXt");
        assert!(admit(&wrong).unwrap_err().contains("IHDR"));
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
        assert!(text.contains("'/opt/c/chrome' --headless"));
        assert!(text.contains("--window-size=800,600"));
        assert!(text.contains("--screenshot='/r/scratch/screenshots'/\"$1\".png \"$2\""));
        assert!(!text.contains("--single-process"));
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
        let from = base.join("from");
        let to = base.join("to");
        std::fs::create_dir_all(&from).unwrap();
        std::fs::write(from.join("a.png"), png(800, 600, 4)).unwrap();
        std::fs::write(from.join("b.png"), png(900, 600, 0)).unwrap();
        std::fs::write(from.join("bad name.png"), png(10, 10, 0)).unwrap();
        std::fs::write(from.join("c.txt"), "x").unwrap();
        for n in ["d", "e", "f", "g"] {
            std::fs::write(from.join(format!("{n}.png")), png(10, 10, 0)).unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(from.join("a.png"), from.join("link.png")).unwrap();
        let (kept, skipped) = collect(&from, &to);
        let names: Vec<_> = kept.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "d", "e", "f"]);
        assert_eq!(kept[0].sha256, crate::sha256::digest(&png(800, 600, 4)));
        assert_eq!(std::fs::read(to.join("a.png")).unwrap(), png(800, 600, 4));
        let joined = skipped.join("\n");
        for needle in [
            "b.png: 900x600",
            "bad name.png: name",
            "c.txt: name",
            "g.png: more than 4",
        ] {
            assert!(joined.contains(needle), "{needle}: {joined}");
        }
        #[cfg(unix)]
        assert!(joined.contains("link.png: not a regular file"), "{joined}");
        assert_eq!(collect(&base.join("missing"), &to), (vec![], vec![]));
        std::fs::remove_dir_all(base.parent().unwrap()).unwrap();
    }
}
