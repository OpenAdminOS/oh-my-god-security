//! Win32 filesystem path encoding, used only at direct API boundaries.
//! Keep caller paths unchanged for admission checks, records and diagnostics.
use std::io::{Error, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

pub(crate) fn wide(path: &Path) -> Result<Vec<u16>> {
    if path.as_os_str().encode_wide().any(|c| c == 0) {
        return Err(Error::other("NUL in storage path"));
    }
    // Unlike std::fs, direct Win32 filesystem calls do not add extended
    // length prefixes. Normalize ordinary paths before adding one: verbatim
    // paths do not interpret forward slashes or relative components.
    let absolute = std::path::absolute(path)?;
    let mut text: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    // Match std's conservative directory limit, including the terminating
    // NUL. Keep ordinary short paths in the ordinary Win32 namespace.
    if text.len() + 1 < 248 {
        text.push(0);
        return Ok(text);
    }
    match absolute.components().next() {
        Some(std::path::Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(_) => {
                text.splice(..0, r"\\?\".encode_utf16());
            }
            std::path::Prefix::UNC(_, _) => {
                text.splice(..2, r"\\?\UNC\".encode_utf16());
            }
            _ => {}
        },
        _ => {
            return Err(Error::other(
                "storage path needs an absolute Windows prefix",
            ))
        }
    }
    text.push(0);
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_paths_use_extended_length_disk_and_unc_names() {
        let suffix = format!("{}\\{}", "x".repeat(130), "y".repeat(130));
        for (input, expected) in [
            (r"C:/storage/child", r"\\?\C:\storage\child"),
            (r"\\server\share\storage", r"\\?\UNC\server\share\storage"),
            (r"\\?\C:\storage\child", r"\\?\C:\storage\child"),
            (
                r"\\?\UNC\server\share\storage",
                r"\\?\UNC\server\share\storage",
            ),
        ] {
            let encoded = wide(&Path::new(input).join(&suffix)).unwrap();
            assert_eq!(encoded.last(), Some(&0));
            assert_eq!(
                String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
                format!("{expected}\\{suffix}")
            );
        }
        let short = wide(Path::new("C:/storage/child")).unwrap();
        assert_eq!(
            String::from_utf16(&short[..short.len() - 1]).unwrap(),
            r"C:\storage\child"
        );
        assert!(wide(Path::new("C:\\bad\0name")).is_err());
    }

    #[test]
    fn ordinary_paths_are_normalized_before_becoming_verbatim() {
        let suffix = "x".repeat(240);
        let input = format!("C:/storage/./discard/../child/{suffix}:extra");
        let encoded = wide(Path::new(&input)).unwrap();
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
            format!(r"\\?\C:\storage\child\{suffix}:extra")
        );
    }
}
