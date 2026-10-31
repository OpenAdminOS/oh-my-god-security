//! Terminal output boundary. Callers supply one logical line, never raw controls.
use std::io::{self, Write};

pub fn line(text: &str) {
    println!("{}", crate::platform::escape_controls(text));
}

pub fn err(text: &str) {
    eprintln!("{}", crate::platform::escape_controls(text));
}

pub fn text(text: &str) {
    print!("{}", crate::platform::escape_controls(text));
}

/// Write logical lines while preserving the status command's broken-pipe contract.
pub fn lines(text: &[String]) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    for line in text {
        writeln!(stdout, "{}", crate::platform::escape_controls(line))?;
    }
    Ok(())
}

/// Keep serialized data valid when the terminal boundary escapes controls.
/// JSON already encodes C0 controls, but permits literal C1 characters.
pub fn json(value: &impl serde::Serialize) -> Result<(), String> {
    let serialized = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let encoded: String = serialized
        .chars()
        .map(|c| {
            if c.is_control() {
                format!("\\u{:04x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect();
    line(&encoded);
    Ok(())
}
