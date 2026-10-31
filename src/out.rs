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

/// Keep serialized data valid without activating controls in display.
pub fn json(value: &impl serde::Serialize) -> Result<(), String> {
    line(&encode_json(value)?);
    Ok(())
}

fn encode_json(value: &impl serde::Serialize) -> Result<String, String> {
    let serialized = serde_json::to_string(value).map_err(|e| e.to_string())?;
    Ok(serialized
        .chars()
        .map(|c| {
            if crate::platform::display_control(c) {
                c.encode_utf16(&mut [0; 2])
                    .iter()
                    .map(|unit| format!("\\u{unit:04x}"))
                    .collect::<String>()
            } else {
                c.to_string()
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_controls_are_inert_and_lossless_for_every_class() {
        let text = "a\0\n\t\u{1b}\u{7f}\u{85}\u{9f}\u{202e}\u{200b}\u{2066}\u{feff}\u{2028}\u{2029}\u{e0001} café";
        let encoded = super::encode_json(&text).unwrap();
        assert!(!encoded.chars().any(crate::platform::display_control));
        assert_eq!(
            serde_json::from_str::<String>(&encoded).unwrap().as_bytes(),
            text.as_bytes()
        );
        assert_eq!(crate::platform::escape_controls(&encoded), encoded);
        assert!(encoded.contains("\\udb40\\udc01"));
    }
}
