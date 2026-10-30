//! Shared vocabulary. New public classes are registered in the bundled file.
use std::sync::OnceLock;
pub fn all() -> &'static [String] {
    static CLASSES: OnceLock<Vec<String>> = OnceLock::new();
    CLASSES.get_or_init(|| {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../skill/intent/classes.json"))
                .expect("class registry");
        v["classes"]
            .as_array()
            .expect("classes")
            .iter()
            .map(|c| c.as_str().expect("class").to_string())
            .collect()
    })
}
pub fn known(class: &str) -> bool {
    all().iter().any(|c| c == class)
}
/// Extension identifiers remain possible without making classification a gate
/// on coverage accountability. Prefer registered classes whenever applicable.
pub fn valid_identifier(class: &str) -> bool {
    !class.is_empty()
        && class.len() <= 96
        && class
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
