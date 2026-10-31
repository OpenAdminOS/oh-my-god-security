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
            .chain(
                v["deprecated_aliases"]
                    .as_object()
                    .expect("aliases")
                    .keys()
                    .cloned(),
            )
            .collect()
    })
}
/// Guidance only: aliases remain unchanged in persisted finding identities.
pub fn replacement(class: &str) -> Option<String> {
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("../skill/intent/classes.json")).expect("class registry");
    registry["deprecated_aliases"][class]
        .as_str()
        .map(str::to_owned)
}
pub fn known(class: &str) -> bool {
    all().iter().any(|c| c == class) || replacement(class).is_some()
}
/// Syntax check for registry maintenance. Registration is required before an
/// identifier can be used in candidate or finding identity.
pub fn valid_identifier(class: &str) -> bool {
    !class.is_empty()
        && class.len() <= 96
        && class
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Finding identity accepts only registered classes. New classes require a
/// registry update, so typos cannot create a second cross-run identity.
pub fn validate(class: &str) -> Result<(), String> {
    if known(class) {
        Ok(())
    } else {
        Err(format!(
            "unknown attack class {class}; expected {}",
            all().join(", ")
        ))
    }
}
