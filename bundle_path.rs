/// Validate a portable bundle destination before joining it to an install root.
pub fn validate(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        || std::path::Path::new(path)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(format!("unsafe skill bundle destination: {path:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_unsafe_destinations() {
        for path in [
            "",
            "../escape",
            "/absolute",
            "C:/prefix",
            "C:relative",
            "a/../b",
            "./a",
            "a//b",
            "a\\b",
            "a\\..\\b",
        ] {
            assert!(super::validate(path).is_err(), "{path:?}");
        }
        assert!(super::validate("schemas/policy.schema.json").is_ok());
    }
}
