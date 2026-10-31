//! Model routing per role with recorded fallbacks. The CLI never calls a
//! model: it tells the orchestrator which model to use for a role and records
//! every reroute after a refusal, so a refusal becomes a recorded reroute
//! instead of a stalled run.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const ROLES: [&str; 5] = ["host", "hunter", "verifier", "evaluator", "guard"];

/// `models.json`: for each role, the models to try in order.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Models {
    #[serde(default)]
    pub roles: BTreeMap<String, Vec<String>>,
}

pub fn load_models(path: &Path) -> Result<Models, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let parse = || -> Result<Models, String> {
        let v = crate::shape::strict_json(&text)?;
        let roles = v
            .as_object()
            .and_then(|o| o.get("roles"))
            .and_then(|r| r.as_object())
            .ok_or("models.json must be an object with a roles object")?;
        for (role, list) in roles {
            let ok = list
                .as_array()
                .is_some_and(|l| l.iter().all(|m| m.is_string()));
            if !ok {
                return Err(format!("role '{role}' must list model names as strings"));
            }
        }
        serde_json::from_value(v).map_err(|e| e.to_string())
    };
    let models = parse().map_err(|e| format!("parse {}: {e}", path.display()))?;
    for (role, list) in &models.roles {
        if !ROLES.contains(&role.as_str()) {
            return Err(format!(
                "{}: unknown role '{role}', expected one of {}",
                path.display(),
                ROLES.join(", ")
            ));
        }
        if list.iter().any(|m| m.trim().is_empty()) {
            return Err(format!(
                "{}: role '{role}' lists an empty model",
                path.display()
            ));
        }
    }
    Ok(models)
}

/// The model to use for `role` once every model in `refused` has refused.
/// `Err` means the role has no model configured or every fallback is used up.
pub fn next_model(models: &Models, role: &str, refused: &[String]) -> Result<String, String> {
    let list = models
        .roles
        .get(role)
        .filter(|l| !l.is_empty())
        .ok_or_else(|| format!("no models configured for role '{role}'"))?;
    list.iter()
        .find(|m| !refused.iter().any(|r| r == *m))
        .cloned()
        .ok_or_else(|| {
            format!(
                "every model configured for role '{role}' has refused ({}); record the blocker and stop this role",
                list.join(", ")
            )
        })
}

/// Host-supplied model names are labels, never permission to dispatch or switch.
pub fn parse_identities(values: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut models = BTreeMap::new();
    for value in values {
        let (role, model) = value.split_once('=').ok_or_else(|| {
            format!(
                "--model expects role=name; valid roles: {}",
                ROLES.join(", ")
            )
        })?;
        if model.chars().any(char::is_control) {
            return Err("--model names must not contain control characters".into());
        }
        if !ROLES.contains(&role)
            || model.trim().is_empty()
            || models.insert(role.into(), model.into()).is_some()
        {
            return Err(format!("--model requires a known role, nonblank model, and one value per role; valid roles: {}", ROLES.join(", ")));
        }
    }
    Ok(models)
}
