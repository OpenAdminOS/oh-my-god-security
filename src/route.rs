//! Model routing per role with recorded fallbacks. The CLI never calls a
//! model: it tells the orchestrator which model to use for a role and records
//! every reroute after a refusal, so a refusal becomes a recorded reroute
//! instead of a stalled run.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const ROLES: [&str; 4] = ["hunter", "verifier", "evaluator", "guard"];

/// `models.json`: for each role, the models to try in order.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Models {
    #[serde(default)]
    pub roles: BTreeMap<String, Vec<String>>,
}

pub fn load_models(path: &Path) -> Result<Models, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let models: Models =
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
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
