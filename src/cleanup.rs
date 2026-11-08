//! Host-attested resource lifecycle. This ledger never kills PIDs or deletes paths.
//! Hosts perform ownership-checked cleanup and retain the receipt with final reports.
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, path::Path};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    pub kind: String,
    pub location: String,
    pub owner: String,
    pub locator: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub id: String,
    pub actor: String,
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofResolution {
    pub token: String,
    pub actor: String,
    pub evidence: String,
    pub processes_stopped: bool,
}
/// Explicit host recovery, never an inference that a missing coordinator means no survivors.
pub fn resolve_proof(run: &Path, resolution: ProofResolution) -> Result<(), String> {
    for s in [&resolution.token, &resolution.actor, &resolution.evidence] {
        text(s)?;
    }
    if !resolution.processes_stopped {
        return Err("host must verify proof processes and descendants are stopped".into());
    }
    crate::runmeta::update(run, |m| {
        if m.contains_key("cleanup_receipt") {
            return Err("cleanup receipt already sealed".into());
        }
        if crate::attempts::states(&crate::attempts::history(m)?)?
            .values()
            .any(|a| a.state == "active")
        {
            return Err("stop or complete active attempts before resolving a proof".into());
        }
        let previous = m
            .get_mut("active_proofs")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|v| v.remove(&resolution.token))
            .ok_or("unknown active proof token")?;
        m.entry("proof_resolutions").or_insert_with(||json!([])).as_array_mut().ok_or("proof_resolutions must be an array")?
            .push(json!({"assurance":"host_attested","resolution":resolution,"previous":previous,"at":crate::runmeta::timestamp(crate::runmeta::now_ms())}));
        m.entry("cleanup_started_at")
            .or_insert_with(|| json!(crate::runmeta::timestamp(crate::runmeta::now_ms())));
        Ok(())
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    resource: Resource,
    release: Option<Release>,
}
fn text(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err("resource fields must be nonblank text".into())
    } else {
        Ok(())
    }
}
fn entries(
    m: &serde_json::Map<String, serde_json::Value>,
) -> Result<BTreeMap<String, Entry>, String> {
    m.get("resources")
        .cloned()
        .map(crate::contract::decode)
        .transpose()
        .map(Option::unwrap_or_default)
}
pub fn register(run: &Path, r: Resource) -> Result<(), String> {
    for s in [&r.id, &r.kind, &r.location, &r.owner, &r.locator] {
        text(s)?;
    }
    if ![
        "checkout",
        "evidence",
        "scratch",
        "process",
        "tunnel",
        "remote_job",
    ]
    .contains(&r.kind.as_str())
    {
        return Err("unknown resource kind".into());
    }
    crate::runmeta::update(run, |m| {
        if m.contains_key("cleanup_started_at") {
            return Err("cleanup started; resource registration closed".into());
        }
        let mut resources = entries(m)?;
        if resources.contains_key(&r.id) {
            return Err("resource id already registered".into());
        }
        resources.insert(
            r.id.clone(),
            Entry {
                resource: r,
                release: None,
            },
        );
        m.insert(
            "resources".into(),
            serde_json::to_value(resources).map_err(|e| e.to_string())?,
        );
        Ok(())
    })
}
pub fn release(run: &Path, r: Release) -> Result<(), String> {
    for s in [&r.id, &r.actor, &r.evidence] {
        text(s)?;
    }
    crate::runmeta::update(run, |m| {
        if m.contains_key("cleanup_receipt") {
            return Err("cleanup receipt already sealed".into());
        }
        let mut resources = entries(m)?;
        let entry = resources.get_mut(&r.id).ok_or("unknown resource")?;
        if entry.release.is_some() {
            return Err("resource already released".into());
        }
        entry.release = Some(r);
        m.insert(
            "resources".into(),
            serde_json::to_value(resources).map_err(|e| e.to_string())?,
        );
        Ok(())
    })
}
pub fn begin(run: &Path) -> Result<(), String> {
    crate::runmeta::update(run, |m| {
        if crate::budget::active_proofs(m)? {
            return Err("active proofs prevent cleanup".into());
        }
        if crate::attempts::states(&crate::attempts::history(m)?)?
            .values()
            .any(|a| a.state == "active")
        {
            return Err("stop or complete active attempts before cleanup".into());
        }
        m.entry("cleanup_started_at")
            .or_insert_with(|| json!(crate::runmeta::timestamp(crate::runmeta::now_ms())));
        Ok(())
    })
}
pub fn finish(run: &Path) -> Result<(), String> {
    crate::runmeta::update(run, |m| {
        if crate::budget::active_proofs(m)? {
            return Err("active proofs prevent cleanup completion".into());
        }
        if !m.contains_key("cleanup_started_at") {
            return Err("begin cleanup first".into());
        }
        let resources = entries(m)?;
        if resources.values().any(|e| e.release.is_none()) {
            return Err("every registered resource needs a host release attestation".into());
        }
        let proof_resolutions = m
            .get("proof_resolutions")
            .cloned()
            .unwrap_or_else(|| json!([]));
        m.entry("cleanup_receipt").or_insert_with(||json!({"proof_resolutions":proof_resolutions,"assurance":"host_attested","finished_at":crate::runmeta::timestamp(crate::runmeta::now_ms()),"resources":resources,"limitation":"Only registered resources covered. OMGS did not independently verify deletion or process termination."}));
        Ok(())
    })
}
pub fn show(run: &Path) -> Result<serde_json::Value, String> {
    let m = crate::runmeta::read(run)?;
    Ok(
        json!({"resources":entries(&m)?,"active_proofs":m.get("active_proofs"),"proof_resolutions":m.get("proof_resolutions"),"started_at":m.get("cleanup_started_at"),"receipt":m.get("cleanup_receipt")}),
    )
}
