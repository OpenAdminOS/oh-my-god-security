//! Presentation and spending defaults only. Evidence validation never reads a persona.
#[derive(Debug, Clone, Copy)]
pub struct Defaults {
    pub name: &'static str,
    pub report_depth: &'static str,
    pub budget_profile: &'static str,
    pub budget: u64,
    pub mode: &'static str,
}

pub fn defaults(name: &str) -> Result<Defaults, String> {
    let (name, report_depth, budget_profile, budget) = match name {
        "builder" => ("builder", "concise", "small", 24),
        "inheritor" => ("inheritor", "full", "deep", 64),
        "team" => ("team", "full", "team", 96),
        _ => return Err("--persona must be builder, inheritor or team".into()),
    };
    // A persona cannot opt a project into a merge gate. That requires trusted policy.
    Ok(Defaults {
        name,
        report_depth,
        budget_profile,
        budget,
        mode: "advisory",
    })
}
