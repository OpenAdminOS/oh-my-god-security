pub mod accounting;
pub mod adjudication;
pub mod approval;
pub mod architecture;
pub mod batch;
pub mod bench;
pub mod budget;
pub mod critic;
pub mod handoff;
pub mod help;
pub mod install;
pub mod intent;
pub mod ledger;
pub mod model;
pub mod paths;
pub mod persona;
pub mod platform;
pub mod policy;
pub mod proof;
pub mod report;
pub mod route;
pub mod run_artifact;
pub mod runmeta;
pub mod sandbox;
pub mod scratch;
pub mod sensors;
pub mod setup;
pub mod sha256;
pub mod shape;
pub mod stacks;
pub mod status;
pub mod supervise;
pub mod watch;

/// Stable, non cryptographic fingerprint for finding identity across runs.
/// Inputs are the semantic identity of a finding, never prose or line numbers.
pub fn fingerprint(attack_class: &str, entry_point: &str, sink: &str, boundary: &str) -> String {
    let joined = format!(
        "{}|{}|{}|{}",
        attack_class.trim().to_lowercase(),
        entry_point.trim(),
        sink.trim(),
        boundary.trim().to_lowercase()
    );
    // FNV-1a 64, chosen for cross run and cross platform stability.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in joined.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("omgs-{hash:016x}")
}

/// Compatibility wrapper shared by sensors and inventory consumers.
pub fn is_vendored_path(rel_path: &str) -> bool {
    paths::classify(rel_path) == paths::Class::Vendored
}

/// Stacks OMGS can seed meaningful coverage for, from relative file paths.
pub fn detect_stacks(rel_paths: &[String]) -> Vec<&'static str> {
    let eligible: Vec<String> = rel_paths
        .iter()
        .map(|p| p.replace('\\', "/"))
        .filter(|p| {
            matches!(paths::classify(p), paths::Class::Code)
                || (paths::classify(p) == paths::Class::Data
                    && ["package.json", "Cargo.toml", "pyproject.toml", "setup.cfg"]
                        .contains(&p.rsplit('/').next().unwrap_or(p)))
        })
        .collect();
    let rel_paths = &eligible;
    let has = |pred: &dyn Fn(&str) -> bool| rel_paths.iter().any(|p| pred(p));
    let count_ext = |exts: &[&str]| {
        rel_paths
            .iter()
            .filter(|p| exts.iter().any(|e| p.to_lowercase().ends_with(e)))
            .count()
    };
    let mut stacks = Vec::new();
    if has(&|p| p.ends_with("/route.ts") || p.ends_with("/route.tsx")) {
        stacks.push("nextjs-app-router");
    }
    if has(&|p| p.ends_with(".csproj") || p.ends_with(".cshtml") || p.ends_with(".sln")) {
        stacks.push("aspnet");
    }
    if count_ext(&[".ps1", ".psm1", ".psd1"]) > 0 {
        stacks.push("powershell");
    }
    if has(&|p| p.ends_with("Package.swift")) || count_ext(&[".swift"]) > 0 {
        stacks.push("swift");
    }
    if has(&|p| p.ends_with("index.html"))
        && count_ext(&[".js"]) > 0
        && !has(&|p| p.ends_with("package.json"))
    {
        stacks.push("static-web");
    }
    if count_ext(&[".py"]) > 0 {
        stacks.push("python");
    }
    if stacks.is_empty() && has(&|p| p.ends_with("package.json")) {
        stacks.push("node");
    }
    if count_ext(&[".sh", ".bash", ".zsh", ".ksh", ".fish", ".cmd", ".bat"]) > 0 {
        stacks.push("shell");
    }
    if count_ext(&[".rs"]) > 0 || has(&|p| p.ends_with("Cargo.toml")) {
        stacks.push("rust");
    }
    stacks
}

/// Attack classes seeded per detected stack in the coverage ledger.
pub fn stack_attack_classes(stack: &str) -> Vec<&'static str> {
    match stack {
        "nextjs-app-router" => vec![
            "missing_authz",
            "idor_tenant_isolation",
            "client_only_auth",
            "webhook_signature",
        ],
        "aspnet" => vec![
            "missing_authz",
            "generated_script_injection",
            "import_parsing",
            "output_encoding",
        ],
        "powershell" => vec![
            "generated_script_injection",
            "feed_to_policy_write",
            "download_and_execute",
            "credential_handling",
            "privileged_local_ops",
        ],
        "swift" => vec![
            "shell_injection",
            "deletion_path_safety",
            "privileged_local_ops",
            "download_integrity",
        ],
        "static-web" => vec![
            "dom_injection",
            "import_parsing",
            "export_integrity",
            "unbounded_import_recursion",
        ],
        "shell" => vec!["shell_injection", "path_traversal", "download_integrity"],
        "browser-extension" => vec!["identity_binding", "missing_authz", "dom_injection"],
        "python" => vec!["command_injection", "deserialization", "path_traversal"],
        _ => vec!["missing_authz", "input_validation"],
    }
}

pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
