pub mod architecture;
pub mod batch;
pub mod critic;
pub mod intent;
pub mod ledger;
pub mod model;
pub mod report;
pub mod route;
pub mod runmeta;
pub mod sandbox;
pub mod sensors;
pub mod shape;
pub mod status;
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

/// Paths that are almost certainly vendored or generated, excluded from
/// hunting surfaces and flagged on sensor hits instead of counted as code.
pub fn is_vendored_path(rel_path: &str) -> bool {
    let lower = rel_path.replace('\\', "/").to_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let vendored_dirs = [
        "node_modules",
        "vendor",
        "third_party",
        "thirdparty",
        "external",
        "monacoeditor",
        "dist",
        "build",
        ".next",
    ];
    if segments.iter().any(|s| vendored_dirs.contains(s)) {
        return true;
    }
    let file = segments.last().copied().unwrap_or("");
    file.ends_with(".min.js")
        || file.ends_with(".min.css")
        || file.ends_with(".dll")
        || file.ends_with(".exe")
        || file.ends_with(".pdb")
        || file.ends_with(".map")
}

/// Stacks OMGS can seed meaningful coverage for, from relative file paths.
pub fn detect_stacks(rel_paths: &[String]) -> Vec<&'static str> {
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
