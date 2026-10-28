use crate::supervise;
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProbe {
    pub tier: Option<String>,
    pub needs_dacl_augmentation: Option<bool>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub probes: WindowsCapabilities,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsCapabilities {
    pub base_container_api_present: bool,
    pub base_container_supports_enumerate_paths: bool,
    pub base_container_supports_deny_paths: bool,
    pub base_container_supports_ingress_host_loopback_allow: bool,
    pub native_capture_available: bool,
}

impl WindowsProbe {
    pub fn parse(text: &str) -> Result<Self, String> {
        let p: Self = serde_json::from_str(text)
            .map_err(|e| format!("invalid Windows MXC probe JSON: {e}"))?;
        match (&p.tier, p.needs_dacl_augmentation, &p.error) {
            (Some(_), Some(_), None) | (None, None, Some(_)) => Ok(p),
            _ => Err(
                "invalid Windows MXC probe: success and detector error must be mutually exclusive"
                    .into(),
            ),
        }
    }

    pub fn require_supported_tier(&self) -> Result<(), String> {
        let p = &self.probes;
        let supported = match self.tier.as_deref().unwrap_or("") {
            "base-container" => p.base_container_api_present,
            "appcontainer-dacl" => {
                !p.base_container_supports_enumerate_paths
                    && !p.base_container_supports_deny_paths
                    && !p.base_container_supports_ingress_host_loopback_allow
            }
            _ => false,
        };
        if supported {
            Ok(())
        } else {
            Err(format!(
                "Windows MXC probe reports an unknown or inconsistent process tier: {}",
                self.tier.as_deref().unwrap_or("detector error")
            ))
        }
    }

    pub fn notes(&self) -> Vec<String> {
        let p = &self.probes;
        let mut notes = vec![format!(
            "Windows MXC probe: tier={}, needsDaclAugmentation={}, enumeratePaths={}, denyPaths={}, ingressHostLoopbackAllow={}, nativeCaptureAvailable={}",
            self.tier.as_deref().unwrap_or("detector error"), self.needs_dacl_augmentation.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".into()), p.base_container_supports_enumerate_paths,
            p.base_container_supports_deny_paths, p.base_container_supports_ingress_host_loopback_allow,
            p.native_capture_available
        )];
        notes.extend(
            self.warnings
                .iter()
                .map(|w| format!("Windows MXC probe warning: {w}{}", if w.contains("wxc-host-prep") { "; advisory only; OMGS never runs wxc-host-prep.exe, which requires administrator rights" } else { "" })),
        );
        notes
    }
}

#[derive(Debug)]
pub enum ProbeFailure {
    Unavailable(String),
    Invalid(String),
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(e) | Self::Invalid(e) => f.write_str(e),
        }
    }
}

pub const DACL_GAP: &str = "MXC temporarily adds host ACEs to granted paths, including toolchain roots, and restores them best effort during cleanup; an interrupted run or forced termination can leave entries until MXC next starts; this is distinct from optional administrator wxc-host-prep.exe preparation, which OMGS never runs";

pub fn windows_policy(
    probe: Result<WindowsProbe, ProbeFailure>,
) -> Result<(bool, bool, Vec<String>, Vec<String>), String> {
    match probe {
        Ok(p) => {
            let mut notes = p.notes();
            if let Some(error) = &p.error {
                notes.push(format!("Windows capability selection: detector error; guarded enumeration refusal/retry fallback: {error}"));
                return Ok((true, true, notes, vec![DACL_GAP.into()]));
            }
            p.require_supported_tier()?;
            let enumerate = p.probes.base_container_supports_enumerate_paths;
            let mut gaps = Vec::new();
            if p.needs_dacl_augmentation == Some(true) {
                gaps.push(DACL_GAP.into());
                notes.push("Optional administrator host preparation can improve metadata and NUL access; OMGS never runs wxc-host-prep.exe, which requires administrator rights".into());
            }
            notes.push("Windows capability selection: probe; enumeration retry disabled".into());
            if !enumerate { gaps.push(enumeration_gap()); }
            Ok((enumerate, false, notes, gaps))
        }
        Err(ProbeFailure::Invalid(e)) => Err(e),
        Err(ProbeFailure::Unavailable(e)) => Ok((true, true, vec![format!(
            "Windows capability selection: probe failed; guarded enumeration refusal/retry fallback: {e}"
        )], vec![DACL_GAP.into()])),
    }
}

pub fn enumeration_gap() -> String {
    "this Windows version refuses parent directory enumeration; relative nested file access is supported, but directory listing, absolute path resolution and NUL device redirection may fail; denied CMD redirection can retain exit 0".into()
}

fn executor_command(executor: &Path, cwd: Option<&Path>) -> Command {
    let mut cmd = Command::new(executor);
    cmd.env_clear();
    if cfg!(windows) {
        for k in [
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
        ] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd
}

fn inspect(mut cmd: Command) -> supervise::Supervised {
    let limits = supervise::Limits {
        wall_ms: 15_000,
        cpu_secs: Some(10),
        file_size_bytes: Some(1 << 30),
        open_files: Some(1024),
        memory_bytes: None,
        tasks: None,
        output_cap_bytes: 64 * 1024,
    };
    cmd.stdin(std::process::Stdio::null());
    supervise::run(cmd, &limits, None)
}

fn completed(run: &supervise::Supervised) -> bool {
    run.exit_code.is_some()
        && !run.executor_error
        && run.capture_complete
        && run.cleanup_complete
        && !run.interrupted
        && !run.timed_out
        && !run.killed
        && run.survivors.is_empty()
        && run.output_bytes_total <= 64 * 1024
}

pub fn windows_probe(executor: &Path) -> Result<WindowsProbe, ProbeFailure> {
    let mut cmd = executor_command(executor, None);
    cmd.arg("--probe");
    let run = inspect(cmd);
    probe_result(&run)
}

fn probe_result(run: &supervise::Supervised) -> Result<WindowsProbe, ProbeFailure> {
    if !completed(run) {
        let detail = format!(
            "Windows MXC probe did not complete: {}",
            crate::proof::redact(&run.output)
        );
        return Err(if run.executor_error {
            ProbeFailure::Unavailable(detail)
        } else {
            ProbeFailure::Invalid(detail)
        });
    }
    let probe = WindowsProbe::parse(&run.stdout).map_err(ProbeFailure::Invalid)?;
    if !run.success && probe.error.is_none() {
        return Err(ProbeFailure::Invalid(
            "Windows MXC probe returned success data with a nonzero exit".into(),
        ));
    }
    Ok(probe)
}

pub fn dry_run(executor: &Path, config: &Path, cwd: &Path) -> supervise::Supervised {
    let mut cmd = executor_command(executor, Some(cwd));
    cmd.arg("--dry-run").arg("--config").arg(config);
    inspect(cmd)
}

pub fn dry_run_result(run: &supervise::Supervised) -> Result<(), String> {
    if completed(run) && run.success {
        return Ok(());
    }
    let detail = crate::platform::escape_controls(&crate::proof::redact(&run.output));
    if completed(run) && run.exit_code.is_some_and(|c| c != 0) {
        Err(format!(
            "MXC configuration rejection (--dry-run); target code was not executed: {detail}"
        ))
    } else {
        Err(format!("MXC dry run did not complete: timeout={}, interrupted={}, executor_error={}, cleanup_complete={}, capture_complete={}, survivors={}; target code was not executed: {detail}",
            run.timed_out, run.interrupted, run.executor_error, run.cleanup_complete,
            run.capture_complete, run.survivors.len()))
    }
}

pub fn workload_command(executor: &Path, config: &Path, cwd: &Path) -> Command {
    let mut cmd = executor_command(executor, Some(cwd));
    cmd.arg("--config").arg(config);
    cmd
}

// https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md
// Windows Server 2025 shares build 26100 with Windows 11 24H2.
const PROCESS_MINIMUMS: &[(u32, u32, &str)] = &[
    (26100, 9278, "24H2"),
    (26200, 9278, "25H2"),
    (26300, 9550, "26H2"),
    (28000, 2804, "26H1"),
];

pub fn describe_windows_build(version: Option<(u32, u32, u32, u32)>) -> String {
    let Some((major, minor, build, ubr)) = version else {
        return "Windows OS build unavailable; MXC probe and configuration validation decide support".into();
    };
    let status = match PROCESS_MINIMUMS.iter().find(|(b, _, _)| *b == build) {
        Some((_, min, release)) if major == 10 && minor == 0 => format!(
            "{} MXC ProcessContainer minimum {build}.{min} ({release})",
            if ubr >= *min { "meets" } else { "below" }
        ),
        _ => "not listed in MXC's published ProcessContainer minimums".into(),
    };
    format!("Windows OS build {major}.{minor}.{build}.{ubr}: {status}; Windows Server 2025 shares build 26100; Microsoft publishes no separate Server minimum; MXC probe and configuration validation decide support")
}

pub fn windows_build_report() -> String {
    describe_windows_build(windows_version())
}

#[cfg(not(windows))]
fn windows_version() -> Option<(u32, u32, u32, u32)> {
    None
}

#[cfg(windows)]
fn windows_version() -> Option<(u32, u32, u32, u32)> {
    use std::ffi::c_void;
    #[repr(C)]
    struct Version {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut Version) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(
            key: *mut c_void,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            ty: *mut u32,
            data: *mut c_void,
            size: *mut u32,
        ) -> i32;
    }
    let mut v = Version {
        size: std::mem::size_of::<Version>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    if unsafe { RtlGetVersion(&mut v) } < 0 {
        return None;
    }
    let key: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0"
        .encode_utf16()
        .collect();
    let name: Vec<u16> = "UBR\0".encode_utf16().collect();
    let mut ubr = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(
            0x80000002u32 as i32 as isize as *mut c_void,
            key.as_ptr(),
            name.as_ptr(),
            0x0001_0010,
            std::ptr::null_mut(),
            (&mut ubr as *mut u32).cast(),
            &mut size,
        )
    };
    (status == 0 && size == 4).then_some((v.major, v.minor, v.build, ubr))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn probe() -> serde_json::Value {
        serde_json::json!({"tier":"base-container", "needsDaclAugmentation":false,
            "warnings":[], "probes": {"baseContainerApiPresent":true,
            "baseContainerSupportsEnumeratePaths":true, "baseContainerSupportsDenyPaths":true,
            "baseContainerSupportsIngressHostLoopbackAllow":false, "nativeCaptureAvailable":false}})
    }
    #[test]
    fn windows_probe_parses_strict_types_and_requires_a_known_consistent_tier() {
        let value = probe();
        let p = WindowsProbe::parse(&value.to_string()).unwrap();
        assert!(p.require_supported_tier().is_ok());
        assert!(p.probes.base_container_supports_enumerate_paths);
        assert!(p.notes()[0].contains("ingressHostLoopbackAllow=false"));
        for bad in ["{}", "null", "[]", "warning\n{}"] {
            assert!(WindowsProbe::parse(bad).is_err());
        }
        for key in ["tier", "needsDaclAugmentation", "warnings", "probes"] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(WindowsProbe::parse(&bad.to_string()).is_err());
        }
        for key in value["probes"].as_object().unwrap().keys() {
            let mut bad = value.clone();
            bad["probes"][key] = "true".into();
            assert!(WindowsProbe::parse(&bad.to_string()).is_err());
            bad["probes"].as_object_mut().unwrap().remove(key);
            assert!(WindowsProbe::parse(&bad.to_string()).is_err());
        }
        let mut v = value.clone();
        v["tier"] = "unknown".into();
        assert!(WindowsProbe::parse(&v.to_string())
            .unwrap()
            .require_supported_tier()
            .is_err());
        let mut v = value;
        v["probes"]["baseContainerApiPresent"] = false.into();
        assert!(WindowsProbe::parse(&v.to_string())
            .unwrap()
            .require_supported_tier()
            .is_err());
    }
    #[test]
    fn detector_error_shape_preserves_text_and_rejects_mixed_results() {
        let mut v = probe();
        v.as_object_mut().unwrap().remove("tier");
        v.as_object_mut().unwrap().remove("needsDaclAugmentation");
        v["error"] = "WRITE_DAC unavailable on path C:\\scratch: detector detail".into();
        let (_, retry, notes, _) =
            windows_policy(WindowsProbe::parse(&v.to_string()).map_err(ProbeFailure::Invalid))
                .unwrap();
        assert!(retry);
        assert!(notes
            .iter()
            .any(|n| n.contains(v["error"].as_str().unwrap())));
        for (key, value) in [
            ("tier", serde_json::json!("base-container")),
            ("needsDaclAugmentation", serde_json::json!(false)),
        ] {
            let mut mixed = v.clone();
            mixed[key] = value;
            assert!(WindowsProbe::parse(&mixed.to_string()).is_err());
        }
        let mut mixed = probe();
        mixed["error"] = "detector error".into();
        assert!(WindowsProbe::parse(&mixed.to_string()).is_err());
        let mut extended = probe();
        extended["futureField"] = true.into();
        assert!(WindowsProbe::parse(&extended.to_string()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn stdout_probe_parsing_and_incomplete_dry_runs_fail_closed() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "printf '%s' \"$1\"; printf 'stray diagnostic' >&2",
            "sh",
            &probe().to_string(),
        ]);
        let mut run = inspect(cmd);
        assert!(probe_result(&run).is_ok(), "{run:?}");
        let mut truncated = run.clone();
        truncated.capture_complete = false;
        assert!(matches!(
            probe_result(&truncated),
            Err(ProbeFailure::Invalid(_))
        ));
        run.stdout = "bad JSON".into();
        assert!(matches!(probe_result(&run), Err(ProbeFailure::Invalid(_))));
        run.success = false;
        run.exit_code = Some(1);
        run.output = "rejected\x1b[31m\r\n".into();
        let rejection = dry_run_result(&run).unwrap_err();
        assert!(rejection.contains("configuration rejection"));
        assert!(!rejection.chars().any(char::is_control));
        for kind in 0..7 {
            let mut failed = run.clone();
            match kind {
                0 => failed.timed_out = true,
                1 => failed.interrupted = true,
                2 => failed.executor_error = true,
                3 => failed.capture_complete = false,
                4 => failed.cleanup_complete = false,
                5 => failed.survivors.push(supervise::Survivor {
                    pid: 123,
                    command: "child".into(),
                }),
                _ => failed.killed = true,
            }
            assert!(dry_run_result(&failed)
                .unwrap_err()
                .starts_with("MXC dry run did not complete:"));
        }
    }

    #[test]
    fn observed_server_dacl_tier_runs_without_claiming_base_container_capabilities() {
        let value = serde_json::json!({"tier":"appcontainer-dacl", "needsDaclAugmentation":true,
            "warnings":["metadata and NUL preparation advised"], "probes": {
            "baseContainerApiPresent":false, "baseContainerSupportsEnumeratePaths":false,
            "baseContainerSupportsDenyPaths":false,
            "baseContainerSupportsIngressHostLoopbackAllow":false, "nativeCaptureAvailable":false}});
        let (enumerate, fallback, notes, gaps) =
            windows_policy(WindowsProbe::parse(&value.to_string()).map_err(ProbeFailure::Invalid))
                .unwrap();
        assert!(!enumerate && !fallback);
        assert!(gaps.contains(&DACL_GAP.into()));
        assert!(notes
            .iter()
            .any(|n| n.contains("metadata and NUL preparation advised")));
        assert!(notes
            .iter()
            .any(|n| n.contains("never runs wxc-host-prep.exe")));
        let mut inconsistent = value;
        inconsistent["probes"]["baseContainerSupportsEnumeratePaths"] = true.into();
        assert!(windows_policy(
            WindowsProbe::parse(&inconsistent.to_string()).map_err(ProbeFailure::Invalid)
        )
        .is_err());
    }

    #[test]
    fn probe_selects_enumeration_and_only_failures_enable_retry() {
        for enumerate in [false, true] {
            let mut v = probe();
            v["probes"]["baseContainerSupportsEnumeratePaths"] = enumerate.into();
            let (selected, fallback, notes, gaps) =
                windows_policy(WindowsProbe::parse(&v.to_string()).map_err(ProbeFailure::Invalid))
                    .unwrap();
            assert_eq!(selected, enumerate);
            assert!(!fallback);
            assert!(notes.iter().any(|n| n.contains("selection: probe;")));
            assert_eq!(gaps.contains(&enumeration_gap()), !enumerate);
        }
        let (selected, fallback, notes, gaps) =
            windows_policy(Err(ProbeFailure::Unavailable("could not start".into()))).unwrap();
        assert!(selected && fallback && notes[0].contains("probe failed"));
        assert!(gaps.contains(&DACL_GAP.into()));
        assert!(
            windows_policy(WindowsProbe::parse("bad JSON").map_err(ProbeFailure::Invalid)).is_err()
        );
        let mut v = probe();
        v["tier"] = "unavailable".into();
        assert!(
            windows_policy(WindowsProbe::parse(&v.to_string()).map_err(ProbeFailure::Invalid))
                .is_err()
        );
    }

    #[test]
    fn pinned_executor_dry_run_accepts_and_rejects_without_running_code() {
        let Ok(located) = super::super::locate_executor() else {
            return;
        };
        let d = std::env::temp_dir().join(format!("omgs-dry-run-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let d = std::fs::canonicalize(d).unwrap();
        let marker = d.join("ran");
        let command = if cfg!(windows) {
            "cmd.exe /d /c echo workload > ran".into()
        } else {
            "echo workload > ran".to_string()
        };
        let mut config = serde_json::json!({"version":"1.0.0",
            "containment":located.executor.containment,
            "process":{"commandLine":command, "cwd":platform_path(&d)},
            "network":{"egress":{"default":"deny"}},
            "filesystem":{"readwritePaths":[platform_path(&d)]}});
        let path = d.join("config.json");
        for valid in [true, false] {
            if !valid {
                config["version"] = "invalid".into();
            }
            std::fs::write(&path, config.to_string()).unwrap();
            let run = dry_run(&located.path, &path, &d);
            let result = dry_run_result(&run);
            assert_eq!(result.is_ok(), valid, "{}", run.output);
            if !valid {
                let message = result.unwrap_err();
                assert!(message.contains("configuration rejection"));
                assert!(!run.output.is_empty());
                assert!(message.contains(
                    crate::platform::escape_controls(&crate::proof::redact(&run.output)).as_str()
                ));
            }
            assert!(!marker.exists());
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_timed_out_proof_restores_granted_scratch_aces() {
        let Ok(located) = super::super::locate_executor() else {
            return;
        };
        let _console = supervise::interruption::Guard::install().unwrap();
        let d = std::env::temp_dir().join(format!("omgs-dacl-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let granted = d.join("granted");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::write(granted.join("file.txt"), "scratch evidence").unwrap();
        let acl = || {
            let output = Command::new("icacls.exe")
                .arg(&granted)
                .arg("/t")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            output.stdout
        };
        let before = acl();
        let nonce = "d".repeat(64);
        for supervisor_timeout in [false, true] {
            let config = serde_json::json!({"version":"1.0.0", "containment":"process",
                "process":{"commandLine":format!("cmd.exe /d /c echo OMGS_START_{nonce}& for /l %i in (1,0,2) do @rem"),
                    "cwd":platform_path(&granted), "timeout":if supervisor_timeout {60000} else {2000}},
                "network":{"egress":{"default":"deny"}},
                "filesystem":{"readwritePaths":[platform_path(&granted)]},
                "processContainer":{"leastPrivilege":true}});
            let path = d.join("config.json");
            std::fs::write(&path, config.to_string()).unwrap();
            let cmd = workload_command(&located.path, &path, &d);
            let limits = supervise::Limits {
                wall_ms: if supervisor_timeout { 5000 } else { 15000 },
                cpu_secs: None,
                file_size_bytes: None,
                open_files: None,
                memory_bytes: None,
                tasks: None,
                output_cap_bytes: 65536,
            };
            let run = supervise::run_marked(cmd, &limits, None, &nonce);
            assert!(run.command_started, "DACL workload did not start: {run:?}");
            assert!(!run.command_finished && !run.success, "{run:?}");
            if supervisor_timeout {
                assert!(run.timed_out, "{run:?}");
                assert!(
                    run.notes
                        .iter()
                        .any(|n| n.contains("exited during cleanup grace")),
                    "{run:?}"
                );
            }
            // Compare before another executor startup can recover leaked ACEs.
            assert_eq!(acl(), before, "granted path ACEs changed: {run:?}");
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    fn platform_path(path: &Path) -> String {
        crate::platform::mxc_path(path)
    }

    #[test]
    fn windows_build_minimums_cover_boundaries_unknown_and_server() {
        for (build, min, _) in PROCESS_MINIMUMS {
            assert!(describe_windows_build(Some((10, 0, *build, min - 1))).contains("below"));
            assert!(describe_windows_build(Some((10, 0, *build, *min))).contains("meets"));
            assert!(describe_windows_build(Some((10, 0, *build, min + 1))).contains("meets"));
        }
        assert!(describe_windows_build(Some((10, 0, 26100, 1))).contains("Server 2025"));
        assert!(describe_windows_build(Some((10, 0, 99999, 1))).contains("not listed"));
        assert!(describe_windows_build(Some((11, 0, 26100, 99999))).contains("not listed"));
        assert!(describe_windows_build(None).contains("unavailable"));
    }
    #[cfg(windows)]
    #[test]
    fn reads_live_windows_version_without_a_shell() {
        let v = windows_version().expect("RtlGetVersion and registry UBR");
        assert!(v.0 >= 10 && v.2 > 0);
    }
}
