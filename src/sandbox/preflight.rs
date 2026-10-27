use crate::supervise;
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProbe {
    pub tier: String,
    pub needs_dacl_augmentation: bool,
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
        serde_json::from_str(text).map_err(|e| format!("invalid Windows MXC probe JSON: {e}"))
    }

    pub fn require_supported_tier(&self) -> Result<(), String> {
        let p = &self.probes;
        let supported = match self.tier.as_str() {
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
                self.tier
            ))
        }
    }

    pub fn notes(&self) -> Vec<String> {
        let p = &self.probes;
        let mut notes = vec![format!(
            "Windows MXC probe: tier={}, needsDaclAugmentation={}, enumeratePaths={}, denyPaths={}, ingressHostLoopbackAllow={}, nativeCaptureAvailable={}",
            self.tier, self.needs_dacl_augmentation, p.base_container_supports_enumerate_paths,
            p.base_container_supports_deny_paths, p.base_container_supports_ingress_host_loopback_allow,
            p.native_capture_available
        )];
        notes.extend(
            self.warnings
                .iter()
                .map(|w| format!("Windows MXC probe warning: {w}")),
        );
        notes
    }
}

pub fn windows_policy(
    probe: Result<WindowsProbe, String>,
) -> Result<(bool, bool, Vec<String>), String> {
    match probe {
        Ok(p) => {
            p.require_supported_tier()?;
            let enumerate = p.probes.base_container_supports_enumerate_paths;
            let mut notes = p.notes();
            if p.needs_dacl_augmentation {
                notes.push("Windows MXC advises administrator DACL preparation; OMGS does not run wxc-host-prep.exe; metadata or NUL access may fail".into());
            }
            notes.push("Windows capability selection: probe; enumeration retry disabled".into());
            if !enumerate {
                notes.push(enumeration_gap());
            }
            Ok((enumerate, false, notes))
        }
        Err(e) => Ok((true, true, vec![format!(
            "Windows capability selection: probe failed; guarded enumeration refusal/retry fallback: {e}"
        )])),
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

fn clean(run: &supervise::Supervised) -> bool {
    run.success
        && run.capture_complete
        && run.cleanup_complete
        && !run.interrupted
        && !run.timed_out
        && !run.killed
        && run.survivors.is_empty()
        && run.output_bytes_total <= 64 * 1024
}

pub fn windows_probe(executor: &Path) -> Result<WindowsProbe, String> {
    let mut cmd = executor_command(executor, None);
    cmd.arg("--probe");
    let run = inspect(cmd);
    if !clean(&run) {
        return Err(format!(
            "Windows MXC probe failed: {}",
            crate::proof::redact(&run.output)
        ));
    }
    WindowsProbe::parse(&run.output)
}

pub fn dry_run(executor: &Path, config: &Path, cwd: &Path) -> supervise::Supervised {
    let mut cmd = executor_command(executor, Some(cwd));
    cmd.arg("--dry-run").arg("--config").arg(config);
    inspect(cmd)
}

pub fn dry_run_result(run: &supervise::Supervised) -> Result<(), String> {
    if clean(run) {
        Ok(())
    } else {
        Err(format!(
            "MXC configuration rejection (--dry-run); target code was not executed: {}",
            crate::proof::redact(&run.output)
        ))
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
    (26100, 9278, "24H2 / Server 2025"),
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
    format!("Windows OS build {major}.{minor}.{build}.{ubr}: {status}; MXC probe and configuration validation decide support")
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
    fn observed_server_dacl_tier_runs_without_claiming_base_container_capabilities() {
        let value = serde_json::json!({"tier":"appcontainer-dacl", "needsDaclAugmentation":true,
            "warnings":["metadata and NUL preparation advised"], "probes": {
            "baseContainerApiPresent":false, "baseContainerSupportsEnumeratePaths":false,
            "baseContainerSupportsDenyPaths":false,
            "baseContainerSupportsIngressHostLoopbackAllow":false, "nativeCaptureAvailable":false}});
        let (enumerate, fallback, notes) =
            windows_policy(WindowsProbe::parse(&value.to_string())).unwrap();
        assert!(!enumerate && !fallback);
        assert!(notes
            .iter()
            .any(|n| n.contains("metadata and NUL preparation advised")));
        assert!(notes
            .iter()
            .any(|n| n.contains("does not run wxc-host-prep.exe")));
        let mut inconsistent = value;
        inconsistent["probes"]["baseContainerSupportsEnumeratePaths"] = true.into();
        assert!(windows_policy(WindowsProbe::parse(&inconsistent.to_string())).is_err());
    }

    #[test]
    fn probe_selects_enumeration_and_only_failures_enable_retry() {
        for enumerate in [false, true] {
            let mut v = probe();
            v["probes"]["baseContainerSupportsEnumeratePaths"] = enumerate.into();
            let (selected, fallback, notes) =
                windows_policy(WindowsProbe::parse(&v.to_string())).unwrap();
            assert_eq!(selected, enumerate);
            assert!(!fallback);
            assert!(notes.iter().any(|n| n.contains("selection: probe;")));
            assert_eq!(notes.contains(&enumeration_gap()), !enumerate);
        }
        let (selected, fallback, notes) = windows_policy(Err("bad JSON".into())).unwrap();
        assert!(selected && fallback && notes[0].contains("probe failed"));
        let mut v = probe();
        v["tier"] = "unavailable".into();
        assert!(windows_policy(WindowsProbe::parse(&v.to_string())).is_err());
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
        let command = format!("echo workload > \"{}\"", marker.display());
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
                assert!(message.contains(crate::proof::redact(&run.output).as_str()));
            }
            assert!(!marker.exists());
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
