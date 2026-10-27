use omgs::supervise::{run, Limits};
use std::process::Command;

fn limits() -> Limits {
    Limits {
        wall_ms: 5000,
        cpu_secs: None,
        file_size_bytes: None,
        open_files: None,
        memory_bytes: None,
        tasks: None,
        output_cap_bytes: 65536,
    }
}

#[test]
fn spawn_failure_is_reported() {
    let result = run(Command::new("/omgs/nonexistent/executor"), &limits(), None);
    assert!(!result.success);
    assert!(!result.capture_complete);
    assert!(result.output.contains("failed to start executor"));
    assert!(!result.notes.is_empty());
    assert!(result.enforced.is_empty());
}

#[cfg(unix)]
fn shell(script: &str) -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.env_clear().env("PATH", "/usr/bin:/bin");
    cmd.args(["-c", script]);
    cmd
}

#[cfg(unix)]
fn assert_gone(pid: i32) {
    let start = std::time::Instant::now();
    loop {
        if unsafe { libc::kill(pid, 0) } != 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            return;
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "pid {pid} survived cleanup"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn output_pid(result: &omgs::supervise::Supervised) -> i32 {
    result
        .output
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("missing pid: {result:?}"))
}

#[cfg(unix)]
#[test]
fn rlimits_are_inherited() {
    let mut limits = limits();
    limits.open_files = Some(64);
    limits.file_size_bytes = Some(1024 * 1024);
    limits.cpu_secs = Some(2);
    let result = run(shell("ulimit -n; ulimit -f; ulimit -t"), &limits, None);
    assert!(result.success, "{result:?}");
    let values: Vec<u64> = result
        .output
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    #[cfg(target_os = "macos")]
    assert_eq!(values, [64, 1024, 2]);
    #[cfg(not(target_os = "macos"))]
    assert_eq!(values, [64, 2048, 2]);
    assert!(result.enforced.contains(&"rlimit_nofile=64".into()));
    assert!(result.enforced.contains(&"rlimit_fsize=1048576B".into()));
    assert!(result.enforced.contains(&"rlimit_cpu=2s".into()));
}

#[cfg(unix)]
#[test]
fn invalid_rlimit_fails_without_panicking() {
    let mut limits = limits();
    limits.open_files = Some(u64::MAX);
    let result = run(shell("exit 0"), &limits, None);
    assert!(!result.success);
    assert!(result.output.contains("not a finite rlimit"));
}

#[cfg(unix)]
#[test]
fn timeout_kills_background_tree() {
    let mut limits = limits();
    limits.wall_ms = 500;
    let result = run(shell("sleep 30 & echo $!; wait"), &limits, None);
    assert!(result.timed_out, "{result:?}");
    assert_eq!(result.exit_code, None);
    assert!(!result.success);
    assert!(result.capture_complete, "{result:?}");
    assert!(result.duration_ms < 4000, "{result:?}");
    assert_gone(output_pid(&result));
}

#[cfg(unix)]
#[test]
fn normal_exit_kills_background_tree_before_reaping_leader() {
    let result = run(shell("sleep 30 & echo $!; exit 0"), &limits(), None);
    assert!(result.success, "{result:?}");
    assert_eq!(result.exit_code, Some(0));
    assert!(result.duration_ms < 4000, "{result:?}");
    assert_gone(output_pid(&result));
}

#[cfg(unix)]
#[test]
fn output_is_capped_and_all_bytes_are_counted() {
    let mut limits = limits();
    limits.output_cap_bytes = 37;
    let result = run(
        shell("head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2"),
        &limits,
        None,
    );
    assert!(result.success, "{result:?}");
    assert_eq!(result.output.len(), 37);
    assert_eq!(result.output_bytes_total, 262144);
}

#[cfg(unix)]
#[test]
fn zero_cap_still_drains_and_counts() {
    let mut limits = limits();
    limits.output_cap_bytes = 0;
    let result = run(shell("printf output; printf error >&2"), &limits, None);
    assert!(result.success, "{result:?}");
    assert!(result.output.is_empty());
    assert_eq!(result.output_bytes_total, 11);
}

#[cfg(unix)]
#[test]
fn stdout_precedes_stderr() {
    let result = run(shell("printf error >&2; printf output"), &limits(), None);
    assert!(result.success, "{result:?}");
    assert_eq!(result.output, "outputerror");
}

#[cfg(unix)]
#[test]
fn nonzero_exit_is_preserved() {
    let result = run(shell("exit 7"), &limits(), None);
    assert_eq!(result.exit_code, Some(7));
    assert!(!result.success);
    assert!(!result.timed_out);
}

#[cfg(target_os = "macos")]
#[test]
fn sweep_kills_detached_sandbox_process_and_spares_unrelated_process() {
    use omgs::supervise::SweepMarkers;
    use std::process::Child;

    struct Unrelated(Child);
    impl Drop for Unrelated {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let interpreter = ["/opt/homebrew/bin/python3", "/usr/bin/python3"]
        .into_iter()
        .find(|path| {
            Command::new(path)
                .arg("-c")
                .arg("import os")
                .status()
                .is_ok_and(|s| s.success())
        });
    let perl = "/usr/bin/perl";
    if interpreter.is_none() && !std::path::Path::new(perl).is_file() {
        eprintln!("skipping survivor sweep: neither python3 nor perl is available");
        return;
    }
    let path = std::env::temp_dir().join(format!("omgs-supervise-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let path = path.canonicalize().unwrap();
    let markers = SweepMarkers {
        allowed: path.join("allowed"),
        denied: path.join("denied"),
    };
    std::fs::write(&markers.allowed, b"allowed").unwrap();
    std::fs::write(&markers.denied, b"denied").unwrap();
    let denied = markers
        .denied
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile = format!("(version 1)(allow default)(deny file-read-data (literal \"{denied}\"))");
    let mut unrelated = Unrelated(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let python = "import os,time\nr,w=os.pipe()\npid=os.fork()\nif pid==0:\n os.close(r)\n os.setsid()\n os.write(w,b'x')\n os.close(w)\n time.sleep(30)\n os._exit(0)\nos.close(w)\nos.read(r,1)\nprint(pid,flush=True)\nos._exit(0)\n";
    let perl_script = "$|=1; pipe(R,W) or die; my $pid=fork(); defined($pid) or die; if($pid==0){close R; defined(POSIX::setsid()) or die; print W 'x'; close W; sleep 30; POSIX::_exit(0);} close W; read(R,my $x,1); print \"$pid\\n\"; POSIX::_exit(0);";
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["-p", &profile]);
    if let Some(interpreter) = interpreter {
        cmd.args([interpreter, "-c", python]);
    } else {
        cmd.args([perl, "-MPOSIX", "-e", perl_script]);
    }
    let result = run(cmd, &limits(), Some(&markers));
    assert!(!result.success, "{result:?}");
    assert!(result.capture_complete, "{result:?}");
    assert_eq!(result.exit_code, Some(0));
    let escaped = output_pid(&result);
    assert!(
        result.survivors.iter().any(|s| s.pid == escaped),
        "{result:?}"
    );
    assert!(result.enforced.contains(&"survivor_sweep".into()));
    assert!(result.notes.is_empty(), "{result:?}");
    assert_gone(escaped);
    assert!(unrelated.0.try_wait().unwrap().is_none());
    assert_eq!(unsafe { libc::kill(unrelated.0.id() as i32, 0) }, 0);
    let mut clean = Command::new("/usr/bin/sandbox-exec");
    clean
        .env_clear()
        .args(["-p", &profile, "/bin/sh", "-c", "exit 0"]);
    let clean = run(clean, &limits(), Some(&markers));
    assert!(clean.success, "{clean:?}");
    assert!(clean.survivors.is_empty());
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_pipe_from_detached_process_has_a_bounded_drain() {
    if !std::path::Path::new("/usr/bin/perl").is_file() {
        eprintln!("skipping bounded drain test: perl is unavailable");
        return;
    }
    let mut detached = Command::new("/usr/bin/perl");
    detached.env_clear().args([
        "-MPOSIX",
        "-e",
        "$|=1; pipe(R,W) or die; my $pid=fork(); defined($pid) or die; if($pid==0){close R; defined(POSIX::setsid()) or die; print W 'x'; close W; sleep 30; POSIX::_exit(0);} close W; read(R,my $x,1); print \"$pid\\n\"; POSIX::_exit(0);",
    ]);
    let result = run(detached, &limits(), None);
    let pid = output_pid(&result);
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    assert_gone(pid);
    assert!(!result.capture_complete, "{result:?}");
    assert!(!result.success);
    assert!(!result.timed_out);
    assert!(result.duration_ms < 4000, "{result:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn cgroup_limits_are_applied_or_explained_without_environment_leaks() {
    let mut limits = limits();
    limits.memory_bytes = Some(128 * 1024 * 1024);
    limits.tasks = Some(32);
    let result = run(
        shell("printf '%s:%s' \"${DBUS_SESSION_BUS_ADDRESS-unset}\" \"${XDG_RUNTIME_DIR-unset}\""),
        &limits,
        None,
    );
    assert!(result.success, "{result:?}");
    assert_eq!(result.output, "unset:unset");
    for control in ["cgroup_memory_max=134217728", "cgroup_tasks_max=32"] {
        if !result.enforced.iter().any(|item| item == control) {
            assert!(
                result.notes.iter().any(|note| note.contains("not applied")),
                "{result:?}"
            );
        }
    }
}

#[test]
fn executor_text_errors_and_outer_exit_codes_cannot_substitute_for_markers() {
    use omgs::supervise::run_marked;
    let scripts = if cfg!(windows) {
        [
            "echo Request error: invalid configuration & exit /b 1",
            "exit /b 0",
        ]
    } else {
        [
            "echo 'Request error: invalid configuration' >&2; exit 1",
            "exit 0",
        ]
    };
    for script in scripts {
        #[cfg(unix)]
        let cmd = shell(script);
        #[cfg(windows)]
        let cmd = {
            let mut cmd = Command::new(omgs::platform::which("cmd").unwrap());
            cmd.args(["/d", "/c", script]);
            cmd
        };
        let result = run_marked(cmd, &limits(), None, "nonce");
        assert!(!result.command_started && !result.command_finished);
        assert_eq!(result.exit_code, None);
        assert!(!result.success);
        assert!(
            result.capture_complete && result.cleanup_complete,
            "{result:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn timeout_words_and_signal_death_are_not_timeouts() {
    let nonce = "nonce";
    let cmd = shell("printf 'OMGS_START_nonce\nscript timed out after 1ms\nOMGS_END_nonce:0\n'");
    let result = omgs::supervise::run_marked(cmd, &limits(), None, nonce);
    assert!(result.success && !result.timed_out, "{result:?}");
    let result = omgs::supervise::run_marked(
        shell("printf 'OMGS_START_nonce\n'; kill -KILL $$"),
        &limits(),
        None,
        nonce,
    );
    assert!(
        result.killed && !result.timed_out && !result.executor_error,
        "{result:?}"
    );
    assert!(!result.success && !result.command_finished);
    let result =
        omgs::supervise::run_marked(Command::new("/omgs/no-executor"), &limits(), None, nonce);
    assert!(
        result.executor_error && !result.timed_out && !result.killed,
        "{result:?}"
    );
}
