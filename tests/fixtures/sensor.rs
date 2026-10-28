// Native fake scanner. Only ever executed through the pinned MXC executor.
use std::{env, fs, path::PathBuf, time::Duration};
fn main() {
    // Stable diagnostic exit codes identify the failed boundary without
    // printing scanner data, paths or raw fixture output.
    fn check(ok: bool, code: i32) {
        if !ok {
            std::process::exit(code);
        }
    }
    let exe = env::current_exe().unwrap();
    let tool = exe.file_stem().unwrap().to_str().unwrap();
    let args: Vec<String> = env::args().skip(1).collect();
    let has = |s: &str| args.iter().any(|a| a == s);
    check(env::var_os("OMGS_TEST_SECRET").is_none(), 31);
    check(env::var("RUSTUP_AUTO_INSTALL").unwrap() == "0", 32);
    let target = PathBuf::from(args.last().unwrap());
    // Gitleaks puts its target after --source instead.
    let target = if tool == "gitleaks" {
        PathBuf::from(&args[args.iter().position(|s| s == "--source").unwrap() + 1])
    } else {
        target
    };
    let data = target.join(".sensor-fixture");
    let fixture = |extension: &str| data.join(format!("{tool}.{extension}"));
    let tmp = PathBuf::from(env::var_os(if cfg!(windows) { "TEMP" } else { "TMPDIR" }).unwrap());
    check(
        fs::write(
            tmp.join("raw-secret.txt"),
            "raw-secret-must-never-be-stored raw-v2-distinct-sentinel extra-data-distinct-sentinel",
        )
        .is_ok(),
        33,
    );
    check(
        fs::write(target.join("scanner-wrote-target"), "bad").is_err(),
        34,
    );
    check(
        fs::OpenOptions::new().append(true).open(&exe).is_err(),
        35,
    );
    check(fs::read(target.join("../outside")).is_err(), 36);
    let outside = fs::read_to_string(fixture("outside"))
        .unwrap_or_else(|_| std::process::exit(37));
    check(fs::read(outside).is_err(), 38);
    if let Ok(db) = env::var("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY") {
        assert!(fs::read(PathBuf::from(&db).join("osv-scanner/crates.io/all.zip")).is_ok());
        assert!(fs::write(PathBuf::from(db).join("scanner-wrote-db"), "bad").is_err());
    }
    let loopback = fs::read_to_string(fixture("port")).unwrap();
    for ip in [loopback.as_str(), "1.1.1.1:443"] {
        assert!(std::net::TcpStream::connect_timeout(
            &ip.parse().unwrap(),
            Duration::from_millis(100)
        )
        .is_err());
    }
    match tool {
        "trufflehog" => {
            assert!(has("--no-verification") && has("--no-update") && has("--json"));
            // Simulate a scanner honoring inline suppression unless disabled.
            if fs::read_to_string(target.join("src/main.rs"))
                .unwrap()
                .contains("trufflehog:ignore")
                && !has("--no-ignore-tag")
            {
                return;
            }
        }
        "osv-scanner" => {
            for flag in [
                "--offline",
                "--offline-vulnerabilities",
                "--no-resolve",
                "--no-call-analysis",
            ] {
                assert!(has(flag));
            }
            let i = args.iter().position(|s| s == "--config");
            if !has("--no-ignore") || i.is_none() {
                println!("{{\"results\":[]}}");
                return;
            }
            assert_eq!(fs::read_to_string(&args[i.unwrap() + 1]).unwrap(), "");
            // A requirements include reaches outside the mount. Reading it must
            // fail even though the file exists and is readable on the host.
            assert!(fs::read_to_string(target.join("requirements.txt"))
                .unwrap()
                .contains("-r ../outside"));
        }
        "semgrep" => {
            assert!(has("--max-target-bytes=1000000"));
            assert!(has("--disable-nosem") && has("--no-git-ignore"));
            assert!(!target.join(".semgrepignore").exists());
            assert!(!target.join("src/.semgrepignore").exists());
        }
        _ => {}
    }
    let mode = fs::read_to_string(fixture("mode")).unwrap();
    if mode == "timeout" {
        std::thread::sleep(Duration::from_secs(30));
    }
    print!(
        "{}",
        fs::read_to_string(fixture("json")).unwrap()
    );
    std::process::exit(mode.parse().unwrap_or(0));
}
