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
    if tool == "python3" {
        // Fake interpreter for the user-install grant regression. Discovery
        // reports only fixture paths, and execution checks the package/data
        // boundary without requiring Python or a real scanner installation.
        let bin = exe.parent().unwrap();
        let local = bin.parent().unwrap();
        let home = local.parent().unwrap();
        let base = home.parent().unwrap().join("python-runtime");
        let site = local.join("lib/python3.13/site-packages");
        check(env::var_os("HOME").map(PathBuf::from).as_deref() != Some(home), 91);
        if args.first().map(String::as_str) == Some("-I") {
            // Discovery must stay isolated (-I), skip site processing (-S)
            // and run only the fixed introspection program.
            check(args.len() == 6 && args[1] == "-S" && args[2] == "-c", 95);
            check(
                args[3].starts_with("import sys,os;") && args[3].contains("sysconfig.get_path"),
                96,
            );
            check(env::var_os("PYTHONPATH").is_none(), 94);
            println!("{{\"base\":{base:?},\"prefix\":{base:?},\"sites\":[{site:?}]}}");
        } else {
            check(env::var_os("PYTHONPATH").map(PathBuf::from) == fs::canonicalize(&site).ok(), 93);
            check(fs::read(local.join("share/private")).is_err(), 90);
            check(fs::read(site.join("semgrep/__init__.py")).is_ok(), 92);
            println!("{{\"results\":[]}}");
        }
        return;
    }
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
    if mode == "private-library" {
        let library = exe.with_file_name(if cfg!(windows) {
            "private.dll"
        } else if cfg!(target_os = "macos") {
            "libprivate.dylib"
        } else {
            "libprivate.so"
        });
        // Simulate a native dependency required to finish the scan. Missing
        // access must produce a scan gap instead of a successful empty report.
        std::process::exit(if fs::read(library).is_err() { 42 } else { 43 });
    }
    if mode == "scratch-overrun" {
        // Many modest files exceed the aggregate cap without RLIMIT_FSIZE
        // stopping a single file. Continue until the supervisor terminates us.
        use std::io::Write;
        let block = vec![b'x'; 1 << 20];
        for n in 0..100_000 {
            let mut file = fs::File::create(tmp.join(format!("flood-{n}"))).unwrap();
            for _ in 0..8 { file.write_all(&block).unwrap(); }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    if mode == "timeout" {
        std::thread::sleep(Duration::from_secs(30));
    }
    print!(
        "{}",
        fs::read_to_string(fixture("json")).unwrap()
    );
    std::process::exit(mode.parse().unwrap_or(0));
}
