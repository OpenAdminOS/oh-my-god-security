# Execution safety and evidence limits

## Execution safety

Every execution of target controlled code, including imports, config loading, test discovery,
lifecycle hooks, tests, builds, migrations, and local app processes, goes only through `omgs prove`.
Reading source as text does not require executing it.

`omgs prove` runs target code only inside the SHA-256 pinned Microsoft MXC executor and enforces the
declared minimum set for the OS (DECISIONS.md, Sandbox requirements): deny by default filesystem
with the target copied into a per-run workspace, external network denied, an environment cleared to
an allowlist with scratch home, temp and cache, a wall clock, and on macOS and Linux process group
cleanup plus CPU time, file size and open file limits; macOS adds a survivor sweep, Linux uses MXC
PID namespace teardown and adds memory and task limits where a systemd user scope exists. On Windows
expiry OMGS sends the executor Ctrl+Break, waits up to 5 seconds for MXC cleanup, then forces
termination; an OMGS-owned kill-on-close job ends every descendant if OMGS dies, which can skip MXC
ACL restoration. Windows has no per-process limits, and Windows tiers whose MXC probe reports DACL
augmentation are refused. System directories, installed toolchain roots,
`~/.cargo/{bin,registry,git}` and `~/.rustup` remain readable when present; caches may contain
private source. There is no total disk quota, only a 1 GiB per-file size limit on Unix and no
per-file limit on Windows. A target file hardlinked to outside content becomes readable in the copy,
a residual risk that git checkouts cannot create. Each proof record lists the readable roots, what
was enforced and every gap; quote them, never claim more. Use only locally present dependencies and
tools. No dependency installation, package fetching, real credentials, or inherited host environment
is permitted during proofs.

Store draft tests outside the target and pass them with `--test-from <draft> --test <target-relative
path>`; the runner stages the draft into its workspace copy and never writes the target. If `prove`
exits 3, nothing ran. If any control in the declared set, a dependency, a runtime, or a needed local
service is unavailable, retain the highest earned tier, record the exact blocker and a safe local
manual validation plan. Never run an unsandboxed fallback. Stop immediately on an unexpected
external destination, real secret, or effect outside the synthetic fixture.

An effect the process sandbox cannot grant (real root, Gatekeeper, a root helper) has no proof tier
and is never run unsandboxed as a fallback. Such a record stays `needs_validation` with a manual
plan, as described in [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md). OMGS never
requires a user to stand up a VM.

Commands and survivor command lines in proof records are redacted before writing. Credential flags
mask their complete next token or inline `=value`, including quoted values with spaces; attached
short flags such as `-pVALUE` are outside this redaction scope. The runner keeps exact input in
`proofs/<n>/command.txt` for replay; this file and the saved config can contain credentials, so
protect the entire run directory. On Unix, proof directories are 0700 and command and config files
are 0600. Content hashes accept hardlinks and symlinks resolving to regular files, with symlink
targets disclosed. Snapshot hashing has no size cap; the Unix 1 GiB per-file limit applies only to
sandboxed processes. FIFOs and sockets in the target are skipped in the workspace copy and snapshot
digest, with up to 20 paths recorded as proof gaps and one aggregate count for the remainder.
Devices are refused before copying. On Unix, both copy paths preserve symlinks as links; outside or
unresolved links are disclosed as a counted proof gap and remain subject to sandbox access rules.
Small trust files use bounded, single-link, no-follow reads. On macOS and Linux, SIGINT, SIGTERM and
SIGHUP during preparation remove the proof directory and release a charged reservation; once
execution begins, interrupted runs retain their charge and an unclean record.
