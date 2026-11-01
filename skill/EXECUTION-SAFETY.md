# Execution safety and evidence limits

## Execution safety

Every execution of target controlled code, including imports, config loading, test discovery,
lifecycle hooks, tests, builds, migrations, and local app processes, goes only through `omgs prove`.
Reading source as text does not require executing it.

`omgs prove` runs target code only inside the SHA-256 pinned Microsoft MXC executor and enforces the
declared minimum set for the OS (DECISIONS.md, Sandbox requirements): deny by default filesystem
with the target copied into a per-run workspace, external network denied, an environment cleared to
an allowlist with scratch home, temp and cache, a wall clock, and on macOS and Linux process group
cleanup plus CPU time, file size and open file limits; macOS requires a dedicated launchd resource
coalition certificate. Linux uses MXC PID namespace teardown and adds memory and task limits where a
systemd user scope exists. On Windows
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

A harness that runs `git` inside the sandbox cannot read the host's system Git configuration (for
example Homebrew's under `/opt/homebrew/etc`); set `GIT_CONFIG_NOSYSTEM=1` before calling it. Code
that checks owner-private storage up to the filesystem root, or that starts its own supervisor,
fails inside MXC because ancestors such as `/Users` are not readable there. Replace only that helper
outside the decision under test with a plain private directory, and disclose the substitution in
the finding's evidence.

## Role-written artifacts

On Unix set `umask 077` before writing role artifacts, create directories with mode 0700 and files
with mode 0600, including candidates, dispositions and draft proofs. On Windows use owner-private
ACLs consistent with the initialized run. The private outer directory protects nested artifacts,
but it is not permission to export them into shared locations. Never copy secrets into tool notes.

The chosen admission guarantee is outer-directory containment, not automatic permission repair.
An owner-held 0644 file or 0755 nested directory may be admitted inside an owner-private 0700 run
root. Run `omgs artifact-check --run OUTPUT_DIR --path drafts/test` for each role-written file
before handoff. This preflight rejects a shared run root, linked components, hardlinked evidence and
writable leaves. It does not normalize role output modes. Before publication outside the run,
create a separate owner-private destination, copy only reviewed nonsecret content with 0600 files
and 0700
directories (owner-only ACLs on Windows), and check the destination permissions before sharing.
Do not export a permissive nested tree directly. Keep the private run root in place for its entire
lifetime, including archival; moving individual artifacts loses its containment guarantee.

On macOS a sealed trusted launchd anchor must be the only active coalition task
before cleanup can be complete. Survivors are named and killed using PID-version
bound audit tokens, and their presence fails the run. An empty process list is
not evidence of cleanup. Records require `launchd_resource_coalition`; rerun older
marker-sweep records. Unavailable launchd domains or private coalition interfaces
block execution without a fallback. Parent death cancels and cleans the workload;
the next proof or sensor invocation recovers abandoned jobs. Normal success, failure, timeout and
interruption remove and verify removal of the one-shot launchd job.

On macOS launchd starts only the hash-verified private anchor under OMGS_HOME/launchd, with an
unprotected working directory. Workspace, scratch, configuration, environment paths and grants must
be outside TCC protected folders and external/network volumes. Protected source may be staged by
the invoking process; launchd never reads it. Refusal names the path and the fix. No Files and
Folders consent is requested. Records also require launchd_tcc_path_admission.
