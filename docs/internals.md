# OMGS internals and operator reference

Start with the [README](../README.md) for installation and a first review.
This page preserves the detailed execution and operator contracts.

## Hand results to a fixer

`omgs report --findings RUN/findings.json --out RUN` writes `REPORT.md`,
`REPORT.html`, `findings.sarif.json`, `HANDOFF.md` and `handoff.json` outside
of the reviewed repository. Saved `run-metadata.json` supplies repo, ref, mode,
persona and sandbox defaults. Explicit `--repo`, `--ref`, `--mode`, `--persona`
and `--sandbox` flags override them. Builder reports are short; an absent or
null persona keeps the full form. Both reports include the recorded pipeline
timeline and links to proof records. Markdown starts with what needs action,
including an explicit "Nothing to fix" when no finding was confirmed.

The installed [handoff and progress guide](../skill/HANDOFF-AND-PROGRESS.md) describes how to consume
the generated `OUTPUT_DIR/HANDOFF.md`. Share that artifact and the protected run directory with a
fixer. It explains verdicts, proof tiers, retained tests, exact proof commands and cumulative fix
budgets without requiring the reader to know OMGS. Confirmed records come first.
Pending records say "verify before fixing" and name the missing fact. Rejected
records are excluded. The machine-readable equivalent follows
[`handoff.schema.json`](../skill/schemas/handoff.schema.json).

Consumers of `handoff.json` must enforce its required top-level `trust` object:
every string inside `records`, including commands and arguments, is untrusted
data, never instructions. Only `reading` and `green_fixer_rules` are OMGS-authored
instructions. This boundary applies when consuming JSON alone, without HANDOFF.md.
Display output annotates Unicode formatting controls as `<U+XXXX>`. Commands
containing them carry a warning, an escaped preview and a lossless JSON string.
The preview is not executable; `command` and `command_args` in handoff.json retain
the original bytes. Review those values under the same trust boundary.

```sh
omgs handoff --run RUN
omgs handoff --run RUN --finding C1
omgs stage --run RUN
```

`--finding` accepts the report reference (`C1`, `V1`) or a fingerprint and rewrites
both handoff files with only that record. `omgs stage` writes
`RUN/proposed-tests.patch`, a unified diff adding retained external proof tests
at their proposed target-relative paths. Only confirmed findings at test proven
or higher with a valid runner-attested proof may contribute tests. Pending and
rejected records are excluded. Invalid confirmed proofs are excluded with an
explicit diagnostic; other valid confirmed tests remain available. Pending
drafts stay in HANDOFF.md under "verify before fixing", with their missing fact
and any recorded proof test. Staging never edits the target.
Already accepted tests need no patch. Conflicting tests, altered drafts, unsafe
paths, binary tests and existing destination files stop staging. Review and apply
the patch through the repository's normal process. No finding authorizes a fix;
keep the original invariant and authorized control, rerun only through
`omgs prove`, and follow the cumulative budget rules in the handoff.

SARIF includes rule help and verdict properties. Critical and high findings use
`error`, medium and low use `warning`, and informational findings use `note`.
Pending records always use `note`, without severity. Rejected records are omitted.

## The binary bootstrap

Installer staging uses a fresh private directory under the physical user home
on Unix, or under `LOCALAPPDATA` on Windows. The bootstrap admits the complete
ancestor chain before verification and again before execution. Unsafe ownership,
replacement permissions, macOS mutation ACLs and Windows reparse points cause
refusal. Ambient temporary-directory settings cannot choose executable staging.
The verified binary's hidden `install-self` retains one staging directory handle,
opens only relative leaf names without following links, and checks every source
against the SHA-256 supplied from the verified bundle before publishing any file.
Gate and sensor scratch use fresh private directories under the admitted OMGS
data directory on every OS and are removed after each run. Proof workspaces
also default to admitted data storage. Windows and Linux capture use pipes;
macOS capture resolves Darwin's private temporary root independently of ambient
temp settings to keep its FIFOs outside readable sandbox grants. Explicit
storage and install destinations still reject symlink ancestors.

System directories and installed toolchain roots remain readable, including
`~/.cargo/{bin,registry,git}` and `~/.rustup` when present. Caches may contain private
source. Doctor and each proof record disclose the actual roots. There is no total
disk quota. Unix limits each file to 1 GiB; Windows has no per-file limit. Hardlinks
to outside content become readable in the workspace copy; git checkouts cannot
create those links.

On Ubuntu 24.04 and later the kernel restricts unprivileged user namespaces, which MXC's bubblewrap backend needs; `omgs doctor` says so when it applies. Either allow them for bubblewrap with an AppArmor profile, or set `kernel.apparmor_restrict_unprivileged_userns=0` on a machine you use for proofs. On Windows, [upstream MXC issue #1465](https://github.com/microsoft/mxc/issues/1465) reports that toolchains can fail with `STATUS_DLL_INIT_FAILED` over SSH session 0 even when their executable files are readable. This observed upstream limitation can require an existing interactive desktop session; it is not a guaranteed OMGS diagnostic. Windows 11 builds where the capability probe reports `needsDaclAugmentation=false` are supported. OMGS refuses augmentation tiers, including the observed `appcontainer-dacl` tier on windows-2025, because MXC 1.0.1 leaves changed ACEs on granted folders even after a successful run. `prove` and `doctor --live` exit 3 before staging a workload or invoking MXC with a config, including a dry run. OMGS never writes host ACLs. No administrator host preparation or ACL repair is attempted.

On supported Windows tiers, OMGS omits parent directory enumeration when the probe reports no support. Known relative paths can still reach nested workspace files and batch scripts, while directory listing, absolute path resolution and redirection to `NUL` can fail. CMD can print `Access is denied` for `>nul` without changing its prior exit code. Use real handles or files inside the workspace or scratch. `doctor --live` checks a nested workspace file and an outside-file denial, and reports "outside read not proven on this host" when path-resolution failure prevents establishing the denial.

For free-text options (`--cmd`, `--note`, `--answer`, `--detail`, `--log`, `--reason`), the next argument may begin with `--`, for example `omgs prove --cmd "--version"`. A free-text value matching a known option of that command, or starting with its inline assignment form, must use `--opt=value` so it cannot silently swallow another option. `--help`, `-h` and values starting with `--help=` are also refused as the next free-text argument; pass them using `--opt=value`. All value options accept `--opt=value`; use this form for other values beginning with `--`.

Proof is attempted by default for every candidate with a locally reachable
runtime, within the proof budget. The [per-stack recipes](../skill/PROOF-RECIPES.md#proof-by-default-per-stack-recipes)
cover PowerShell, Node, Python isolated mode, shell and Swift, including exact
commands, invariant assertions and blockers. `doctor --live` launches each
runtime's bounded version command (or `sh -c 'exit 0'`) inside MXC before
calling it reachable. The probe uses the same command lookup as proofs,
including the `/usr/bin/swiftc` and `/usr/bin/clang` shims when selected by
the sandbox PATH. On macOS, these compiler probes have a thirty-second
budget for xcrun's first-launch SDK discovery. Other tools retain their
three-second budget. One 180-second wall-clock deadline covers the entire
`doctor --live` operation, starting before executor discovery and preparation,
including staging, policy validation, and all probes. When it expires, OMGS
stops active execution, reports the current and remaining probes as not checked,
and exits nonzero. Bounded executor cleanup and output draining still finish
before exit, so cleanup can extend the elapsed time beyond 180 seconds.
A working direct toolchain binary cannot make a
failing shim pass this check. `TMPDIR` points to per-proof scratch; OMGS
does not grant access to the host user cache for compiler discovery.
Missing tools print `<runtime> not on host PATH`.
Installed tools whose probes fail print
`<runtime> on host PATH but failed to launch inside MXC` and a reason.
Retain those exact lines and the proof startup diagnostic with the pending finding. No installation or
unsandboxed fallback is attempted. Windows gets an explicit safe `PATHEXT`,
scratch `CARGO_HOME`, the existing `RUSTUP_HOME` and `RUSTUP_AUTO_INSTALL=0`.
Host credentials and broad home access stay outside the grants. Linux explicitly
grants read-only `/usr/include` for local compiler headers; MXC does not mount
that system directory by default.

### macOS proof ownership and storage

On macOS every proof and sensor workload runs below a unique one-shot launchd
job. Its trusted anchor is a private copy of this executable, verified by SHA-256.
The job has `KeepAlive=false`, `RunAtLoad=false`, no demand triggers, and starts
only after an explicit kickstart. The parent admits the fresh resource coalition
before permitting target execution through the pinned executor. Existing process
group cleanup, limits and output capture still apply.

After waiting for the executor, the anchor permanently stops spawning. Cleanup
is complete only when coalition `tasks_started - tasks_exited == 1`, meaning
only that sealed anchor remains. Member enumeration locates survivors to record
and kill with PID-version-bound audit tokens. An empty member list is never a
certificate. A fork then exit chain cannot hide behind a later empty scan: its
remaining task keeps the count above one. Unrelated same-user processes and
independent proofs belong to other coalitions and are never counted or signalled.
Observed survivors fail the proof even when cleanup succeeds. Unidentified owned
activity or failure to obtain the certificate also leaves the proof unclean.

The required controls are `launchd_resource_coalition` and
`launchd_tcc_path_admission`. Records missing either control must be rerun. Each invocation checks the private Darwin
interfaces, including a trusted child probe for inheritance, enumeration,
accounting and audit-token signalling, before target execution. A usable
`gui/<uid>` launchd domain is preferred, otherwise `user/<uid>` is attempted.
Unavailable launchd submission or coalition interfaces cause a clear refusal;
there is no sweep or unsandboxed fallback. CI explicitly runs this capability
check on the macOS 15 arm64 runner and fails if the domain is unavailable.

The anchor, job plist and handshake files live in admitted, owner-private
`OMGS_HOME/launchd/<nonce>` storage (default `~/.local/share/omgs`). The binary is
copied and hash-verified by the invoking process before launchd starts it.
Launchd receives an explicit unprotected working directory. The executor,
configuration, workspace, scratch, environment paths and readable grants are
checked before submission. Anonymous capture pipes still use the OS-selected
private Darwin temp directory. Neither private location may overlap a grant.

Launchd processes have their own TCC responsible identity and do not inherit a
terminal's Files and Folders access. OMGS therefore refuses launchd inputs under
Desktop, Documents, Downloads, cloud storage, user Library and media folders,
and removable, external or network volumes, including case aliases and resolved
links. Parent traversal is refused before filesystem inspection. Volume
properties must establish local, internal, non-removable storage. The error names
the path and the fix: move the run or tool, or set `OMGS_HOME` to an unprotected
local directory. A target in a protected location may be copied by the invoking
process into an unprotected workspace; the launchd side never reads that source.
A staging or admission failure blocks execution. OMGS does not request TCC
consent, reset privacy settings or treat an executor access failure as clean.
This avoids Files and Folders prompts even when the executable was built on
Desktop or its ad hoc signing identity changes after a rebuild.

The parent holds a per-job lock. Parent death cancels execution,
and the anchor cleans its coalition before exiting. The next proof or sensor invocation recovers
abandoned jobs before starting work. Normal success, failure, timeout and
interruption remove the launchd job and verify its removal. A killed invocation
cannot produce a final clean record. Recovery errors block the next proof and
retain state for diagnosis. Arbitrary file access by another process as the same
OS user remains outside the local trust boundary described in DECISIONS.md.

## What a proof record does and does not prove

`omgs prove` writes `proofs/<n>.json` itself, beside the findings. Code under test cannot touch it: inside MXC it can write only its workspace copy and scratch. `omgs validate`, `report` and `critic` require a pinned MXC executor, the saved config with the expected containment, wrapped command, workspace and deny network policy, matching regular-file test and redacted-output digests, and a clean run with no surviving processes. Traced findings must omit `proof_ref` and keep their source trace in `evidence`. A `local_app` proof requires Linux bubblewrap containment. Without a declared contract, a non-rejected finding above traced requires an inner exit code of 1 or 3 through 125. A rejected control may also exit 0. Exit 2 is always a usage or harness error and never supports a proof, as are exits 126, 127 and signals. Every recipe must declare `--expect-marker BOUNDARY_ASSERTION_FAILED`: a declared contract requires exit 1, the exact lines `OMGS_BOUNDARY_<nonce>_BOUNDARY_ASSERTION_FAILED` and `OMGS_CONTROL_<nonce>`. The harness reads the fresh run nonce from `OMGS_PROOF_NONCE` and the declared label from `OMGS_PROOF_CONTRACT`. Schema `omgs-proof/3` stores a required `contract` object with `kind: "recipe"`, `expect_marker`, `boundary_marker_seen` and `authorized_control_seen`. Every field is required and non-null. Uncontracted runs explicitly store `{"kind":"none"}`. The saved MXC environment binds the contract and nonce to the config digest and reconstructed saved command; changing or removing the declaration invalidates the record. Both marker flags come from full stdout and stderr before capping and redaction. Validation and CLI support require these flags, even when neither marker fits in the saved output. Replay retains the contract, generates a fresh nonce and compares the marker flags. Fixed or wrong-nonce markers do not satisfy it. Hostile code sharing the harness process can read the nonce and forge the markers, so the independent evaluator stays required.

Every generated policy is checked by the pinned executor with `--dry-run --config` before the workload starts. A completed nonzero dry run exits 3, reports a configuration rejection and runs no target code. Timeout, interruption, executor startup failure, survivors and incomplete capture or cleanup instead report "MXC dry run did not complete" with exit 3. Blocked `doctor --live` runs also exit 3 without a usage hint. The pinned macOS, Linux and Windows executors all support this check. A workload failure after a successful validation remains a workload failure. The dry-run control is required in `enforced` during proof validation. Earlier development records, including older `omgs_version: "0.1.0"` records, may lack this evidence and must be rerun; the unchanged version cannot identify records made before this check. The `notes` list is optional for current-schema records; older schema versions are always rejected.

On Windows, OMGS first calls the pinned `wxc-exec.exe --probe`. Only a supported, consistent tier with `needsDaclAugmentation=false` permits configuration validation and workload execution. An augmentation requirement blocks up front with exit 3, naming the tier, the MXC 1.0.1 ACL issue and support for Windows 11 builds without augmentation. Detector errors retain their text and default missing warnings and probe facts, but cannot establish a safe tier and therefore block. Failure to start the probe, timeout, interruption, nonzero exit without detector-error JSON, malformed data, mixed success/error data and unknown or inconsistent tiers also block. There is no configuration refusal/retry fallback when probe safety is unknown. JSON is parsed from stdout only. OMGS never runs `wxc-host-prep.exe`; administrator preparation does not override this gate.

Windows doctor also reads the full OS build, including the update revision, and compares it with Microsoft's published ProcessContainer minimums. Windows Server 2025 shares build 26100 with Windows 11 24H2; Microsoft publishes no separate Server minimum. A build below the minimum or absent from that table is reported plainly; the capability probe and config validation decide whether a proof can run. The [MXC build reference](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md) supplies these minimums.

With `--finding`, `--test` is required and its full path or file name must be a token of the command. Runner-generated start and end markers contain a fresh random nonce. Both markers must appear for a clean record, even if the saved output is capped. Missing start means executor error unless the executor was killed or the run interrupted. Missing end means incomplete execution; timeout, signal death and executor errors are recorded separately. On macOS and Linux, SIGINT, SIGTERM and SIGHUP during copy, hashing or staging remove the proof directory and release a charged reservation. Once execution begins, those signals trigger process group cleanup, plus coalition cleanup on macOS and PID namespace teardown on Linux, before an interrupted run is recorded as unclean and keeps its budget charge. Before running the command, the wrapper checks that the named test is a file it can read inside the sandbox and records `test_reachable`. An unreachable test stops execution with exit 126. Missing or false reachability evidence cannot support any proven verdict, including a rejected finding backed by a passing control. This checks readability, not that the command executed the intended assertion. The recorded exit code comes from the end marker. The markers catch accidents such as executor failure, truncation and timeout. They do not establish integrity against a hostile target: the nonce is visible to sandboxed code, so the target can print a forged end marker. Replay and the independent evaluator provide the stronger check that the real target and intended assertion ran. The independent evaluator must check that the command exercised the real target and the intended assertion. Records from `omgs-proof/1`, including records written before `RUSTUP_AUTO_INSTALL=0` became part of the execution policy, predate the current policy and must be rerun with `omgs prove`. Validation and replay reject them with a rerun diagnostic. There is no format migration or compatibility allowlist.

These checks catch mistakes and hand-edited records. They do not defend against a program running as you that sets out to forge every file, because nothing on your own machine can. The defence is that every proof is reproducible: anyone can rerun a record with `omgs prove --run <run-dir> --replay <n>`, and the independent evaluator stage does exactly that before a verdict stands. Replay requires the recorded `timeout_ms` and rejects `--timeout-ms` overrides, consumes one proof-run budget unit, checks the marker-derived inner exit code and cleanliness, and refuses if either the target commit or the versioned execution input identity (including dirty changes, config, hooks, and meaningful Git index state) differs from the original snapshot. In the same way, `omgs approve` records your consent to tier 2; it is not a lock an agent could not pick, and the app under test stays inside MXC either way.

The [proof contract](../skill/PROOF-CONTRACT.md) specifies execution input version 4, fresh sorted workspace materialization, exact Unix link text, Windows target-link rejection, deterministic workspace access/write timestamps (plus creation timestamps where supported), allow-listed index extensions, normalized index stat/cache fields, exact multi-file harness retention and bounded marker observations with redaction and truncation ranges. A target's retained `input-manifest.json` supplies per-path mismatch diagnostics. Root Git metadata is always included in a scoped selection. Old proof schemas and unsupported identity versions require a fresh proof. Each execution gets a fresh workspace; there is no mutable snapshot cache.

Selected input components must match enumerated directory-entry names exactly, including case and Unicode normalization bytes. A successful alias lookup cannot admit a different spelling. Admission and the completed workspace both require every selected path exactly once, including automatically included root `.git`. Copy traversal uses the manifest's sorted batches of at most 256 names per active directory level. Every sibling counts toward the 2,000,000 traversal budget before selection filtering, and each rescan checks the directory entry limit before retaining another name. Special-file and live-link diagnostics retain only 20 sorted paths plus aggregate counts. Harness enumeration stops at child 257 before inspecting child contents.

Before copying, staging streams the source identity without retaining entries or a serialized manifest. After copying it computes the staged identity and streams the source identity again. The pre-copy source, post-copy source and staged identities must all match before target execution. Divergence or failure to recheck the source refuses execution with `target changed during staging` and emits no proof record. This applies to fresh proofs and replay. It detects changed or mixed inputs without claiming an atomic filesystem snapshot; a writer restoring prior content between observations is outside this comparison guarantee. There is no retry.

Workspace directories and regular files are created afresh, with dense file writes and independent files for source hard links. Only Unix 0777 permission bits or the Windows read-only bit survive; setuid, setgid, sticky bits, source ownership, xattrs, ACLs, flags, sparse holes and insertion order do not. The root has fixed permissions (0755 on Unix, writable on Windows). Fresh objects use the staging user's ownership and destination security defaults. Windows staging and validation both reject all target links and reparse points, including dangling links, rather than converting them to files or junctions. Unix links retain exact text with fixed 0777 link permissions, including macOS where symlink creation otherwise applies umask. Scratch cache links use the same fixed mode. Existing sandbox access rules still apply. OS-assigned ctime, inode numbers and filesystem-specific enumeration or allocation details remain nondeterministic execution properties. Code observing those values can produce replay mismatches when the harness detects a changed outcome; unobserved differences cannot be certified by replay.

Run directories can be moved or archived without rewriting the saved config. Validation checks workspace, scratch and marker grants against the original `proof_dir` recorded beside the config, requiring its `proofs/<n>` layout, then verifies the readable roots granted at proof time and exact reconstructed environment entries. Validation is independent of the current HOME. Unknown saved-config keys are rejected. If the original target still exists, validation also checks the current in-target test digest and reports a changed or unreadable test. Replay still requires the original target and an unchanged target snapshot.


Commands and survivor command lines in proof records are redacted before writing. Credential flags mask their complete next token or inline `=value`, including quoted values with spaces; attached short flags such as `-pVALUE` are outside this redaction scope. `command_sha256` and `wrapped_command_sha256` bind the exact replay command and saved config. The runner keeps exact input in `proofs/<n>/command.txt` for replay; this file and the saved config can contain credentials, so protect the entire run directory. On Unix, proof directories are 0700 and command and config files are 0600. Small trust files (approvals, records, configs and answer stores) use bounded, single-link, no-follow reads. Approval stores are limited to 1 MiB. Answer stores and run-local answer snapshots enforce a 1 MiB limit on reads and writes. Executor, proof-test and snapshot content hashes accept hardlinks and symlinks resolving to regular files, with symlink targets disclosed. Execution input manifests are bounded at 2,000,000 entries and 12,800,065,536 serialized bytes, with optional dependency selections; the Unix 1 GiB per-file limit applies only to sandboxed processes. Target FIFOs and sockets are skipped in the workspace copy and snapshot digest, with up to 20 sorted paths recorded as proof gaps and one aggregate count for the remainder. Devices are refused before copying. On Unix, both copy paths preserve symlinks as links; outside or unresolved links are disclosed as a counted proof gap. Copied links that still reach the live target, including absolute links and relative links that leave and re-enter it, have separate path gaps, sorted and capped at 20 paths followed by a count, and remain subject to sandbox access rules. Directory harness files use their recorded modes. Single-file drafts always stage as 0755 on Unix or writable on Windows; retained draft mode changes cannot affect execution. New harness ancestors, empty workspace roots and scratch directories explicitly use 0755 on Unix or writable on Windows, independent of umask. Existing target ancestors keep their identity-bound modes. The empty macOS OpenSSL config and Windows marker wrapper are fresh dense files with fixed 0644 or Windows writable permissions; wrapper content binds the command, test path and fresh nonce. Index normalization occurs during create-new staging, preserving identity-bound modes such as 0664 without private-storage admission. Manifest construction is read-only. Index input is independently capped at 16 MiB. Backslashes and colons in target names are refused before copying with the canonical relative path error, including on Unix. Version 4 manifests use canonical JSON Lines: a version/count/selection header followed by depth-first, UTF-8 component-sorted entry objects, each terminated by LF. The digest covers exactly the written bytes. Generation counts paths, then streams entries without a full collection or serialized buffer. Directory sorting retains batches of at most 256 children per active level and rescans wide directories; the 1024-byte path limit bounds depth. Entry admission checks the 2,000,000 maximum before constructing each entry. Private atomic publication uses a sibling temporary file, flush, fsync and rename before sandbox execution, and computes the identity over exactly the bytes written, refusing a changed entry count. Republishing an existing descriptor also checks its digest. Replay selection is in the proof record. Validation and replay recompute the current workspace identity without parsing retained manifests. Only mismatch diagnostics read retained JSON Lines through private, single-link, no-follow admission, with a 1 MiB header bound, 6,400-byte entry-line bound, strict fields and duplicate-key rejection, validated paths/kinds/modes/hashes/order, and running entry limits checked before the next entry allocation. Diagnostics stop at the first divergence and name at most two paths; malformed diagnostics never permit execution. The serialized cap remains 6,400 bytes per maximum entry plus 65,536 bytes overhead. Version 3 identities require a fresh proof.

Staging write policy (all permission setters fail closed):

| Write site | Deterministic materialization |
| --- | --- |
| `copy_tree_with_gaps`, `copy_selected` | Workspace root explicitly 0755 or Windows writable before traversal and after copying. |
| `copy_recursive` | Fresh directories temporarily use the fixed directory mode, then receive the manifest-bound source mode after children. Regular files go through `stage_file`. |
| `stage_file`, `stage_content` | Fresh exclusive files, dense byte writes, explicit final 0777-masked Unix mode or Windows read-only bit. Target modes and directory harness modes are identity-bound. |
| `stage_content` missing ancestors | Each new ancestor explicitly 0755 or Windows writable; existing ancestors are neither replaced nor chmodded. |
| `create_staging_link`, `copy_link` | Exact target link text, fixed 0777 Unix link mode. macOS uses no-follow `lchmod`; Linux creates links as 0777. Windows target links are rejected. |
| `copy_recursive` Git index normalization | Normalized identity-bound bytes, fresh create-new file with explicit manifest-bound permissions during staging. |
| `stage_workspace` single-file draft | Admitted retained bytes, fixed 0755 or Windows writable, ignoring retained permissions. |
| `stage_workspace` empty root and scratch setup | Fresh root, scratch, cache, clang-cache and cargo-home directories explicitly 0755 or Windows writable. Empty OpenSSL config uses 0644 or Windows writable. |
| `link_dir` scratch cache links | Selected readable cache root, fixed 0777 Unix links or explicit writable Windows junction directory before reparse setup. |
| `write_wrapper` | Fresh exclusive Windows wrapper with writable mode, command/test/nonce-derived name and content. No wrapper file on Unix. |
| `normalize_timestamps` | Workspace entries normalized in postorder to 2000-01-01 UTC without following links, including creation time where supported. |

The private run directory, copied executor and saved config sit outside both workload write roots.
They are control artifacts, not target or harness entries. The executor is copied and hash-checked
against the pinned binary, then forced to 0700 on Unix. Private run/config storage uses the separate
owner-private artifact policy; it is never copied into the workspace.

## Optional local sensors

`audit init` and `check` look for installed sensors on PATH (PATH plus native
PATHEXT extensions on Windows). They read source and dependency files as data,
never run target builds, tests or package scripts, and install nothing.
`audit init --no-sensors` skips them.

All sensor scanners run inside the same SHA-256 pinned Microsoft MXC executors
as `omgs prove`. Missing MXC, rejected preflight and Windows tiers requiring
DACL augmentation are explicit gaps. There is no unsandboxed fallback. MXC
denies external network egress, inbound connections and host loopback on every
supported OS. Offline flags do not substitute for this enforcement.

- Gitleaks detects credentials without git history. OMGS supplies its own
  default-rule config and disables inline allow comments.
- Semgrep requires an existing local `OMGS_SEMGREP_CONFIG` rules file or
  directory. Registry shorthand and `OMGS_SEMGREP_ALLOW_REGISTRY` no longer
  enable fetching. Download rules separately before scanning. The disposable
  copy removes every `.semgrepignore`, and `--no-git-ignore --disable-nosem`
  disables repository ignores and inline `nosemgrep` comments. Scanner defaults
  may still skip unsupported inputs; reported skips remain gaps. Inside MXC,
  Semgrep can read its whole site-packages directory, including unrelated
  packages and anything stored there; install it in a dedicated virtual
  environment.
- TruffleHog uses `--no-verification --no-update --json --no-ignore-tag`.
  It cannot verify a secret online, update itself or honor inline ignore tags.
- OSV-Scanner uses `--offline-vulnerabilities --offline --no-call-analysis
  --no-resolve --no-ignore` and an OMGS-owned empty `--config`. Repository
  `osv-scanner.toml` overrides and `.gitignore` cannot suppress results. Set
  `OMGS_OSV_DB` to an existing cache root with
  `osv-scanner/<ecosystem>/all.zip`; the default is `<OMGS data dir>/osv-db`.
  Missing or corrupt databases remain gaps. No dependency resolution, target
  builds, tests or package scripts are requested.

OSV database downloads remain a separate explicit network opt-in. The download
runs outside MXC only because it is a network fetch the user has opted into.
After approving that network access, run the following command
with your already installed OSV-Scanner outside an OMGS audit. Replace CACHE
with an absolute cache directory and TARGET with the local repository:

```sh
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=CACHE osv-scanner scan source --offline-vulnerabilities --download-offline-databases --no-call-analysis --no-resolve TARGET
```

PowerShell: set `$env:OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY = 'CACHE'`, then run
the same `osv-scanner` command. Set `OMGS_OSV_DB` to CACHE for the subsequent
audit. OMGS never runs this download command automatically. See the upstream
[OSV offline database documentation](https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md)
for manual ecosystem archive downloads and cache layout.

Every scanner gets a bounded read-only workspace copy, read-only installed
binary/runtime roots, read-only rules/database and a private writable scratch
home/cache outside permanent run artifacts. Native scanners receive only an
executable-file grant. Python entry points also receive narrow installation/runtime
prefixes. Grants exposing the whole HOME or
user profile, or overlapping the original target or artifacts, are refused.
Scratch is checked against the target, artifacts and all grants before creation.
The original target is not mounted.
The disposable tree, including raw scanner temp files, is removed after
supervised cleanup on success, failure, interruption and timeout. Cleanup failure
is a gap. OMGS does not retain raw stdout, stderr or diagnostics. It preserves
only metadata and generic gap reasons. Custom seccomp and sandbox-exec sensor
paths have been removed in favor of MXC.

Input is bounded to 16 MiB per file, 64 MiB total, 100,000 enumerated entries, 10,000 staged files
and 64 directory levels per scanner; links, special files, unreadable files and entries exceeding
these bounds are skipped with an explicit gap. Up to 128 per path skip records per scanner
retain paths of at most 1024 characters and reasons, with omitted record counts. A skipped directory describes an unenumerated
subtree, never a count of all its files. Copied files are read with no-follow bounded reads. Runtime
and database installations are operator-supplied readable inputs, not part of
this source byte budget. They can affect parser memory usage. No total process
memory cap is claimed on macOS or Windows. Semgrep additionally uses
`--max-target-bytes=1000000 --max-memory=512 --jobs=1`; its reported skipped
inputs and diagnostics become gaps. OMGS independently counts copied files above
the 1,000,000 byte target limit, even when quiet output omits skipped paths.

Scanners have a 120 second MXC deadline, supervised teardown (up to 15 seconds
extra on Unix) and a 4 MiB combined output cap. Unix adds CPU, file size and open
file limits. Linux requests a 2 GiB cgroup memory limit and 128 tasks through an
available systemd user scope. If unavailable, OMGS records the same gap as
`prove`. Sensors follow the same per-OS enforced set as `prove`: macOS and
Windows have no memory/task cap by design. Oversized output, malformed JSON,
missing metadata, unexpected exit codes, reported omissions and incomplete cleanup are
explicit gaps. No sensor is a successful zero-hit scan merely because it failed.

`sensors.json` records successful tools, unavailable tools, gaps and redacted
hits; `sensor-hits.json` lists the same hits separately. Each hit keeps the tool,
detector or advisory ID, relative file, line when supplied, shared path class and
a SHA-256 fingerprint of that metadata plus a per run keyed occurrence identity for
non-package hits, keeping distinct matches separate without storing match text. OSV hits also
retain package name, version and ecosystem in JSON, fingerprints and reports, so distinct affected versions
require separate ledger resolutions. Raw secrets and scanner output are never
saved by the sensors. Both reports list hits from every class and all gaps.
Each code hit seeds a `sensor:<tool>:<fingerprint>` candidate ledger unit. Hunt it
with `covered` and evidence, or resolve it with a reason using `deferred`,
`blocked` or `out_of_scope`. The critic rejects unresolved or missing hit units.
Non-code hits remain visible and require the existing exclusion group review.
Old sensor artifacts without class/fingerprint metadata or OSV package identity
must be regenerated.

## Persona defaults and accounting

`omgs audit init --target <repo> --persona builder|inheritor|team` records the persona and selects presentation and spending defaults. Builder uses concise coverage detail and a budget of 24 calls/proofs, inheritor uses full detail and 64, and team uses full detail and 96. Without a committed base policy, every persona defaults to advisory and explicit `--mode` and `--budget` override the defaults. Without `--persona`, the existing budget behavior is unchanged. A committed base policy takes precedence and conflicting overrides fail before run creation. Proof rules, verdict semantics and the evidence required to confirm a finding are identical.

Inventory uses a heuristic path classifier for stack detection, first-party size statistics and hunting priority only. Code is the default, including unknown formats, SQL, HTML and templates. JSON, JSONL, NDJSON, CSV and TSV files of at least 1 MiB are prioritized as data, even though they may contain interpreted logic or renamed scripts. Documentation uses md, rst and adoc extensions or conventional notices. Only conventional notices such as README.txt, LICENSE.txt, NOTICE.txt, CHANGES.txt, AUTHORS.txt, CONTRIBUTING.txt and COPYING.txt classify as docs by the txt suffix; other txt files default to code. Conventional executable and build names (including CMakeLists.txt, Makefile, GNUmakefile, Dockerfile, Containerfile, Justfile, Rakefile, Gemfile, Gradle and CMake scripts, Jenkinsfile, Vagrantfile, BUILD, BUILD.bazel, WORKSPACE and meson.build) take precedence over docs/data rules. `requirements*.txt` is dependency configuration and classifies as code. Inventory-root test/spec and dependency containers and conventional test suffixes set test or vendored priority; nested directory hints and minified names alone cannot exclude a file. Recognized asset
extensions such as png, woff and pdf classify as assets and require exclusion review.

Classification never removes accountability. Every nonempty test, docs, data, assets or vendored class gets a `planned` coverage unit with its total count and first 20 sorted paths across all files, plus supplemental source counts and paths. A hunter must skim or sample each group, then either hunt (`covered` with evidence) or explicitly resolve it as `out_of_scope` with `reviewed, not security relevant: <reason>`. The disposition must cite at least one sampled path in its evidence. The reason must explain the review, not repeat the classifier label. Planned, candidate, blocked and deferred exclusions fail the critic. Ledger output and both reports show review reasons. Shell scripts and browser extensions with a valid manifest version are detected alongside existing stacks. Nested project markers produce separate subproject roots in run metadata, coverage units and the architecture seed.

Supply host usage cumulatively per role with `--accounting ROLE=TOKENS,COST_USD,DURATION_MS` on status or report. The roles are `red-hunter`, `blue-verifier`, `evaluator` and `green-fixer`. Repeat the option for multiple roles. For example:

```sh
omgs status --run <run-dir> --stage hunt --state done --accounting red-hunter=12000,0.32,45000
omgs report --findings <run-dir>/findings.json --out <run-dir> --accounting blue-verifier=8000,unknown,30000
```

Each supplied entry replaces that role's cumulative totals. Empty fields or `unknown` mean unavailable. Missing usage round-trips as JSON null and renders as `unknown`, including roles that have not run. Explicit zero means a measured zero. Reports reuse saved status accounting.

`omgs budget --run <run-dir>` reports the shared cumulative calls/proofs and remaining allowance. Start each fix run with `omgs audit init --target <repo> --out <fix-run-dir> --no-sensors --fix-of <original-run-dir>` to register it and compute its cap. Each run records only its own spending; never fold fix usage into the original counters. Multiple fix rounds share the original cap. Exhaustion returns zero, an uncapped original returns null, and invalid links or counter overflow are errors. Fix runs must be direct siblings of the original in its trusted runs directory. Linked metadata records each run's random identity and the parent's identity, and accounting and charging verify these identities with no-follow reads. Symlinked runs, symlinked metadata and Windows reparse points are refused, as are links outside that directory. Old linked registrations lacking identities fail closed; start a new review family rather than guessing identity. Unidentified standalone legacy runs remain chargeable, but cannot start a linked fix family.

### Storage migration

Upgrade existing runs with care: older runs with automatic vendor exclusions now fail the critic. Re-review those exclusions and explicitly resolve them with review evidence and a reason, or start a fresh run. Never prepend `reviewed, not security relevant:` automatically to a legacy note.

Budget guarantees require owner-private run storage that cannot change concurrently. The runs directory and every run directory must be owned by the current user, with mode 0700 on Unix and a Windows DACL whose write grants name only that user, SYSTEM, BUILTIN\Administrators or CREATOR OWNER (mapping to that user). This allowlist covers effective and inheritable grants, including files-only and inherit-only grants, and existing metadata and lock files. Existing profile subfolders carrying write grants for other principals are refused, even under a restrictive parent. Start fresh in a new private runs directory or secure the existing subfolders, metadata and lock files before reusing them. On Unix, existing storage directories must have mode 0700; metadata and lock files must be owned by the current user and must not be group- or world-writable. On macOS, extended ACL allow entries granting mutation rights to any principal other than the owner are refused, including inherited and inherit-only entries. Deny entries such as `everyone deny delete` and allow entries for the owner are admitted. New storage directories have their inherited macOS ACLs cleared immediately after exclusive creation, before creating children or publishing metadata. Existing directories and files are never repaired automatically. Refusals name the path and offending ACL entry or ownership and mode. Move to fresh private storage or have the owner review and secure the named object before retrying. OMGS checks every ancestor through the filesystem root, including ancestors above HOME or USERPROFILE. On Unix, each ancestor must be owned by the current user or root and must not be group- or world-writable, except for sticky ancestors whose checked child is owned by the user or root. The publication or run directory itself never gets the sticky exception. Symlink and reparse ancestors are refused; use the physical path (for example `/private/tmp` rather than `/tmp` on macOS). On Windows, ancestors may also be owned by TrustedInstaller, SYSTEM or Administrators. Inherit-only ancestor ACEs are ignored; effective rights to delete children, delete the ancestor, change its DACL or owner, or write its attributes are refused for untrusted principals. Creating new entries on an ancestor alone is allowed. Run and publication directories and leaf files retain the strict allowlist above. Do not rename or replace storage during a run. Sandboxed target code cannot write there. Metadata reads refuse links, but atomic publications use paths rather than retaining directory handles across validation and write.

Inventory refuses symlink and reparse traversal and stops below depth 12. Skipped links, depth truncation, directory/entry read failures and the file limit produce blocked inventory units, architecture gaps and report coverage notes. Each records a reason, an omitted entry/subtree event count (not a file total) and at most 20 sorted path samples. Resolve every inventory gap explicitly before the critic can pass.

Role contracts live under `skill/agents/`: red-hunter, blue-verifier, evaluator and green-fixer. The host passes each brief verbatim with its scope. The identity-binding and fail-closed-semantics packs add reusable intent questions and minimal proof shapes.

## Committed policy and gate

Commit `.omgs/policy.json` under normal owner review, using the strict
[policy schema](../skill/schemas/policy.schema.json). Every field below is required,
including explicit nulls. Unknown fields, duplicate JSON keys, missing fields,
invalid intent IDs and duplicate intent/suppression identities are errors.

```json
{
  "schema": "omgs-policy/1",
  "mode": "advisory",
  "persona": null,
  "budget": null,
  "severity_threshold": "high",
  "excluded_paths": [],
  "accepted_intent": [],
  "suppressions": [],
  "gate_tests": []
}
```

These are also the defaults when no base policy exists. Null persona keeps full
report depth and no persona selection; null budget is unbounded. An integer
budget caps combined calls and proofs. Set persona to `builder`, `inheritor` or
`team` for its presentation profile; committed budget remains explicit.
Thresholds are `informational`, `low`, `medium`, `high`, `critical` in ascending
order. Use `mode: "gate"` to enable blocking.

```sh
omgs audit init --target /path/to/repo --base origin/main --out /private/run --no-sensors
omgs gate --target /path/to/repo --base "$BASE_SHA" --head "$HEAD_SHA" --run /private/run
omgs intent propose --run /private/run
```

`--base` must resolve to a locally present commit. Initialization reads only that
commit's `.omgs/policy.json`, never HEAD's policy or the working tree. Omit
`--base` for an explicit local run using defaults and optional CLI overrides.
A missing blob uses the defaults; a bad ref or malformed committed blob is an
error. The resolved commit, source, exact blob, parsed policy and SHA-256 are
saved in `run-metadata.json` under `policy` for review. The CLI also records the
full base SHA and policy blob digest beside the reviewer's intent store, outside
the run and target, bound to their canonical paths, a fresh run generation and
the physical directory identity. Records are exclusive and never replaced;
reinitializing a retired output path requires a new path. Store directories and
opened records undergo owner-private admission on every platform. Reports, fix
runs and policy proposals reload policy using this trusted record. Edited snapshots warn and are
ignored. No-base CLI settings are retained in the trusted record for inheritance.
Gate independently reads its explicit immutable base from Git at invocation
time. Conflicting mode, persona or budget flags cannot override committed policy.
Fix runs inherit authenticated policy and spend only the computed remaining
budget, bounded by the original run's authenticated cap rather than edited
metadata. Older or moved runs without trusted provenance require a fresh audit;
see [policy provenance](../docs/policy-workflow.md#reviewer-owned-policy-provenance).

The object reader executes the following commands with a cleared environment,
retaining only PATH and platform runtime variables. Each invocation is prefixed
with `git --no-pager --no-replace-objects -c core.fsmonitor=false -c core.hooksPath=/dev/null -c diff.external= -c core.attributesFile=/dev/null -c protocol.allow=never`:

```text
rev-parse --verify --end-of-options <ref>^{commit}
ls-tree -z <resolved-commit> -- .omgs/policy.json
cat-file blob <blob-object-id>
```

`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` (`NUL` on Windows),
`GIT_NO_REPLACE_OBJECTS=1`, `GIT_NO_LAZY_FETCH=1` and
`GIT_TERMINAL_PROMPT=0` are set. Git environment redirections and config injection
are removed. These built-ins read objects without hooks, fsmonitor, checkout,
filters, external diff or textconv. Transport is disabled, symlink/tree policy
entries are rejected. Policy is bounded to 1 MiB, Git output to 64 MiB per call,
and each Git child has a three-second deadline with process cleanup. Local
`include` and `includeIf` sections are rejected before Git opens them, including
FIFO includes. Redirected `.git` files, linked Git directories and common-dir
redirection are rejected; use a standalone checkout. Explicit Git directory and
worktree arguments override local worktree redirection. Missing objects fail locally.

Excluded paths are literal relative file or directory prefixes using `/`, with
no leading slash, trailing slash, traversal or backslash. They do not hide files
from inventory. Each prefix creates a `planned` ledger unit with the matching
count and first 20 sorted paths, including source counts and samples. Review it
with evidence before exclusion, just like automatic inventory exclusions. Path
exclusion does not suppress a confirmed finding.

Accepted intent entries contain `id`, `answer`, `scope` (`repo` or a relative path
prefix) and `source`. They seed run intent answers from the trusted base. Record
new owner answers with `omgs intent answer`; `omgs intent propose --run <dir>`
merges the reviewer's stored answers into the base policy and writes
`<run>/policy.patch`, a unified diff for owner review. It never edits the target.
Review and apply the patch separately, then commit it for future runs. A policy
proposal has no effect on the current gate.

Suppressions require a finding `fingerprint`, a nonempty `reason` and
`expires_unix` as UTC Unix seconds through year 9999. Missing, null and out-of-range
expiries are invalid. Expiry cannot be more than 365 days after the commit that
last changed policy, so unrelated commits cannot extend it. Expired suppressions
do not apply. Only the base policy supplies suppressions.

`gate_tests` is the owner-reviewed registry. Each entry specifies `id`, committed
`test` path, exact `command`, `expect_marker` (the `prove --expect-marker` recipe
contract), `severity`, `timeout_ms`, and optional originating `fingerprint`.
`omgs intent propose` and `omgs stage --run <dir>` add validated test-proven
findings and their tests to a reviewable patch. Review the command, contract and
test together. Applying a patch requires normal owner review before a future
base commit can authorize the test.

```json
{
  "id": "tenant-boundary",
  "test": "tests/security/tenant.sh",
  "command": "sh tests/security/tenant.sh",
  "expect_marker": "TENANT_BOUNDARY",
  "severity": "high",
  "timeout_ms": 10000
}
```

`omgs gate --target <checkout> --base <base-sha> --head <head-sha> [--run <dir>]`
requires full immutable SHAs and checks the checkout's HEAD with safe Git reads.
It exports committed head files into a fresh temporary checkout, ignoring dirty
and untracked files. Registered tests at or above threshold that are not
suppressed execute through the same MXC machinery as `omgs prove`, each with a
fresh nonce. Exit 1 requires exit 1 plus both nonce-qualified boundary and control
markers. Exit 0 means every active test passed (exit 0), or no tests were active.
Invalid policy, missing tests, contract errors, unclean runs, unavailable MXC and
head mismatch return 3. Gate currently requires regular committed files and
refuses symlinks and submodules in the exported tree. Each blob is limited to
64 MiB. Dependencies must already be part of the committed tree or available in
the existing sandbox toolchain; gate installs nothing. The gate runs head content.
Owners should protect registered test paths with CODEOWNERS or branch protection.
Modified or deleted active tests print `registered gate test modified in head`
in both modes; modifications retain the normal result.

Once valid base policy establishes advisory mode, execution and infrastructure
results are display-only and exit 0. Invalid base policy still returns 3 because
it cannot establish advisory mode. Optional `--run` prints confirmed findings not
yet registered as gate tests. Missing, corrupt or edited run artifacts never
change the result. Only owner-authorized deterministic tests can block. See the
[GitHub workflow example](../docs/policy-workflow.md).

## Setup wizard and scripts

`omgs setup` at a terminal offers skill installation into detected agent roots,
a live MXC deny test and an optional repository policy with gate or advisory
mode. It installs the pack as `omgs-security-review`, the same name used by the
Skills CLI. It detects existing `.claude`, `.codex`, `.agents`, `.cursor`,
`.gemini`, `.copilot`, `.config/opencode` and `.codeium/windsurf` directories in
your home. It leaves absent roots alone. No agent or tool is downloaded.

```sh
omgs setup --dry-run
omgs setup --yes --from /path/to/skill
omgs setup --install-skills --from /path/to/skill
omgs setup --verify-mxc
omgs setup --write-policy /path/to/repo --mode advisory
omgs setup --install-skills --verify-mxc --write-policy /path/to/repo --mode gate
```

`--yes` installs skills and runs `doctor --live` without prompts. Explicit step
flags perform only the selected steps without prompts. `--dry-run` performs no
writes or live test and lists only detected destinations. Noninteractive setup
without step flags or `--yes` is also a dry run. The live test has the same
fail-closed exit behavior as `doctor --live`, including exit 3 when MXC cannot
establish its controls. Policy creation requires `--write-policy` or an explicit
wizard repository choice, and refuses to overwrite existing policy even with
`--yes`. The complete skill pack is embedded in the release binary, so bootstrap
checksum verification covers it and setup works from any working directory.
`--from` explicitly selects a local source instead. Identical installs are
no-ops. Differing content is refused with the file names. `--replace` stages a
complete sibling tree, renames the old tree to a printed backup path, then
publishes the replacement. A failed publish restores the backup without mixing
trees; retain backups until you are satisfied with the install.

### Gate and sensor scratch limits and recovery

Disposable gate and sensor data uses admitted OMGS data storage, never an
arbitrary temporary directory. Immediate cleanup removes it on completion,
errors and handled interruption, including SIGINT or SIGTERM during HEAD
export. Crash recovery runs on the next gate, sensor or doctor invocation.
Recovery checks private ownership, safe paths, a name and directory identity
record, the expected layout and a free per-run OS lock before removing an
orphan. Admission, locking and recursive removal retain the parent and root
handles. Unix deletion uses relative opens and unlink operations without following
links. Windows opens relative to retained handles, denies delete sharing and
deletes by handle. Active runs stay intact. Invalid, foreign and legacy directories are
left alone and reported for manual inspection. Links are never followed.

Gate export defaults to `GATE_EXPORT_BYTES` (4 GiB expanded content) and
`GATE_EXPORT_ENTRIES` (200,000 files and distinct directories) caps. Repeated
paths referencing one blob each consume their full expanded size. Both caps
are checked before materializing files. Exceeding either cap blocks gate mode
with exit 3 and a cap diagnostic; advisory mode remains display-only. Existing
Git reads also have a 64 MiB per-object or tree-listing bound.

For a large repository, the owner can commit an optional `gate_limits` object in
`.omgs/policy.json`, for example `"gate_limits": {"bytes": 8589934592, "entries": 400000}`
for 8 GiB and 400,000 entries. Both positive integer fields are required when the
object is present. The hard maxima are 64 GiB (68,719,476,736 bytes) and 2,000,000
entries. Existing policies without this object retain the defaults. Only the
immutable base commit supplies these settings; a head-only policy edit cannot
raise its own caps. Merge the owner-reviewed policy change into the base before
retrying a larger export. The per-object Git read bound still applies. The execution identity uses the same hard entry maximum,
with a serialized bound of 12,800,065,536 bytes so the proof stage does not impose
a smaller entry cap on accepted gate exports. Gate has no `--inputs-from` option.

Writable sensor scratch has `SENSOR_WRITE_BYTES` (1 GiB) and
`SENSOR_WRITE_ENTRIES` (100,000) caps, with a 64-level traversal limit. The
per-file supervisor limit is retained where supported and clamped to 1 GiB.
MXC exposes no portable disk quota, so OMGS checks usage every 100 ms and after
supervision. The first observed overrun or failed inspection requests the existing
graceful then forced workload and descendant shutdown. OMGS verifies cleanup,
discards output and records a gap. Diagnostics identify the byte limit, entry
limit or unavailable inspection, include the configured limits and suggest a
recovery step. Windows accounting includes named streams on files, directories
and the traversal root. Polling permits overshoot and can miss files created and deleted
between samples. Recovery removes eligible abandoned payloads on the next
invocation; these limits do not cap aggregate storage across concurrent runs.

## Field review controls

`omgs review --repo-url https://github.com/example/project --persona inheritor
--clone-root /private/campaign/clones --out /private/campaign/run` clones and initializes directly.
Batch initialization accepts the same persona and clone root; its `--out` is the batch run root.
Neither flag relocates intent answers, routing configuration, scratch or offline databases.
Inspect `omgs <command> --help` for command-specific defaults and exit semantics.

Charge host calls before dispatch with `omgs budget --run RUN --charge-calls N`. Proofs charge
themselves; reports, handoffs and batch indexes include cumulative spend and remaining allowance.
Record a refusal or provider block with `omgs route --run RUN --role verifier --refused NAME
--reason "provider block: reason"`, even with no models.json. Exit 1 records a blocker without
selecting a fallback. Known identities can be supplied using repeatable report `--model role=name`.

Validate candidates, dispositions and evaluator handoffs through the corresponding `omgs validate`
flags. `omgs ledger ingest --ledger RUN/coverage-ledger.json --dispositions FILE` applies a complete
validated hunter handoff atomically. The critic checks independent evaluator verdicts for finalized
records and attested reproduced replays for upheld proofs. Reports disclose evaluator decisions,
gaps, blockers, architecture omissions and sensor limits. See the
[proof contract](../skill/PROOF-CONTRACT.md) for outer exit 0 (clean success), 1 (supported assertion),
2 (harness/execution error), 3 (unavailable tier 2), and replay's separate 0 (reproduced) convention.
A proof tier measures behavior, not confirmation; pending records can have proven behavior while
intent remains unresolved. Zero sensor hits never establish safety. Gitleaks includes an Azure
Functions URL-key rule; unknown formats can still be missed and no live credential is tested.
## Routing without configuration

Without `models.json`, `route` returns `host-default` and keeps the host's current
selection. A refusal with no configured fallback records a blocker. An explicitly
requested missing or malformed `--models` file remains an error.
