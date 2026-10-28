<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/omgs-pipeline-dark.svg">
  <img alt="OMGS pipeline: red hunters find candidates in isolation, an independent blue verifier makes survivors earn sandbox proof, a separate evaluator adjudicates every verdict, and green turns confirmed findings into fix briefs and regression tests" src="docs/omgs-pipeline-light.svg" width="820">
</picture>

# Oh My God Security

**Red hunts. Blue verifies. Green guards.**

[![License](https://img.shields.io/badge/License-Apache_2.0-2f6fe8)](LICENSE) &nbsp; ![Status](https://img.shields.io/badge/status-early_v0-f59e0b) &nbsp; ![Platforms](https://img.shields.io/badge/platforms-macOS,_Linux,_Windows-6b7280)

</div>

OMGS is an open source security review suite for codebases built with AI coding agents. Your agent hunts for real trust boundary violations, a fresh verifier tries to disprove every candidate, a separate evaluator adjudicates each verdict, and surviving findings must earn proof: a failing test, or a locally built copy of the app exercised inside an OS enforced sandbox. What remains becomes regression tests in your repo, so fixed stays fixed.

No OMGS cloud. No telemetry. Your code goes only where your agent already sends it.

## Quickstart

Three steps. You do not install a binary by hand.

1. **Install the skill** (add `--global` for a user level install across projects):
   ```bash
   npx skills add https://github.com/OpenAdminOS/oh-my-god-security --skill omgs-security-review
   ```
2. **Ask your coding agent** (Claude Code, T3 Code, and similar):
   - A local folder: open the agent in the folder and say `run an OMGS security review on this project`.
   - A remote repository: say `run an OMGS security review on https://github.com/owner/repo`. OMGS clones it locally first, then reviews it exactly like a local folder. It never reviews code in the cloud.
3. **On first run, approve both one-time downloads: the OMGS binary and the pinned Microsoft MXC executor.** The skill fetches the `omgs` binary for your platform, verifies it against the published SHA-256 checksums, installs it without elevation into a per-user directory, and continues into the review. Later runs reuse both. The executor is mirrored unmodified in the same pinned OMGS release, with its original Microsoft signature and MIT notice.

You read the report it produces (a self contained `REPORT.html`, plus `REPORT.md` and SARIF) in a run directory that lives outside your code. As a side effect of the reconnaissance it also maps your application: `ARCHITECTURE.html` (and `ARCHITECTURE.md`) show your stack, components by trust zone, data flows, and attack surface as an auto-laid-out diagram. OMGS changes nothing in your repository and applies no fixes unless you explicitly ask.

> Early v0 status: the first public signed release is not published yet, so the automatic download cannot resolve today. Until it is, build the binary once and place it where the skill looks for it, then the agent flow above works:
> ```sh
> git clone https://github.com/OpenAdminOS/oh-my-god-security
> cd oh-my-god-security && cargo build --release
> mkdir -p ~/.local/share/omgs/bin && cp target/release/omgs ~/.local/share/omgs/bin/omgs
> ```
> On Windows, copy `target\release\omgs.exe` to `%USERPROFILE%\.local\share\omgs\bin\omgs.exe`.

## What happens when you run it

The skill guides your coding agent through mapping, hunting, independent verification
and reporting. The deterministic `omgs` binary manages records, budgets, sensors,
proof execution and reports. Target tests and builds run only through the pinned
MXC sandbox, on a workspace copy with synthetic data. The original target stays
unchanged. Output lives outside it: `findings.json`, SARIF, `REPORT.md`, the offline
`REPORT.html`, architecture maps, coverage and retained proof artifacts. Accepted
regression tests enter your repository only through an approved change.

## What the binary does and never does

The binary makes no model calls and sends no telemetry. There is no OMGS account
or hosted service. Your chosen agent still sends code context to its configured
provider unless it runs locally.

Network use is specific: `review` and `batch init` use `git clone` over HTTPS;
`watch` serves only loopback HTTP. The installer downloads release assets over
HTTPS after consent. Sensors default to local tools and local data. Setting
`OMGS_SEMGREP_ALLOW_REGISTRY=1` permits Semgrep rule downloads. OSV database preparation is
opt-in and separate from proof execution. At this revision the binary only detects
OSV availability and never downloads its database. Proofs never download target
dependencies or access the external network. The CLI's git subprocess can also
inherit user git configuration and credentials; use an appropriate review account.

## Why target code only runs in a sandbox

Imports, build hooks and tests can execute arbitrary repository code. OMGS runs
them through [Microsoft MXC](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/)
with a deny-by-default filesystem, a per-run workspace copy, scratch writes, an
environment allowlist and external network denial. macOS uses Seatbelt on Apple
Silicon macOS 15 or later, Linux uses bubblewrap namespaces, and Windows uses
ProcessContainer only when its probe reports no DACL augmentation.

Unix adds CPU, open-file and per-file size limits. Linux tears down descendants
through a PID namespace and applies memory/task limits when a systemd user scope
is available. macOS sweeps for escaped process-group survivors. Windows uses an
owned kill-on-close job and a bounded cleanup grace period. Every OS has a wall
clock. [Platform support](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/platform-support)
and `omgs doctor` explain what is enforceable on the current host. Missing controls
block execution and leave the finding pending.

## Handing results to an agent

Pass the run's `HANDOFF.md` to the agent that will implement a fix, alongside the
run directory and source revision. The handoff contains the fix brief and proof
acceptance checks; keep the associated findings, tests and proof artifacts
available. Run `omgs handoff --run RUN` to generate `HANDOFF.md` and
`handoff.json`, optionally selecting a finding with `--finding C1`. Run
`omgs stage --run RUN` to export verified retained tests as
`RUN/proposed-tests.patch` for review before applying them. Treat all run
artifacts as sensitive.

## Known limitations

- Tier 2 runs only on Linux. Intel Macs cannot run MXC proofs. Under Rosetta on Apple Silicon, install `omgs-aarch64-apple-darwin` instead of the x86_64 binary.
- macOS and Linux handle SIGINT, SIGTERM and SIGHUP cleanup. Linux MXC PID namespace teardown kills detached descendants. On supported Windows tiers, `process.timeout = 0` leaves expiry to OMGS's finite supervisor wall clock. Expiry or interruption requests Ctrl+Break and allows five seconds for cleanup before forced termination. OMGS assigns itself to a kill-on-close job before spawning any executor, using a non-inherited handle; force-terminating OMGS kills the executor and its workloads without a spawn race. Before the first config-bearing invocation, including the dry run, OMGS resolves granted roots and snapshots their ACLs while retaining object identities. Every dry-run outcome and workload exit is checked. ACL drift, replacement or failed inspection blocks execution or marks cleanup incomplete. Inspection remains bounded and ignores a pending interrupt. OMGS only detects drift and never repairs ACLs. Descendants and `enumeratePaths` parents are not inspected, so unchanged roots do not prove complete host ACL restoration. Force termination skips executor cleanup; operators of earlier augmentation runs should inspect ACLs and recover from trusted backups as described in DECISIONS.md.
- Windows DACL augmentation tiers, including the observed windows-2025 tier, are refused before any config-bearing invocation. Supported Windows 11 tiers can differ in parent enumeration support. Without it, directory listing, absolute path resolution and `NUL` redirection can fail; doctor cannot prove the outside read denial. Over SSH session 0 on Windows, PowerShell and other GUI-sensitive toolchains can fail with `STATUS_DLL_INIT_FAILED`; an existing interactive desktop session may be needed.
- Toolchain roots and caches remain readable and can contain private source. There is no total disk quota; Unix has a 1 GiB per-file limit and Windows has no per-file limit. Memory and task limits need an available Linux systemd user scope. Target hardlinks can copy outside content into the workspace.
- The same-process nonce limit: hostile target code sharing the harness process can read the proof nonce and forge marker lines. Run markers catch accidents. They cannot authenticate a result against hostile target code; replay and the independent evaluator remain required. Exact command and config artifacts may retain credentials even though record displays are redacted.

## How it works

OMGS is a multi-agent pipeline by default, not a single review pass. Each stage runs in its own fresh context, so no agent ever certifies its own work.

- **Map.** Read the architecture, principals, input surfaces, and enforcement. Seed a coverage ledger of surface by boundary by attack class.
- **Hunt (red).** Several isolated hunters, normally one per trust boundary, each read only their scope and cannot see the others. They return candidate violations with no severity.
- **Verify (blue).** A fresh, independent verifier that did no hunting tries to disprove every candidate, follows shared and delegated controls, and rejects the leads a control defeats.
- **Prove.** Survivors earn proof inside an OS enforced sandbox with the network denied: a failing test (tier 1), or a locally built copy of the app on dummy data with your approval (tier 2). An effect the sandbox cannot grant stays unproven, never run unsandboxed.
- **Adjudicate.** A separate evaluator, independent of both the hunt and the verify, upholds, adjusts, or overturns every verdict and checks that each proof matches the evidence. This is where overclaimed confirmations and mislabelled proofs are caught.
- **Guard (green).** Confirmed findings become fix briefs and regression tests committed to your repo, so a fix cannot silently regress.

Proof tiers decide what confirmed means. Traced is a source argument only. Test proven is a failing test run in the sandbox. Sandbox exploited is a locally built app exercised in the sandbox on dummy data. Only the top two tiers can be confirmed, severity is assigned only after confirmation, and only committed proof tests or scanner rules can ever block a merge in gate mode. OMGS publishes no score and no coverage percentage; it names what it did not examine.

## Hand results to a fixer

`omgs report --findings RUN/findings.json --out RUN` writes `REPORT.md`,
`REPORT.html`, `findings.sarif.json`, `HANDOFF.md` and `handoff.json` outside
of the reviewed repository. Saved `run-metadata.json` supplies repo, ref, mode,
persona and sandbox defaults. Explicit `--repo`, `--ref`, `--mode`, `--persona`
and `--sandbox` flags override them. Builder reports are short; an absent or
null persona keeps the full form. Both reports include the recorded pipeline
timeline and links to proof records. Markdown starts with what needs action,
including an explicit "Nothing to fix" when no finding was confirmed.

Share `HANDOFF.md` and the protected run directory with a fixer. It explains
verdicts, proof tiers, retained tests, exact proof commands and cumulative fix
budgets without requiring the reader to know OMGS. Confirmed records come first.
Pending records say "verify before fixing" and name the missing fact. Rejected
records are excluded. The machine-readable equivalent follows
[`handoff.schema.json`](skill/schemas/handoff.schema.json).

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

The skill carries `skill/VERSION`. It requires `omgs --version` to match exactly,
including an already installed binary. A mismatch stops the review with both
versions shown. The scripts download that exact tag, never `latest`.

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

Before either download, the skill and scripts show the identical consent text in
[SKILL.md](skill/SKILL.md#setup), including source, maximum sizes, verification and
install location. A typed `yes` authorizes the downloads. The scripts print resolved
paths, versions and verification results afterwards. They install both the binary
and the platform's MXC executor, plus its MIT notice, without elevation. No target
dependencies or toolchains are fetched.

`SHA256SUMS` covers both downloads. The binary must also pass its publisher check
on macOS or Windows. MXC must match the skill's pinned hash and Microsoft's native
signature where supported. Authenticated `gh` adds `gh attestation verify`; an
unavailable or failed attestation is reported as unverified, not as tampering.
Linux has no native publisher check, so checksum verification alone is not proof
of publisher identity. See [SECURITY.md](SECURITY.md#verifying-a-release).

To run tier 1 or tier 2 proofs OMGS uses Microsoft MXC, the only sandbox it trusts with your code: `mxc-exec-mac` on Apple Silicon macOS 15 or later, `lxc-exec` on Linux, `wxc-exec.exe` on Windows 11 builds whose probe reports no DACL augmentation. Windows Server 2025's observed augmentation tier is refused. OMGS accepts only the executor whose SHA-256 matches the MXC release it is pinned to, found at `OMGS_MXC_EXEC`, then `<OMGS data dir>/mxc/<version>/`, then `PATH`. Run `omgs doctor` to see what is installed, what each proof run enforces on your machine and what it does not, and `omgs doctor --live` to watch a denial happen. Without a verified executor OMGS stops at the traced tier and tells you rather than running your code unsandboxed. Intel Macs have no MXC executor, so proofs there stay at the traced tier.

The release contains the five executors listed in [skill/mxc-pins.txt](skill/mxc-pins.txt),
unmodified from MXC 1.0.1. Individual executors are about 3.8 to 11.9 MiB, instead
of the 542,051,775-byte upstream archive. The binary download is bounded to 100 MiB;
checksums and the notice are each bounded to 1 MiB. The installer enforces these
limits. The data directory defaults to `~/.local/share/omgs` (Windows:
`%USERPROFILE%\.local\share\omgs`). Executors go under `mxc/1.0.1/`.

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
runtime, within the proof budget. The [per-stack recipes](skill/VALIDATION-AND-REPORTING.md#proof-by-default-per-stack-recipes)
cover PowerShell, Node, Python isolated mode, shell and Swift, including exact
commands, invariant assertions and blockers. `doctor --live` launches each
runtime's bounded version command (or `sh -c 'exit 0'`) inside MXC before
calling it reachable. Missing tools print `<runtime> not on host PATH`.
Installed tools whose probes fail print
`<runtime> on host PATH but failed to launch inside MXC` and a reason.
Retain those exact lines and the proof startup diagnostic with the pending finding. No installation or
unsandboxed fallback is attempted. Windows gets an explicit safe `PATHEXT`,
scratch `CARGO_HOME`, the existing `RUSTUP_HOME` and `RUSTUP_AUTO_INSTALL=0`.
Host credentials and broad home access stay outside the grants. Linux explicitly
grants read-only `/usr/include` for local compiler headers; MXC does not mount
that system directory by default.

## What a proof record does and does not prove

`omgs prove` writes `proofs/<n>.json` itself, beside the findings. Code under test cannot touch it: inside MXC it can write only its workspace copy and scratch. `omgs validate`, `report` and `critic` require a pinned MXC executor, the saved config with the expected containment, wrapped command, workspace and deny network policy, matching regular-file test and redacted-output digests, and a clean run with no surviving processes. Traced findings must omit `proof_ref` and keep their source trace in `evidence`. A `local_app` proof requires Linux bubblewrap containment. Without a declared contract, a non-rejected finding above traced requires an inner exit code of 1 or 3 through 125. A rejected control may also exit 0. Exit 2 is always a usage or harness error and never supports a proof, as are exits 126, 127 and signals. Every recipe must declare `--expect-marker BOUNDARY_ASSERTION_FAILED`: a declared contract requires exit 1, the exact lines `OMGS_BOUNDARY_<nonce>_BOUNDARY_ASSERTION_FAILED` and `OMGS_CONTROL_<nonce>`. The harness reads the fresh run nonce from `OMGS_PROOF_NONCE` and the declared label from `OMGS_PROOF_CONTRACT`. Schema `omgs-proof/2` stores a required `contract` object with `kind: "recipe"`, `expect_marker`, `boundary_marker_seen` and `authorized_control_seen`. Every field is required and non-null. Uncontracted runs explicitly store `{"kind":"none"}`. The saved MXC environment binds the contract and nonce to the config digest and reconstructed saved command; changing or removing the declaration invalidates the record. Both marker flags come from full stdout and stderr before capping and redaction. Validation and CLI support require these flags, even when neither marker fits in the saved output. Replay retains the contract, generates a fresh nonce and compares the marker flags. Fixed or wrong-nonce markers do not satisfy it. Hostile code sharing the harness process can read the nonce and forge the markers, so the independent evaluator stays required.

Every generated policy is checked by the pinned executor with `--dry-run --config` before the workload starts. A completed nonzero dry run exits 3, reports a configuration rejection and runs no target code. Timeout, interruption, executor startup failure, survivors and incomplete capture or cleanup instead report "MXC dry run did not complete" with exit 3. Blocked `doctor --live` runs also exit 3 without a usage hint. The pinned macOS, Linux and Windows executors all support this check. A workload failure after a successful validation remains a workload failure. The dry-run control is required in `enforced` during proof validation. Earlier development records, including older `omgs_version: "0.1.0"` records, may lack this evidence and must be rerun; the unchanged version cannot identify records made before this check. The `notes` list is optional for current-schema records; older schema versions are always rejected.

On Windows, OMGS first calls the pinned `wxc-exec.exe --probe`. Only a supported, consistent tier with `needsDaclAugmentation=false` permits configuration validation and workload execution. An augmentation requirement blocks up front with exit 3, naming the tier, the MXC 1.0.1 ACL issue and support for Windows 11 builds without augmentation. Detector errors retain their text and default missing warnings and probe facts, but cannot establish a safe tier and therefore block. Failure to start the probe, timeout, interruption, nonzero exit without detector-error JSON, malformed data, mixed success/error data and unknown or inconsistent tiers also block. There is no configuration refusal/retry fallback when probe safety is unknown. JSON is parsed from stdout only. OMGS never runs `wxc-host-prep.exe`; administrator preparation does not override this gate.

Windows doctor also reads the full OS build, including the update revision, and compares it with Microsoft's published ProcessContainer minimums. Windows Server 2025 shares build 26100 with Windows 11 24H2; Microsoft publishes no separate Server minimum. A build below the minimum or absent from that table is reported plainly; the capability probe and config validation decide whether a proof can run. The [MXC build reference](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md) supplies these minimums.

With `--finding`, `--test` is required and its full path or file name must be a token of the command. Runner-generated start and end markers contain a fresh random nonce. Both markers must appear for a clean record, even if the saved output is capped. Missing start means executor error unless the executor was killed or the run interrupted. Missing end means incomplete execution; timeout, signal death and executor errors are recorded separately. On macOS and Linux, SIGINT, SIGTERM and SIGHUP during copy, hashing or staging remove the proof directory and release a charged reservation. Once execution begins, those signals trigger process group cleanup, plus the survivor sweep on macOS and PID namespace teardown on Linux, before an interrupted run is recorded as unclean and keeps its budget charge. Before running the command, the wrapper checks that the named test is a file it can read inside the sandbox and records `test_reachable`. An unreachable test stops execution with exit 126. Missing or false reachability evidence cannot support any proven verdict, including a rejected finding backed by a passing control. This checks readability, not that the command executed the intended assertion. The recorded exit code comes from the end marker. The markers catch accidents such as executor failure, truncation and timeout. They do not establish integrity against a hostile target: the nonce is visible to sandboxed code, so the target can print a forged end marker. Replay and the independent evaluator provide the stronger check that the real target and intended assertion ran. The independent evaluator must check that the command exercised the real target and the intended assertion. Records from `omgs-proof/1`, including records written before `RUSTUP_AUTO_INSTALL=0` became part of the execution policy, predate the current policy and must be rerun with `omgs prove`. Validation and replay reject them with a rerun diagnostic. There is no format migration or compatibility allowlist.

These checks catch mistakes and hand-edited records. They do not defend against a program running as you that sets out to forge every file, because nothing on your own machine can. The defence is that every proof is reproducible: anyone can rerun a record with `omgs prove --run <run-dir> --replay <n>`, and the independent evaluator stage does exactly that before a verdict stands. Replay requires the recorded `timeout_ms` and rejects `--timeout-ms` overrides, consumes one proof-run budget unit, checks the marker-derived inner exit code and cleanliness, and refuses if either the target commit or the digest of the copied target tree (including all `.git` content and dirty changes) differs from the original snapshot. In the same way, `omgs approve` records your consent to tier 2; it is not a lock an agent could not pick, and the app under test stays inside MXC either way.

Run directories can be moved or archived without rewriting the saved config. Validation checks workspace, scratch and marker grants against the original `proof_dir` recorded beside the config, requiring its `proofs/<n>` layout, then verifies the readable roots granted at proof time and exact reconstructed environment entries. Validation is independent of the current HOME. Unknown saved-config keys are rejected. If the original target still exists, validation also checks the current in-target test digest and reports a changed or unreadable test. Replay still requires the original target and an unchanged target snapshot.


Commands and survivor command lines in proof records are redacted before writing. Credential flags mask their complete next token or inline `=value`, including quoted values with spaces; attached short flags such as `-pVALUE` are outside this redaction scope. `command_sha256` and `wrapped_command_sha256` bind the exact replay command and saved config. The runner keeps exact input in `proofs/<n>/command.txt` for replay; this file and the saved config can contain credentials, so protect the entire run directory. On Unix, proof directories are 0700 and command and config files are 0600. Small trust files (approvals, records, configs and answer stores) use bounded, single-link, no-follow reads. Approval stores are limited to 1 MiB. Answer stores and run-local answer snapshots enforce a 1 MiB limit on reads and writes. Executor, proof-test and snapshot content hashes accept hardlinks and symlinks resolving to regular files, with symlink targets disclosed. Snapshot hashing has no size cap; the Unix 1 GiB per-file limit applies only to sandboxed processes. Target FIFOs and sockets are skipped in the workspace copy and snapshot digest, with up to 20 sorted paths recorded as proof gaps and one aggregate count for the remainder. Devices are refused before copying. On Unix, both copy paths preserve symlinks as links; outside or unresolved links are disclosed as a counted proof gap. Copied links that still reach the live target, including absolute links and relative links that leave and re-enter it, have separate path gaps, sorted and capped at 20 paths followed by a count, and remain subject to sandbox access rules. Draft executable permissions are preserved when staged.

## Releases and verifying your download

The tag-only [release workflow](.github/workflows/release.yml) signs and notarizes
macOS binaries, signs Windows binaries through Azure Trusted Signing, mirrors the
five pinned MXC executors and publishes `SHA256SUMS` plus build provenance. Signing
identities must be configured before the first public release. Follow the binary
and MXC verification commands in [SECURITY.md](SECURITY.md#verifying-a-release).

Homebrew formula and winget manifests are generated from final asset hashes,
retained under `packaging/generated/` in the workflow artifact, and attached to the
release. The owner publishes them to a tap and winget-pkgs. Winget installs the
portable binary only; use the matching skill installer for MXC. No public release
or package-manager publication is implied by this PR. See [packaging/README.md](packaging/README.md).

## Environment variables

This table covers source reads (`env::var`, `var_os` and variable-key reads),
installer controls, child-process assignments and regression hooks. Signing
secrets are listed separately in [SECURITY.md](SECURITY.md#release-owner-configuration).

| Variable | Meaning and default |
| --- | --- |
| `OMGS_HOME` | Absolute per-user data/install root; defaults to `<home>/.local/share/omgs`. |
| `OMGS_RELEASE_BASE` | Installer only: HTTPS release asset base or absolute offline bundle directory; defaults to the tag from `skill/VERSION`. A custom source still requires checksums, signatures and pins. |
| `OMGS_MXC_EXEC` | Explicit executor path, authoritative and SHA-256 pinned; otherwise data directory then PATH. |
| `OMGS_SEMGREP_CONFIG` | Local Semgrep rules path; registry/URL values require the next opt-in. |
| `OMGS_SEMGREP_ALLOW_REGISTRY` | Only `1` permits Semgrep registry downloads; unset means offline rules only. |
| `HOME`, `USERPROFILE` | Host home discovery; HOME wins, then USERPROFILE on Windows. Sandboxed values point to scratch. |
| `PATH`, `PATHEXT` | Host tool lookup, absolute entries only. Sandboxed PATH is rebuilt; Windows PATHEXT is explicit. |
| `SYSTEMROOT`, `WINDIR` | Windows host helpers and MXC bootstrap. SYSTEMROOT defaults to `C:\Windows` where applicable; never a target-controlled grant. |
| `TEMP`, `TMP`, `TMPDIR` | OS-selected internal temporary storage, resolved to its physical root before admission. Installer executable staging ignores these settings. Replaced with scratch in proof workloads. |
| `LOCALAPPDATA` | Windows executor bootstrap; replaced with scratch in workloads. |
| `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS` | Linux systemd wrapper bus access only; stripped before target execution. |
| `XDG_CACHE_HOME`, `CLANG_MODULE_CACHE_PATH` | Generated scratch cache directories for proof workloads. |
| `LANG` | Proof workload locale, fixed to `C.UTF-8` on Unix. |
| `OPENSSL_CONF` | macOS proof workload uses an empty scratch configuration. |
| `CARGO_HOME`, `RUSTUP_HOME` | Generated proof environment points Cargo to scratch linked caches and Rustup to the discovered readable toolchain. Host overrides do not broaden grants. |
| `CARGO_NET_OFFLINE`, `RUSTUP_AUTO_INSTALL` | Proof workload values `true` and `0`; installers also set auto-install to `0`. |
| `OMGS_PROOF_NONCE`, `OMGS_PROOF_CONTRACT` | Runner-generated recipe inputs. Same-process target code can read them; they are not a private attestation channel. |
| `GIT_TERMINAL_PROMPT` | Set to `0` for noninteractive clone operations. |
| `GH_TOKEN`, `GITHUB_TOKEN`, `GH_HOST`, `GH_CONFIG_DIR` | Read by external gh, not the binary. Existing gh authentication/configuration controls optional provenance checks. |
| `OMGS_REQUIRE_RECIPES` | Test suite only: comma-separated runtimes whose absence must fail recipe tests. |
| `OMGS_TEST_PUBLICATION_DIR`, `OMGS_OWNER_TEST_DIR`, `OMGS_CAPTURE_CHILD`, `OMGS_TEST_PROBE_JSON` | Regression child-process hooks, with no installer authority or production signature bypass. |

Without `models.json`, `route` returns `host-default` and keeps the host's current
selection. A refusal with no configured fallback records a blocker. An explicitly
requested missing or malformed `--models` file remains an error.

## For agents: install and run

If you are a coding agent asked to install OMGS and review a project, follow these steps exactly and do not improvise around the safety rules.

1. If the OMGS skill is not installed, add it with the Skills CLI command above, then load `SKILL.md` from the installed skill directory.
2. Follow the skill's binary resolution (PATH, per-user location, bundled bootstrap). Record the resolved binary path and use it for every command. Building from source (`cargo build --release`) is the fallback when no release binary exists for the platform.
3. Initialize a run against the target: `omgs audit init --target <repo> --mode advisory --budget 24`. The command prints a run directory outside the target tree. Never write findings, ledgers, or reports inside the target tree.
4. Follow the skill's pipeline (map, isolated hunt, independent verify, prove, adjudicate, report). Validate every findings file with `omgs validate --findings <run-dir>/findings.json` before reporting.
5. Run `omgs doctor` before proofs to check the pinned executor and declared controls; use `omgs doctor --live` for a live probe. Execute proof tests or a locally built app only through `omgs prove --run <run-dir> --finding <fingerprint> --test <test path> --cmd "<test command>"`. It copies the target into a per-run workspace, runs the command under MXC, and writes `proofs/<n>.json` beside the findings; put the printed `proof_ref` on the record, because a `test_proven` or `sandbox_exploited` record without a matching proof record fails `omgs validate`. Each proof run counts as one unit of the run budget set by `audit init --budget`, alongside the agent calls `report` records; when the budget is spent, prove exits 3 without running anything. Tier 2 (`--tier 2`) runs only on Linux, where the sandbox has its own private loopback, and needs a one-time approval that a person gives with `omgs approve --target <repo>` at a terminal. If prove reports that no verified MXC executor is available (exit 3), stop at the traced tier, record the exact blocker, and tell the user. Never run target code unsandboxed to keep the flow moving.
6. Render outputs with `omgs report --findings <run-dir>/findings.json --out <run-dir> --repo <name> --ref <commit> --mode <gate|advisory>`. Present `REPORT.html` or `REPORT.md`, ask intent questions in plain language, and hand over fix briefs. Do not apply fixes or commit anything unless the user explicitly asks.
7. During reconnaissance, record the architecture map in `architecture.json` (schema in the skill's `schemas/`) and render it with `omgs architecture --in <run-dir>/architecture.json --out <run-dir>`. It produces `ARCHITECTURE.md` and a self-contained `ARCHITECTURE.html` describing the target's stack, components, trust boundaries, data flows, and attack surface. Descriptive only; it never changes a verdict.

Shortcuts: `omgs review --repo-url <github-url>` clones a repository into the local OMGS targets area and initializes a run with stack detection and sensors. `omgs check --target <repo>` runs deterministic sensors and counts committed proof tests without executing target code. `omgs ledger set --ledger <run-dir>/coverage-ledger.json --unit <id> --status covered --evidence <fingerprint>` records coverage progress (`ledger add` and `ledger list` manage units), and `omgs critic --run <run-dir>` checks that every unit, candidate, and finding is reconciled and that no finding was verified by its own hunter. `omgs batch init --list <urls.txt> --out <dir>` initializes one run per repository and `omgs batch index` renders an overall index. `omgs watch --run <run-dir>` serves the optional live progress page on loopback, `omgs route` picks a fallback model per role after a refusal and records it, and `omgs intent list` / `omgs intent answer` hold reusable intent questions and your recorded answers.

## For humans: direct use

Asking your coding agent is the intended experience. Driving the CLI yourself works too:

```sh
cargo build --release
./target/release/omgs setup --yes                      # install detected skills and verify MXC live
./target/release/omgs setup --dry-run                  # list detected skill destinations only
./target/release/omgs audit init --target /path/to/your/repo
./target/release/omgs check --target /path/to/your/repo
```

Offline benchmark scoring: `omgs bench score --cases <manifest> --runs <run-dir>` reads saved artifacts and emits JSON plus Markdown. See the [benchmark guide](benchmark/README.md#score-saved-runs-offline) and [corpus research inventory](benchmark/corpus/README.md).

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

Input is bounded to 16 MiB per file, 64 MiB total, 10,000 entries and 64 directory
levels per scanner; links, special files, unreadable files and entries exceeding
these bounds are skipped with an explicit gap. A skipped directory accounts for
its entire subtree. Copied files are read with no-follow bounded reads. Runtime
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
a SHA-256 fingerprint of that metadata. OSV hits also retain package name, version
and ecosystem in JSON, fingerprints and reports, so distinct affected versions
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

Inventory uses a heuristic path classifier for stack detection, first-party size statistics and hunting priority only. Code is the default, including unknown formats, SQL, HTML and templates. JSON, JSONL, NDJSON, CSV and TSV files of at least 1 MiB are prioritized as data, even though they may contain interpreted logic or renamed scripts. Documentation uses md, rst and adoc extensions or conventional notices. Only conventional notices such as README.txt, LICENSE.txt, NOTICE.txt, CHANGES.txt, AUTHORS.txt, CONTRIBUTING.txt and COPYING.txt classify as docs by the txt suffix; other txt files default to code. Conventional executable and build names (including CMakeLists.txt, Makefile, GNUmakefile, Dockerfile, Containerfile, Justfile, Rakefile, Gemfile, Gradle and CMake scripts, Jenkinsfile, Vagrantfile, BUILD, BUILD.bazel, WORKSPACE and meson.build) take precedence over docs/data rules. `requirements*.txt` is dependency configuration and classifies as code. Inventory-root test/spec and dependency containers and conventional test suffixes set test or vendored priority; nested directory hints, minified names and binary extensions alone cannot exclude a file.

Classification never removes accountability. Every nonempty test, docs, data or vendored class gets a `planned` coverage unit with its total count and first 20 sorted paths across all files, plus supplemental source counts and paths. A hunter must skim or sample each group, then either hunt (`covered` with evidence) or explicitly resolve it as `out_of_scope` with `reviewed, not security relevant: <reason>`. The disposition must cite at least one sampled path in its evidence. The reason must explain the review, not repeat the classifier label. Planned, candidate, blocked and deferred exclusions fail the critic. Ledger output and both reports show review reasons. Shell scripts and browser extensions with a valid manifest version are detected alongside existing stacks. Nested project markers produce separate subproject roots in run metadata, coverage units and the architecture seed.

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

## Repository layout

- `src/`: the deterministic Rust CLI (findings schema, finding identity across runs, stack detection, coverage ledger, redacted sensor execution, sandbox proof execution, report rendering to Markdown, a self contained HTML one pager, and SARIF, and the architecture map renderer).
- `schemas/`: coverage ledger JSON schema. Findings, candidate and architecture schemas live in `skill/schemas/`.
- `skill/`: the agent skill pack and attack class packs that your agent follows.
- `.github/workflows/release.yml`: the signed, notarized, checksummed release pipeline.
- `benchmark/`: the open benchmark design and case manifest format.
- `DECISIONS.md`: the locked product decisions this implementation follows.
- `NOTICE`: third party attribution for pinned and integrated components.

## Contributing

Attack class packs and benchmark cases are the highest leverage contributions. Every confirmed finding claim needs a proof tier and evidence, and every claim about coverage must name what was not examined. Read DECISIONS.md before proposing scope changes.

## License

Apache-2.0. See LICENSE and NOTICE.

## Committed policy and gate

Commit `.omgs/policy.json` under normal owner review, using the strict
[policy schema](skill/schemas/policy.schema.json). Every field below is required,
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
saved in `run-metadata.json` under `policy` for review. Gate independently reads
base policy from Git at invocation time; run metadata cannot authorize tests. Conflicting mode, persona or budget flags
cannot override committed policy. Fix runs inherit the original snapshot and
spend only the computed remaining budget.

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
[GitHub workflow example](docs/policy-workflow.md).

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
