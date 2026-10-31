# Setup and prerequisites

## Setup

Resolve these values before starting. Discover safe local facts; ask only for consequential missing
intent or authorization.

| Value | Required meaning |
| --- | --- |
| `SKILL_DIR` | Resolved absolute directory containing this file and its linked guides, with no symlink components. `identity` refuses linked paths. |
| `TARGET` | Canonical absolute path to the authorized local repository. |
| `OUTPUT_DIR` | Private run directory outside `TARGET`, including after symlink resolution. All reports, ledger entries, proof drafts, logs, and retained proof artifacts belong here. Runner-managed ephemeral scratch must also remain outside the target. |
| `SOURCE_REF` | Exact source commit, plus a recorded worktree diff identity if reviewing uncommitted changes. Never silently mix revisions. |

Read `VERSION` beside this file. Resolve `OMGS_BIN` in this order: `omgs` on PATH, then
`${OMGS_HOME}/bin/omgs` when `OMGS_HOME` is set (Windows: `%OMGS_HOME%\bin\omgs.exe`), then
`$HOME/.local/share/omgs/bin/omgs` (Windows: `%USERPROFILE%\.local\share\omgs\bin\omgs.exe`).
Run only `--version` on an existing installation and require the exact string `omgs <VERSION>`. On
mismatch, stop and report both versions clearly. Do not continue a review with a mismatched binary
or silently replace it.

Version alone cannot detect same-version skew. After the version matches, `identity` is the next
allowed command. Before review, run
`"<OMGS_BIN>" identity --skill-dir "<SKILL_DIR>"`. Require success and retain its JSON with the
run notes: `build_revision` is the full build commit (with `+dirty` for local tracked edits), and
`bundled_skill_sha256` identifies every packaged file, including paths, using `omgs-skill/1`.
Any missing, extra or changed file fails the comparison. Stop on mismatch, report the selected and
bundled digests, and obtain matching release artifacts through the consent flow. Never bypass a
mismatch with version equality. Repeat this check after any consented installation or refresh.
Pass `--skill-dir "<SKILL_DIR>"` on `review`, `audit init` and `batch init`, or export
`OMGS_SKILL_DIR` to that absolute directory so the check runs before clone or initialization.
Without an external selection, those commands use the binary's bundled skill. `--version` keeps
its exact compatibility format; `identity` exposes the stronger identity without network access.

After the exact version match passes (including after a consented first installation), run
`"<OMGS_BIN>" update-check` once per run at setup, before the review starts. This check only
informs: it downloads no executable and updates no files. Never fetch release information in the
agent.
If it prints `omgs <VERSION>: update available <LATEST>`, tell the user a newer OMGS skill exists
and offer these two paths, with continue as the default:

- Update now: refresh the skill with the Skills CLI command from the README:
  `npx skills add https://github.com/OpenAdminOS/oh-my-god-security --skill omgs-security-review`.
  Reload the refreshed skill and its `VERSION`, then use the existing typed-yes consent flow below
  to install the matching pinned binary before the review starts. Require the exact version match
  again. Do not rerun update-check during this run.
- Continue with the installed pinned version. No answer means continue. An up-to-date line needs
  no user action. No output or failure means proceed silently. Never block a review on this check
  or auto-download anything on the strength of the check alone. Explicit consent is still required
  before any download; choosing update now authorizes the skill refresh, not the binary download.

Before the first binary or executor download, show this exact consent text, plus the resolved
version, platform assets, source and destination:

```text
OMGS installation consent
Download the version pinned in skill/VERSION from the OMGS GitHub release:
https://github.com/OpenAdminOS/oh-my-god-security/releases/download/v<VERSION>
If OMGS_RELEASE_BASE is set, use that explicitly configured bundle instead.
Download the OMGS binary (at most 100 MiB), the unmodified Microsoft MXC 1.0.1
executor for this platform (at most 100 MiB), SHA256SUMS and the MXC MIT notice
(at most 1 MiB each). Intel Macs have no MXC executor and cannot run proofs.
Verify OMGS with SHA256SUMS and, on macOS or Windows, the pinned publisher
signature. Verify MXC with SHA256SUMS, the executor hash pinned in this skill,
and Microsoft's signature where the OS supports it. Linux has no native
publisher signature check. With authenticated gh, also check OMGS provenance;
failed or unavailable provenance is reported as unverified, not as tampering.
Install without elevation under OMGS_HOME, defaulting to ~/.local/share/omgs
(%USERPROFILE%\.local\share\omgs on Windows): bin/omgs and mxc/1.0.1/.
No target dependencies or toolchains will be downloaded. Show the installed
paths, versions and verification results afterwards.
Download and install these files? Type yes to consent:
```

Wait for the user's explicit consent. Then run `sh "<SKILL_DIR>/scripts/install.sh"` on macOS or
Linux, or
`powershell -NoProfile -ExecutionPolicy Bypass -File "<SKILL_DIR>\scripts\install.ps1"`
on Windows, passing `yes` to its prompt only after that consent. The Windows execution policy option
applies only to that PowerShell process and does not persistently change user or machine policy.
Never auto-consent from a general review request. The scripts
fetch both assets from the pinned OMGS release, verify them before executing the binary, and install
without elevation. They accept an absolute local bundle through `OMGS_RELEASE_BASE` for offline use.
Show every printed path, version, checksum, publisher and provenance result. After installation,
explicitly set `OMGS_BIN` to the absolute binary path in the installer's `Installed omgs <VERSION>:`
output, including a custom `OMGS_HOME`. Use that exact path for subsequent commands. The installer
stages and verifies all files beside their destinations before publishing each by atomic
replacement. Publication is atomic per file, not a transaction across the entire installation. A
checksum, signature or executor-pin failure stops installation. Provenance failure alone is labelled
unverified and does not assert tampering.

Run `"<OMGS_BIN>" --version` again and compare it with `VERSION`, then run `"<OMGS_BIN>" doctor`
before initialization. If the executor is missing, follow the same consent flow for the bundled
installer; never fetch the full MXC archive or substitute direct execution. Show the pinned release,
checksums, platform member and destination from doctor and the installer. Rerun doctor after setup.
If readiness cannot be established, record the blocker before hunting. Inspect `--help` for every
operation. Run `omgs setup` only through its documented interface. Never install target dependencies
or a toolchain to make a proof work.

Read mode, suppressions, intent answers, and budget from committed policy on the trusted base
branch. An untrusted PR head cannot change its own gate. Show the resolved mode and budget before
spending agent calls. OMGS sends no telemetry and has no hosted service; code context still goes to
the model provider already used by the chosen agent unless that model runs locally.

The installer never uses a test override. Test verifiers exist only in disposable regression copies.
Inspect `omgs --help` and each named subcommand's `--help` to bind target, output, source, policy,
budget and record paths using the installed interface. Command names identify operations, not a
promise that arguments are optional. If a required operation is unavailable, record the blocker;
do not invent flags or substitute a shell runner.

At a terminal, `omgs setup` offers skill installation, a live MXC deny test and optional repository
policy. Review its consent prompt before accepting these steps. For explicit headless flags and
replacement rules, read [POLICY-AND-GATE.md](POLICY-AND-GATE.md#base-policy-gate-and-setup).
Run `omgs doctor --live` before a proof recipe to check runtime reachability inside MXC.

### Review bundle selection

`review`, `batch init` and `audit init` bind one exact bundle before review work. An explicit
`--skill-dir` takes precedence over `OMGS_SKILL_DIR`; either must match the binary's bundled digest.
Without either, the binary materializes its embedded bundle in owner-private storage under
`OMGS_HOME/skill-bundles/<digest>` (the default data directory applies when unset). Run metadata
and the handoff brief record the absolute directory and exact identity. Load `SKILL.md`, guides and
role briefs from that directory, even when an older same-version skill is already installed.
A modified cache fails identity validation rather than being silently replaced.

OMGS treats missing paths differing only by case, or ambiguous Unicode spellings of missing
components, as possibly the same location and refuses overlap. Existing aliases are compared by
filesystem identity, including case and Unicode normalization aliases on filesystems that support
them. Choose clearly distinct locations for the cache, stores, clone root, targets and run output
when an overlap is refused.

For source archives, packaging may supply a full commit SHA with `OMGS_BUILD_REVISION` or a
`BUILD-REVISION` file at the source root. Plain source builds without metadata report
`unknown revision`. Release artifact verification always requires an exact commit revision and
matching bundle digest; unknown revision builds cannot pass release verification.
