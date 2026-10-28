# Setup and prerequisites

## Setup

Resolve these values before starting. Discover safe local facts; ask only for consequential missing
intent or authorization.

| Value | Required meaning |
| --- | --- |
| `SKILL_DIR` | Absolute directory containing this file and its linked guides. |
| `TARGET` | Canonical absolute path to the authorized local repository. |
| `OUTPUT_DIR` | Private run directory outside `TARGET`, including after symlink resolution. All reports, ledger entries, proof drafts, logs, and retained proof artifacts belong here. Runner-managed ephemeral scratch must also remain outside the target. |
| `SOURCE_REF` | Exact source commit, plus a recorded worktree diff identity if reviewing uncommitted changes. Never silently mix revisions. |

Resolve the OMGS binary first and record it as `OMGS_BIN`. Try, in order: `omgs` on PATH, then
`$HOME/.local/share/omgs/bin/omgs` (Windows: `%USERPROFILE%\.local\share\omgs\bin\omgs.exe`). If
neither exists, this is a first run: run the bundled bootstrap for this platform, `sh
"<SKILL_DIR>/scripts/install.sh"` on macOS or Linux or `powershell -NoProfile -File
"<SKILL_DIR>\scripts\install.ps1"` on Windows. The bootstrap downloads only the OMGS release binary
for this platform from `OMGS_RELEASE_BASE` (default: the project GitHub releases), verifies it
against the release `SHA256SUMS`, installs it without elevation into the user cache above, and
prints its path. Tell the user this one-time download is happening and show the binary path and
version it prints. If the download or checksum verification fails, stop and record the blocker;
never substitute an unverified binary. Run `omgs setup` if needed through its documented headless
interface. Never run target installation hooks or fetch target dependencies to make a proof work;
the bootstrap fetches only OMGS itself. Inspect `omgs --help` and each named subcommand's `--help`
to bind target, output, source, policy, budget, and record paths using the installed interface.
Command names below identify operations, not a promise that arguments are optional. If a required
operation is unavailable, record the blocker; do not invent flags or substitute a shell runner.

Run `"<OMGS_BIN>" --version` and record the installed version. At a terminal, `omgs setup`
offers skill installation, a live MXC deny test and optional repository policy. Review the
consent prompt before accepting these steps. For explicit headless flags and replacement rules,
read [POLICY-AND-GATE.md](POLICY-AND-GATE.md#base-policy-gate-and-setup).

Run `"<OMGS_BIN>" doctor` before initialization or hunting. If it reports `sandbox: not ready`, show
the user its MXC install steps, including the pinned release, archive checksum, platform member,
executor checksum and destination. Explain that the bootstrap downloaded only OMGS; this second
download supplies Microsoft's OS sandbox executor, which is required to run target code safely.
Follow the [MXC installation
instructions](https://github.com/OpenAdminOS/oh-my-god-security#the-binary-bootstrap) and the exact
destination doctor prints, then rerun doctor. If readiness cannot be established, record the blocker
before any hunting starts. Never substitute direct execution.

Read mode, suppressions, intent answers, and budget from committed policy on the trusted base
branch. An untrusted PR head cannot change its own gate. Show the resolved mode and budget before
spending agent calls. OMGS sends no telemetry and has no hosted service; code context still goes to
the model provider already used by the chosen agent unless that model runs locally.
