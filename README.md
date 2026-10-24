# Oh My God Security

Red hunts. Blue verifies. Green guards.

OMGS is an open source security review suite for codebases built with AI coding agents. Your agent hunts for real trust boundary violations, a fresh verifier tries to disprove every candidate, and surviving findings must earn proof: a failing test, or a locally built copy of the app exercised inside an OS enforced sandbox. What remains becomes regression tests in your repo, so fixed stays fixed.

No OMGS cloud. No telemetry. Your code goes only where your agent already sends it.

Status: early v0. The deterministic CLI, schemas, skill pack and benchmark design are in this repository. Distribution is skill first, described in DECISIONS.md: install the skill, and the skill bootstraps the signed binary on first run after verifying its checksum. Until the first public signed release is published, the same flow is exercised against local release bundles, and building from source remains the fallback documented below. Timed cold installs from a clean home to a first validated report have passed on macOS, Linux, and Windows against a local unsigned bundle; see `benchmark/feature-coverage.md` for the numbers and the remaining gaps.

## Install

Install the skill with the Skills CLI (add `--global` for a user level install):

```bash
npx skills add https://github.com/OpenAdminOS/oh-my-god-security --skill omgs-security-review
```

Then ask your coding agent: run an OMGS security review on this project. On first run the skill downloads the OMGS binary for your platform from the project releases, verifies it against the published SHA-256 checksums, installs it without elevation into a per-user directory, and continues into the audit. You never install an executable by hand in the primary flow. Direct binary installation stays available for humans and enterprises that prefer it: download the release binary for your platform, verify it, and run `omgs setup` to install the skill into your agents.

## For agents: install and run

If you are a coding agent asked to install OMGS and review a project, follow these steps exactly and do not improvise around the safety rules.

1. If the OMGS skill is not installed, add it with the Skills CLI command above, then load `SKILL.md` from the installed skill directory.
2. Follow the skill's binary resolution: `omgs` on PATH, then the per-user install location, then the bundled bootstrap script in the skill's `scripts/` directory, which downloads and checksum verifies the release binary. Record the resolved binary path and use it for every command below. Building from source (`cargo build --release` in this repository) is the fallback when no release binary exists for the platform.
3. Initialize a run against the target repository: `omgs audit init --target <repo> --mode advisory --budget 24`. The command prints a run directory outside the target tree. Never write findings, ledgers or reports inside the target tree.
4. Follow the skill's six phases. Write run artifacts only in the printed run directory. Validate every findings file with `omgs validate --findings <run-dir>/findings.json` before reporting.
5. Execute proof tests or a locally built app only through `omgs prove --cmd "<test command>"`. If prove reports that no sandbox backend is available, stop at the traced tier, record the exact blocker, and tell the user. Never run target code unsandboxed to keep the flow moving.
6. Render outputs with `omgs report --findings <run-dir>/findings.json --out <run-dir> --repo <name> --ref <commit> --mode <gate|advisory>`. Present `REPORT.html` or `REPORT.md` to the user, ask any intent questions in plain language, and hand over fix briefs. Do not apply fixes or commit anything unless the user explicitly asks.

Shortcuts: `./target/release/omgs review --repo-url <github-url>` clones a repository into the local OMGS targets area and initializes a run with stack detection and sensors. `./target/release/omgs check --target <repo>` runs deterministic sensors and counts committed proof tests without executing target code. `./target/release/omgs ledger set --ledger <run-dir>/coverage-ledger.json --unit <id> --status covered` records coverage progress.

## For humans

Ask your coding agent: run an OMGS security review on this project. That is the intended experience.

Direct use works too:

```sh
cargo build --release
./target/release/omgs setup
./target/release/omgs audit init --target /path/to/your/repo
./target/release/omgs check --target /path/to/your/repo
```

## How it works

- The `omgs` binary is deterministic Rust. It owns the findings schema, finding identity across runs, stack detection and the coverage ledger, sensor execution with redacted results, sandbox proof execution (an MXC executor when configured, otherwise OS native Seatbelt on macOS or bubblewrap on Linux, always with network denied and writes confined to scratch), and report rendering to Markdown, a self contained HTML one pager and SARIF.
- The skill pack in `skill/` is markdown your agent follows: reconnaissance, isolated hunting by attack class, adversarial verification, tiered proof, intent questions and fix briefs.
- Proof tiers decide what confirmed means. Traced is a source argument only. Test proven is a failing test run in the sandbox. Sandbox exploited is a locally built app exercised in the sandbox on dummy data. Only the top two tiers can be confirmed, and only committed proof tests or scanner rules can ever block a merge in gate mode.
- Run output lives outside the audited repository. The only things ever committed to a target repo are policy and intent answers, suppressions, and proof tests its owner accepts.

## Repository layout

- `src/`: the deterministic CLI.
- `schemas/`: findings and coverage ledger JSON schemas.
- `skill/`: the agent skill pack and attack class packs.
- `benchmark/`: the open benchmark design and case manifest format.
- `DECISIONS.md`: the locked product decisions this implementation follows.
- `NOTICE`: third party attribution for pinned and integrated components.

## Contributing

Attack class packs and benchmark cases are the highest leverage contributions. Every confirmed finding claim needs a proof tier and evidence, and every claim about coverage must name what was not examined. Read DECISIONS.md before proposing scope changes.

## License

Apache-2.0. See LICENSE and NOTICE.
