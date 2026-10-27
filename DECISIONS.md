# Oh My God Security: Locked Decisions

Status: Final. Locked by the founder on 2026-10-16 after a grill review.
Short name: OMGS. CLI name: `omgs`.

## Goal

An open source, local first, model and agent agnostic security audit suite for codebases in the vibe coding era. It audits a repository, proves or disproves each finding, and leaves behind regression tests and a plain language report. It shrinks the red, blue and green loop from enterprise security operations down to a single repository, built on the audit discipline of Cloudflare's security-audit-skill.

## Positioning

Public framing, settled after the main lock and revised once: OMGS stands entirely on its own name and story. Red hunts, blue verifies, green guards: red agents hunt and prove in the sandbox, blue agents verify, triage and ask intent questions, and green agents produce fix briefs, regression tests and hardening proposals that a human approves. Red, blue and green team language is generic security vocabulary and needs no vendor framing. No other company's name or product appears in the project name, tagline, README hero, landing material or marketing comparisons, and OMGS never claims affiliation with, equivalence to, or endorsement by any vendor. Attribution exists only in the provenance layer where it is legally or technically required: preserved license notices for reused MIT licensed material, a third party credits file, and dependency names in build and lock files, including the MXC SDK. This decision record itself is provenance, not marketing copy.

## Prime directive: dead easy

Ease of use outranks every feature. The target experience is one sentence to the coding agent the user already has: run an OMGS security review on this project. The agent installs OMGS from its GitHub repository, runs the review and the tests, and returns a report the user can act on. If a feature cannot survive that flow, it does not ship in v0.

Acceptance test for this directive: a new user goes from zero to a first proven finding with one prompt or one command, no OMGS account, no OMGS API key, no config file, and no manual sandbox setup.

## Locked decisions

1. Users, revised after field testing: everyone who ships code with agents, served by one engine with persona modes rather than separate products. Builder mode serves product, script, and small tool authors reviewing their own work before shipping, with plain language intent questions, visual proof, and fix briefs their agent can act on. Inheritor mode serves AppSec, platform engineers, and maintainers auditing code they did not write, with full traces, SARIF, and coverage detail. Team mode serves larger products with gate or advisory CI behavior and base-branch policy. Persona modes change defaults, report depth, and budget profiles only. The evidence bar, proof tiers, and sandbox rules are identical for everyone.
2. Cloudflare's security-audit-skill stays upstream and pinned. Attack class pack content is contributed back upstream where possible. OMGS owns only the deterministic layer upstream does not ship: the runner, scanners as sensors, finding identity across runs, sandbox proof execution, budgets, modes and the public benchmark.
3. The OMGS CLI is deterministic and never calls a model. The user's agent does the reasoning locally, or a headless agent does it in CI under a tool allowlist the runner enforces. Schema validation, deduplication, identity, sensors, budgets, gates and proof execution are code, not prompts.
4. Gate mode and advisory mode both ship, and the user can switch between them. In gate mode only deterministic artifacts block a merge: a committed failing security test or a scanner rule. Model output never blocks. In advisory mode nothing blocks. The mode lives in committed policy loaded from the base branch under normal code owner review, never from a pull request head, so no change can switch off its own gate.
5. Proof is a tiered ladder, and a finding earns the tier it actually reached:
   - Level 0, traced: a complete source trace from input to sink. Candidate only, never confirmed.
   - Level 1, test proven: an agent written failing test, executed by the project's own test runner inside the sandbox. This earns confirmed, becomes the regression test, and is eligible to gate.
   - Level 2, sandbox exploited: an agent exercises a locally built copy of the running app inside the sandbox on synthetic data. Highest confidence, used only when a test cannot decide, and a human approves its first run per repository.
   Escalation is decided by the deterministic runner under the run budget, cheapest decisive tier first. Public wording is sandbox verified against a local build. OMGS never claims to pen test a live system.
6. Findings never live in the target tree. Run output defaults to a directory outside the repository. Only intent answers, policy, suppressions and accepted proof tests are committed.

## Sandbox requirements for proof execution

Target controlled code, including builds, tests and the running app at level 2, executes only inside an OS enforced sandbox. Amended on 2026-10-27: Microsoft MXC is the only backend on every OS (Seatbelt through `mxc-exec-mac` on Apple Silicon macOS 15 or later, bubblewrap through `lxc-exec` on Linux, ProcessContainer through `wxc-exec.exe` on Windows 11); OMGS's own Seatbelt and bubblewrap profiles are removed. The executor is pinned by SHA-256 to one MXC release and refused on any mismatch. Every proof run aims for all of the following, and its proof record names exactly what was enforced and what was not:

- No external network. Local client and server traffic stays on an isolated loopback.
- An empty environment built from an explicit allowlist, with scratch local home, temp and cache directories. Dummy principals and dummy secrets only.
- A read only target and toolchain. The target process writes only inside its assigned scratch directory.
- Explicit limits on CPU, memory, processes, file size, disk and wall clock time.
- No dependency installation and no network fetching during proof execution. Only tools and dependencies already present locally are used.
- Execution stops at the minimum local effect that proves the boundary violation.

Declared minimum set per OS (amended on 2026-10-27, replacing the rule that every control above must hold everywhere, because no OS sandbox offers all of them). Below this set OMGS refuses to run target code:

- macOS (Apple Silicon): MXC deny-by-default filesystem with the target copied into a per-run workspace, external network denied, environment cleared to an allowlist, CPU time, file size and open file limits, a wall clock with the whole process group killed, and a survivor sweep that finds and kills sandboxed processes which left the group and fails the run. Intel Macs have no MXC executor, so `omgs prove` refuses there.
- Linux: the same, plus memory and task limits through a systemd user scope where one exists; descendants die with MXC's PID namespace.
- Windows 11: MXC ProcessContainer with the same filesystem, network and environment policy and the wall clock; no per-process CPU, file size or open file limits, which every proof record states. The container may list (not read) the parent directories of the workspace and toolchains, which runtimes such as Node need to resolve paths.
- Tier 2 runs only on Linux, decided on 2026-10-27: there the sandbox has its own network namespace, so the app and its client talk over a private loopback while host services stay unreachable (verified). On macOS the sandbox shares the host loopback (a Seatbelt app could reach services on the host loopback, observed), and on Windows the container blocks loopback even within itself unless the host loopback is exempted, so `omgs prove --tier 2` refuses on both and names the reason. Tier 2 also requires the per-repository human approval given at a terminal with `omgs approve`.

If any control in the declared set cannot be enforced on the current platform, OMGS does not execute the target code. The finding stays at the highest tier already earned, the missing sandbox capability is recorded as the exact blocker, and the report gives a safe manual validation plan. Degrading honestly beats running unsandboxed silently.

## Installation and use

Installation must work for agents first, because in practice an agent does the installing. The repository README is written so an agent can follow it end to end without human help, and the same instructions serve humans.

Distribution decision, settled after the main lock and revised once: skill first. The primary install is the skill pack through the Skills CLI or an agent prompt, the same shape as the reference skill this project builds on. On first run the skill bootstraps the deterministic binary itself: a bundled per-platform install script downloads the matching signed release binary, verifies its SHA-256 against the release SHA256SUMS, and installs it without elevation into a per-user OMGS directory. Direct binary installation (GitHub Releases, later Homebrew and winget) remains the secondary path for humans and enterprises. There is no npm package for OMGS itself and no hosted service. Signing is mandatory from the first public release: Apple Developer ID with notarization on macOS and Windows code signing on Windows, with checksums and signatures published for every release asset. The CLI runs proofs only through the pinned Microsoft MXC executor for the platform. OMGS mirrors the five Microsoft-signed executors (macOS arm64, Linux arm64 and x64, Windows arm64 and x64) as release assets, unmodified and pinned by SHA-256 with the MIT notice, so installing them is part of installing OMGS and the 542 MB MXC release archive is never needed; the skill explains both downloads before making them. A graphical setup wizard is a non goal for v0 and a deferred decision afterwards.

Three supported entry points, all zero config by default:

1. Skill install, the primary path: the user installs the skill with one Skills CLI command or asks their agent to add it, then says "run an OMGS security review on this project". On first run the skill bootstraps the signed binary through its bundled install script, verifying the checksum, and the agent continues into the audit without further user steps.
2. Human install: the user installs the signed binary and runs `omgs setup` once. Setup is a terminal wizard: it detects the installed coding agents, installs the skill pack into each, verifies the MXC backend enforces its policy, writes the default policy, and offers the gate or advisory choice. Every setup step also works through flags with no interaction, for agents and scripts.
3. Skill install: the pack installs into any agent that supports skills, with a plain instruction file fallback for agents without a skill system. Model agnostic by construction, because OMGS never calls a model and holds no provider keys. Users keep the agent and subscription they already have.

Defaults that protect the prime directive: no account, no telemetry, no OMGS server, no Docker requirement, no Node or other language runtime requirement, and sensible defaults for budget, profile and mode that the user can change later in the committed policy file. The audit command shows the budget and mode before spending anything and writes the report outside the tree.

## Visual evidence

Sandbox proofs may capture screenshots as supporting evidence, opt-in per run. Web targets are the first supported surface: the locally built app runs in the sandbox, a headless browser already present on the system captures proof moments against dummy data, and the CLI embeds resized copies into REPORT.html as inline data so the one pager stays a single offline file. Originals stay in the run directory under artifacts with hashes recorded in findings.json. Screenshots never replace a proof test or trace, must contain dummy data only, are size capped, and are skipped with the exact blocker recorded when no browser or GUI access exists inside the sandbox. Desktop GUI capture and terminal rendering are later surfaces, since GUI access inside sandboxes is platform sensitive, as the Windows PowerShell host limitation in field testing showed.

## Reporting

Every run produces three views of the same verified records. `findings.json` and SARIF are the machine readable truth. `REPORT.md` is the plain text record. `REPORT.html` is a single self contained one pager for humans, rendered deterministically by the CLI from the same records: verdict summary without any coverage score, confirmed findings with severity and proof tier, pending intent questions, what was not examined, and run metadata covering mode, budget, model and sandbox backend. The HTML file carries inline styling only, makes no external requests, works offline, prints cleanly to PDF, and escapes all target derived content so audited code cannot inject markup into the report. It is stored with the other run output outside the target tree and treated as sensitive, because it describes vulnerabilities.

## Privacy and network

OMGS itself sends nothing anywhere. There is no OMGS server, no telemetry and no analytics, reports stay on the local machine outside the target tree, and target code inside the sandbox has no external network access, so the app under test cannot phone home during proof execution.

Two flows do leave the computer, and public wording must never hide them. First, installation and updates download packages from their normal public sources. After installation, the deterministic checks can run offline against locally present tools and data. Second, the hunting and verification agents read the code, and that context goes to whichever model provider the user's chosen agent uses, exactly as it does in normal coding agent use. OMGS adds no new recipient, because the CLI never calls a model. A run is fully local only when the user pairs OMGS with a locally hosted model, with the quality tradeoffs that implies.

Approved public wording: no OMGS cloud, no telemetry, your code goes only where your agent already sends it. The unqualified claim that nothing leaves the computer is not approved.

## v0 scope boundary

In scope: one stack done deeply (TypeScript with Next.js App Router and Postgres or Supabase), the audit flow with tiered proof, sensors for secrets and supply chain with no model tokens spent on them, LLM hunting focused on missing authorization, IDOR and tenant isolation, client only auth checks and skipped webhook verification, SARIF output, and a benchmark built from real post cutoff CVE pairs with recall, false positives, cost and variance published.

Done means: the one prompt flow works on the benchmark apps, every confirmed finding carries its proof tier and evidence, gate and advisory modes both function, and OMGS passes an audit run against its own repository.

## Non goals for v0

- No auto fix pull requests. OMGS emits a fix brief with the proof test as the acceptance check.
- No live or production targets, ever, in the open source project.
- No coverage percentage or security score. Reports list what was not examined.
- No community pack registry. A documented pack format in the repository is enough.
- No second language until the first stack meets the benchmark bar.

## Deferred to later decisions

Each of these returns for its own decision before any work starts: final brand treatment of the name, benchmark corpus licensing, additional stacks and languages, additional sandbox backends, and whether an optional hosted runner should ever exist. Accepting this record does not approve any of them.
