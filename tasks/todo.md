# v0.1.0 public release: nothing deferred

Full plan: six themed PRs, then the Awesome Intune benchmark campaign and release readiness. Each PR
gets Muse Wonder Full review rounds (review partner), a GPT-6.1-Sol full-diff review before merge,
and a separate Claude evaluator; merge only when all are green.

Decisions: MXC is the only sandbox backend on every OS; one brief per role under `skill/agents/`;
benchmark is the 26 earlier Awesome Intune targets plus about 6 new, results private; the public
release uses a fresh squashed history.

Decisions 2026-10-27 (round 2): GPT-6.1-Sol writes the process supervision module
(`src/supervise.rs`: rlimits, group signal before reap, macOS survivor sweep); `omgs prove` refuses
on Intel Macs (no MXC executor there), documented in doctor and Known limitations; PR 5 will mirror the five MXC
executors as OMGS release assets with Microsoft signatures intact, pinned by SHA-256,
MIT notice included; tier 2 runs only on Linux (decided after testing showed the macOS sandbox
shares the host loopback in both directions, and Windows blocks loopback inside the container).

## PR 1: MXC sandbox and runner-attested proofs (`feat/mxc-sandbox-proofs`)

- [x] Spike MXC 1.0.1 on macOS (Swift fixture, cargo, cc, python3, node, pwsh; denials)
- [x] Spike on the Lima Ubuntu VM and the Windows mini PC
- [x] `src/sandbox.rs` emits MXC configs and runs the pinned executor; built-in profiles removed
- [x] Per-run writable workspace copy of the target; target untouched
- [x] rlimits, `waitid(WNOWAIT)` group signal, macOS survivor sweep (GPT-6.1-Sol, `src/supervise.rs`)
- [x] `prove --run --finding` proof records; `proof_ref` and `trace`; `validate` checks proofs
- [x] Budget enforcement and tier-2 first-run approval
- [x] `omgs doctor`; Windows portability; Windows CI through Test (round 5 verification below)
- [x] DECISIONS.md amendment: declared minimum set per OS
- [x] Tests and docs for rounds 1 through 5
- [x] Independent round 5 full-diff re-reviews and merge (merged as #11)
  - Round 2 (2026-10-27): GPT-6.1-Sol implements the round 2 fixes; evidence that the named test ran
    uses runner start and end markers (not per-stack adapters); windows-2025 CI must be fully green
    through the Test step before merge.

## PR 1b: follow-ups from the final PR 1 review (before release)

- [x] Redaction: carry quote state forward in one pass (no quadratic rescans on long lines)
- [x] Record absolute or re-entering symlinks that point back into the live target as a gap
- [x] Sort skipped special files before listing; escape control characters in printed gap paths
- [x] Usage text and README: say `--help`, `-h` and `--help=` are refused as free-text values
- [x] Refresh the copy and digest notes in this file to match skipped FIFOs and sockets
- [x] Test-name check: split only on shell delimiters, like the redaction fix (gate R9-N1)
- [x] Windows: use `wxc-exec --probe` for capabilities (enumeratePaths, deny paths, tier) instead of run-and-retry; show the tier in doctor and records
- [x] Validate every config with the executor's `--dry-run` before running, so a rejected config is reported as such
- [x] doctor: check the Windows build against MXC's published minimum builds and say when a feature is unavailable
- [x] README: link Microsoft's MXC docs where it explains why proofs run in a sandbox

Decided 2026-10-27: the four MXC items above are in 0.1; Windows Learning Mode capture is not.

PR 1b local verification: macOS passed fmt, Clippy with warnings denied and all
222 tests; Lima Ubuntu arm64 passed all 218 tests; Windows 11 x64 passed all
190 tests. All three pinned executors accepted valid dry-runs, rejected invalid
configs without starting a workload, and passed the live doctor check. The Lima
host has no rustfmt; no toolchain components were installed. Windows 11 reported
build 10.0.26200.9711 and base-container probe capabilities, including enumeration.
The windows-2025 CI probe reports appcontainer-dacl with DACL augmentation. CI
showed MXC 1.0.1 leaving changed ACEs on granted folders even after a successful
dry run, so on 2026-10-28 the owner decided that OMGS never writes host ACLs and
refuses augmentation tiers with exit 3 before any config-bearing MXC call;
windows-2025 CI now asserts that refusal. At head ff15a4e the Windows 11 x64
mini PC (build 26200.9807, base-container, no augmentation) passed the full
test suite and `doctor --live` with real MXC workloads inside the OMGS
kill-on-close job.
The five push CI jobs, including windows-2025 through Test, remain the head check;
parent-owned full-diff reviews and PR creation are separate from this implementation.

## PR 2: role briefs, stacks and packs (`feat/role-briefs-packs`)

- [x] `skill/agents/` briefs: red hunter, blue verifier, evaluator, green fixer
- [x] Proof by default with per-stack recipes
- [x] Windows toolchains reachable inside MXC: replace the batch-expanded `%t` lookup loop with actual version launches, supply a safe PATHEXT and disable Rust auto-install. The Windows 11 mini PC reports cargo, node and pwsh reachable in its interactive desktop session; real proofs launch all three. SSH session 0 DLL initialization remains an explicit runtime blocker.
- [x] Supervisor drain flake: Darwin pipe creation had a pipe()/fcntl(CLOEXEC) inheritance window across concurrent spawns. Capture uses atomically close-on-exec FIFO opens and executor children seal non-stdio descriptors. The 2 s drain bound is unchanged; deliberate inheritance and 192 interleaved supervisor calls pass.
- [x] Shared path classifier; shell and browser-extension stacks; monorepo detection
- [x] Packs: identity binding, fail-closed semantics
- [x] Persona modes; host-provided accounting

## PR 3: output people can trust and act on (`feat/report-handoff`)

- [x] HANDOFF.md, handoff.json, `omgs handoff`
- [x] `omgs stage` proposed-tests.patch
- [x] REPORT.md parity, timeline, SARIF rules and levels, metadata defaults
- [x] trufflehog and osv-scanner run; sensor hits become candidates

## PR 4: committed policy, gate and setup (`feat/policy-gate-setup`)

- [x] `.omgs/policy.json` from the base ref only; `intent propose`; `omgs gate`
- [x] `omgs setup` wizard per DECISIONS

## PR 5: onboarding, trust and distribution (`feat/onboarding-trust`)

- [x] README for newcomers; consent text before downloads
- [x] Version pin, signature checks, attestations, MXC pinning
- [x] Homebrew and winget files; subcommand help; env docs; SECURITY.md; stale docs

## PR 6: benchmark runner, corpus, screenshots, self-audit (`feat/benchmark`)

- [x] `omgs bench score`; at least 5 post-cutoff CVE pairs
  - Offline scorer and arithmetic fixtures implemented. The metadata-only inventory now contains five eligible pairs with verified SHAs, disclosure and public-fix dates, sources, and the complete 2026-06-30 cutoff. Both existing pairs are retained, including the May pair excluded from the post-cutoff count. See `benchmark/corpus/README.md`.
  - Phase 7 converts each pair into a scored manifest entry only after human confirmation, offline fixture preparation, dependency snapshot hashing and paired sandbox assertions. Inventory eligibility alone cannot be scored.
- [ ] Opt-in screenshots; self-audit; fix round trip on the fixture

## Phase 7: Awesome Intune campaign

- [ ] Pilot 4 repos after PR 3; tune and fix
- [ ] Full run after PR 6; scored against the 2026-10-16 baseline; anonymized aggregates only

## Phase 8: release readiness

- [ ] Re-sweep all docs for open items; squashed public history and private archive
- [ ] User steps: visibility, tag ruleset, tag push, tap and winget; fresh-machine install test

## Review

PR 1 round 5 fixes all twelve requested review items. The starting head
`f924e85` passed all four existing CI jobs, including windows-2025 through Test.
The updated branch adds Rust 1.89.0 build and test coverage as a fifth job.

Content hashing now accepts regular content through symlinks and hardlinks,
without a snapshot size cap. Small trust files keep bounded, single-link,
no-follow reads. Linux copies break hardlink relationships. Copy and digest
both skip target FIFOs and sockets; copy records their sorted paths as gaps (first
20, then a remaining count). Both refuse devices before reading them. Regression coverage includes
an intra-target hardlink pair, an 8 MiB file, symlinked executor and test paths,
and prompt FIFO skipping and device refusal. Symlink destinations are disclosed.

Credential flag components are redacted in output, saved command displays and
survivor lines, including quoted flags and single-dash long names. Every CLI
subcommand rejects unknown and duplicate options before mutation, preserving the documented repeatable evidence and counter
options. Shell operators delimit unquoted test names. Validation requires
bubblewrap for local-app records, forbids proof references on traced findings,
and avoids a test-name diagnostic after a missing or altered saved command.

Unix proof directories are 0700 and exact command and config artifacts are
0600. Unix signal guards cover preparation through execution; interrupted
preparation removes the proof directory and releases a charged reservation. Tests exercise
SIGINT, SIGTERM and SIGHUP before and after executor launch. Denial tests create
their home probe directly in the real home, with a scoped skip if unwritable.
Forged readable roots and extended Windows UNC proof directories have regression
coverage. README, skill and decision text agree on replay timeout, all `.git`
content, credential artifacts, Linux PID namespaces and Windows MXC teardown.

Round 5 local verification: macOS passed fmt, clippy with warnings denied and
all 192 tests; Lima Ubuntu arm64 passed all 188 tests; Windows 11 x64 passed
all 163 tests. All three live doctor probes passed with the pinned executors.
The Windows host has no Clippy component; its lint check runs in CI. The workflow
lint and skill metadata validator passed. Rust 1.89.0 is checked by the new CI job.

All five final PR CI jobs must pass on the pushed head, including windows-2025
through Test. Independent full-diff reviews and the separate evaluator remain
pending; implementation is not approval. Nothing from round 5 is deferred out
of 0.1. No merge is authorized by this implementation task.
