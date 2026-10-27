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
- [x] `omgs doctor`; Windows portability; Windows CI through Test (round 3 green; round 4 verification below)
- [x] DECISIONS.md amendment: declared minimum set per OS
- [x] Tests and docs for rounds 1 through 4
- [ ] Independent round 4 full-diff reviews and merge
  - Round 2 (2026-10-27): GPT-6.1-Sol implements the round 2 fixes; evidence that the named test ran
    uses runner start and end markers (not per-stack adapters); windows-2025 CI must be fully green
    through the Test step before merge.

## PR 2: role briefs, stacks and packs (`feat/role-briefs-packs`)

- [ ] `skill/agents/` briefs: red hunter, blue verifier, evaluator, green fixer
- [ ] Proof by default with per-stack recipes
- [ ] Shared path classifier; shell and browser-extension stacks; monorepo detection
- [ ] Packs: identity binding, fail-closed semantics
- [ ] Persona modes; host-provided accounting

## PR 3: output people can trust and act on (`feat/report-handoff`)

- [ ] HANDOFF.md, handoff.json, `omgs handoff`
- [ ] `omgs stage` proposed-tests.patch
- [ ] REPORT.md parity, timeline, SARIF rules and levels, metadata defaults
- [ ] trufflehog and osv-scanner run; sensor hits become candidates

## PR 4: committed policy, gate and setup (`feat/policy-gate-setup`)

- [ ] `.omgs/policy.json` from the base ref only; `intent propose`; `omgs gate`
- [ ] `omgs setup` wizard per DECISIONS

## PR 5: onboarding, trust and distribution (`feat/onboarding-trust`)

- [ ] README for newcomers; consent text before downloads
- [ ] Version pin, signature checks, attestations, MXC pinning
- [ ] Homebrew and winget files; subcommand help; env docs; SECURITY.md; stale docs

## PR 6: benchmark runner, corpus, screenshots, self-audit (`feat/benchmark`)

- [ ] `omgs bench score`; at least 5 post-cutoff CVE pairs
- [ ] Opt-in screenshots; self-audit; fix round trip on the fixture

## Phase 7: Awesome Intune campaign

- [ ] Pilot 4 repos after PR 3; tune and fix
- [ ] Full run after PR 6; scored against the 2026-10-16 baseline; anonymized aggregates only

## Phase 8: release readiness

- [ ] Re-sweep all docs for open items; squashed public history and private archive
- [ ] User steps: visibility, tag ruleset, tag push, tap and winget; fresh-machine install test

## Review

PR 1 results before round 4: commit `0bb66b0` passed all four CI jobs, including
windows-2025 through Test. Local macOS, Lima Ubuntu and Windows 11 exercised the
pinned MXC executors. Earlier reviews required in-sandbox test reachability,
marker-based execution evidence, canonical proof grants, honest platform gaps,
readable-root isolation and full-diff independent review. Those fixes remain.

Round 4 implements bounded no-follow hashing, exact replay timeout, digest-only
executor identity, recorded readable roots, full environment values, closed
config schema, command redaction with replay digests, nested `.git` hashing,
traced-reference identity checks, ordered console output, SIGHUP cleanup,
executable draft staging, canonical Windows overlap checks, Rosetta guidance and
Rust 1.89 minimum. Linux `setsid` and `posix_spawn(SETSID)` probes on Lima exited
cleanly with no marked descendants in the host process table. Regression tests
include a live host-process positive control before PID namespace teardown.
Windows wall-clock and doctor enumeration limitations are disclosed explicitly.

Round 4 local verification: macOS passed fmt, clippy with warnings denied and all
182 tests; Lima Ubuntu arm64 passed all 178 tests; Windows 11 x64 passed all 156
tests, including canonical root overlap and supervisor wall-clock disclosure.
All three live doctor probes passed. Linux escape probes observed each detached
child in the host process table before teardown and found no survivor after it.
The x86_64 macOS build passed, but Rosetta execution could not be checked because
this host has no translation runtime. Installer shell syntax was checked.

Every final PR CI job must pass on the pushed head, including windows-2025
through Test. Independent reviews and merge remain required; implementation is
not approval.
