# OMGS feature coverage from field rounds

Status after rounds on 2026-10-16: the first six projects, the next twenty projects, implementation reruns, and targeted proof rounds. Tested means exercised end to end with evidence in this session. Partial means the surface ran but a decisive path remains unproven. Untested means the capability exists in code or docs but no field evidence exists yet.

## CLI commands

| Surface | Status | Evidence |
| --- | --- | --- |
| setup dry run and --yes | Tested | Installed into three agent skill directories, byte identical, idempotent on rerun. |
| review --repo-url | Tested | Cloned a GitHub repo, initialized a run, reused the clone on a second call and created run-2. |
| audit init | Tested | 26 field targets plus reruns. Stack detection, sensors, outside-tree enforcement, owner-only permissions, shared-temp warning, gate and advisory metadata. |
| validate | Tested | 26 report sets accepted; deliberately invalid records rejected for fingerprint, severity, proof tier, and evidence violations with exit 1. Since 2026-10-24 also rejects missing or equal `hunted_by` and `verified_by`, repeated locations, and invalid or doubly merged `candidates` (unit tests). |
| fingerprint | Tested | Stable across repeated and case-variant inputs. Used by every hunter record. |
| prove, MXC on macOS | Tested | 2026-10-27, MXC 1.0.1 `mxc-exec-mac`: installer-trust fixture (vulnerable exits 1, fixed exits 0), home and `~/.ssh` reads, outside writes, network, `defaults write`, `open`, `launchctl` and clipboard denied, Apple Events not delivered, workspace writable, target byte-identical, `setsid` grandchild killed and named, timeout kills the tree (`tests/sandbox.rs`). Earlier runs used the retired Seatbelt profile. |
| prove, MXC on Windows | Tested | 2026-10-27, MXC 1.0.1 `wxc-exec.exe` on the Windows 11 mini PC: `omgs doctor --live` denial, home reads denied, workspace writable, proof records written. PowerShell hosts still need an interactive desktop session; over SSH only cmd workloads run. |
| prove, MXC on Linux | Tested | 2026-10-27, MXC 1.0.1 `lxc-exec` on Ubuntu 24.04 arm64: home shows only the toolchain mounts, outside reads, writes and network denied, timeout kills the tree, memory and task limits applied through a systemd user scope. |
| prove proof records | Tested | `prove --run --finding` writes `proofs/<n>.json` with executor digest, config digest, enforced controls, gaps, exit, survivors and redacted output; `validate`, `report` and `critic` reject a tier above traced without a matching clean record. |
| report (Markdown, HTML, SARIF) | Tested | 26 targets rendered; HTML escaping and zero external requests covered by unit tests; SARIF emitted one result for the single confirmed finding and parses as JSON. |
| ledger set | Tested | Valid transitions applied, unknown unit rejected with exit 2. Since 2026-10-24 `covered` requires `--evidence` and `deferred`, `blocked`, `out_of_scope` require `--note` (unit and end-to-end tests). |
| ledger add, ledger list | Unit tested | Duplicate ids and unknown statuses refused; list exits 1 on rule violations. No field run yet. |
| batch init, batch index | Unit tested | URL validation table, index determinism and escaping, run summaries. No field batch yet. |
| status, watch | Unit tested | Status updates, routes, Host check, loopback bind, shutdown on completion over a real socket. |
| route | Unit tested | Fallback order, persisted refusals, exhaustion recorded as a blocker. |
| intent list, intent answer | Unit tested | Library well formed, unknown ids rejected, grouping, path-scoped answers keyed by target. |
| critic | Unit tested | Every gap class covered by tests and one end-to-end CLI run; report embeds the result. No field run yet. |
| check | Partial | Sensor execution and proof-test counting verified. Trufflehog, osv-scanner, and semgrep paths are detection only in code and were unavailable on the test machine. |
| Gate enforcement | Untested by design gap | Mode is recorded in metadata and reports, but no CLI command fails a build in gate mode. Locked design says deterministic proof tests gate in the target CI, which no field target has exercised yet. |

## Proof tiers and lifecycle

| Surface | Status | Evidence |
| --- | --- | --- |
| Tier 0 traced | Tested | 79 records across 26 projects. |
| Tier 2 sandbox exploited | Tested once | Intune Drive Mapping Generator: unmodified target template plus generator-faithful replacement executed in Seatbelt sandbox; injected statement printed the marker. Record upgraded to confirmed, high severity, by an independent verifier pass. |
| Tier 1 test proven | Partial | The tier is enforced by validation and unit tests, but no field proof has yet run through a target project's own test runner. The AppPruner shell interpolation was replicated line-faithfully in the sandbox and deliberately left at needs validation. |
| Finding identity across runs | Tested | Same inputs produce identical fingerprints across invocations; prior findings revalidated and re-rendered in fresh run directories. Cross-run automatic deduplication does not exist yet. |
| Intent questions to policy | Partial | Questions are generated and rendered everywhere. Answering one into committed target policy has never been exercised because no policy file format is implemented. |
| Fix brief to fix to green test | Untested | Fix briefs exist on records. No field target has gone through fix application and proof re-run. |
| Sensors | Partial | Gitleaks executed on 26 targets with redaction and vendored flags. Sensor hits are not yet converted into dispositioned finding records. |

## Skill packs

| Pack | Status | Field evidence |
| --- | --- | --- |
| generated-script-safety | Tested | Dominant class across both batches, including the one confirmed finding. |
| feed-to-policy | Tested | Feed rollback, fail-open conversions, and filter broadening candidates. |
| privileged-local-ops | Tested | Deletion, symlink, guest-to-host, and elevated helper candidates. |
| powershell | Tested | Majority of field targets. |
| nextjs-authz | Partial | Applied in scoped Next.js reviews; no route-level proof attempted. |
| data-isolation-and-rls | Partial | Tenant candidates traced in several targets; no live schema or RLS proof. |
| client-only-auth | Partial | Static targets reviewed for DOM and client trust; no dedicated middleware-gap candidate survived. |
| webhooks-and-integrations | Partial | One unsigned-webhook shape appeared in the sample report design only; no field target produced a webhook candidate. Weakest pack evidence. |

## Multi-machine results (Tailscale mini PCs, 2026-10-16)

| Host | Result |
| --- | --- |
| Mac mini (macOS 27, arm64) | The locally built arm64 binary ran unchanged. Setup dry run, stack detection, and Seatbelt containment (scratch write allowed, outside write denied, network denied) all passed. |
| Linux NUC (Ubuntu, x86_64) | Built from source with a user level Rust toolchain. All 9 tests passed. Bubblewrap containment passed every check: scratch write, outside write denied with a read-only root, network namespace denied, timeout enforced. |
| Windows mini PC (Windows build 26200, AMD64) | Built from source with the GNU Rust toolchain, all 9 tests passed, and setup, stack detection, audit init, and check all ran. `prove` correctly failed closed with exit 3 before MXC was installed. With MXC SDK v1.0.0 release binaries installed and the new config-based OMGS backend, cmd workloads run contained: scratch write allowed, outside write denied, network denied. Native PowerShell AST parsing independently confirmed the Drive Mapping breakout statements. Two Windows-only bugs were found and fixed through this host: canonicalized extended-length paths that cmd.exe rejects, and the MXC environment and UI policy requirements. One limitation remains: both PowerShell hosts fail with STATUS_DLL_INIT_FAILED inside MXC when launched from an SSH session, even with ui.disable false and processContainer desktop isolation applied and dry-run validation passing. This matches MXC's documented PowerShell UI restriction sensitivity and likely requires an interactive desktop session to test further. Windows Sandbox is disabled on this host. |

## Cold install results (skill first path, 2026-10-16)

Timed runs from a clean fake home to a validated `REPORT.html`, against the locally staged unsigned v0.1.0 bundle in `dist/v0.1.0` served over the tailnet. Both bootstrap scripts verify the downloaded asset against the bundle `SHA256SUMS` and fail closed on mismatch. The sample target produced zero findings, so these runs prove the install and empty-report chain, not finding quality. Download time over a LAN is not representative of the public internet.

| Host | Result |
| --- | --- |
| macOS (this Mac, fake HOME) | 2.6 s end to end. Real Skills CLI install (`npx skills add`), POSIX bootstrap downloaded and checksum verified the arm64 binary, then audit init, validate, and report all exited 0 with `REPORT.html` produced. |
| Linux NUC over SSH | 0.5 s for bootstrap to report. POSIX bootstrap checksum verified the x86_64 Linux binary; audit init, validate, and report passed. The Skills CLI install was verified separately on this host (`npx skills add` installed `SKILL.md` into a fresh project). |
| Windows mini PC over SSH | 2.5 s for bootstrap to report. PowerShell bootstrap checksum verified the Windows exe; audit init, validate, and report passed. The Skills CLI install was verified separately on this host the same way. |

First cold run attempt failed on both remote hosts for a test-harness reason only: the script targeted a stale Tailscale address for this Mac. After correcting the address, both passed unchanged. Remaining install gaps: the bundle is unsigned and unpublished, so the public GitHub Releases path, code signing and notarization, and first-run OS prompts are still unproven.

## Field run 2026-10-23 (Swift macOS updater with root helper)

One public third party target reviewed through `omgs review --repo-url` in advisory mode at a pinned commit. Details remain in the private run directory pending disclosure.

- Full pipeline exercised: review clone, audit init (stack `swift`, 74 files, gitleaks 0 hits), two isolated Red hunters, Blue verification, `omgs prove` (Seatbelt), an independent evaluator pass with adjudicated corrections, `validate` (13 records), `ledger set`, and `report` producing agreeing HTML, Markdown, JSON, and SARIF outside the target tree. The target worktree was never written to. Final verdicts: 0 confirmed, 10 needs validation, 3 rejected.
- Tier 1 stays partial, with a sharper data point: invariant assertions executed against unmodified target modules inside `omgs prove` with an authorized control, but through a `swiftc` built harness because `swift test` cannot run under the Seatbelt profile. At the time the independent evaluator refused the `test_proven` label for that substitution and both records were demoted to traced needs-validation. The doctrine has since been clarified (see the proof ladder in [../skill/VALIDATION-AND-REPORTING.md](../skill/VALIDATION-AND-REPORTING.md)): a harness that exercises the unmodified target code and asserts the real invariant inside `omgs prove` does earn `test_proven` when the runner substitution is disclosed; only a harness that reimplements or stubs the logic does not. Under that rule, a harness compiling the unmodified target modules would qualify, whereas the separate synthetic reproducer shipped in `benchmark/fixtures/installer-trust` proves the class and fix, not the target, and does not promote a target record.
- Blue disproof produced rejected records with sandbox counterevidence, the first field run where rejected candidates were decided by executed tests (archive tool behavior with the helper's exact flags) rather than source reading alone. The evaluator also overturned one needs-validation record to rejected (defense-in-depth without an attacker capability) and added two missed needs-validation records (destination swap pinning, helper resource budgets).
- New sandbox limits observed: daemon mediated writes (preferences through cfprefsd) escape file containment, and `NSTemporaryDirectory()` ignores the scratch home. Both are recorded as suite learnings in IMPROVEMENTS.md.
- Root-level confirmation was deferred during the main run: records requiring an installed root helper or a Developer ID signed probe package stayed needs validation with manual validation plans. The signer-trust and downgrade defects are decision-logic defects, and the `benchmark/fixtures/installer-trust` reproducer demonstrates that defect class and its fix in the sandbox (vulnerable fails, fixed passes, entirely inside `omgs prove`, no VM). That reproducer models the logic; it is proof of the class and recipe, not of any specific vendor build, so it does not by itself promote the target records. The target records themselves come from a separate static review of the real code and stay `needs_validation`/`traced`; the effect that needs real root has no proof tier and stays `needs_validation`. A separate live run did first exercise the real helper's paths as root, which established the effect, on a machine that turned out to be productive rather than disposable; that was a mistake, since remediated (Gatekeeper re-enabled, passwordless sudo and test artifacts removed), and such a live run is a manual step outside OMGS, never a tier and never required. Two symlink-handling leads were refuted. The write-ups are in [field-cases.md](field-cases.md) (candidates 4 to 6); vendor material stays in the private run directory.

## Not yet existing, therefore untestable

Signed release binaries and package-manager distribution, proof test staging into target suites, base-branch policy loading, batch mode, benchmark runner, and model rerouting on refusal. These are tracked in IMPROVEMENTS.md.

## Field run 2026-10-24 (full multi-agent pipeline on a macOS updater)

A second field run on the same public macOS updater with a root helper, this time the full multi-agent pipeline rather than a single pass: three isolated red hunters (one per boundary), an independent blue verifier that deduped and disproved, tier-1 `omgs prove` sandbox proofs on unmodified target code, and a separate evaluator adjudication. About 21 raw candidates deduped to 12 records: 0 confirmed, 8 needs validation, 4 rejected, 3 of them carrying test_proven mechanism evidence. The run exercised the coverage ledger end to end (six boundary units, five covered, one deferred) and produced agreeing HTML, Markdown, JSON, and SARIF outside the target tree. It demonstrated both halves of the discipline: it surfaced sharper genuine issues the earlier static pass missed and it independently rejected four weak leads with counterevidence. Target specifics stay in the private run directory pending disclosure.
