# OMGS feature coverage from field rounds

Historical capability evidence from anonymous field reviews and regression tests. Tested means exercised end to end in those reviews. These observations are not published benchmark measurements. Partial means the surface ran but a decisive path remains unproven. Untested means the capability exists in code or docs but no field evidence exists yet.

## CLI commands

| Surface | Status | Evidence |
| --- | --- | --- |
| setup dry run and --yes | Tested | Installed into three agent skill directories, byte identical, idempotent on rerun. |
| review --repo-url | Tested | Cloned a GitHub repo, initialized a run, reused the clone on a second call and created run-2. |
| audit init | Tested | Anonymous field targets and reruns. Stack detection, sensors, outside-tree enforcement, owner-only permissions, shared-temp warning, gate and advisory metadata. |
| validate | Tested | Field report sets accepted; deliberately invalid records rejected for fingerprint, severity, proof tier, and evidence violations with exit 1. Since 2026-10-24 also rejects missing or equal `hunted_by` and `verified_by`, repeated locations, and invalid or doubly merged `candidates` (unit tests). |
| fingerprint | Tested | Stable across repeated and case-variant inputs. Used by every hunter record. |
| prove, MXC on macOS | Tested | 2026-10-27, MXC 1.0.1 `mxc-exec-mac`: installer-trust fixture (vulnerable exits 1, fixed exits 0), home and `~/.ssh` reads, outside writes, network, `defaults write`, `open`, `launchctl` and clipboard denied, Apple Events not delivered, workspace writable, target byte-identical, `setsid` grandchild killed and named, timeout kills the tree (`tests/sandbox.rs`). Earlier runs used the retired Seatbelt profile. |
| prove, MXC on Windows | Tested | 2026-10-27, MXC 1.0.1 `wxc-exec.exe` on Windows 11: `omgs doctor --live` denial, home reads denied, workspace writable, proof records written. PowerShell hosts still need an interactive desktop session; over SSH only cmd workloads run. |
| prove, MXC on Linux | Tested | 2026-10-27, MXC 1.0.1 `lxc-exec` on Ubuntu 24.04 arm64: home shows only the toolchain mounts, outside reads, writes and network denied, timeout kills the tree, memory and task limits applied through a systemd user scope. |
| prove proof records | Tested | `prove --run --finding` writes `proofs/<n>.json` with executor digest, config digest, enforced controls, gaps, exit, survivors and redacted output; `validate`, `report` and `critic` reject a tier above traced without a matching clean record. |
| report (Markdown, HTML, SARIF) | Tested | Anonymous field reports rendered; HTML escaping and zero external requests covered by unit tests; SARIF result output parses as JSON. |
| ledger set | Tested | Valid transitions applied, unknown unit rejected with exit 2. Since 2026-10-24 `covered` requires `--evidence` and `deferred`, `blocked`, `out_of_scope` require `--note` (unit and end-to-end tests). |
| ledger add, ledger list | Unit tested | Duplicate ids and unknown statuses refused; list exits 1 on rule violations. No field run yet. |
| batch init, batch index | Unit tested | URL validation table, index determinism and escaping, run summaries. No field batch yet. |
| status, watch | Unit tested | Status updates, routes, Host check, loopback bind, shutdown on completion over a real socket. |
| route | Unit tested | Fallback order, persisted refusals, exhaustion recorded as a blocker. |
| intent list, intent answer | Unit tested | Library well formed, unknown ids rejected, grouping, path-scoped answers keyed by target. |
| critic | Unit tested | Every gap class covered by tests and one end-to-end CLI run; report embeds the result. No field run yet. |
| check | Partial | Sensor execution and proof-test counting verified. Trufflehog and osv-scanner are detection only at this revision. Semgrep executes when local rules are configured or registry downloads are explicitly enabled; it was unavailable on the original field machine. |
| Gate enforcement | Untested by design gap | Mode is recorded in metadata and reports, but no CLI command fails a build in gate mode. Locked design says deterministic proof tests gate in the target CI, which no field target has exercised yet. |

## Proof tiers and lifecycle

The earlier tier 2 field run predates the 2026-10-27 decision that tier 2 runs only on Linux.

| Surface | Status | Evidence |
| --- | --- | --- |
| Tier 0 traced | Tested | Traced records exercised across anonymous projects. |
| Tier 2 sandbox exploited | Tested once | An anonymous field target exercised the tier-2 proof and independent-verification workflow. Target identity and finding details are withheld pending disclosure. |
| Tier 1 test proven | Partial | The tier is enforced by validation and unit tests, but no field proof has yet run through a target project's own test runner. A synthetic mechanism reproduction was deliberately left at needs validation for the field target. |
| Finding identity across runs | Tested | Same inputs produce identical fingerprints across invocations; prior findings revalidated and re-rendered in fresh run directories. Cross-run automatic deduplication does not exist yet. |
| Intent questions to policy | Partial | Questions are generated and rendered everywhere. Answering one into committed target policy has never been exercised because no policy file format is implemented. |
| Fix brief to fix to green test | Untested | Fix briefs exist on records. No field target has gone through fix application and proof re-run. |
| Sensors | Partial | Gitleaks executed on anonymous targets with redaction and vendored flags. Sensor hits are not yet converted into dispositioned finding records. |

## Skill packs

| Pack | Status | Field evidence |
| --- | --- | --- |
| generated-script-safety | Tested | Generated-script capability exercised on anonymous field targets. |
| feed-to-policy | Tested | Feed rollback, fail-open conversions, and filter broadening candidates. |
| privileged-local-ops | Tested | Deletion, symlink, guest-to-host, and elevated helper candidates. |
| powershell | Tested | Majority of field targets. |
| nextjs-authz | Partial | Applied in scoped Next.js reviews; no route-level proof attempted. |
| data-isolation-and-rls | Partial | Tenant candidates traced in several targets; no live schema or RLS proof. |
| client-only-auth | Partial | Static targets reviewed for DOM and client trust; no dedicated middleware-gap candidate survived. |
| webhooks-and-integrations | Partial | One unsigned-webhook shape appeared in the sample report design only; no field target produced a webhook candidate. Weakest pack evidence. |

## Platform and proof-method lessons

Historical testing exercised macOS arm64, Linux and Windows builds. Unsupported
sandbox capabilities must fail closed. Windows PowerShell startup can depend on
an interactive desktop session. See the current platform guidance in the
[project README](../README.md).

A harness compiling unmodified modules can support tier 1 when the substitution
is disclosed. A synthetic reproduction proves only the class and cannot promote
a target record. Anonymous examples live in [field-cases.md](field-cases.md).

## Current implementation and remaining release evidence

Batch initialization/indexing and routing with recorded refusals exist and have
regression tests. The offline benchmark scorer exists with arithmetic and evidence
validation fixtures. The public corpus contains synthetic examples only; no real-project measurement is claimed. Proof drafts stage into workspace
copies; committing accepted tests to target suites is an approved follow-up.

Installation includes consent, version pinning, native publisher verification,
mirrored MXC executors, provenance and package metadata generation. Local-bundle
installer tests cover forged checksums with signature rejection, version mismatch,
executor-pin mismatch and refusal of test overrides in the real installer. Public
signed release installation, package-manager publication and fresh-machine OS
prompts still require owner release evidence. Consult the current policy guidance for base-branch gates. See [the technical learnings](../IMPROVEMENTS.md) for further context.
