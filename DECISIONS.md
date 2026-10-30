# Oh My God Security: Locked Decisions

Status: Final. Locked by the founder on 2026-10-16 after a grill review.
Short name: OMGS. CLI name: `omgs`.

## Goal

An open source, local first, model and agent agnostic security audit suite for codebases in the vibe coding era. It audits a repository, proves or disproves each finding, and leaves behind regression tests and a plain language report. It shrinks the red, blue and green loop from enterprise security operations down to a single repository, built on the audit discipline of Cloudflare's security-audit-skill.

## Positioning

Public framing, settled after the main lock and revised once: OMGS stands entirely on its own name and story. Red hunts, blue verifies, green guards: red agents hunt and draft proof plans, blue agents verify and run initial proofs in the sandbox, triage and ask intent questions, and green agents produce fix briefs, regression tests and hardening proposals that a human approves. Red, blue and green team language is generic security vocabulary and needs no vendor framing. No other company's name or product appears in the project name, tagline, README hero, landing material or marketing comparisons, and OMGS never claims affiliation with, equivalence to, or endorsement by any vendor. Attribution exists only in the provenance layer where it is legally or technically required: preserved license notices for reused MIT licensed material, a third party credits file, and dependency names in build and lock files, including the MXC SDK. This decision record itself is provenance, not marketing copy.

## Prime directive: dead easy

Ease of use outranks every feature. The target experience is one sentence to the coding agent the user already has: run an OMGS security review on this project. The agent installs OMGS from its GitHub repository, runs the review and the tests, and returns a report the user can act on. If a feature cannot survive that flow, it does not ship in v0.

Acceptance test for this directive: a new user goes from zero to a first proven finding with one prompt or one command, no OMGS account, no OMGS API key, no config file, and no manual sandbox setup.

## Locked decisions

1. Users, revised after field testing: everyone who ships code with agents, served by one engine with persona modes rather than separate products. Builder mode serves product, script, and small tool authors reviewing their own work before shipping, with plain language intent questions, visual proof, and fix briefs their agent can act on. Inheritor mode serves AppSec, platform engineers, and maintainers auditing code they did not write, with full traces, SARIF, and coverage detail. Team mode serves larger products with gate or advisory CI behavior and base-branch policy. Persona modes change defaults, report depth, and budget profiles only. The evidence bar, proof tiers, and sandbox rules are identical for everyone.
2. Cloudflare's security-audit-skill stays upstream and pinned. Attack class pack content is contributed back upstream where possible. OMGS owns only the deterministic layer upstream does not ship: the runner, scanners as sensors, finding identity across runs, sandbox proof execution, budgets, modes and the public benchmark.
3. The OMGS CLI is deterministic and never calls a model. The user's agent does the reasoning locally, or a headless agent does it in CI under a tool allowlist the runner enforces. Schema validation, deduplication, identity, sensors, budgets, gates and proof execution are code, not prompts.
4. Gate mode and advisory mode both ship, and the user can switch between them. In gate mode only deterministic artifacts block a merge: a committed failing security test or a scanner rule. Model output never blocks. In advisory mode nothing blocks. The mode lives in committed policy loaded from the base branch under normal code owner review, never from a pull request head, so no change can switch off its own gate. A security test is gate-authorized only by the base policy registry after owner review; gate reruns its exact recipe contract against committed head files with a fresh nonce. Saved run findings, proof records and policy snapshots never authorize blocking.
5. Proof is a tiered ladder, and a finding earns the tier it actually reached:
   - Level 0, traced: a complete source trace from input to sink. Candidate only, never confirmed. Traced findings must omit `proof_ref` and retain the trace in `evidence`.
   - Level 1, test proven: an agent written failing test, executed by the project's own test runner inside the sandbox. This earns confirmed, becomes the regression test, and is eligible to gate.
   - Level 2, sandbox exploited: an agent exercises a locally built copy of the running app inside the sandbox on synthetic data. Highest confidence, used only when a test cannot decide, and a human approves its first run per repository.
   Escalation is decided by the deterministic runner under the run budget, cheapest decisive tier first. Public wording is sandbox verified against a local build. OMGS never claims to pen test a live system.
6. Findings never live in the target tree. Run output defaults to a directory outside the repository. Only intent answers, policy, suppressions and accepted proof tests are committed.

## Local trust and CI enforcement

The enforcement point is `omgs gate` in CI. It reads policy from the base
commit, reruns committed tests in MXC, and trusts no local run artifacts.
CI gate results remain authoritative.

Locally, OMGS protects against run artifacts written or edited through the run
directory, including agent output and imported or copied runs, and against other
OS users. Owner-private storage and admission checks enforce this boundary.

A process running as the same OS user with arbitrary file access can change
anything that user owns, including `OMGS_HOME`. Local reports cannot be protected
against such a fully compromised agent shell. This is a documented limit.
Local provenance does not isolate a run from its owner.

## Sandbox requirements for proof execution

Target controlled code, including builds, tests and the running app at level 2, executes only inside an OS enforced sandbox. Amended on 2026-10-27: Microsoft MXC is the only backend on every OS (Seatbelt through `mxc-exec-mac` on Apple Silicon macOS 15 or later, bubblewrap through `lxc-exec` on Linux, ProcessContainer through `wxc-exec.exe` on Windows 11 builds where the MXC probe reports no DACL augmentation; tiers that need augmentation, such as the one observed on Windows Server 2025, are refused); OMGS's own Seatbelt and bubblewrap profiles are removed. The executor is pinned by SHA-256 to one MXC release and refused on any mismatch. Every proof run aims for all of the following, and its proof record names exactly what was enforced and what was not:

- No external network. Local client and server traffic stays on an isolated loopback.
- An empty environment built from an explicit allowlist, with scratch local home, temp and cache directories. Dummy principals and dummy secrets only.
- A read only target and toolchain. The target process writes only inside its assigned scratch directory and a per-run copy of the target; the original target is never mounted.
- Explicit limits on CPU, memory, processes, per-file size and wall clock time where supported. There is no total disk quota. Unix limits each file to 1 GiB; Windows has no per-file limit.
- No dependency installation and no network fetching during proof execution. Only tools and dependencies already present locally are used. Rust proxies receive `RUSTUP_AUTO_INSTALL=0`.
- Attempt a sandbox proof for every candidate whose runtime is reachable, within the declared budget. Use the per-stack recipes; record exact runtime, sandbox or budget blockers when an attempt cannot proceed. Runtime reachability means a successful version-command launch inside MXC, not a PATH lookup.
- Execution stops at the minimum local effect that proves the boundary violation.

Declared minimum set per OS (amended on 2026-10-27, replacing the rule that every control above must hold everywhere, because no OS sandbox offers all of them). Below this set OMGS refuses to run target code:

- macOS (Apple Silicon): MXC deny-by-default filesystem with the target copied into a per-run workspace, external network denied, environment cleared to an allowlist, CPU time, file size and open file limits, a wall clock with the whole process group killed, and dedicated launchd resource coalition ownership that certifies cleanup, records and kills escaped descendants and fails the run when survivors existed. Intel Macs have no MXC executor, so `omgs prove` refuses there.
- Linux: MXC deny-by-default filesystem with a per-run workspace copy, external network denied, environment cleared to an allowlist, CPU time, file size and open file limits, process group cleanup on wall-clock expiry, and PID namespace teardown for descendants, including detached sessions. There is no macOS survivor sweep on Linux. Memory and task limits also apply through a systemd user scope where one exists.
- Windows: only a supported, consistent MXC probe tier with `needsDaclAugmentation=false` may run proofs. Windows 11 builds reporting no augmentation remain supported. The observed `appcontainer-dacl` tier on windows-2025 is refused by `prove` and `doctor --live` with exit 3, before proof staging or any config-bearing MXC invocation, including a dry run. The message names the tier, explains that MXC 1.0.1 leaves changed ACEs on granted folders even after a successful run, and identifies the supported Windows 11 case. CI run 40663981530 observed this drift after a successful dry run on workspace, scratch and several toolchain roots. The owner decided that OMGS never writes host ACLs. Exact DACL restoration, administrator preparation and automatic ACL repair are not part of OMGS.

  Detector-error JSON is parsed with default warnings and probe facts when absent, retaining its error text. Neither a detector error nor an unavailable probe establishes safety. Both block before configuration, as do probe timeout, interruption, invalid output, nonzero success data and unknown or inconsistent tiers. The earlier guarded enumeration retry is no longer used when probe safety is unknown. Supported tiers omit enumeration if the probe says it is unavailable; relative nested paths remain usable, while directory listing, absolute paths and `NUL` redirection can fail. Doctor reports OS build minimums as information, but the probe safety gate decides support. Windows Server 2025 shares build 26100 with Windows 11 24H2; Microsoft publishes no separate Server minimum.

  The supported tier keeps a fail-closed ACL check: before the first config-bearing invocation, resolve workspace, scratch and read-only roots, retain handles and object identities, and snapshot ACLs with bounded `icacls /l` calls. Verify after every dry-run outcome and every workload exit before returning or starting another executor. ACL drift, replacement or failed inspection marks cleanup incomplete; dry-run cleanup failure blocks execution and retry. The wrapper end marker cannot erase executor termination evidence. Inspection ignores pending interruption while keeping its own time bound. OMGS performs no repair. These checks do not walk descendants or inspect `enumeratePaths` parent directories, which an unexpected augmentation path could also affect. Unchanged roots cannot establish restoration of every host object.

  Lifetime ownership is race-free: before spawning any executor, OMGS places itself in an unnamed `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job. Its only handle is non-inherited and retained until process teardown. Children inherit membership at creation, without breakaway permission, and Windows supports MXC's nested job. Failure to establish ownership blocks spawning. `process.timeout = 0` disables MXC's internal timer; OMGS's finite wall clock requests Ctrl+Break, allows five seconds for cleanup, and forces termination if necessary. The lifetime regression force-terminates an owner supervising a native executor and infinite child, retains handles to both and requires termination within five seconds, without needing an augmentation-tier MXC invocation.

  Force-terminating OMGS skips executor cleanup. The supported tier should not augment DACLs, but ACLs left by older augmentation runs can remain changed, and a killed OMGS cannot write a final proof record. Treat such a run as unclean. Inspect granted roots, descendants and any enumeration parents using `icacls`, comparing against a trusted ACL backup. An operator may explicitly run the pinned `wxc-exec.exe --probe` for MXC's best-effort orphaned-state recovery and inspect its diagnostics; it does not guarantee exact inheritance restoration. Have the owner or administrator restore affected ACLs from trusted backups if needed. OMGS neither repairs host ACLs nor claims recovery succeeded.

  On augmentation CI hosts, real proof-run tests assert refusal, the diagnostic, absence of config invocation/artifacts and unchanged root ACLs. Safe Windows tiers keep real proof coverage. Probe parsing, strict success shapes, error-only shapes, build boundaries, supervisor timeout ownership, native job lifetime, linked-root identity and simulated ACL drift remain tested without augmentation. Real dry-run and timeout fixtures run only when the probe establishes no augmentation; forced LPAC fallback fixtures were replaced with the up-front refusal contract. No per-process CPU, file size or open file limits apply on Windows.
- Tier 2 runs only on Linux, decided on 2026-10-27: there the sandbox has its own network namespace, so the app and its client talk over a private loopback while host services stay unreachable (verified). On macOS the sandbox shares the host loopback (a Seatbelt app could reach services on the host loopback, observed), and on Windows the container blocks loopback even within itself unless the host loopback is exempted, so `omgs prove --tier 2` refuses on both and names the reason. Tier 2 also requires the per-repository human approval given at a terminal with `omgs approve`.

Sensors follow the same per-OS enforced set as `omgs prove`, including no memory or task cap on macOS or Windows. Linux sensors request a systemd cgroup scope and record the same missing-cgroup gap as proofs when it is unavailable. Native scanner grants cover only the executable file; Python entry points receive only the entry script, interpreter file, interpreter prefixes reported by isolated Python introspection inside pinned MXC, a venv prefix identified by `pyvenv.cfg`, and the specific site-packages containing Semgrep. Directory names such as `bin` and `Scripts` never establish an installation prefix. Discovery starts with file-only grants, `-I -S`, and no host interpreter execution. Interpreters that cannot bootstrap this way are refused with a gap rather than receiving guessed directory grants. A proven user site-packages under HOME is acceptable because it contains third-party executable code already trusted as the installed sensor; it does not authorize its parent user prefix. The whole selected site-packages stays readable to the scanner, including unrelated packages, `.pth` contents and anything a package stored there, so a dedicated virtual environment for Semgrep is recommended. Whole profiles, shared data prefixes (including `.local`, `.local/share`, `Library` and AppData roots), secret locations (including `.ssh`, `.aws`, `.config` and keychains), and grants overlapping the original target or permanent artifacts are refused with a gap before sensor execution. Sensor scratch must not overlap the target, artifacts or any readable grant, checked before creation.

System directories and the installed toolchain roots remain readable, including `~/.cargo/{bin,registry,git}` and `~/.rustup` when present. Homebrew grants cover only build subdirectories, excluding `etc` and `var`. Doctor and every proof record disclose the actual roots and conditional gaps. Target hardlinks to outside content become readable workspace content; git checkouts cannot create them. Runner start and end markers catch accidents such as executor failure, truncation and timeout. They cannot establish integrity against a hostile target: the per-run nonce is visible to sandboxed code, which can print a forged end marker. The wrapper must open the named test inside the sandbox before running the command; an unreachable test or missing reachability evidence makes the record unclean for every verdict, including rejected controls. This cannot prove that the named test executed. Replay and the independent evaluator remain the stronger check. Replay requires the recorded timeout and rejects overrides, checks the target commit, copied-tree digest including all `.git` content, inner exit code and cleanliness, consumes proof budget, and is paired with the independent evaluator.

Linux grants `/usr/include` read-only explicitly. The pinned MXC bubblewrap baseline does not mount it. C and Swift builds need its public system headers, so this narrow system grant is accepted; it grants no writes and does not include user data. The Swift recipe regression compiles against it inside `omgs prove`.

Content hashing follows executor and test symlinks only to regular files, discloses their destinations and accepts hardlinks. Snapshot hashing has no size cap. Target FIFOs and sockets are skipped in the workspace copy and snapshot digest, with up to 20 paths recorded as proof gaps and one aggregate count for the remainder. Devices are refused before copying. Linux copies break hardlink relationships. On Unix, both copy paths preserve symlinks as links; outside or unresolved links are disclosed as a counted proof gap; live-target link disclosures are sorted, capped at 20 paths and followed by a remainder count and remain subject to sandbox access rules. Small trust files retain bounded, single-link, no-follow reads. Exact command and config artifacts can contain credentials; protect the entire run directory. On Unix proof directories are 0700 and command and config files are 0600. On macOS and Linux, SIGINT, SIGTERM and SIGHUP guards cover preparation and execution: blocked preparation removes the proof directory and releases its budget charge; interrupted execution retains an unclean record and its charge.

If any control in the declared set cannot be enforced on the current platform, OMGS does not execute the target code. The finding stays at the highest tier already earned, the missing sandbox capability is recorded as the exact blocker, and the report gives a safe manual validation plan. Degrading honestly beats running unsandboxed silently.

## Installation and use

Installation must work for agents first, because in practice an agent does the installing. The repository README is written so an agent can follow it end to end without human help, and the same instructions serve humans.

Distribution decision, settled after the main lock and revised once: skill first. The primary install is the skill pack through the Skills CLI or an agent prompt, the same shape as the reference skill this project builds on. On first run the skill bootstraps the deterministic binary itself: a bundled per-platform install script downloads the matching signed release binary, verifies its SHA-256 against the release SHA256SUMS, and installs it without elevation into a per-user OMGS directory. Direct binary installation (GitHub Releases, later Homebrew and winget) remains the secondary path for humans and enterprises. There is no npm package for OMGS itself and no hosted service. Signing is mandatory from the first public release: Apple Developer ID with notarization on macOS and Windows code signing on Windows, with checksums and signatures published for every release asset. The CLI runs proofs only through the pinned Microsoft MXC executor for the platform. Release work in PR 5 will mirror the five Microsoft-signed executors (macOS arm64, Linux arm64 and x64, Windows arm64 and x64) as release assets, unmodified and pinned by SHA-256 with the MIT notice, so installing them will be part of installing OMGS without the 542 MB MXC release archive; the skill will explain both downloads before making them. This mirroring is planned for 0.1, not shipped in PR 1. A graphical setup wizard is a non goal for v0 and a deferred decision afterwards.

Three supported entry points, all zero config by default:

1. Skill install, the primary path: the user installs the skill with one Skills CLI command or asks their agent to add it, then says "run an OMGS security review on this project". On first run the skill bootstraps the signed binary through its bundled install script, verifying the checksum, and the agent continues into the audit without further user steps.
2. Human install: the user installs the signed binary and runs `omgs setup` once. Setup is a terminal wizard: it detects the installed coding agents, installs the skill pack into each, verifies the MXC backend enforces its policy, writes the default policy, and offers the gate or advisory choice. Every setup step also works through flags with no interaction, for agents and scripts.
3. Skill install: the pack installs into any agent that supports skills, with a plain instruction file fallback for agents without a skill system. Model agnostic by construction, because OMGS never calls a model and holds no provider keys. Users keep the agent and subscription they already have.

Defaults that protect the prime directive: no account, no telemetry, no OMGS server, no Docker requirement, no Node or other language runtime requirement, and sensible defaults for budget, profile and mode that the user can change later in the committed policy file. The audit command shows the budget and mode before spending anything and writes the report outside the tree.

## Visual evidence

Sandbox proofs may capture screenshots as supporting evidence, opt-in per run. Web targets are the first supported surface: the locally built app runs in the sandbox, a headless browser already present on the system captures proof moments against dummy data, and the CLI embeds resized copies into REPORT.html as inline data so the one pager stays a single offline file. Originals stay in the run directory under artifacts with hashes recorded in findings.json. Screenshots never replace a proof test or trace, must contain dummy data only, are size capped, and are skipped with the exact blocker recorded when no browser or GUI access exists inside the sandbox. Desktop GUI capture and terminal rendering are later surfaces, since GUI access inside sandboxes is platform sensitive, as the Windows PowerShell host limitation in field testing showed.

## Reporting

Every run produces three views of the same verified records. `findings.json` and SARIF are the machine readable local record, subject to the local trust limits above. `REPORT.md` is the plain text record. `REPORT.html` is a single self contained one pager for humans, rendered deterministically by the CLI from the same records: verdict summary without any coverage score, confirmed findings with severity and proof tier, pending intent questions, what was not examined, and run metadata covering mode, budget, model and sandbox backend. The HTML file carries inline styling only, makes no external requests, works offline, prints cleanly to PDF, and escapes all target derived content so audited code cannot inject markup into the report. It is stored with the other run output outside the target tree and treated as sensitive, because it describes vulnerabilities.

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

## 2026-10-28: required proof contracts and nonce-qualified recipe evidence

Proof schema `omgs-proof/2` requires an explicit `contract` discriminator, either
`none` or `recipe`. Recipe declarations and both marker evidence flags are
required and non-null. The MXC environment records the declaration and fresh
per-run nonce, binding them to the saved config digest and reconstructed command.
Older schemas predate the current policy, including `RUSTUP_AUTO_INSTALL=0`, and
must be rerun. No compatibility shim weakens the environment allowlist.

Recipes emit `OMGS_CONTROL_<nonce>` and `OMGS_BOUNDARY_<nonce>_<label>` using
`OMGS_PROOF_NONCE` and `OMGS_PROOF_CONTRACT`. Fixed or wrong-nonce output cannot
satisfy the contract. Hostile code sharing the harness process can read the nonce
and forge those lines. The independent evaluator remains required. Real
provenance would need assertion reporting separated from target execution, for
example a trusted reporter in a separately isolated process with a private
channel unavailable to target code. That option needs a defined isolation policy
and is not implemented in this PR.


## Complete storage-chain admission and verified publication

Onboarding installers verify SHA256SUMS, publisher signatures, optional provenance
and MXC pins in newly created owner-only staging. Only then do they invoke the
staged executable's internal `install-self` command. Rust owns admission and
publication for OMGS, the mirrored MXC executor and its license. There is no
second shell or PowerShell permission policy.

One shared safe-path check covers installation and run storage. It walks the
complete existing directory chain through the filesystem root, including above
HOME and USERPROFILE. Root-owned intermediate directories are not anchors.
Symlink and reparse ancestors are refused; callers must use physical paths.
On Unix, ancestors must be owned by root or the current user and must not be
writable by other users. A sticky writable ancestor is allowed only when its
child is owned by root or the current user. macOS extended ACL mutation grants
are checked on every ancestor and leaf under the existing ACL rules, including
inheritable grants. The publication or run directory never gets a sticky
exception. Run directories still require mode 0700.

Windows ancestors allow the current user, SYSTEM, BUILTIN\Administrators and
TrustedInstaller as owners and mutation principals. An INHERIT_ONLY_ACE is
ignored on ancestors because it grants no rights on that directory; each child
is checked independently using its own DACL. Effective DELETE_CHILD, DELETE,
WRITE_DAC, WRITE_OWNER and FILE_WRITE_ATTRIBUTES grants to other principals
are refused, including generic write/all mappings. FILE_ADD_FILE and
FILE_ADD_SUBDIRECTORY alone are allowed on ancestors because they cannot
replace an existing entry. This permits default drive roots without trusting
profile paths implicitly. Publication directories, run directories and leaf
files retain the strict current-user ownership and existing mutation allowlist
(current user, SYSTEM, Administrators, and CREATOR OWNER mapping to that user),
including effective and inheritable ACEs. TrustedInstaller gets no exception
there. New Windows directories and files receive owner-only protected DACLs
at creation.

Existing installation files must be single-link regular files, owned by the
current user and without write grants for other principals. Unsafe existing
objects are refused with their path and are never repaired. All verified files
are copied to exclusive same-filesystem siblings and checked for complete bytes
before any publication. Unix rename and Windows MoveFileEx(REPLACE_EXISTING)
replace the exact destination entry. The latter retains the fresh source DACL,
unlike File.Replace, which preserves destination permissions. Admission is
rechecked before and after publication. Sharing violations preserve the locked
destination, report stop-and-retry guidance, and clean remaining siblings.
A failure after an earlier successful publication can leave a mix of complete,
verified versions; retry completes the installation. Trusted owners must not
rename or replace storage concurrently with a run or installation.

## Run evidence and source content admission

Run evidence is private, bounded data read relative to the trusted run directory
through `run_artifact::read`. Descendant directories and leaves cannot be links
or Windows reparse points. The opened leaf must be a regular file without
hardlink aliases, and descriptor validation and byte limits apply before parsing
or hashing. Only genuine absence is optional; linked, special, unreadable and
oversized artifacts are errors. Named limits cover each artifact kind, including
16 MiB run metadata and retained test drafts, 2 MiB proof records and configs,
and 1 MiB saved commands. Concurrent atomic replacement may leave an already
opened snapshot with zero links; it has no aliases and remains safe to read.

Target checkout content has a separate policy. Proof validation and handoff
validation deliberately follow the checkout's own source symlinks and accept
hardlinked source content. They hash only opened regular files, reject special
files without blocking, and stream SHA-256 through a fixed 64 KiB buffer rather
than loading source files into memory. Snapshot hashing records symlinks as
links. Source inventory and sensor input selection retain their existing
contained, bounded policies. None of these source policies authorize following
links in run evidence.

Report publication charges initial usage under the run lock, renders outside
the lock, then publishes completion against fresh metadata under the lock.
Completion never writes a rendered usage snapshot back over concurrent charges.

## Disposable gate and sensor storage

Gate and sensor scratch live directly under admitted OMGS data storage, using
`omgs-gate-<nonce>` and `omgs-sensor-<nonce>` names. Each has a private owner
record bound to its name and physical directory identity, a per-run OS file lock
(the same `File::try_lock` mechanism as run storage), and one `payload` tree.
The owner retains the lock throughout preparation, execution and cleanup.
A parent storage lock serializes publication, recovery and removal, including
closing the run lock for deletion on Windows. Active locks are never reaped.

Immediate cleanup and crash recovery are separate guarantees. Signal guards
cover scratch creation, gate export, sensor input copy, supervision and cleanup.
Normal completion, errors and handled interruptions remove disposable data
immediately. After an unhandled crash or forced kill, the next gate, sensor or
doctor invocation validates both scratch kinds and removes only admitted,
identity-matching layouts with free locks. Links are never followed during
recovery. Recursive payload deletion unlinks links rather than traversing them.
Foreign owners, unsafe permissions, links at the scratch or payload root,
missing or mismatched ownership records and unexpected top-level entries are
left alone with a diagnostic. Legacy scratch without ownership records and
incomplete ownership publication require manual inspection. Trusted owners
must not rename or replace storage concurrently, as with other OMGS storage.

Fixed defaults, intentionally independent of target policy, are
`GATE_EXPORT_BYTES` (4 GiB) and `GATE_EXPORT_ENTRIES` (200,000 files plus distinct
directories), and `SENSOR_WRITE_BYTES` (1 GiB) and `SENSOR_WRITE_ENTRIES`
(100,000 entries). Gate export accounts every path's expanded blob size,
including repeated references to the same object, before writing any files.
Exceeding either cap blocks gate mode with infrastructure exit 3. Advisory mode
retains its display-only semantics. The existing bounded Git object reader
also limits each blob and tree listing to 64 MiB.

Pinned MXC does not expose a portable filesystem quota. Sensors retain the
supervisor's per-file limit where the OS supports it, clamped to 1 GiB, and
check writable scratch every 100 ms and after supervision. Usage is bounded
by both byte and entry counts and traversal depth (64 levels). Unix counts
the greater of logical bytes and allocated blocks per entry; Windows counts
logical bytes including named NTFS streams. Traversal does not follow links. An observed overrun or an
unavailable usage check discards scanner output, records a generic gap and
fails closed. This polling fallback can overshoot between samples and cannot
detect a file created and deleted entirely between samples; it is not a hard
quota. Crash recovery bounds accumulation of eligible abandoned payloads on
the next invocation, rather than imposing a global concurrent-run quota.

## macOS parallel proof ownership (0.1)

Independent proofs must remain parallel. The former same-uid sandbox-policy
marker sweep was conservative but unrelated processes that vanished before
inspection made cleanup inconclusive. The recorded reproduction failed seven
of ten concurrent pairs. Accepting a later clean scan is unsound: A can fork B
and exit before inspection, B can fork C after the next enumeration and exit,
and C can survive without appearing in either scan.

Each workload now has a unique one-shot launchd job and a trusted anchor made
from a private copy of the running executable, verified by SHA-256. No KeepAlive,
RunAtLoad, restart or demand trigger is enabled. An explicit kickstart creates
an isolated resource coalition. Before granting execution, both ends check
exclusive anchor membership and a coalition different from the parent's.
The anchor probes the private interfaces with a trusted child, checking inherited
membership, start and exit accounting, enumeration and correct and incorrect PID-version signals.
Only then may the pinned executor start target code with the existing controls.
After the executor is waited for, the anchor is sealed and never spawns again.

Only `tasks_started - tasks_exited == 1` while the sealed anchor remains alive
certifies cleanup. Enumeration is for locating tasks, never for proving absence.
The fork then exit counterexample leaves the count above one while any member
can still execute or fork. Double forks, new sessions and posix_spawn preserve
resource coalition membership. Signals use proc_signal_with_audittoken and
pidversion, with identity checks surrounding membership lookup. Reused PIDs
cannot redirect a signal to another proof or an unrelated process. Survivors
remain recorded and fail the proof even after successful cleanup. Count-only
activity that disappears before identification is conservatively unclean.
Scan work and cleanup time remain bounded; unresolved owned activity fails closed.

The private, long-standing PROC_PIDCOALITIONINFO and libSystem coalition and
signal interfaces are runtime requirements, not stable public API promises.
Symbols are resolved dynamically. If the coalition-list symbol is absent,
process enumeration supplies candidates filtered by PROC_PIDCOALITIONINFO;
identity is still bracketed before signalling, and the same task-count certificate
is mandatory. This is a membership-query compatibility path, not a policy sweep.
Unexpected layouts, unavailable required operations,
failed accounting or launchd submission block execution or certification. There
is no conservative-sweep fallback, since it would restore cross-run interference.
Proof records require `launchd_resource_coalition`; old marker-based records are
rejected for rerun. Linux and Windows ownership semantics do not change.
The macOS CI job explicitly exercises admission and certification on macos-15
arm64. A runner without a usable user-owned launchd domain must fail that step.

IPC, the plist and the staged anchor live under admitted owner-private
`OMGS_HOME/launchd/<nonce>` storage, outside all grants. The invoking process
copies and SHA-256 verifies the executable before launchd starts it. Random
labels, exclusive creation, no-follow reads and the saved launchd domain prevent
accidental collisions. Anonymous capture pipes remain under OS-selected Darwin
private temp storage; both locations are checked against grants. Private IPC
storage also refuses baseline-readable system trees, including /System, /Library,
/usr and /opt, even when an owner prepared a private directory there.

macOS uses public CommonCrypto SHA-256 for content verification. Repeated full
binary verification otherwise consumes the startup budget in unoptimized builds
when many proofs prepare at once. Known vectors and comparisons with the portable
implementation cover streaming and padding boundaries. Linux and Windows retain
the in-tree implementation. Verification and fixture deadlines do not increase.

Launchd owns the TCC responsible identity of its processes. It does not inherit
the invoking terminal's Desktop access. To prevent repeated Files and Folders
prompts after ad hoc rebuilds, nothing on the launchd side may require protected
storage. Admission checks the binary, arguments that are absolute paths, working
directory, environment path values, workspace, scratch and readable grants.
Desktop, Documents, Downloads, user Library, cloud storage and media folders are
refused, including case aliases, resolved links and Data-volume path aliases. Parent
traversal is refused before filesystem inspection. Volume metadata
must establish local, internal, non-removable storage. External, removable and
network volumes are refused even when mounted at unusual paths. An unknown
volume property fails closed. Broad grants encompassing protected folders are
also refused. The diagnostic names the path and directs the operator to move the
run/tool or set an unprotected OMGS_HOME. The terminal-side parent may copy a
protected target into unprotected staging using its existing access; a failed
copy blocks execution. No privacy permissions are requested or changed.
`launchd_tcc_path_admission` is required alongside coalition ownership in proof
validation. Tests use unprotected temp/data paths and check TCC unified logs.

There is no stronger claim against a same-user process with arbitrary file
access: it can replace the executable, private state or all local proof records.
Sandboxed target code has no grant to these files or launchd service endpoints.

The owner holds a per-job advisory lock. An anchor monitors loss of that lock or
explicit cancellation while supervising the executor. A killed owner therefore
causes cleanup without waiting for another invocation. The next proof or sensor invocation locks
and recovers abandoned registry entries, terminates remaining coalition members
with version-bound signals, removes the job and retains state on failure.
Registry recovery and publication are serialized briefly; proof execution is not.
Normal completion waits for the anchor to leave, removes the job, verifies it is
absent and deletes private staging. Interruption follows the same cleanup path.
An absent resource coalition after anchor exit is acceptable only for teardown:
Darwin cannot reap a resource coalition while it still contains tasks. It never
substitutes for the live sealed-anchor certificate used by a clean proof.
