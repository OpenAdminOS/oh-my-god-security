# Validation and reporting

## Disprove first

A fresh verifier receives the candidate contract, relevant source, trusted intent, and proof artifacts, not the hunter's confidence or a proposed severity. In a separate context, reconstruct the path and try to break it: unreachable export, earlier authorization, a trusted identifier, effective RLS, wrapper enforcement, safe return projection, or intended public access. Follow delegation to the limit of locally available evidence.

Reject a candidate only with concrete counterevidence that defeats the claimed result. A missing dependency, external policy, unclear product intent, or unavailable sandbox is `needs_validation`, with the exact missing fact. Never use absence of proof as proof of safety. Before any execution, independently check the proof's minimal scope and all execution controls in [SKILL.md](SKILL.md#execution-safety).

## Proof ladder

| Tier | Machine value | Evidence and verdict |
| --- | --- | --- |
| 0 | `traced` | Complete input-to-sink trace and claimed boundary violation. Candidate only; never confirmed. Omit `proof_ref` and keep the source trace in `evidence`. |
| 1 | `test_proven` | A security invariant test fails because the real target path permits the unauthorized effect, inside `omgs prove`, under the project's own test runner or, when that runner cannot run in the sandbox, an equivalent harness that compiles and exercises the unmodified target code and asserts the same invariant. Decisive evidence earns confirmed. |
| 2 | `sandbox_exploited` | Sandbox verified against a locally built copy of the app on synthetic data. Use only when a test cannot decide, after human approval of the first tier 2 run per repository. |

The deterministic runner selects escalation under the run budget. The agent supplies the missing fact and cheapest proposed decisive proof; it cannot self-award a tier, bypass approval, or escalate merely for a more dramatic demonstration. Evidence that already decides the boundary ends execution. Retain the highest earned tier on blockage; a failed build or timeout earns no new tier. A tier describes evidence, while verdict describes whether that evidence supports the claim.

There is no tier above `sandbox_exploited`. An effect the OS sandbox cannot contain, such as a privileged installer or a root LaunchDaemon or XPC helper that needs real root and Gatekeeper, has no proof tier: it cannot be confirmed, because OMGS has no backend that executes it through `omgs prove`, and running it unsandboxed on a manually chosen machine is never permitted. Keep such a record `needs_validation` with the exact missing fact and a safe manual validation plan; never promote it to confirmed. Most privileged-target findings do not need this anyway: a decision-logic defect such as a nil expected signer disabling verification, or a missing downgrade check, lives in a pure function and is decided at tier 1 by an invariant test on that function with synthetic inputs, no VM and no root (`benchmark/fixtures/installer-trust` is a worked example, and this is the path OMGS expects). A person may separately demonstrate live impact on a throwaway, network-isolated, snapshot-and-discard VM to inform severity, but that is a manual step outside OMGS, not a proof tier, and OMGS never requires a user to stand up a VM.

Non-web and non-sandboxable targets need a documented proof recipe, because the project's own test runner may not run under the sandbox. For a Swift package whose `swift test` cannot run under MXC (SwiftPM spawns a nested sandbox, which a sandboxed process cannot do), compile the unmodified target modules with `swiftc -emit-library` and run the same invariant assertions through a small harness inside `omgs prove`, keeping the XCTest file as the proposed regression test and disclosing the runner substitution in evidence. Such a harness earns `test_proven` as long as it exercises the unmodified target code, asserts the real invariant, and the substitution is disclosed. A harness that reimplements, stubs, or mocks the logic under test does not earn `test_proven`; it is at most a synthetic reproducer for the pack, evidence about the class and not about this target.

Do not rely on the sandbox to contain daemon-mediated effects. Under MXC on macOS, `defaults write`, `open`, `launchctl` and the clipboard are denied and Apple Events are not delivered (observed 2026-10-27), but a proof that needs such an API is testing the daemon, not the target. `NSTemporaryDirectory()` resolves to the real per-user temp dir, which MXC denies, so a harness that uses it fails rather than escaping. Cleaning up afterward never counts as containment: if an effect could leave the sandbox, the escape has already happened. Redirect temp to a scratch-relative path. For preferences, launchd, or similar daemon IPC, avoid the API in the proof or record a blocker and leave the record `needs_validation`; never rely on post-run cleanup as the containment, and never reach for an unsandboxed machine instead. A proof harness that crashes before reaching the code under test (a missing dynamic library, a load error, a build failure) must fail loudly and distinctly: never read a harness abort as the target refusing the operation, or a crash will masquerade as a passing control.

## Proof by default: per-stack recipes

For every candidate, attempt the cheapest decisive sandbox proof when its runtime
is reachable locally, within the declared proof budget. A budget stop is also an
exact blocker, never a silent omission. Hand the relevant recipe below to the
hunter with its scope. The verifier checks the harness against the real source.
Run `omgs doctor --live` first. Its `toolchains reachable inside the sandbox` list
means a version command actually launched, not merely that a filename was found.
Doctor prints `<runtime> not on host PATH` for an absent executable, or
`<runtime> on host PATH but failed to launch inside MXC` followed by a reason
for an installed tool whose bounded launch probe fails. It probes `sh` too.
Record the exact line, its reason and the
startup output from `omgs prove`, or its printed `needs_validation` reason on
exit 3. Do not suggest an installation during proof. No runtime, missing local
modules, a refused OS tier, failed DLL initialization, syntax or build errors,
and exhausted budgets remain blockers with `needs_validation`, never rejection.

All commands below run from the reviewer's shell. Replace `RUN`, `FP` and `DRAFT`
with the resolved external run directory, fingerprint and draft file. Staged test
paths are relative to the target. The invariant must fail with an explicit
`BOUNDARY_ASSERTION_FAILED` marker immediately before exit 1 on vulnerable
source, then print `BOUNDARY_ASSERTION_OK` and exit 0 on fixed source.
Require `AUTHORIZED_CONTROL_OK` in both. Import, compile, load and authorized
control failures exit 2 and earn no proof support. Every recipe invocation must
include `--expect-marker BOUNDARY_ASSERTION_FAILED`. This declares a contract
recorded as `expect_marker`: support requires exit 1, the exact boundary line,
and the exact `AUTHORIZED_CONTROL_OK` line. The runner records
`boundary_marker_seen` and `authorized_control_seen` from the full stdout and
stderr streams before capping or redaction; validation and CLI support use those
fields. Markers must occupy complete lines (LF or CRLF). Replay preserves the
contract and compares the marker results. Inspect the harness as well: markers
are accident checks, not authentication against hostile target output.
Exit 2 is universally rejected as a usage or harness error, including without
a contract. Without a contract, assertion exits 1 and 3 through 125 remain
available for other frameworks; rejected controls may also exit 0. Import or compile
the real unmodified target implementation, never a copy of its decision logic.
Tiny executable examples for all five recipes live in `tests/recipes.rs`; its
fixtures are staged into disposable targets, and every execution, including
runtime probes and compilation, uses the actual `omgs prove` CLI.

CI sets `OMGS_REQUIRE_RECIPES=sh,python3,node,pwsh,swiftc` on macOS and Ubuntu
using their preinstalled runtimes. A required skip fails. The recipes test
prints executed/skipped counts with `--nocapture`. Missing MXC and the Windows
augmentation refusal are the other intentional skips; all other failed probes
fail the test, including exit 3, timeouts and incomplete runner records.

Every recipe uses the same deny-by-default MXC policy: external network denied,
host home and credentials unreadable except the disclosed read-only toolchain
roots and caches, scratch home/temp/cache, and writes only to the workspace copy
and scratch. Readable caches may contain private source. Read each proof's actual
controls and gaps, including OS limits; never infer broader containment. No
package downloads, real services or root operations are part of these recipes.

### PowerShell

Use a `test.ps1` harness with `$ErrorActionPreference = 'Stop'`, dot-source the
actual target script or import its local module, check the authorized control,
then print the boundary marker and explicitly `exit 1` if the forbidden result
occurs and `exit 0` otherwise. Wrap dot-sourcing, imports and the control in
`try`/`catch`, with `exit 2` in the catch.
Do not mock the authorization or policy-writing operation under test. A startup
exception must be distinguishable from the boundary assertion. For inline checks,
`pwsh -NoProfile -NonInteractive -Command ...` is also supported.

Example harness (replace the local target path and function with the real source):

```powershell
$ErrorActionPreference = 'Stop'
try {
  . ./target.ps1
  if (-not (Test-CanRead 'owner' 'owner')) { throw 'AUTHORIZED_CONTROL_FAILED' }
  Write-Output 'AUTHORIZED_CONTROL_OK'
  $forbidden = Test-CanRead 'intruder' 'owner'
  if ($forbidden -isnot [bool]) { throw 'INVALID_TARGET_RESULT' }
} catch { Write-Error -ErrorAction Continue $_; exit 2 }
if ($forbidden) { Write-Output 'BOUNDARY_ASSERTION_FAILED'; exit 1 }
Write-Output 'BOUNDARY_ASSERTION_OK'
exit 0
```

```sh
omgs prove --run RUN --finding FP --test test.ps1 --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "pwsh -NoProfile -NonInteractive -File test.ps1"
```

Common blockers: `pwsh not on host PATH`,
`pwsh on host PATH but failed to launch inside MXC`, absent local modules and
Graph/network calls requiring real services. Upstream MXC issue
[microsoft/mxc#1465](https://github.com/microsoft/mxc/issues/1465) reports
`STATUS_DLL_INIT_FAILED` in Windows session 0. This is an observed upstream
limitation, not a guaranteed OMGS diagnostic. Use an existing interactive desktop session for the
Windows container; never grant home access or change ACLs. Windows augmentation
tiers remain refused. Network and home denials above apply to PowerShell too.

### Node

Use `test.cjs` to import the real local target module and check the authorized
result inside `try`/`catch`; imports, control failures and unexpected target
exceptions call `process.exit(2)`. Evaluate the unauthorized effect in the
same guarded block. Outside it, print `BOUNDARY_ASSERTION_FAILED` and exit 1
only for the forbidden result; fixed code prints `BOUNDARY_ASSERTION_OK` and
exits 0. Keep external effects synthetic.

Example harness (replace the local target path and function with the real source):

```javascript
let forbidden;
try {
  const {canRead} = require('./target.cjs');
  if (canRead('owner', 'owner') !== true) throw new Error('AUTHORIZED_CONTROL_FAILED');
  console.log('AUTHORIZED_CONTROL_OK');
  forbidden = canRead('intruder', 'owner');
} catch (error) { console.error(error); process.exit(2); }
if (typeof forbidden !== 'boolean') { process.exit(2); }
if (forbidden) { console.log('BOUNDARY_ASSERTION_FAILED'); process.exit(1); }
console.log('BOUNDARY_ASSERTION_OK');
```

```sh
omgs prove --run RUN --finding FP --test test.cjs --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "node test.cjs"
```

Common blockers: `node not on host PATH` or
`node on host PATH but failed to launch inside MXC`, missing local
`node_modules`, unsupported module formats and denied absolute-path enumeration
on Windows builds without that capability. No npm install or registry access;
network and home denials above apply to Node too.

### Python

Use `test.py` with the authorized assertion followed by the boundary assertion.
Run isolated mode; `-I` removes the script directory from the import path, so
load a local file explicitly with `runpy.run_path('./target.py')` or use an
explicit local module search path in the harness. Do not load host user packages.
Wrap imports, control checks and target invocation in `try`/`except Exception`
with `sys.exit(2)` on error. Only the forbidden result prints
`BOUNDARY_ASSERTION_FAILED` and calls `sys.exit(1)`; fixed code prints
`BOUNDARY_ASSERTION_OK` and exits 0.

Example harness (replace the local target path and function with the real source):

```python
import sys
try:
    import runpy
    can_read = runpy.run_path('./target.py')['can_read']
    if not can_read('owner', 'owner'):
        raise RuntimeError('AUTHORIZED_CONTROL_FAILED')
    print('AUTHORIZED_CONTROL_OK', flush=True)
    forbidden = can_read('intruder', 'owner')
    if type(forbidden) is not bool:
        raise RuntimeError('INVALID_TARGET_RESULT')
except Exception as error:
    print(error, file=sys.stderr)
    sys.exit(2)
if forbidden:
    print('BOUNDARY_ASSERTION_FAILED', flush=True)
    sys.exit(1)
print('BOUNDARY_ASSERTION_OK')
```

```sh
omgs prove --run RUN --finding FP --test test.py --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "python3 -I test.py"
```

Common blockers: `python3 not on host PATH` or
`python3 on host PATH but failed to launch inside MXC`, unavailable local
packages and fixtures expecting user-site imports. Never run pip; network and
home denials above apply to Python too.

### Shell

Use `test.sh` to source the real local implementation, verify the authorized
control, exiting 2 if sourcing or the control fails. Print
`BOUNDARY_ASSERTION_FAILED` and exit 1 when the forbidden effect is observed. Exit 0
only after checking denied behavior and resulting synthetic state. Prefer POSIX
`sh` and explicit status checks so a pipeline's final command cannot hide failure.
For the unauthorized call, status 0 means allowed, 1 means expected denial,
and every other status is an execution error that makes the harness exit 2.
A missing dependency or command must never count as denial.

Example harness (replace the local target path and function with the real source):

```sh
. ./target.sh || exit 2
can_read owner owner || exit 2
echo AUTHORIZED_CONTROL_OK
can_read intruder owner
status=$?
case $status in
  0) echo BOUNDARY_ASSERTION_FAILED; exit 1 ;;
  1) echo BOUNDARY_ASSERTION_OK; exit 0 ;;
  *) exit 2 ;;
esac
```

```sh
omgs prove --run RUN --finding FP --test test.sh --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "sh test.sh"
```

Common blockers: `sh not on host PATH` or
`sh on host PATH but failed to launch inside MXC`, absent commands or a
non-POSIX target requiring an unavailable interpreter. No host shell fallback on
Windows. Network and home denials above apply to shell subprocesses too.

### Swift

Keep the XCTest regression draft, but when SwiftPM's nested sandbox is blocked,
compile the real module plus a `main.swift` invariant harness directly. Assert an
authorized success with `exit(2)` on control failure, print
`BOUNDARY_ASSERTION_FAILED` and `exit(1)` on the
vulnerable path, then exit 0 on fixed code. Use a throwing target API with
`do`/`catch` so dependency and invocation errors exit 2. For a nonthrowing API,
remove `try` and the catch after checking its error channel explicitly.
Disclose the runner substitution.

Example harness (replace the local target path and function with the real source):

```swift
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
do {
  guard try canRead("owner", "owner") else { exit(2) }
  print("AUTHORIZED_CONTROL_OK")
  if try canRead("intruder", "owner") { print("BOUNDARY_ASSERTION_FAILED"); exit(1) }
  print("BOUNDARY_ASSERTION_OK")
} catch { exit(2) }
```

```sh
omgs prove --run RUN --finding FP --test main.swift --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "swiftc target.swift main.swift -o fixture || exit 2; ./fixture"
```

For modules needing a library, use `swiftc -emit-library` inside the same proof
and link an explicit workspace-relative library path. Common blockers:
`swiftc not on host PATH` or
`swiftc on host PATH but failed to launch inside MXC`, missing SDKs or local libraries,
unavailable Linux system headers (the runner grants `/usr/include` read-only),
nested SwiftPM sandbox creation, denied daemon APIs and real root helpers. A
compile/load failure earns no tier. Network and home denials above apply to
Swift too; redirect temporary files into the workspace or scratch.

## Write a regression test

1. Use the target's existing test framework and conventions. Write a draft beneath the external output directory, with a proposed target-relative path for later human acceptance. The runner stages the test into the workspace copy; never write audit logs or generated fixture data into the target.
2. Create dummy principals A and B, synthetic resources and local secrets. State the intended invariant as the test assertion, such as B cannot read A's private row. Include an authorized success control so a broken harness cannot look like protection.
3. Exercise the actual route/action/service and enforcement chain. Mock only unrelated external effects. Do not mock out the authorization check, tenant predicate, signature verification, or RLS whose failure is at issue. A mock database that simply returns a forbidden row cannot establish a real RLS bypass.
4. Assert the minimum decisive effect: response contents for a read, unchanged synthetic state for a denied write, or no privileged effect for an invalid event. A status code alone is insufficient when a mutation could occur before the response.
5. Submit the test and exact runner invocation to `omgs prove`. Whenever using a recipe, declare `--expect-marker BOUNDARY_ASSERTION_FAILED`; do not omit the contract. Run test discovery, setup, builds, and prerequisites only there. No installs, downloads, remote credentials, or external endpoints. Record runner exit, assertion output, authorized control, observed effect, backend/policy/limits, and source identity.
6. Confirm only when the invariant fails for the claimed security reason. Syntax errors, missing modules, unrelated assertions, and all-denied fixtures are blockers or harness failures. Preserve the test as the fix acceptance check. A future approved patch should make the same test pass without weakening the invariant, with all reruns still sandboxed.

Validation requires bubblewrap containment for every `local_app` proof record. Replay requires the recorded `timeout_ms`, rejects overrides, consumes proof budget and checks the target commit, copied-tree digest including all `.git` content, inner exit code and cleanliness. Exact command and config artifacts can contain credentials, so protect the entire run directory. On Unix proof directories are 0700 and command and config files are 0600. Content hashing accepts hardlinks and symlinks resolving to regular files; small trust files retain bounded, single-link, no-follow reads. Snapshot hashing has no size cap. Target FIFOs and sockets are skipped in the workspace copy and snapshot digest, with up to 20 paths recorded as proof gaps and one aggregate count for the remainder. Devices are refused before copying.

For tier 2 (Linux only), the runner builds and runs a writable workspace copy with only local synthetic services on the sandbox's private loopback. Tier 2 uses the same convention as tier 1: a named harness or test, passed with `--test`, that fails with an assertion when the unauthorized effect happens and passes when it does not. Approval must cover the local effect and stop condition. Stop after one minimal decisive result; never point the client, app, webhook, or database at a live or third party system. If local dependencies or enforced controls are missing, record the exact blocker and a manual plan with the same safety constraints.

## Missing intent

Ask about expected behavior, not security jargon. Example: "Should a signed-in member of one workspace be able to read a private project from another workspace if they know its ID?" Record the affected surface and the exact missing expectation in `intent_question`; leave verdict pending and omit severity.

Record the owner's answer with `omgs intent answer --target <repo> --id <intent_id> --answer <text> --source <who> [--scope repo|<path>]`. Answers are stored on the reviewer's machine keyed by the target's full path, never in the reviewed repository, and every later `omgs audit init` on that target copies them into the run so the report shows them beside the matching questions. An answer recorded after a run was initialized applies from the next run; for a repository reviewed by URL, `omgs review` creates the clone the answer's `--target` names. The store is trusted only when it lives outside the target and is a regular file with a single link, so stored answers are supported on Unix (macOS, Linux) only. Proposing the same rule as committed project policy through normal owner review stays a separate, optional step. Keep the question and run evidence outside the target. An answer from a PR head cannot change the gate or rewrite trusted base policy. Do not invent an answer, treat a pending proposal as accepted policy, or call a policy answer execution evidence. Reevaluate the candidate and run the necessary proof after intent is resolved.

## Findings record

Serialize the following semantic fields using the installed CLI schema. Fields unavailable for a pending record use the schema's absent or null representation, never fabricated values. Internal hunter context stays in linked evidence rather than adding unsupported fields.

| Field | Requirement |
| --- | --- |
| `fingerprint` | Deterministic `omgs fingerprint` result from attack class, entry point, sink symbol, boundary. |
| `title` | Concrete unauthorized result, without inflated impact. |
| `verdict` | Exactly `confirmed`, `needs_validation`, or `rejected`. |
| `severity` | Required only for confirmed findings, using the CLI's accepted scale and demonstrated impact. Omit for all other verdicts. |
| `proof_tier` | Exactly `traced`, `test_proven`, or `sandbox_exploited`; never exceed runner evidence. |
| `attack_class` | Stable class used for identity. |
| `entry_point` | Stable path and route/method or action symbol. |
| `sink` | Stable module and effect-producing symbol. |
| `boundary` | Principal/resource boundary and violated invariant. |
| `location` | Object containing repository-relative `path` and one-based `line` in the reviewed source. |
| `locations` | Further locations of the same root cause, each with `path` and `line`. One defect copied into several places stays one record and counts once; do not emit one record per copy. |
| `hunted_by` | Identity of the hunter whose candidate produced the record, matching that candidate's `hunter`. Required. |
| `verified_by` | Identity of the independent verifier that decided the record. Required, and `omgs validate` rejects it when it equals `hunted_by`. |
| `candidates` | Fingerprints of further candidates merged into this record: several hunters raising one root cause under different identities, or the original candidate fingerprint when verification changed an identity input. The record's own fingerprint is implicit. |
| `evidence` | Source trace, attacker prerequisites, concrete result, controls/counterevidence, external artifact references and runner evidence. For pending records include the exact missing fact and blocker; for rejection include the decisive refutation. |
| `fix_brief` | Confirmed: invariant, narrowest effective change, proof test acceptance check. Otherwise null or absent per schema. |
| `intent_question` | Unresolved plain language intent question with scope, otherwise null or absent per schema. |
| `intent_id` | Library question the record asks, from `omgs intent list`. Prefer it over a free-text question when one fits: records sharing an id are grouped into one question in the report, and one recorded answer resolves all of them. `omgs validate` rejects an unknown id. |

Severity follows the confirmed boundary and effect, including privilege, data scope, and prerequisites. Do not claim bulk exposure, account takeover, or remote execution from a single unrelated symptom. No severity belongs on unresolved questions or rejected hypotheses.

Fix brief example: **Invariant:** members access only their workspace's private projects. **Narrowest change:** constrain `loadProject` to the trusted workspace membership and project ID before returning data, preserving authorized reads. **Acceptance check:** the saved project test denies cross-workspace access and permits the owner's read. Include the test path and evidence reference; do not auto-apply a fix.

## Validate, render, and hand off

Use `omgs fingerprint` after any identity correction, then `omgs validate --findings <run-dir>/findings.json` over the final records. Then run `omgs critic --run <run-dir>`: it reconciles the ledger, every `candidates*.json`, and `findings.json`, and exits 1 on any gap (a unit still `planned` or `candidate`, a `covered` unit without evidence, a candidate no finding accounts for, a finding whose verifier hunted one of its candidates, a finding no unit cites as evidence). Close each gap in the ledger with `omgs ledger set` (evidence or a note) or by verifying the missing candidate; do not report over open gaps. `omgs report` also runs the critic and prints its result in the report. Resolve schema errors, duplicate identity conflicts, missing evidence, invalid severity/verdict combinations, and inconsistent tiers before `omgs report`. A validator pass checks structure and deterministic consistency, not the truth of an agent's claim.

The CLI renders `findings.json`, SARIF, `REPORT.md`, and `REPORT.html` from the same verified records outside the target. Check that the offline HTML escapes target text, embeds no scripts from the target, makes no external requests, and agrees with the other views. Treat reports as sensitive. Include pending intent, exact blockers, unexamined ledger units, mode, budget and spend, agent/model identity, and sandbox backend/policy. No score or coverage percentage.

In gate mode, only committed proof tests and scanner rules may block a merge. A model verdict, source trace, pending question, or uncommitted proof cannot gate, including a tier 2 demonstration without a committed deterministic guard. Advisory mode blocks nothing. Propose accepted proof tests, intent rules, policy and suppressions for normal review; keep run output external and never silently change the gate mode or policy source.
