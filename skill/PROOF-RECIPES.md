# Local sandbox proof recipes

## Proof by default: per-stack recipes

For every candidate, attempt the cheapest decisive sandbox proof when its runtime is reachable
locally, within the declared proof budget. A budget stop is also an exact blocker, never a silent
omission. Hand the relevant recipe below to the hunter with its scope. The verifier checks the
harness against the real source. Run `omgs doctor --live` first. Its `toolchains reachable inside
the sandbox` list means a version command actually launched, not merely that a filename was found.
Doctor prints `<runtime> not on host PATH` for an absent executable, or `<runtime> on host PATH but
failed to launch inside MXC` followed by a reason for an installed tool whose bounded launch probe
fails. It probes `sh` too. Record the exact line, its reason and the startup output from `omgs
prove`, or its printed `needs_validation` reason on exit 3. Do not suggest an installation during
proof. No runtime, missing local modules, a refused OS tier, failed DLL initialization, syntax or
build errors, and exhausted budgets remain blockers with `needs_validation`, never rejection.

All commands below run from the reviewer's shell. Replace `RUN`, `FP` and `DRAFT` with the resolved
external run directory, fingerprint and draft file. Staged test paths are relative to the target.
Every recipe invocation must include `--expect-marker BOUNDARY_ASSERTION_FAILED`. OMGS supplies a
fresh per-run `OMGS_PROOF_NONCE` and the declared label as `OMGS_PROOF_CONTRACT` through the
allowlisted MXC environment. Print `OMGS_CONTROL_<nonce>` only after the authorized control
succeeds. Print `OMGS_BOUNDARY_<nonce>_<label>` immediately before exit 1 when the invariant fails
on vulnerable source. Fixed source prints `BOUNDARY_ASSERTION_OK` and exits 0. Import, compile, load
and authorized control failures exit 2 and earn no proof support.

Proof schema `omgs-proof/2` requires a `contract` object with `kind: "recipe"`, `expect_marker`,
`boundary_marker_seen` and `authorized_control_seen`. All four fields are required and non-null.
Runs without a declaration store the explicit `{"kind":"none"}` variant. The saved config
environment binds the declaration and nonce to its digest, and validation reconstructs it with the
saved command. Support requires exit 1 and both exact nonce-qualified lines. The evidence flags come
from full stdout and stderr before capping or redaction. Markers must occupy complete lines (LF or
CRLF). Replay retains the declaration, generates a fresh nonce and compares the evidence flags.
Older records predate the current policy, including `RUSTUP_AUTO_INSTALL=0`, and must be rerun, with
no compatibility shim or relaxed environment allowlist.

Fixed or wrong-nonce output cannot satisfy the contract. This is an accident and collision check,
not provenance: hostile code sharing the harness process can read the nonce and forge both lines.
The independent evaluator remains required to check that the real target and intended assertion
executed. Real provenance would need assertion reporting separated from target execution. A separate
trusted reporter process with a private channel unavailable to target code is an option for a future
design; it needs a concrete isolation policy and is outside this PR. Exit 2 is universally rejected
as a usage or harness error, including without a contract. Without a contract, assertion exits 1 and
3 through 125 remain available for other frameworks; rejected controls may also exit 0. Import or
compile the real unmodified target implementation, never a copy of its decision logic. Tiny
executable examples for all five recipes live in `tests/recipes.rs`; its fixtures are staged into
disposable targets, and every execution, including runtime probes and compilation, uses the actual
`omgs prove` CLI.

CI sets `OMGS_REQUIRE_RECIPES=sh,python3,node,pwsh,swiftc` on macOS and Ubuntu using their
preinstalled runtimes. A required skip fails. The recipes test prints executed/skipped counts with
`--nocapture`. Missing MXC and the Windows augmentation refusal are the other intentional skips; all
other failed probes fail the test, including exit 3, timeouts and incomplete runner records.

Every recipe uses the same deny-by-default MXC policy: external network denied, host home and
credentials unreadable except the disclosed read-only toolchain roots and caches, scratch
home/temp/cache, and writes only to the workspace copy and scratch. Readable caches may contain
private source. Read each proof's actual controls and gaps, including OS limits; never infer broader
containment. No package downloads, real services or root operations are part of these recipes.

### PowerShell

Use a `test.ps1` harness with `$ErrorActionPreference = 'Stop'`, dot-source the actual target script
or import its local module, check the authorized control, then print the boundary marker and
explicitly `exit 1` if the forbidden result occurs and `exit 0` otherwise. Wrap dot-sourcing,
imports and the control in `try`/`catch`, with `exit 2` in the catch. Do not mock the authorization
or policy-writing operation under test. A startup exception must be distinguishable from the
boundary assertion. For inline checks, `pwsh -NoProfile -NonInteractive -Command ...` is also
supported.

Example harness (replace the local target path and function with the real source):

```powershell
$ErrorActionPreference = 'Stop'
try {
  . ./target.ps1
  if (-not (Test-CanRead 'owner' 'owner')) { throw 'AUTHORIZED_CONTROL_FAILED' }
  Write-Output "OMGS_CONTROL_$env:OMGS_PROOF_NONCE"
  $forbidden = Test-CanRead 'intruder' 'owner'
  if ($forbidden -isnot [bool]) { throw 'INVALID_TARGET_RESULT' }
} catch { Write-Error -ErrorAction Continue $_; exit 2 }
if ($forbidden) { Write-Output "OMGS_BOUNDARY_$($env:OMGS_PROOF_NONCE)_$($env:OMGS_PROOF_CONTRACT)"; exit 1 }
Write-Output 'BOUNDARY_ASSERTION_OK'
exit 0
```

```sh
omgs prove --run RUN --finding FP --test test.ps1 --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "pwsh -NoProfile -NonInteractive -File test.ps1"
```

Common blockers: `pwsh not on host PATH`, `pwsh on host PATH but failed to launch inside MXC`,
absent local modules and Graph/network calls requiring real services. Upstream MXC issue
[microsoft/mxc#1465](https://github.com/microsoft/mxc/issues/1465) reports `STATUS_DLL_INIT_FAILED`
in Windows session 0. This is an observed upstream limitation, not a guaranteed OMGS diagnostic. Use
an existing interactive desktop session for the Windows container; never grant home access or change
ACLs. Windows augmentation tiers remain refused. Network and home denials above apply to PowerShell
too.

### Node

Use `test.cjs` to import the real local target module and check the authorized result inside
`try`/`catch`; imports, control failures and unexpected target exceptions end with exit code 2.
Evaluate the unauthorized effect in the same guarded block. Outside it, print the nonce-qualified
boundary marker and exit 1 only for the forbidden result; fixed code prints `BOUNDARY_ASSERTION_OK`
and exits 0. Set `process.exitCode` and return instead of calling `process.exit()`, which can
discard output still queued for a pipe, including the markers. Keep external effects synthetic.

Example harness (replace the local target path and function with the real source):

```javascript
function check() {
  let forbidden;
  try {
    const {canRead} = require('./target.cjs');
    if (canRead('owner', 'owner') !== true) throw new Error('AUTHORIZED_CONTROL_FAILED');
    console.log('OMGS_CONTROL_' + process.env.OMGS_PROOF_NONCE);
    forbidden = canRead('intruder', 'owner');
  } catch (error) { console.error(error); return 2; }
  if (typeof forbidden !== 'boolean') return 2;
  if (forbidden) { console.log('OMGS_BOUNDARY_' + process.env.OMGS_PROOF_NONCE + '_' + process.env.OMGS_PROOF_CONTRACT); return 1; }
  console.log('BOUNDARY_ASSERTION_OK');
  return 0;
}
// process.exit() can drop queued pipe writes; exitCode lets them drain.
process.exitCode = check();
```

```sh
omgs prove --run RUN --finding FP --test test.cjs --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "node test.cjs"
```

Common blockers: `node not on host PATH` or `node on host PATH but failed to launch inside MXC`,
missing local `node_modules`, unsupported module formats and denied absolute-path enumeration on
Windows builds without that capability. No npm install or registry access; network and home denials
above apply to Node too. Because the harness returns instead of calling `process.exit()`, a target
that leaves a timer, server or other open handle keeps Node running until the wall clock expires; a
timed out run never supports a proof, even with both markers printed. Close target-owned resources
in the harness through the target's own cleanup API (for example `server.close()` or
`clearInterval`) before `check()` returns, and record the timeout as the blocker if the target
offers no way to release them.

### Python

Use `test.py` with the authorized assertion followed by the boundary assertion. Run isolated mode;
`-I` removes the script directory from the import path, so load a local file explicitly with
`runpy.run_path('./target.py')` or use an explicit local module search path in the harness. Do not
load host user packages. Wrap imports, control checks and target invocation in `try`/`except
Exception` with `sys.exit(2)` on error. Only the forbidden result prints the nonce-qualified
boundary marker and calls `sys.exit(1)`; fixed code prints `BOUNDARY_ASSERTION_OK` and exits 0.

Example harness (replace the local target path and function with the real source):

```python
import os, sys
nonce = os.environ['OMGS_PROOF_NONCE']
marker = os.environ['OMGS_PROOF_CONTRACT']
try:
    import runpy
    can_read = runpy.run_path('./target.py')['can_read']
    if not can_read('owner', 'owner'):
        raise RuntimeError('AUTHORIZED_CONTROL_FAILED')
    print(f'OMGS_CONTROL_{nonce}', flush=True)
    forbidden = can_read('intruder', 'owner')
    if type(forbidden) is not bool:
        raise RuntimeError('INVALID_TARGET_RESULT')
except Exception as error:
    print(error, file=sys.stderr)
    sys.exit(2)
if forbidden:
    print(f'OMGS_BOUNDARY_{nonce}_{marker}', flush=True)
    sys.exit(1)
print('BOUNDARY_ASSERTION_OK')
```

```sh
omgs prove --run RUN --finding FP --test test.py --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "python3 -I test.py"
```

Common blockers: `python3 not on host PATH` or `python3 on host PATH but failed to launch inside
MXC`, unavailable local packages and fixtures expecting user-site imports. Never run pip; network
and home denials above apply to Python too.

### Shell

Use `test.sh` to source the real local implementation, verify the authorized control, exiting 2 if
sourcing or the control fails. Print the nonce-qualified boundary marker and exit 1 when the
forbidden effect is observed. Exit 0 only after checking denied behavior and resulting synthetic
state. Prefer POSIX `sh` and explicit status checks so a pipeline's final command cannot hide
failure. For the unauthorized call, status 0 means allowed, 1 means expected denial, and every other
status is an execution error that makes the harness exit 2. A missing dependency or command must
never count as denial.

Example harness (replace the local target path and function with the real source):

```sh
. ./target.sh || exit 2
can_read owner owner || exit 2
echo "OMGS_CONTROL_${OMGS_PROOF_NONCE:?}"
can_read intruder owner
status=$?
case $status in
  0) echo "OMGS_BOUNDARY_${OMGS_PROOF_NONCE:?}_${OMGS_PROOF_CONTRACT:?}"; exit 1 ;;
  1) echo BOUNDARY_ASSERTION_OK; exit 0 ;;
  *) exit 2 ;;
esac
```

```sh
omgs prove --run RUN --finding FP --test test.sh --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "sh test.sh"
```

Common blockers: `sh not on host PATH` or `sh on host PATH but failed to launch inside MXC`, absent
commands or a non-POSIX target requiring an unavailable interpreter. No host shell fallback on
Windows. Network and home denials above apply to shell subprocesses too.

### Swift

Keep the XCTest regression draft, but when SwiftPM's nested sandbox is blocked, compile the real
module plus a `main.swift` invariant harness directly. Assert an authorized success with `exit(2)`
on control failure, print the nonce-qualified boundary marker and `exit(1)` on the vulnerable path,
then exit 0 on fixed code. Use a throwing target API with `do`/`catch` so dependency and invocation
errors exit 2. For a nonthrowing API, remove `try` and the catch after checking its error channel
explicitly. Disclose the runner substitution.

Example harness (replace the local target path and function with the real source):

```swift
import Foundation
let nonce = ProcessInfo.processInfo.environment["OMGS_PROOF_NONCE"]!
let marker = ProcessInfo.processInfo.environment["OMGS_PROOF_CONTRACT"]!
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
do {
  guard try canRead("owner", "owner") else { exit(2) }
  print("OMGS_CONTROL_\(nonce)")
  if try canRead("intruder", "owner") { print("OMGS_BOUNDARY_\(nonce)_\(marker)"); exit(1) }
  print("BOUNDARY_ASSERTION_OK")
} catch { exit(2) }
```

```sh
omgs prove --run RUN --finding FP --test main.swift --test-from DRAFT --expect-marker BOUNDARY_ASSERTION_FAILED --cmd "swiftc target.swift main.swift -o fixture || exit 2; ./fixture"
```

For modules needing a library, use `swiftc -emit-library` inside the same proof and link an explicit
workspace-relative library path. Common blockers: `swiftc not on host PATH` or `swiftc on host PATH
but failed to launch inside MXC`, missing SDKs or local libraries, unavailable Linux system headers
(the runner grants `/usr/include` read-only), nested SwiftPM sandbox creation, denied daemon APIs
and real root helpers. A compile/load failure earns no tier. Network and home denials above apply to
Swift too; redirect temporary files into the workspace or scratch.
