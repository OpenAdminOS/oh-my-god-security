# Lessons

## 2026-10-23: never run installer/root proofs on a machine with real data

What happened: during the macOS root-helper field run, the installer and nil-signer proofs were
executed on a Mac reached over ssh as "the sacrificial mini". It was actually a productive machine
with real data and Keychain access. Gatekeeper was disabled and passwordless sudo added on it to
run unnotarized Developer ID packages as root. The user caught this.

Why it matters: OMGS's core invariant is sandbox-only. All target code runs through `omgs prove`
in an OS-enforced sandbox; there is never an unsandboxed fallback. Privileged installers and root
helpers are the one class the sandbox cannot contain, and there is no tier or backend for running
them, so their root-execution step has no proof tier: leave it `needs_validation` with a manual
plan rather than running it anywhere unsandboxed. Weakening a real machine (Gatekeeper off,
passwordless sudo) to run such a step is exactly the mistake this lesson records. If a person runs
a live demonstration purely to inform severity, that is a manual step outside OMGS on a genuinely
disposable machine (throwaway VM or wiped box, no real data, no credentials, no Keychain),
snapshotted and discarded, and never a substitute for the `needs_validation` verdict.

Rules for next time:
- An effect the sandbox cannot contain (real root, Gatekeeper, a root helper) has no proof tier
  and is never run unsandboxed as a fallback. Leave the record `needs_validation` with a manual
  plan. There is no `dedicated_host` tier: a tier whose decisive step runs outside `omgs prove`
  cannot satisfy the sandbox-only invariant (removed after the second review).
- If a person does a live demonstration for severity, it is a manual step outside OMGS on a
  throwaway, network-isolated, snapshot-and-discard VM with no real data, credentials, or Keychain,
  and the host and every weakening step (and its reversal) are recorded. Never a productive machine.
- A proof harness that crashes before reaching the code under test (missing dylib, load error,
  build failure) must fail loudly and distinctly. Never read a harness abort as the target refusing
  the operation; on the first field run a bare-leaf dylib load silently aborted every case and
  produced false "refused" results.

## 2026-10-24: never default a required field in a security input

What happened: in the coverage critic PR, four review rounds in a row found the same defect one
level deeper each time: a `#[serde(default)]` on a required container or field (`candidates`,
`units`, `findings`, then unit `surface`/`attack_classes` and candidate identity fields) let a
misspelled or dropped key parse as empty, which the critic then certified as a pass.

Rules for next time:
- A field the schema marks required has no serde default. Missing input must be a parse error,
  never an empty value a checker can pass.
- When fixing one instance of a bug class, sweep every struct the same input flows through
  before asking for re-review.

## 2026-10-27: nothing discussed is deferred out of a release

What happened: sandbox hardening was moved to "Deferred past 0.1" when it got hard, and other
roadmap items stayed "still open" or "tracked" while the release was called ready. The user's
rule: everything discussed for the release ships in that release.

Rules for next time:
- Never mark a discussed item as deferred, tracked, or "later" to close out a release. If it
  is blocked, say so, say why, and keep it in scope until the user explicitly removes it.
- Before calling a release ready, sweep IMPROVEMENTS.md, tasks/todo.md, DECISIONS.md, and
  benchmark/feature-coverage.md for open, partial, tracked, or deferred items and list them.


## 2026-10-28: make inventory exclusions fail safe

What happened: successive review rounds found production paths hidden by directory hints for docs,
specs, tests, fixtures, dumps and exports. Name-by-name exceptions left the same coverage failure.

Rules for next time:
- Default unknown files to Code. Exclusion needs a specific convention, not a broad folder hint.
- Runtime ancestry wins over directory hints; SQL, HTML and templates stay in hunting scope.
- Record excluded counts and sorted path samples in the coverage ledger, including source paths.
- Test adversarial runtime paths end to end, including the hunting units and critic result.
