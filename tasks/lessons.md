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
