# Lessons

## 2026-10-23: never run installer/root proofs on a machine with real data

What happened: during the macOS root-helper field run, the installer and nil-signer proofs were
executed on a Mac reached over ssh as "the sacrificial mini". It was actually a productive machine
with real data and Keychain access. Gatekeeper was disabled and passwordless sudo added on it to
run unnotarized Developer ID packages as root. The user caught this.

Why it matters: OMGS's core invariant is sandbox-only. All target code runs through `omgs prove`
in an OS-enforced sandbox; there is never an unsandboxed fallback. Privileged installers and root
helpers are the one class the sandbox cannot contain, so they move to a dedicated host. That
exception is only safe on a genuinely disposable machine (throwaway VM or wiped box, no real data,
no credentials, no Keychain), snapshotted and discarded. Weakening a real machine (Gatekeeper off,
passwordless sudo) exposes it for as long as the change stands.

Rules for next time:
- Before any elevated or installer proof, confirm the host is disposable. If it has real data,
  credentials, or Keychain secrets, stop. Stand up a throwaway VM instead.
- Record the disposable-host attestation and every host-weakening step in `prerequisites`, and
  revert each one when done (verify `spctl --status` = assessments enabled, remove NOPASSWD
  sudoers, delete root-owned test artifacts and package receipts).
- A tier-3 `dedicated_host` record without a disposable-host attestation now fails `omgs validate`;
  do not work around that check, satisfy it.
- A proof harness that crashes before reaching the code under test (missing dylib, load error,
  build failure) must fail loudly and distinctly. Never read a harness abort as the target refusing
  the operation; on the first field run a bare-leaf dylib load silently aborted every case and
  produced false "refused" results.
