# Privileged local operations

Hunt tools that delete, move, install, or extract files with more privilege than the principal who influenced the paths. Local does not mean safe when an operator, agent, or management system runs the tool elevated.

## What to hunt

- Recursive deletion built from discovered or imported paths without canonicalization, symlink checks, or an allowlist of roots. A symlinked parent redirects deletion outside the intended tree.
- Executing helper binaries from user-writable locations before dropping to their owner, or resolving tools through a caller-controlled PATH while elevated.
- Guest-to-host transfer from sandboxes and VMs: result extraction that honors guest-supplied paths on the host, shared folders that let guest installers write host project files that later execute.
- Cleanup logic that treats a captured top-level directory as disposable when it is a shared root.
- Dry-run modes that still execute lookups, hooks, or shell commands built from untrusted values.
- Code-signature, signer-identity, or notarization checks that become a no-op when the expected value is nil, empty, or omitted. An optional expected-signer argument that is enforced when present but skipped when absent fails open; a privileged installer then runs any validly signed, not necessarily notarized, payload and its root install hooks.
- Installer paths that bind only the signer and not the payload's real bundle identifier and version, so a wrong or unrelated package satisfies an update request for another application.
- Version or downgrade guards that trust a caller-claimed or coarse version instead of the version actually written, or that never compare the installed version at all, allowing a silent rollback to an older, known-vulnerable build.

## Source patterns that matter

- Path joins from bundle identifiers, app names, manifest entries, or captured installer behavior, passed to remove or move operations.
- Existence checks followed later by deletion of the same path (time-of-check gaps a symlink swap can win).
- Pre/post-flight hooks defined in data files an operator imports, executed without a distinct trust decision.
- An optional expected-team, expected-signer, or expected-version parameter whose check sits behind a nil or empty guard, so the caller disables verification by passing nothing.
- Equality-only version comparisons, or acceptance of a version string the caller or payload claims, with no read-back of the version actually installed.

## Proof shape

In `omgs prove`, build a dummy tree where a discovered path segment is a symlink to a sentinel directory outside the allowed root, run the tool's own dry-run or test path with dummy data, and assert the sentinel is untouched and the resolved target is rejected. The authorized control removes only the dummy app inside the allowed root.

For signer and version trust on a privileged installer, prove the decision logic in the sandbox first. The nil-signer and downgrade defects live in a pure decision function, so a tier 1 invariant test on that function with synthetic signer and version values decides them with no VM and no root. See `benchmark/fixtures/installer-trust` for a worked reproducer that fails on the vulnerable logic and passes on the fixed logic entirely inside `omgs prove`. A live demonstration that the vulnerable logic really runs as root is the optional tier 3 `dedicated_host` path: use it only for impact, never to establish the finding, and only on a throwaway VM or wiped machine with no real data, credentials, or Keychain secrets, snapshotted and discarded, never a productive machine, with the disposable-host attestation recorded. Drive the install path with a synthetic, owner-signed probe whose root hook drops a sentinel, and assert it is refused both when the expected signer is wrong and when it is nil, with no sentinel either time; then assert an older payload or a mismatched expected version is refused rather than silently installed. Record the host and that it is a manual dedicated-host proof, not `sandbox_exploited`.

## False leads a verifier should kill

- Canonicalization plus root-prefix enforcement applied at deletion time, not only at discovery time.
- Operations that never run elevated by design and cannot cross into another principal's files.
- Symlink components rejected explicitly before any recursive operation.
- A destination or in-archive symlink pointing outside the allowed tree that the installer replaces atomically rather than writing through: if the out-of-tree target's owner and contents are unchanged and a sentinel survives, the symlink path is sound.
- A signer check that fails closed when the expected value is absent, or a version guard that reads back the installed version and refuses a downgrade.
