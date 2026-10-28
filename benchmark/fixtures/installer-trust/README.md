# installer-trust fixture

A synthetic reproducer of a privileged updater's install-decision logic, modelled on the
2026-10-23 macOS root-helper field run (benchmark/field-cases.md, candidates 4 to 6). It proves
that the defect class is catchable through the ordinary sandboxed proof path, with no VM and no
privileged execution, so any OMGS user can reproduce it.

This is a pack reproducer and proof-recipe demonstration, not a scored benchmark corpus case. It
carries no real signing material, contacts nothing, and installs nothing. It only exercises a pure
`decide(_:)` function.

## What it shows

The harness `main.swift` asserts four security invariants plus one authorized control against the
`decide(_:)` provided by a snapshot:

- A nil expected signing team must not accept an unnotarized, mismatched signer (candidates 4 and 5).
- An explicit wrong expected team is refused (the existing check must keep working).
- A downgrade over a newer installed version is refused (candidate 6).
- The caller-claimed version must match the payload actually installed (candidate 6).
- Control: a matching signer installing a forward version is accepted.

`vulnerable/Verifier.swift` violates three of the invariants and exits non-zero; `fixed/Verifier.swift`
upholds all of them and the control, and exits zero.

## Run it through the sandbox (the expected path)

```
omgs prove --target benchmark/fixtures/installer-trust --test main.swift \
  --expect-marker BOUNDARY_ASSERTION_FAILED \
  --cmd 'swiftc main.swift vulnerable/Verifier.swift -o "$TMPDIR/probe" || exit 2; "$TMPDIR/probe"'
```

The vulnerable snapshot makes the invariant harness fail, which is the tier 1 `test_proven` evidence
of the defect. Swap `vulnerable` for `fixed` and the same command succeeds. The proof needs only a
Swift toolchain and the OMGS sandbox backend; the harness emits nonce-qualified
control and boundary markers under the declared recipe contract; it never needs root, a real installer, Gatekeeper, or a
dedicated host.

Benign lines may appear in the output, such as `xcodebuild` reporting that it could not read
`DARWIN_USER_CACHE_DIR`, or `xcrun` failing to create a cache file under `/var/folders`. That is
MXC denying writes to the real per-user cache and temp directories, outside the run's scratch. The
compile and the proof still complete; it is the containment working, not a failure.

## Scope of this proof

This fixture proves the defect class and its fix: it models the install-decision logic rather than
compiling any specific vendor build, so it is evidence about the class and the recipe, not about a
particular target. Promoting a real target finding needs separate evidence against that target's own
unmodified code.

Actually running the installer as root to show live impact has no OMGS proof tier and is never run
unsandboxed as a fallback; such a record stays `needs_validation` with a manual plan. A person may
demonstrate live impact on a throwaway, network-isolated, snapshot-and-discard VM to inform severity,
but that is a manual step outside OMGS and is never required. This sandboxed logic proof is the path
OMGS expects.
