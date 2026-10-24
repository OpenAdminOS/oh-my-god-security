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
omgs prove --cwd benchmark/fixtures/installer-trust \
  --cmd 'swiftc main.swift vulnerable/Verifier.swift -o "$TMPDIR/probe" && "$TMPDIR/probe"'
```

The vulnerable snapshot makes the invariant harness fail, which is the tier 1 `test_proven` evidence
of the defect. Swap `vulnerable` for `fixed` and the same command succeeds. The proof needs only a
Swift toolchain and the OMGS sandbox backend; it never needs root, a real installer, Gatekeeper, or a
dedicated host.

A benign line may appear in the output:

```
swiftc: error: couldn't create cache file '/var/folders/.../T/xcrun_db-...' (errno=Operation not permitted)
```

That is the sandbox denying `xcrun` a write to the real per-user temp dir, outside scratch. The
compile and the proof still complete; it is the containment working, not a failure.

## Relationship to the dedicated_host tier

A live demonstration that the vulnerable logic really runs as root belongs to the optional
`dedicated_host` tier and requires a disposable VM, never a productive machine. It is not needed to
establish the finding: this sandboxed logic proof is sufficient and is the path OMGS expects.
