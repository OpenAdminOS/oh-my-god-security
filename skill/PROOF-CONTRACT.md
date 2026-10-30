# Proof contract

Whenever a hunter or verifier uses a proof recipe, the verifier must declare `--expect-marker
BOUNDARY_ASSERTION_FAILED` on `omgs prove`. Require inner `record.exit_code: 1` and the runner's
full-stream
`contract.boundary_marker_seen` and `contract.authorized_control_seen` fields before claiming recipe
proof support. Harnesses read `OMGS_PROOF_NONCE` and `OMGS_PROOF_CONTRACT` from the environment,
then emit `OMGS_CONTROL_<nonce>` after the authorized control and `OMGS_BOUNDARY_<nonce>_<label>`
immediately before assertion exit 1. Require schema `omgs-proof/3` with `contract.kind: "recipe"`;
missing or null contract fields are invalid. Fixed or wrong-nonce markers earn no support. Hostile
code sharing the harness process can read the nonce, so the independent evaluator remains required.
Exit 2 is a harness or usage error and never supports a proof.

## CLI exits and record cleanliness

For an original `omgs prove`, outer exit 0 means clean command success, outer exit 1 means a
supported assertion, outer exit 2 means a harness, usage or execution error, and outer exit 3
means execution was blocked before the command ran, including unavailable tier 2. These outer codes
are distinct from `record.exit_code`, the inner
harness code. For a recipe, require outer exit 1 AND inner `exit_code: 1`, both contract flags
and the clean fields below. Never use the outer exit alone to confirm a finding.
With a recipe contract, an inner usage code such as 64 without the required markers yields outer
exit 2. It is a harness error, not assertion support. Without a declared contract, the existing
assertion convention accepts inner exits 1 or 3 through 125; every recipe must declare its contract.


For `--replay`, outer exit 0 means reproduced, 1 means mismatch, 2 means setup error, and 3
means execution was blocked before the command ran. Keep `proof_ref` on the original; cite replay
paths in evaluator
evidence. Replay numbering shares the proof sequence and `replays` names the original number.

A clean record has `command_started`, `command_finished`, `capture_complete` and
`cleanup_complete` true; an exit code and valid nonce; `test_reachable: true` when a test is
specified; `timed_out`, `killed`, `interrupted` and `executor_error` false; and no `survivors`.
Cleanliness is necessary but does not prove the semantic assertion or production impact.
`timeout_ms` is the inner execution timeout; the outer wall clock adds 15000 ms for executor
startup and cleanup. This allowance is not extra target execution time.

## Execution input identity and replay

Schema `omgs-proof/3` requires `execution_inputs.version: 1` for a target. Its SHA-256
matches `target_sha256` and the canonical `proofs/N/input-manifest.json`. The manifest retains
bounded per-path kinds, modes and content hashes for mismatch diagnostics. Validation and replay
use the same version and normalization. Older proof schemas and unknown identity versions are
refused with a request to rerun the proof, never silently interpreted under the new rules.

The disposable workspace contains normalized SHA-1 Git index versions 2 and 3. Stat fields and
TREE, UNTR, FSMN, EOIE and IEOT cache extensions are removed or zeroed before hashing and execution;
the checksum is regenerated. Paths, modes, object IDs, stages, flags and all other extensions
remain bound, as do config, hooks, refs, objects and other Git files. Normalization applies only
to `index` directly inside `.git` directories. Hook data named `index`, shared indexes and
auxiliary Git metadata remain byte-bound. Unsupported or malformed
indexes, including split indexes, fail closed. A linked worktree or external Git directory requires
a standalone checkout.
Do not execute Git against the target: config and hooks can execute programs. An incidental index
stat refresh does not invalidate a proof, but execution-relevant input changes do.

For a smaller immutable input boundary, pass `--inputs-from SELECTION.json`, containing
`{"version":1,"paths":["src/decision.rs","Cargo.toml"]}`. Paths can name files or directories.
Everything else is absent from the workspace, except root `.git`, which is always included.
Selections allow 1 to 256 canonical relative non-overlapping paths; scoped trees cannot contain
links. Include the actual decision code, enforcement chain, configuration and required local
dependencies. Omitted dependencies must block the proof, never be replaced with fabricated
security behavior. Disclose the selection and challenge its sufficiency during evaluation.
The retained identity is capped at 100000 entries and 16 MiB; use a selection if a full tree
exceeds either bound. Copy and hash start/completion phases report elapsed time and entry count.
Each execution receives a fresh disposable copy; no mutable workspace cache is reused.

`--test-from` accepts a regular file or a directory outside the target. A directory's files are
mapped beneath the parent of `--test`, and must include that test's basename. For example,
`--test checks/main.swift --test-from DRAFT_DIR` stages `DRAFT_DIR/main.swift` at
`checks/main.swift` and `DRAFT_DIR/stubs.swift` at `checks/stubs.swift`. Directory harnesses retain
at most 128 regular files and 16 MiB total, with canonical relative paths, per-file hashes and
modes. Links, special files, empty directories, and paths deeper than 32 directories are refused.
Retained files live beneath `proofs/N/harness/`;
replay reads them through the private artifact boundary and never reads the original draft path.
Single-file drafts retain the existing `test-draft` representation. Replay output says
`replay record` and names the original path; it never offers a replacement `proof_ref`.

## Redaction and marker observations

`output_audit.version: 1` records the first exact nonce-qualified control and boundary observations
independently of retained output. Each observation names its kind, stream (0 stdout, 1 stderr),
and raw stream byte range excluding line endings. The marker text is reconstructed from the
contract label and nonce. These are runner observations, not proof of the target's semantic claim.
Validation checks observation bounds and agreement with the contract flags. Output flooding and
unterminated private key blocks cannot erase the separate observations.

`stream_bytes` and `retained_stream_bytes` expose each stream's omitted suffix as the half-open
range `[retained_stream_bytes[i], stream_bytes[i])`. `redactions` are half-open ranges in the
UTF-8 capture before redaction (stdout prefix followed by stderr prefix), covering changed lines
or whole private key blocks. After 1024 ranges, later ranges are conservatively coalesced
into the last range, which can also cover intervening unchanged text. `captured_text_bytes` gives
that coordinate space's length. If lossy UTF-8 conversion expanded
the retained raw prefixes beyond the text cap, the additional omitted text range is
`[captured_text_bytes, decoded_capture_bytes)` in the decoded-prefix coordinate space.
The output digest still covers only the saved redacted text. An unterminated private key block
remains redacted through the end of the capture; no marker line is treated as a safe end.
Exact command, harness and configuration artifacts may contain credentials and remain private.
