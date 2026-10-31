# Proof contract

Whenever a hunter or verifier uses a proof recipe, the verifier must declare `--expect-marker
BOUNDARY_ASSERTION_FAILED` on `omgs prove`. Require inner `record.exit_code: 1` and the runner's
full-stream
`contract.boundary_marker_seen` and `contract.authorized_control_seen` fields before claiming recipe
proof support. Harnesses read `OMGS_PROOF_NONCE` and `OMGS_PROOF_CONTRACT` from the environment,
then emit `OMGS_CONTROL_<nonce>` after the authorized control and `OMGS_BOUNDARY_<nonce>_<label>`
immediately before assertion exit 1. Require schema `omgs-proof/2` with `contract.kind: "recipe"`;
missing or null contract fields are invalid. Fixed or wrong-nonce markers earn no support. Hostile
code sharing the harness process can read the nonce, so the independent evaluator remains required.
Exit 2 is a harness or usage error and never supports a proof.

## CLI exits and record cleanliness

For an original `omgs prove`, outer exit 0 means clean command success, outer exit 1 means a
supported assertion, outer exit 2 means a harness, usage or execution error, and outer exit 3
means unavailable tier 2. These outer codes are distinct from `record.exit_code`, the inner
harness code. For a recipe, require outer exit 1 AND inner `exit_code: 1`, both contract flags
and the clean fields below. Never use the outer exit alone to confirm a finding.

For `--replay`, outer exit 0 means reproduced, 1 means mismatch, 2 means setup error, and 3
means unavailable tier 2. Keep `proof_ref` on the original; cite replay paths in evaluator
evidence. Replay numbering shares the proof sequence and `replays` names the original number.

A clean record has `command_started`, `command_finished`, `capture_complete` and
`cleanup_complete` true; an exit code and valid nonce; `test_reachable: true` when a test is
specified; `timed_out`, `killed`, `interrupted` and `executor_error` false; and no `survivors`.
Cleanliness is necessary but does not prove the semantic assertion or production impact.
`timeout_ms` is the inner execution timeout; the outer wall clock adds 15000 ms for executor
startup and cleanup. This allowance is not extra target execution time.

## Assertion and replay requirements

Every non-rejected `test_proven` or `sandbox_exploited` record needs its named test or harness
failing
on the target with an assertion (inner exit 1 or 3 through 125 without a contract); a rejected
control without a contract can also exit 0. Exit 2 is always rejected as a harness or usage
error. A recipe contract requires exit 1 and both nonce-qualified marker flags, and neither may
rest on a missing command (126, 127) or a signal. The command must include the full `--test`
path or its file name as a token. Runner-generated start and end markers catch accidents such as
executor failure, truncation and timeout. They cannot establish integrity against a hostile
target: the per-run nonce is visible to sandboxed code, so a target can print a forged end
marker. They also cannot prove that the named test executed. Replay and the independent evaluator
remain the stronger check. Missing start indicates an executor error unless the run was killed or
interrupted; missing end means incomplete execution. Timeout, signal death and executor errors
are recorded separately. During adjudication the evaluator replays every proof it upholds with
`omgs prove --run OUTPUT_DIR --replay <n>` and independently checks that
the real target and intended assertion executed. Replay requires the recorded `timeout_ms` and
rejects `--timeout-ms` overrides, consumes one proof-run budget unit, checks the marker-derived
inner exit code and cleanliness, and refuses if either the target commit or the digest of the
copied target tree (including all `.git` content and dirty changes) differs from the original
snapshot; a replay that is NOT reproduced overturns the tier and recomputes identities with `omgs
fingerprint` after any semantic change, so records are final before adjudication.
