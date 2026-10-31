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

Schema `omgs-proof/3` requires `execution_inputs.version: 4` for a target. Its SHA-256
matches `target_sha256` and the canonical `proofs/N/input-manifest.json`. The manifest retains
bounded per-path kinds, modes and content hashes for mismatch diagnostics. Validation and replay
use the same version and normalization. Older proof schemas and unknown identity versions are
refused with a request to rerun the proof, never silently interpreted under the new rules.

The disposable workspace contains normalized SHA-1 Git index versions 2 and 3. Stat fields and
TREE, UNTR, FSMN, EOIE and IEOT cache extensions are removed or zeroed before hashing and execution;
the checksum is regenerated. Paths, modes, object IDs, stages, flags and the supported REUC
resolve-undo extension remain bound, as do config, hooks, refs, objects and other Git files.
Every unknown extension signature is rejected. Normalization applies only
to `index` directly inside `.git` directories. Hook data named `index`, shared indexes and
auxiliary Git metadata remain byte-bound. Unsupported or malformed
indexes, including split indexes, fail closed. A linked worktree or external Git directory requires
a standalone checkout.
Do not execute Git against the target: config and hooks can execute programs. An incidental index
stat refresh does not invalidate a proof, but execution-relevant input changes do.

Version 4 materializes the workspace from fresh directories and regular files in sorted,
depth-first path order. Regular file content is written densely; hard links become independent
files with link count one. The only source permissions admitted are Unix 0777 bits or the Windows
read-only bit. Setuid, setgid and sticky bits are removed. Source ownership, extended attributes,
ACLs, file flags, sparse allocation and directory insertion order are never copied. The workspace
root uses fixed permissions (0755 on Unix, writable on Windows), independent of the target root.
Fresh objects belong to the staging user and receive the destination environment's default security
metadata; no source security descriptors or alternate data streams are imported.

On Unix, links bind and preserve their exact stored link text and kind, including dangling links
and `./` prefixes, with fixed link permissions of 0777 independent of source mode or umask.
Scratch cache links use the same fixed link mode. On Windows, all target links and reparse points
(file, directory, junction, outside and dangling) are rejected before execution with an
unsupported-input message. Manifest
validation uses the same admission rule, so no link is converted, rewritten or silently omitted.
After hashing and all harness staging, access and modification times on workspace files,
directories and links are reset to 2000-01-01 UTC without following links. Creation times are
also reset on macOS and Windows. The workspace root is normalized last. This policy is identical
for original proofs and replays; source timestamps are never modified.

OS-managed ctime, inode numbers, filesystem enumeration behavior, physical allocation details
beyond dense writes, and creation times on filesystems without a setter are properties of the
disposable execution. Code depending on these values is nondeterministic. A detectable change in
the recorded outcome makes replay report a mismatch; replay cannot detect differences the harness
does not observe. Identical identity is not a guarantee of deterministic behavior for such code.
Version 1 and 2 identities require a fresh proof.

For a smaller immutable input boundary, pass `--inputs-from SELECTION.json`, containing
`{"version":1,"paths":["src/decision.rs","Cargo.toml"]}`. Paths can name files or directories.
Everything else is absent from the workspace, except root `.git`, which is always included.
Selections allow 1 to 256 canonical relative non-overlapping paths; scoped trees cannot contain
links. Every component must exactly match one enumerated on-disk directory entry, including
case and Unicode normalization bytes. Filesystem lookup aliases are refused even if the host
resolves them successfully. After copying, every selected path, including automatically included
root Git metadata, must again be present exactly once under its exact spelling. Include the actual
decision code, enforcement chain, configuration and required local dependencies. Omitted
dependencies must block the proof, never be replaced with fabricated
security behavior. Disclose the selection and challenge its sufficiency during evaluation.
Target names containing backslashes or colons are refused with the canonical relative path
error before copying, including on Unix. Git indexes are normalized during fresh create-new
staging with their identity-bound modes, including group-writable 0664 indexes. Manifest
construction never rewrites the source tree. Index input remains capped at 16 MiB.
The retained identity shares the gate hard maximum of 2,000,000 entries and is capped at
12,800,065,536 serialized bytes (6,400 per allowed entry plus 65,536 bytes of overhead).
Version 4 uses canonical JSON Lines at `input-manifest.json`: one header object with fields
`version`, `entries` and `selection`, then one entry object per line with fields `path`,
`kind`, `mode` and `sha256`, in that field order. Every line ends with a single LF.
Entries use depth-first, UTF-8 component-sorted path order. SHA-256 covers exactly these
bytes, including the header and line endings. The proof record also carries the selection
in `execution_inputs.selection`, so reproduction never depends on parsing the retained artifact.
Older identity versions, including version 3, require a fresh proof.

Generation counts admitted paths before writing the header, enforces the entry limit before
constructing each entry, and streams content hashes and canonical JSON into SHA-256.
Publication streams through a private sibling temporary file, flushes and fsyncs it, then
renames it atomically before target execution. Publication computes the identity over the
bytes written; a changed entry count aborts publication. A separately computed identity must
still match when republished. No full entry list, JSON value, string or serialized manifest
buffer is retained. Directory traversal retains
a single sorted name collection per active directory level, including during workspace copying.
Each directory is enumerated once per traversal. Every enumerated sibling is charged against the
shared 2,000,000 entry traversal budget before selection filtering. Only selected candidates
(including root Git metadata) are retained and sorted. Each directory permits at most 200,000
retained names and 32 MiB of UTF-8 name bytes, whichever is reached first; exceeding either
limit refuses staging with a message naming the directory. Unselected siblings consume only
the traversal budget, never sort memory. Gap diagnostics retain only the first 20 sorted paths
and aggregate counts. The 1024-byte canonical path limit bounds recursion depth. Git index
normalization still uses its separate 16 MiB bound.

Validation and replay recompute the target or staged workspace digest and compare it with
the proof record. They do not open the retained manifest to decide reproduction. Only mismatch
diagnostics open it through the same private, single-link, no-follow run artifact admission.
Diagnostics parse one line at a time, limited to 1 MiB for the header and 6,400 bytes for an
entry (including LF), reject duplicate keys and unknown fields, validate paths, kinds, modes,
hashes and ordering, and enforce the declared count and hard entry limit before reading or
allocating another entry. Diagnostics stop at the first divergent entry, reporting at most
two paths. Diagnostic failures cannot allow reproduction. Copy and hash phases report elapsed
time and entry count.
Each execution receives a fresh disposable copy; no mutable workspace cache is reused.
The target must not be modified while a proof is staged. Before reading source content or
copying, OMGS streams a canonical digest of OS change stamps for every admitted entry,
including the target root and each traversed directory itself. Unix stamps bind st_dev, st_ino,
st_size, st_mtime and st_ctime with nanoseconds. Windows stamps bind volume serial, file index,
size, LastWriteTime and ChangeTime from FILE_BASIC_INFO through no-follow handles.
After copying and all source content reads, a fresh stamp walk must have identical membership
and stamps. Directory stamps detect membership changes even if entries are removed again.
Change stamp comparison detects accidental or ordinary concurrent modification on all platforms.
Unix ctime cannot be set by user space. On Windows, a process with write attribute access can
set or suppress ChangeTime and LastWriteTime; deliberate forgery by such a same user process
is outside the documented threat model.
The stamp stream is hashed incrementally without retaining an entry map. These stamps guard
staging only and are never part of replay identity.
OMGS also streams the source identity before copying, then both the staged identity and a fresh
source identity after copying. All three must agree before any target execution, including for
a fresh proof. Any stamp, membership or content difference, or failed source recheck refuses
execution with `target changed during staging`; no proof record is emitted. There is no retry.
This comparison guards ordinary concurrent modification without locking the source or claiming
an atomic filesystem snapshot. Keep the source unchanged until staging completes.

Staging has a fixed 8 GiB aggregate content read budget across source hashing, dense copying and
staged hashing, and a ten-minute deadline from before the first walk through completion of
staging, independent of the executor timeout. Repeated reads count again; the budget is reserved
from each file size before reading or copying. Files are read only through their admitted size;
growth or truncation refuses with `target changed during staging`. Byte budget or deadline
exhaustion refuses before executor startup. Deadline and interruption checks run between files,
directory entries and read chunks. Shared harness and selection ancestors are enumerated once
per parent per check, with every sibling charged to the shared traversal entry budget. These
fixed limits have no configuration override.

`--test-from` accepts a regular file or a directory outside the target. A directory's files are
mapped beneath the parent of `--test`, and must include that test's basename. For example,
`--test checks/main.swift --test-from DRAFT_DIR` stages `DRAFT_DIR/main.swift` at
`checks/main.swift` and `DRAFT_DIR/stubs.swift` at `checks/stubs.swift`. Directory harnesses retain
at most 128 regular files and 16 MiB total, with canonical relative paths, per-file hashes and
modes. Each harness directory retains at most 256 child names and refuses immediately when
child 257 is enumerated, before reading child contents. Links, special files, empty directories,
and paths deeper than 32 directories are refused.
Before staging any file, all destinations are checked against both the copied workspace and
the original target, including omitted input paths. Existing file, directory or link destinations
are rejected. Existing directory ancestors are allowed only under their exact names, without
links. Harness names use portable ASCII letters, digits, dots, underscores and hyphens; hidden
components, trailing dots, Windows device names, short-name syntax and alternate separators
are refused. Case aliases, overlapping harness paths and ambiguous Unicode siblings are also
refused. Move the harness to an unambiguous fresh path when admission fails.
Retained files live beneath `proofs/N/harness/`;
replay reads them through the private artifact boundary and never reads the original draft path.
Single-file drafts retain the existing `test-draft` representation and bind bytes only.
They always stage with mode 0755 on Unix or writable on Windows, regardless of source or retained
file permissions. Use a directory harness when a specific per-file mode matters. Every new harness
directory ancestor uses mode 0755 on Unix or writable on Windows; existing target ancestors retain
their identity-bound modes. Scratch directories use the same fixed directory policy. The empty
macOS OpenSSL config and Windows command wrapper use mode 0644 on Unix or writable on Windows.
The wrapper content and name derive from the recorded command, test path and fresh marker nonce.
These materialization constants continue to apply with version 4. Replay output says
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
copied target tree (including dirty changes and execution-relevant Git metadata under the
versioned normalization above) differs from the original
snapshot; a replay that is NOT reproduced overturns the tier and recomputes identities with `omgs
fingerprint` after any semantic change, so records are final before adjudication.
