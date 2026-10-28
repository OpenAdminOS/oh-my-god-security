# Policy, gate and setup

## Base policy, gate and setup

For a pull request, initialize with `omgs audit init --target TARGET --base BASE_REF` using the
trusted base branch ref or event base SHA. The ref must be locally available. Never select a head
policy as the base. Initialization reads only `BASE_REF:.omgs/policy.json` through object-only Git
commands and records the resolved commit, policy source, raw blob, parsed policy and SHA-256 in run
metadata. A missing base blob uses advisory, high threshold, null persona, unbounded budget and
empty exclusions, intent and suppressions. Omitting --base deliberately uses local defaults. An
invalid base ref or policy is an error, never a fallback.

See [schemas/policy.schema.json](schemas/policy.schema.json). All top-level fields are required,
even nullable persona and budget; unknown keys are refused. Base policy fixes mode, persona and
budget. Excluded paths are literal relative path prefixes and create planned ledger units with
counts and sorted path samples. Review and resolve them with evidence; do not silently discard them
or treat an exclusion as suppression. Accepted intent records require id, answer, scope and source.
Suppressions require fingerprint, reason and expires_unix in UTC Unix seconds through year 9999, at
most 365 days after the commit that last changed policy. Missing, null or out-of-range expiry is
invalid. Expired entries do not apply.

After recording an owner's answers with `omgs intent answer`, run `omgs intent propose --run
OUTPUT_DIR` to write `OUTPUT_DIR/policy.patch` for owner review. It never changes the target and
never changes this run's gate. Only reviewed, committed base policy can accept those answers or
suppress future runs.

Use `omgs intent propose --run OUTPUT_DIR` or `omgs stage --run OUTPUT_DIR` to propose registered
gate tests from validated test-proven findings. The patch includes tests and policy entries with id,
committed test path, exact command, expect_marker, severity, timeout_ms and optional finding
fingerprint. Owner review of that patch authorizes tests only for later base commits.

Run `omgs gate --target TARGET --base BASE_SHA --head HEAD_SHA [--run OUTPUT_DIR]` with full
immutable event SHAs. Gate reads policy directly from the base commit, checks HEAD safely and
exports only committed head files. It executes active registered tests inside MXC with fresh nonces.
Exit 1 requires a registered test at or above threshold to exit 1 with both nonce-qualified recipe
markers. Passing tests exit 0. Missing tests, contract errors, unavailable MXC, head mismatch and
invalid policy return 3. Valid advisory policy makes all execution results display-only and exits 0,
including infrastructure errors. Invalid base policy cannot establish advisory mode and returns 3.
Optional run findings are advisory only; edited findings, proofs or metadata cannot affect the exit
code. Gate refuses redirected Git directories and config includes, uses bounded Git children with
cleanup, and currently exports regular files only, refusing symlinks and submodules. Gate installs
no dependencies. It does not replace independent proof replay or evaluation.

For setup scripts, `omgs setup --install-skills --verify-mxc` installs only into detected home
directories under the Skills CLI name omgs-security-review and runs the same live deny probe as
doctor --live. The verified binary embeds the complete skill, including bootstrap installs launched
from unrelated directories. Use --from only to explicitly select another local source. Identical
installs are no-ops. Differing files are named and refused unless --replace is explicit; replacement
stages a complete tree and retains the old tree at a printed backup path. Failed publishing restores
the old tree without mixing files. `omgs setup --dry-run` lists only detected destinations and
changes nothing. `omgs setup --write-policy TARGET --mode gate|advisory` creates default policy only
on explicit request and refuses replacement. `omgs setup --yes` installs detected skills and
verifies MXC without interaction; it never silently writes repository policy. Never claim live
verification passed if setup reports a missing executor or a platform refusal.
