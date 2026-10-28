# Base-branch policy in GitHub Actions

Use the same workflow for gate and advisory. Commit the policy described in the
[README](../README.md#committed-policy-and-gate) on the base branch. Choose
`"mode": "gate"` to fail on failing registered security tests, or
`"mode": "advisory"` to print what would fail. A pull request changing that field
cannot change its own gate. Missing policy defaults to advisory; enforce policy
presence separately if your organization requires opt-in before every review.

This example assumes an ephemeral self-hosted Linux runner in the group
`omgs-ready`. Provision a verified OMGS binary, its pinned MXC executor, local
toolchains and dependencies before running the job. Do not install dependencies
from the pull request or run its scripts on the host. `/opt/omgs/bin/review-run`
is an operator-owned pipeline integration, outside the checkout: it drives the
isolated hunt, independent verify and evaluation stages through OMGS, writes
adjudicated findings and validates the completed run. Configure its executable
path and allowlist for your environment before enabling this example. It must
exit nonzero on incomplete review. Gate alone is not a completeness check.

```yaml
name: Security review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on:
      group: omgs-ready
      labels: [self-hosted, linux]
    timeout-minutes: 30
    env:
      RUSTUP_AUTO_INSTALL: "0"
      OMGS_BIN: /opt/omgs/bin/omgs
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Initialize from immutable base commit
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        shell: bash
        run: |
          set -euo pipefail
          run_dir="$RUNNER_TEMP/omgs-run"
          "$OMGS_BIN" audit init --target "$GITHUB_WORKSPACE" \
            --base "$BASE_SHA" --out "$run_dir" --no-sensors
          echo "OMGS_RUN=$run_dir" >> "$GITHUB_ENV"
      - name: Complete trusted review pipeline
        shell: bash
        run: |
          set -euo pipefail
          /opt/omgs/bin/review-run --run "$OMGS_RUN"
          "$OMGS_BIN" validate --findings "$OMGS_RUN/findings.json"
          "$OMGS_BIN" critic --run "$OMGS_RUN"
      - name: Evaluate committed policy
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        shell: bash
        run: |
          "$OMGS_BIN" gate --target "$GITHUB_WORKSPACE" \
            --base "$BASE_SHA" --head "$HEAD_SHA" --run "$OMGS_RUN"
```

Do not add `continue-on-error` for advisory. Advisory is selected by valid base
policy and always exits 0, printing test failures and infrastructure errors.
Invalid base policy cannot establish advisory mode and returns 3. In gate mode,
exit 1 requires a registered committed security test to fail with its recipe
contract; infrastructure errors return 3. The optional review run is advisory
only. Gate reads base policy independently and executes active registered tests
from committed head files through MXC with fresh nonces. Keep gate as a separate
required check if review completeness should be reported separately.
Never use `pull_request_target` to run an untrusted checkout with elevated
credentials. Avoid interpolation of PR titles, branch names or bodies into shell
scripts. Keep findings and policy proposals outside the checkout and restrict
artifact access, since they describe vulnerabilities.

For gate mode, commit the default policy with `mode` changed to `gate`. For
advisory mode, commit the default as shown. In both modes the event base SHA,
source and policy digest remain visible in run metadata. Upload reports through
your organization's approved artifact step only after its privacy review.

## Registered test ownership and dependencies

The gate runs head content, including registered tests. Protect registered test
paths with CODEOWNERS or branch protection and require owner review of changes.
Both modes print `registered gate test modified in head: <id> <path>` when an
active test's blob changes or disappears. Modification keeps the normal result;
a missing test is an infrastructure error (exit 3 in gate mode, display-only in
advisory mode).

The gate exports only committed files. Checkout-local `node_modules` and `.venv`
directories are dropped unless committed. Provision dependencies outside proof
execution in an owner-managed, sandbox-readable location. For example, provision
and pin a Python environment under `/opt/omgs/python` during runner preparation,
then register the absolute command `/opt/omgs/python/bin/python security_test.py`.
The interpreter and its dependencies must be admitted by the runner's read-only
toolchain configuration. Verify that location is readable inside MXC before
enabling the gate. Proofs never install dependencies or fetch packages.

## Pre-policy runs

Runs created before reviewer-owned policy provenance was introduced cannot seed
`audit init --fix-of` or generate policy proposals, even if they contain a policy
snapshot. OMGS rejects them when no trusted record exists. Reports can still show
answers recorded independently in the reviewer's intent store, but omit
policy-derived answers with a warning. Keep the old run for evidence, then
initialize a fresh audit with `omgs audit init --target /path/to/repo
--base <full-base-sha> --out /private/runs/new-audit`. Complete that audit before
using its path with `--fix-of`. This is a new budget family, not a continuation
or refund of the legacy allowance. Set the reviewed budget in base policy and
account for any earlier spending separately. Do not fabricate a snapshot in old
metadata. Existing target and cumulative budget constraints continue to apply
to supported fix runs.

## Reviewer-owned policy provenance

At initialization, the CLI resolves `--base` and records the full commit SHA and
exact policy blob digest beside the target's reviewer-owned intent store. Each
record binds the canonical target and run paths. The record lives outside both
the target and the run directory. A later init for the same target creates a
separate record and does not retarget earlier runs.

Reports, fix initialization and policy proposals obtain the base only from this
record. They require a full immutable SHA, re-read the policy through the safe
object-only Git reader, and verify its digest against the trusted record.
Run-local policy snapshots are diagnostic copies: disagreements warn and are
ignored, including edits to the base SHA and matching digest. Missing or invalid
trusted provenance never falls back to metadata. Gate continues to read its
explicit caller-supplied base independently.

When no committed policy exists, the trusted record retains the CLI-selected
mode, persona and budget. Fix runs inherit those settings, subject to existing
explicit override rules and cumulative budget limits. When a policy blob exists,
fix runs inherit its authenticated mode, persona, excluded paths, suppressions
and test registrations. Policy patches use the exact authenticated base blob as
their baseline. Moving a run to another path or machine requires a fresh audit;
copying its snapshot alone cannot establish provenance.

## Building the embedded skill

The default setup source is the skill embedded in the binary. Only explicit
`--from` selects another source; adjacent sidecar directories do not override it.
The build embeds every regular file under `skill`. Keep that directory clean
when building releases: remove untracked files and review all tracked changes
before building. Bundle roots and entries must not be symlinks. Unsafe relative
destinations are rejected during the build and checked again during installation.
