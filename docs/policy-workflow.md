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
