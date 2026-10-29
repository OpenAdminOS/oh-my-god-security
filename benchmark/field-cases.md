# Benchmark capability case candidates

These capability-level candidates use synthetic fixtures. They become benchmark cases only after human adjudication and a sandbox proof exist. Until then they are case candidates, not ground truth.

## Candidate 1: generated script values must stay data

Shape: values must stay data when a generator emits a script.
Proof test idea: use a synthetic generator fixture with a value containing quote characters. Parse its output in the sandbox and assert that the value remains data and does not become a statement. An ordinary value must round-trip unchanged.
Why it matters: generated script injection is a recurring class worth benchmark coverage.

## Candidate 2: dry run must preserve data boundaries

Shape: untrusted values must remain data, and dry run must remain free of side effects.
Proof test idea: use a synthetic fixture and sandbox-local observations to assert that untrusted values cause no side effects in dry run. Include an ordinary-value control.
Why it matters: dry run is a trust boundary operators rely on to preview destructive tools safely.

## Candidate 3: policy updates must preserve security minimums

Shape: external input must not lower a security minimum automatically.
Proof test idea: use synthetic policy values and mock writes in the sandbox. Assert that a proposed reduction causes no write and an allowed increase causes exactly one write.
Why it matters: policy automation needs benchmark coverage for monotonicity guarantees.

## Additional synthetic installer cases

These anonymous decision-logic shapes are modeled by the synthetic reproducer in
`benchmark/fixtures/installer-trust`. Its vulnerable and fixed variants exercise
invariants inside `omgs prove`, without root or vendor source. These examples do
not establish a finding against any specific project.

## Candidate 4: nil expected signer must not disable code-signature verification

Shape: a privileged installer helper takes an optional expected signing-team argument and,
when it is nil, installs the payload and runs its root install hooks without binding the
signer at all. A non-nil team is checked and a mismatch is refused; nil skips the check
entirely rather than failing closed.
Proof test idea: test the decision function directly in the sandbox. Assert that a request
with a nil expected team and a mismatched, unnotarized signer is refused, alongside a control
that a matching signer is accepted. The vulnerable logic authorizes the nil case and fails the
invariant; this is tier 1 with no root, as in `benchmark/fixtures/installer-trust`.
Why it matters: an optional security argument that becomes a no-op when omitted gives any
Developer ID signed, not even notarized, package root code execution through the helper.

## Candidate 5: the pkg install path must bind bundle identity and version, not only the signer

Shape: on the package branch, the helper trusts the installer to place the payload and binds
neither the caller-claimed bundle identifier nor the version to what the package actually
contains. With the expected signer nil (candidate 4), an unrelated bundle id and a bogus
version are accepted and the package's own scripts run as root.
Proof test idea: in the sandbox, assert the decision function refuses a request whose bundle
identity or version does not match the payload under a nil expected team. A fixed helper binds
the payload's real identity to the request. Tier 1, no root.
Why it matters: binding only the signer, and only when a signer is demanded, lets a wrong or
hostile package satisfy an update request for an unrelated application.

## Candidate 6: an update must refuse a downgrade and enforce the requested version against the payload

Shape: the helper installs a payload whose version is older than what is already installed
and reports success, and the caller-supplied expected version is never checked against the
version actually written. Coarse or claimed versions are trusted over the real payload.
Proof test idea: in the sandbox, assert the decision function refuses an older payload over a
newer installed version, and refuses when the expected version does not match the payload. A
fixed helper never silently lowers the installed version. Tier 1, no root.
Why it matters: silent downgrade through a trusted updater rolls an application back to a
known-vulnerable build, a persistence and re-exploitation primitive.
