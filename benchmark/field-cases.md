# Field derived benchmark case candidates

Cases below came from traced field reviews on 2026-10-16. They become benchmark cases only after human adjudication and a sandbox proof exist. Until then they are case candidates, not ground truth.

## Candidate 1: apostrophe in generated PowerShell data

Shape: a web tool serializes configuration to JSON and string-replaces it into a single-quoted PowerShell literal in a template. A favorite value containing an apostrophe must stay data.
Proof test idea: generate a script from a fixture value containing an apostrophe plus a harmless marker command, parse the generated script in the sandbox, and assert the marker is inside the data string and never becomes a statement. Requires a PowerShell runtime in the sandbox image.
Why it matters: generated script injection was the dominant candidate class across the field reviews.

## Candidate 2: dry run must not execute manifest data

Shape: a CLI looks up running processes by interpolating a manifest supplied name into a shell command before the dry run branch. A manifest name containing quote and command separator characters must not execute anything in dry run or real mode.
Proof test idea: run the lookup path in the sandbox with a fixture name that appends a harmless marker file write, with a scratch-only writable area, and assert the marker file never appears while an ordinary name still resolves.
Why it matters: dry run is a trust boundary operators rely on to preview destructive tools safely.

## Candidate 3: feed must never lower a security minimum

Shape: an updater writes a feed-derived compliance minimum after comparing only for equality. A fixture feed whose newest version is older than the current policy must produce no write.
Proof test idea: run the decision function against a fixture feed and a mock policy value inside the sandbox. Assert no update call for the older feed and exactly one update for a genuinely newer feed.
Why it matters: external feeds quietly becoming enterprise policy is a recurring Intune ecosystem pattern.

## 2026-10-23 additions: privileged macOS updater with a root helper

These came from the 2026-10-23 field run against a public macOS app updater with a root
LaunchDaemon helper. All three are decision-logic defects, so their decisive proof is a
sandboxed tier 1 invariant test on the pure decision function, with synthetic signer and
version values and no root. The worked reproducer lives at `benchmark/fixtures/installer-trust`:
it fails on the vulnerable logic and passes on the fixed logic entirely inside `omgs prove`,
with no VM. This is the proof that matters, because it is the one every OMGS user can
reproduce. The repository ships only that synthetic reproducer, never the vendor's source or
signed fixtures, which stay in the private run directory pending maintainer disclosure.

A separate live run did execute the real helper's code paths as root against synthetic signed
payloads, which first established these as real. It ran on a machine that turned out to be
productive, not disposable; that was a mistake, the machine was restored afterward (Gatekeeper
re-enabled, passwordless sudo and test artifacts removed). A live run of that kind is a manual
step outside OMGS, for impact only, on a throwaway network-isolated VM, and is never an OMGS
proof tier and never required to establish a finding. The historical `Proof (2026-10-23)` notes
below record what that run observed.

## Candidate 4: nil expected signer must not disable code-signature verification

Shape: a privileged installer helper takes an optional expected signing-team argument and,
when it is nil, installs the payload and runs its root install hooks without binding the
signer at all. A non-nil team is checked and a mismatch is refused; nil skips the check
entirely rather than failing closed.
Proof test idea: test the decision function directly in the sandbox. Assert that a request
with a nil expected team and a mismatched, unnotarized signer is refused, alongside a control
that a matching signer is accepted. The vulnerable logic authorizes the nil case and fails the
invariant; this is tier 1 with no root, as in `benchmark/fixtures/installer-trust`. An optional
live VM run (outside OMGS) can additionally show the real helper running a signed package's postinstall
as root, for impact only.
Proof (2026-10-23): wrong team was refused ("Team ID mismatch"), nil team succeeded and the
postinstall executed as uid 0, dropping the sentinel. Observed in the live run (machine since restored).
Why it matters: an optional security argument that becomes a no-op when omitted gives any
Developer ID signed, not even notarized, package root code execution through the helper.

## Candidate 5: the pkg install path must bind bundle identity and version, not only the signer

Shape: on the package branch, the helper trusts the installer to place the payload and binds
neither the caller-claimed bundle identifier nor the version to what the package actually
contains. With the expected signer nil (candidate 4), an unrelated bundle id and a bogus
version are accepted and the package's own scripts run as root.
Proof test idea: in the sandbox, assert the decision function refuses a request whose bundle
identity or version does not match the payload under a nil expected team. A fixed helper binds
the payload's real identity to the request. Tier 1, no root; the live live VM run (outside OMGS) is
optional and only adds impact.
Proof (2026-10-23): the call succeeded with an unrelated bundle id and a bogus version and
the probe postinstall ran as root. Observed in the live run (machine since restored); same root cause as
candidate 4.
Why it matters: binding only the signer, and only when a signer is demanded, lets a wrong or
hostile package satisfy an update request for an unrelated application.

## Candidate 6: an update must refuse a downgrade and enforce the requested version against the payload

Shape: the helper installs a payload whose version is older than what is already installed
and reports success, and the caller-supplied expected version is never checked against the
version actually written. Coarse or claimed versions are trusted over the real payload.
Proof test idea: in the sandbox, assert the decision function refuses an older payload over a
newer installed version, and refuses when the expected version does not match the payload. A
fixed helper never silently lowers the installed version. Tier 1, no root; the destination
read-back in the live live VM run (outside OMGS) is optional confirmation of real effect.
Proof (2026-10-23): destination moved from the newer installed version down to the older
payload version, expected version never matched the payload, and the call still reported
success with no error. Observed in the live run (machine since restored).
Why it matters: silent downgrade through a trusted updater rolls an application back to a
known-vulnerable build, a persistence and re-exploitation primitive.

## Rejected leads from the same run (symlink handling was sound)

Kept so a future verifier does not reopen them without new evidence. Both were tested on the
live run (machine since restored) and refuted:

- A dmg whose top-level app is a symlink pointing outside the image did not cause a write
  through that symlink: the out-of-image target's owner and contents were unchanged after
  the install.
- A destination that is itself a symlink to a victim app outside the Applications directory
  was not followed: the helper replaced the symlink with a fresh root-owned directory and
  the victim's sentinel survived intact.
