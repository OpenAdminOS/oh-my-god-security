# 0.1.0 release notes

OMGS 0.1.0 ships skill-first installation, signed macOS and Windows binaries,
mirrored MXC executors and layered release verification.

## Installation and trust

The primary entry point is the skill. Before its first download it explains both
OMGS and Microsoft MXC, their source, size limits, verification and install paths,
and waits for consent. It installs into the current user's OMGS directory without
elevation. It does not install a toolchain or target dependencies.

The skill pins an exact OMGS version. Existing and downloaded binaries must report
that version before a review continues. This prevents a newer skill from silently
using an incompatible older binary.

Installers verify SHA256SUMS and require the expected publisher's native signature
on macOS and Windows. Authenticated GitHub CLI adds provenance verification, with
unavailable or failed verification clearly reported as unverified. Linux has no
native publisher signature check, so its checksum result alone does not establish
publisher identity.

## Smaller sandbox download

Releases mirror the five MXC 1.0.1 executors without modification, preserving their
Microsoft signatures and MIT notice. Each executor is about 3.8 to 11.9 MiB, so
users no longer need the 542 MB upstream archive. The release workflow verifies
the archive and each executor against committed SHA-256 pins; installers and the
runner independently check the executor pin.

## Usability and packaging

Newcomer documentation explains the skill, binary, sandbox, outputs and network
use. Every existing subcommand accepts --help. Routing without a configuration
retains the host's current selection; a refusal records a blocker when no fallback
exists. Homebrew and winget metadata are generated from final release hashes and
attached for owner publication. Winget installs the binary only; the matching skill
installer supplies MXC.

## Compatibility and operator requirements

Apple Silicon macOS 15 or later, Linux with usable bubblewrap namespaces, and
Windows probe tiers without DACL augmentation can execute proofs. Intel Macs
cannot. Windows augmentation tiers, including the observed Server 2025 tier, are
refused before configuration. Windows SSH session 0 can prevent PowerShell startup.
Tier 2 remains Linux only. Same-process nonce markers cannot authenticate hostile
target assertions; replay and independent evaluation remain required.

The two public signing identities were configured in the installers. Before
release, the owner must provide the eleven signing secrets documented in
SECURITY.md and configure repository visibility and immutable tag protection.
Package-manager publication remains an owner action.
No migration rewrites older proof records; rerun evidence that predates the current
proof schema and execution policy.

## Development bundle cleanup

The old unsigned dist/v0.1.0 bundle was a local 2026-10-16 cold-install fixture.
It is stale, untracked and absent from this worktree. It is not regenerated or
published: doing so would present old unsigned bytes as the new signed release.
The /dist ignore rule stays in place for build staging. Fresh release assets are
built from the owner-selected immutable tag and are not committed to the source.
