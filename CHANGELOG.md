# Changelog

## Unreleased

### Proof reliability and validation

Proof validation now uses bounded no-follow reads of regular files, includes all
`.git` content in snapshots, accepts executor names by their pinned digest, and
checks the full saved configuration with recorded readable roots and exact
environment values. Replay requires the recorded timeout. Traced findings with
proof references must match the referenced fingerprint.

Proof records redact commands and survivor command lines. Exact command and
config artifacts remain available for replay and must be protected. Executable
drafts retain their permissions, child output precedes runner summaries, and
macOS and Linux handle SIGHUP alongside SIGINT and SIGTERM.

### Platform behavior and compatibility

Linux tests cover detached sessions with a live host-process positive control.
Windows doctor reports when outside reads cannot be proven, and wall-clock
limits disclose the dependency on MXC for descendant teardown. Windows readable
root overlap checks canonicalize both paths. Rosetta installations prefer the
arm64 binary. Building requires Rust 1.89 or later. Existing proof records that
lack the new grants and command digests must be rerun.
