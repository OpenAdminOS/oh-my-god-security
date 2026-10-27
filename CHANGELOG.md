# Changelog

## Unreleased

### Proof reliability and validation

Proof validation uses bounded no-follow reads for small trust files and regular
content reads for executor, test and snapshot hashes. Content accepts hardlinks
and symlinks to regular files; snapshot hashing has no size cap. Target FIFOs,
sockets and devices are refused before copying. Linux workspace copies break
hardlink relationships. Snapshots include all `.git` content. Validation accepts
executor names by their pinned digest and checks the full saved configuration with recorded readable roots and exact
environment values. Replay requires the recorded timeout. Traced findings must
omit proof references, and local-app proof records require Linux bubblewrap containment. Missing or altered commands produce one diagnostic.

Proof records redact commands and survivor command lines, including credential
components in hyphenated and underscored flags. CLI commands reject unknown and
duplicate options before any budget charge, except documented repeatable options.
Shell operators delimit unquoted proof-test tokens. Exact command and
config artifacts remain available for replay and must be protected. On Unix,
proof directories are 0700 and command and config files are 0600. Executable
drafts retain their permissions, child output precedes runner summaries, and
macOS and Linux handle SIGHUP alongside SIGINT and SIGTERM from preparation
through execution. Interrupted preparation releases the reservation and removes
the workspace.

### Platform behavior and compatibility

Linux tests cover detached sessions with a live host-process positive control.
Windows doctor reports when outside reads cannot be proven, and wall-clock
limits disclose the dependency on MXC for descendant teardown. Windows readable
root overlap checks canonicalize both paths. Rosetta installations prefer the
arm64 binary. Building requires Rust 1.89 or later, with CI build and test
coverage of 1.89.0. Windows extended UNC paths use the same normalization in
writing and validation. Existing proof records that lack the new grants and
command digests must be rerun.
