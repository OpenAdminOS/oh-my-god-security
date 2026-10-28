# Release packaging

`release.py mirror <mxc.zip> <output>` verifies the pinned archive and all five
executor hashes before copying their exact bytes and the upstream MIT notice.
`release.py packages <tag> <assets> <output>` fills the committed `.in` templates
with the tag and SHA-256 of final signed assets. It refuses drift from the skill
version and MXC pins. Release CI generates into `packaging/generated/`, uploads
that directory as a workflow artifact and attaches the rendered files to the
release. Generated checksums cannot be committed before the signed build exists.

The owner publishes `omgs.rb` to the Homebrew tap and the three winget manifests
to winget-pkgs after validating the public release. Homebrew includes the matching
MXC resource where supported and exposes it on PATH. Its downloads are hash pinned.
Winget installs the portable x64 binary, also on ARM64 through Windows emulation;
the skill installer selects the native ARM64 MXC executor. Winget users must run
that version-matched installer before proofs. Neither package flow publishes itself.

Set the public publisher constants in the two skill installers and all signing
secrets listed in [SECURITY.md](../SECURITY.md#release-owner-configuration). The
release workflow uses only tag pushes or explicit dispatch, never pull requests.
Local installer tests are run with:

```sh
cargo build --locked
python3 tests/installers.py --allow-test-verifiers
```

The explicit test flag belongs to the test harness, not either real installer.
Fake signatures and fake executor pins are injected into disposable copies only.
