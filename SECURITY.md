# Security Policy

OMGS is a defensive security tool for code you own or are authorized to test.

## Supported use

- Audit source code you have the right to review.
- Execute proofs only against locally built copies, inside the sandbox, on dummy data.
- Never point OMGS at live systems, production data, or third party services.

## Reporting a vulnerability in OMGS

Use the [private security advisory form](https://github.com/OpenAdminOS/oh-my-god-security/security/advisories/new), or request a private reporting channel through the repository owner listed on the [organization profile](https://github.com/OpenAdminOS). Include the affected version, the exact command, and a minimal reproduction that runs fully locally. Do not include real secrets or third party data in a report.

## Handling findings OMGS produces

Run output describes vulnerabilities in the audited codebase. Keep it outside the target repository, treat it as sensitive, and share it only with people who need to fix the issues. Accepted proof tests are safe to commit once the underlying issue is fixed or the owner accepts the disclosure timing.

## Verifying a release

The [private advisory form](https://github.com/OpenAdminOS/oh-my-god-security/security/advisories/new)
is the security contact. If it is unavailable, use the repository owner's private
contact channel listed on the [organization profile](https://github.com/OpenAdminOS)
to request a secure reporting channel. Do not publish an exploit or credentials in
an issue. There is no dedicated security email address advertised by this project.

Use the exact version in `skill/VERSION`. Download its binary, platform MXC asset,
`SHA256SUMS` and `MXC-LICENSE.txt` from that tag's release. The installers perform
the following checks before executing the downloaded binary:

1. Compare SHA-256 of every downloaded asset with its single exact-name entry in
   `SHA256SUMS`. For example, `sha256sum <asset>` on Linux, `shasum -a 256 <asset>`
   on macOS, or `Get-FileHash -Algorithm SHA256 <asset>` on Windows. A manifest
   fetched beside a binary detects corruption, but alone does not authenticate
   its publisher if both are replaced.
2. On macOS require the OMGS Developer ID Team ID, configured as the public
   `OMGS_TEAM_ID` constant in `skill/scripts/install.sh`:

   ```sh
   codesign --verify --strict -R '=anchor apple generic and certificate leaf[subject.OU] = "OWNER_TEAM_ID"' ./omgs-aarch64-apple-darwin
   codesign --verify --strict -R '=anchor apple generic and certificate leaf[subject.OU] = "UBF8T346G9"' ./mxc-1.0.1-macos-arm64
   ```

   Replace `OWNER_TEAM_ID` with the owner-published value. The Microsoft executor
   keeps Team ID `UBF8T346G9`, verified on the pinned upstream bytes. OMGS binaries
   are also notarized during release; the installer checks the signature, not an
   offline notarization ticket. Gatekeeper remains enabled.
3. On Windows inspect both files using the native signature cmdlet:

   ```powershell
   $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath .\omgs-x86_64-pc-windows-msvc.exe
   $sig.Status
   $sig.SignerCertificate.Subject
   $mxc = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath .\mxc-1.0.1-windows-x64.exe
   $mxc.Status
   $mxc.SignerCertificate.Subject
   ```

   Require status `Valid` and an exact subject match with `$OmgsSubject` in
   `install.ps1`, which the owner configures before publication. MXC must match
   `CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`.
   A valid signature from an unrelated publisher is rejected. If OS trust cannot
   establish validity, installation stops.
4. Compare the MXC executor hash with its exact platform row in
   [skill/mxc-pins.txt](skill/mxc-pins.txt), also pinned in `src/sandbox.rs`.
   The release workflow first verifies the MXC 1.0.1 archive SHA-256
   `0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9`, then all
   five executors. Files are mirrored without modifying their bytes or signatures.
   Linux executors have no native publisher signature verifier; use the hard pin.
5. With authenticated GitHub CLI, run:

   ```sh
   gh attestation verify ./omgs-aarch64-apple-darwin --repo OpenAdminOS/oh-my-god-security
   ```

   Use your actual binary filename. A successful check adds build provenance.
   Missing authentication, unavailable attestation services or failed verification
   are reported as **unverified**. That status alone is not evidence of tampering.
   It does not waive checksums, native signatures or MXC pins.
6. Only after these checks, run `omgs --version` and require the exact value from
   `skill/VERSION`. Then run `omgs doctor` to check executor discovery and readiness.

The real installers have no fake verifier, unsigned mode or test-only environment
override. Regression tests explicitly create disposable installer copies and inject
fake signing tools there. They also execute the real installers with proposed
bypass variables and assert refusal. On Linux, simulated macOS copies exercise
publisher rejection while production Linux checks remain checksum and pin based.

## Release owner configuration

Before the first public release, replace `OWNER_TEAM_ID` in `install.sh` with the
Apple Developer ID Team ID and `CN=OWNER_WINDOWS_SIGNER_SUBJECT` in `install.ps1`
with the exact Azure Trusted Signing leaf certificate subject. These are public
identities, not secrets. Keep the values under review with the skill. Never take
expected publisher identities from a downloaded manifest or environment override.

The existing signing pipeline requires all of these repository secrets:

| Platform | Required secrets |
| --- | --- |
| macOS | `MAC_CSC_LINK` (base64 Developer ID PKCS#12), `MAC_CSC_KEY_PASSWORD`, `APPLE_API_KEY` (notarization key contents), `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` |
| Windows | `AZURE_SIGNING_TENANT_ID`, `AZURE_SIGNING_CLIENT_ID`, `AZURE_SIGNING_CLIENT_SECRET`, `AZURE_TRUSTED_SIGNING_ENDPOINT`, `AZURE_TRUSTED_SIGNING_ACCOUNT_NAME`, `AZURE_TRUSTED_SIGNING_CERTIFICATE_PROFILE_NAME` |

Provenance uses the job's short-lived GitHub OIDC token with `id-token: write`
and `attestations: write`; it needs no additional repository secret. Release
uploads use the built-in `GITHUB_TOKEN`. No keys or certificates belong in git.
The owner controls repository visibility, immutable tag rules, tag creation,
release execution, tap publication and winget-pkgs submission. This change does
none of those operations.


### Internal verified installer publication

`omgs install-self --to <absolute-OMGS_HOME> [--mxc <verified-mirrored-asset>
--license <verified-license>]` is an internal command, omitted from normal help.
It publishes its own running executable and the optional MXC files. The
bootstrap must verify all source files in private staging before calling it;
this command is not a replacement for publisher, checksum or pin verification.
It admits the complete destination chain using the same Rust safe-path policy
as run storage, rejects unsafe existing leaves without repair, and stages all
copies before exact-path atomic replacement. Windows replacements retain the
fresh owner-only DACL, and locked-file failures preserve the locked destination
and clean temporary siblings. See DECISIONS.md for ancestor-specific Windows
rights and the Unix sticky-ancestor exception.
