# PowerShell

PowerShell is the operating system of Windows endpoint management. Scripts and modules here usually run elevated, in SYSTEM context, or fleet-wide through a management platform, so small quoting and trust mistakes scale.

## What to hunt

- `Invoke-Expression` and download-then-execute patterns, especially where the executed text comes from files, feeds, metadata, or parameters another principal can influence.
- Double-quoted string interpolation of untrusted values into commands, Graph request URIs and OData filters, and generated script files (see generated-script-safety).
- Credential handling: plaintext secrets in parameters or logs, SecureString conversions that expose values, tokens written to disk outside protected stores, app-only scopes broader than the task.
- Execution policy bypasses and unsigned script requirements shipped as deployment instructions.
- Object handling that trusts deserialized files (CLIXML, imported CSV or JSON driving destructive loops without per-item validation).
- Remediation and detection scripts whose exit-code contract lets an attacker-influenced condition report compliance.

## Source patterns that matter

- Parameters flowing into `Start-Process -ArgumentList` as joined strings instead of arrays.
- Graph calls built with string formatting where an ID or filter value is not encoded.
- Write paths guarded only by equality checks where a weaker target value would also be written (see feed-to-policy).
- Broad `catch` blocks that convert failures into success exit codes for the calling platform.

## Proof shape

Use the project's Pester tests or a new test file where one exists, run inside `omgs prove` on hosts where PowerShell is available in the sandbox. Where no Windows PowerShell exists in the sandbox, stay at the traced tier and record the exact missing runtime instead of simulating execution on an incompatible shell. Assert behavior on dummy objects and endpoints only.

## False leads a verifier should kill

- `Invoke-Expression` over text the operator just authored in the same session with no import or sharing boundary.
- Serializer-built request bodies where feed text cannot add fields.
- Broad scopes that are documented, least-privilege-reviewed requirements of the single task, recorded as intent.
