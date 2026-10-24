# Security Policy

OMGS is a defensive security tool for code you own or are authorized to test.

## Supported use

- Audit source code you have the right to review.
- Execute proofs only against locally built copies, inside the sandbox, on dummy data.
- Never point OMGS at live systems, production data, or third party services.

## Reporting a vulnerability in OMGS

Open a private security advisory on the project repository, or contact the maintainers through the channel listed on the repository front page once published. Include the affected version, the exact command, and a minimal reproduction that runs fully locally. Do not include real secrets or third party data in a report.

## Handling findings OMGS produces

Run output describes vulnerabilities in the audited codebase. Keep it outside the target repository, treat it as sensitive, and share it only with people who need to fix the issues. Accepted proof tests are safe to commit once the underlying issue is fixed or the owner accepts the disclosure timing.
