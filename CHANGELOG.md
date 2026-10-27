# Changelog

## Unreleased

### Reliability

- Select Windows parent enumeration from the pinned executor's capability probe, record the selection path and capabilities, and retain guarded refusal/retry only when probing fails.
- Validate each generated policy with the executor's dry-run before running target code. Configuration rejections exit 3 with the executor's diagnostic and release the proof reservation.
- Show the full Windows OS build and its published ProcessContainer minimum alongside runtime capabilities in doctor and proof records. A build alone does not refuse proofs.

### Fixes

- Carry credential quote state forward without repeated prefix scans on long output lines. Keep Unicode whitespace inside unquoted test arguments.
- Disclose copied links that still reach the live target, sort skipped socket and FIFO paths before truncation, and escape control characters in printed proof gaps.
- Document free-text help-value refusals and link Microsoft's sandbox and platform support guides.

- Redact complete quoted credential values while preserving following arguments, Rust namespace names and Go test results.
- Preserve Unix symlink layout and snapshot identity across fast and fallback workspace copies, so sockets appearing or disappearing do not prevent replay. Record outside and unresolved links as a proof gap.
- Report at most 20 skipped socket or FIFO paths, followed by a count of the remaining entries. Devices remain refused.
- Reject ambiguous free-text option values before spending proof budget. Use `--opt=value` when the text begins with another known option.
- Enforce the 1 MiB answer-store limit before writing, preserve the existing store on refusal, and use bounded single-link reads for run-local answer snapshots.
- Refuse filesystem roots as tier 2 approval targets before prompting.
