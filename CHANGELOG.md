# Changelog

## Unreleased

### Fixes

- Redact complete quoted credential values while preserving following arguments, Rust namespace names and Go test results.
- Preserve Unix symlink layout and snapshot identity across fast and fallback workspace copies, so sockets appearing or disappearing do not prevent replay. Record outside and unresolved links as a proof gap.
- Report at most 20 skipped socket or FIFO paths, followed by a count of the remaining entries. Devices remain refused.
- Reject ambiguous free-text option values before spending proof budget. Use `--opt=value` when the text begins with another known option.
- Enforce the 1 MiB answer-store limit before writing, preserve the existing store on refusal, and use bounded single-link reads for run-local answer snapshots.
- Refuse filesystem roots as tier 2 approval targets before prompting.
