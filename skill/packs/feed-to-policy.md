# Feed and import to policy writes

Hunt automation that turns external data (feeds, imported files, exported policy) into security policy writes. The boundary is whoever controls the input versus every principal the written policy governs.

## What to hunt

- Update logic that compares current policy to a feed-derived target only for equality, then writes the target. A shortened, stale, or manipulated feed rolls a security minimum backwards.
- Imports that silently drop unsupported restrictions (group filters, conditions, targeting) and deploy the result more broadly than the source allowed. Fail-open conversion is a finding shape, not a compatibility detail.
- Feed values interpolated into request URLs, OData filters, or hand-built JSON bodies instead of serializer-built payloads.
- Automation credentials (managed identity, app registration) whose write scope exceeds the single policy the tool claims to maintain.
- Error and empty-feed paths that write a default, minimum, or empty value instead of stopping.

## Source patterns that matter

- Version selection from feed ordering (first, last, count-back offsets) without a monotonic guard against the currently configured value.
- Absence of feed provenance checks where the platform offers them, and absence of a dry-run or approval step for posture-lowering writes.
- Conversion warnings that are logged but do not stop deployment of a broadened policy.

## Proof shape

Feed the updater a fixture feed whose newest entry is older than the current policy value, against a mock policy endpoint or the project's own test harness inside `omgs prove`. Assert no write occurs, or that the write keeps the higher minimum. The authorized control is a genuinely newer feed version updating the policy exactly once.

## False leads a verifier should kill

- A monotonic guard implemented in a shared helper the hunter did not follow.
- Intentional rollback support behind an explicit operator flag, recorded as intent.
- Feed data that only ever tightens policy because the platform rejects weaker values, demonstrated from platform behavior in source or tests, not assumed.
