# Fail-closed semantics

Hunt errors, unknown values and unsupported restrictions that silently widen authority. Failure handling is a security boundary when it controls a protected effect.

## What to hunt

- Missing signer, issuer, owner or policy values that disable checks instead of refusing the operation.
- Unsupported filters or malformed imports converted to unrestricted rules.
- Exceptions, timeouts and partial lookups treated as authorization success or compliance.
- Empty feeds or stale caches falling back to weaker policy or permissive defaults.

## Source patterns that matter

Trace null, empty, parse-error, unsupported and timeout paths to the first protected sink. Compare each with the documented success path and trusted intent. Follow catch blocks, option defaults, ignored return values, partial batch results and retries. Prove the permissive path is reachable by the claimed lower-trust principal, not simply unusual syntax.

## Proof shape

Run the actual decision function inside omgs prove with synthetic missing, malformed or unsupported input. Assert refusal before any protected dummy effect, alongside a valid-input success control. Preserve real checks rather than reimplementing them. A harness load failure or all-denied fixture cannot decide the claim. Stop at one minimal local effect, with no live policy writes or privileged execution.

## False leads a verifier should kill

- The caller enforces a required value before the optional helper can run.
- A documented public or best-effort operation has no protected result on failure.
- A shared guard or downstream platform rejects the broadened operation.
- A test aborts before the target decision or deliberately removes its real guard.

Unclear failure policy remains needs_validation until trusted intent or decisive local evidence resolves it.

## Intent questions

- `policy.failure-behavior`: Must an unavailable or unsupported security decision stop the protected operation?
- `feed.unsupported-filter`: When an imported rule uses a filter the tool does not support, should the rule be dropped or applied without the filter?
- `local.installer-signer`: Must every installed payload be signed by one expected team and match the requested version?
