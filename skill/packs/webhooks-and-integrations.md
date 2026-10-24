# Webhooks and integrations

Use for `webhook_verification`, `webhook_replay`, and `integration_url` units. The result must be a privileged local effect by an unauthorized event or destination, not simply an unusual handler shape.

## What to hunt

- Event handlers that mutate state before verifying authenticity, skip verification on a branch, trust a payload's claimed sender, or catch verification errors and continue.
- Repeated authenticated events that duplicate a non-idempotent effect when the documented event contract requires one effect.
- Integration destinations selected by a lower privilege caller without the intended URL/destination policy or ownership check, including unsafe redirect following and forwarding credentials to a different origin.

## Source patterns that matter

Trace webhook `POST` exports in `app/**/route.ts` and `src/app/**/route.ts`, signature headers, `request.text()`/raw bytes versus parsed JSON, the actual verifier call, its awaited result, failure paths, and the first privileged sink. Check the installed integration protocol's signed bytes, algorithm/key selection, and freshness contract using locally present documentation. A raw-body read is not verification by itself. Next.js permits raw text in route handlers: [route handler reference](https://nextjs.org/docs/app/api-reference/file-conventions/route#webhooks).

For replay, follow verified event IDs through durable uniqueness, transactional writes and retry behavior. A timestamp check is only one possible freshness control. For URL handling, follow request fields and saved integration config into `new URL`, `fetch`, SDK constructors, redirect settings, origin/scheme validation, and credential headers. Distinguish caller-selected destinations from fixed, trusted configuration. Inspect existing guards before alleging a bypass.

## Minimal proof tests

- **Signature:** call the real handler with a synthetic event and absent or invalid signature. Assert denial and zero privileged effects. A correctly signed event under a dummy local key must exercise the success path. The failing invariant must come from the handler accepting the invalid event, not a mock that bypasses verification.
- **Replay:** send the same valid dummy event twice. Assert the intended single effect using final scratch state, including concurrent handling only if needed to decide the claim. Do not call ordinary delivery retries a defect if they are safely idempotent.
- **Destination:** exercise the real destination policy with a disallowed synthetic origin and assert rejection before transport or credential forwarding. A recording transport can prove an incorrect destination decision if it leaves validation intact. If actual delivery is decisive, use an approved local build and a runner-managed loopback canary only. Never probe real private networks, metadata endpoints, arbitrary domains, or external receivers.

Write tests in the existing framework and run only through `omgs prove`. Stop at one unauthorized dummy state change or the minimum local canary observation. Network denial, a URL string reaching a mock, or a planned request alone does not prove successful delivery. State the exact effect proven and keep missing delivery facts pending.

## Reject these false positives

- A shared wrapper verifies the signed bytes before all privileged branches.
- The route intentionally accepts unauthenticated public data and cannot trigger the claimed privileged result.
- Uniqueness or idempotent state transitions prevent duplicate effects without a separate replay cache.
- An intended customer destination is bound to the caller's integration and constrained by the trusted policy.
- A mock or sandbox transport failure is the only evidence of a supposed external request.

If event freshness, accepted senders, or destination scope is unclear, ask a plain language intent question and store the reviewed answer as policy. Never invent a universal requirement that every webhook needs login or every configurable URL is unsafe.
