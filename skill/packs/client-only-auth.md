# Client-only authorization and middleware gaps

Use for `client_only_authorization` units. Hunt a server effect that remains reachable by an unauthorized principal despite a UI guard or an incomplete middleware rule.

## What to hunt

- Private data sent to a client component and then hidden based on `useSession`, `useEffect`, local storage, client role flags, or `router.push`/`replace`.
- Buttons and links hidden from lower privilege users while their server actions or route handlers lack effective authorization.
- Middleware or proxy matchers that cover a page but omit its API/action path or a relevant method, and request-derived headers trusted without an enforced producer.

## Source patterns that matter

Start at `'use client'` components, client redirects, conditional rendering, fetch calls and action imports. Trace backwards to the server data source and forwards to the operation. Inspect private fields passed as props or action return values; hidden markup is not the only possible disclosure.

Read `middleware.ts` or the framework-version-appropriate `proxy.ts`, matcher configuration, exclusions, early returns, rewrites, route handlers, server actions, and their shared data layer. Map public URL paths rather than assuming route groups are URL prefixes. A check in a page/layout is not automatically inherited by its actions or API. Match the checked-in framework version and local config; do not assert a generic routing bypass without tracing the real path. See [Next.js authentication guidance](https://nextjs.org/docs/app/guides/authentication) and [data security guidance](https://nextjs.org/docs/app/guides/data-security).

Identify the intended principal, input, server sink, and concrete result before proposing a candidate. A middleware exclusion becomes relevant only if the excluded path reaches an effect without another effective control. Treat unknown hosting-layer enforcement as missing evidence rather than inventing its absence.

## Minimal proof test

Use an unauthenticated or lower privilege dummy session and the existing test framework. Invoke the actual server handler/action path without relying on client navigation. Assert denial and no sensitive response/state change, with an authorized success control. Do not import an arbitrary internal helper and assume it is remotely reachable.

For prop/serialized-data exposure, assert that the unauthorized server response contains no selected synthetic private marker before any client filtering. For a matcher claim, exercise the actual matcher/enforcement chain. A direct handler test that deliberately omits mandatory middleware cannot prove a deployed path bypass; if routing is decisive, let the runner request escalation to an approved local build with synthetic fixtures. All tests, builds, and local requests run only through `omgs prove`.

## Reject these false positives

- Client guards improve navigation while a server guard or effective backend policy independently denies the operation.
- Data sent to the client is an intentionally public projection, not the claimed private fields.
- An excluded path is public by reviewed policy or is protected by its actual entry-point chain.
- The suspected helper is not exposed to the claimed principal in the reviewed build.
- The test bypasses a control that the real request must traverse.

Ask whether the resource is intended to be public if intent is missing. Preserve the exact unknown hosting or routing fact as `needs_validation`, without severity. Reuse identity inputs through `omgs fingerprint`; do not report the same boundary twice merely because both a hidden button and a missing server check appear in its trace.
