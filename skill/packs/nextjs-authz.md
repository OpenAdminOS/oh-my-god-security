# Route and action authorization

Use for `missing_authz` and `idor` units. Hunt a concrete private read or privileged write by the wrong principal, not the mere absence of an inline guard.

## What to hunt

- Route handlers and server actions that accept an object ID, user ID, tenant ID, or role and use it without checking the caller's authority over that resource and operation.
- Login checks followed by unrestricted lookup/update/delete by primary key, bulk endpoints that omit ownership predicates, and nested resources whose parent ownership is never checked.
- Ownership checks after mutation or disclosure, guards whose return value is ignored, role flags accepted from a form or JSON body, and privileged clients reachable from lower privilege callers.

## Source patterns that matter

Enumerate every method in `app/**/route.ts` and `src/app/**/route.ts`, dynamic `params`, `request.json()`, `request.nextUrl.searchParams`, `FormData`, and bound action arguments. Follow exported and inline `'use server'` actions into their actual data access helpers. Record the trusted session's identity and membership, the selector reaching `findUnique`, `update`, `delete`, raw SQL, or `.from(...).select/update/delete`, and the data returned to the caller.

A page/layout guard, hidden button, opaque action identifier, UUID, or `import 'server-only'` does not itself enforce object ownership. An action can delegate enforcement to a shared data layer; inspect that layer before alleging a gap. Route and action entry points require their own effective authorization chain. See [Next.js data security guidance](https://nextjs.org/docs/app/guides/data-security).

For a query by ID alone, trace database role and RLS with [data-isolation-and-rls.md](data-isolation-and-rls.md). Do not assume application filtering is the only possible control. Separate private object access from intentionally public reads and explicit administrator operations.

## Minimal proof test

Use the existing framework and real handler/action path. Seed two dummy users and a private object owned by A in scratch. Call as B with A's known object ID. Assert denial and no protected fields or state change; an authorized call as A must succeed. The security assertion fails on the vulnerable code because it returns A's synthetic field or changes A's row. For anonymous access, repeat only the decisive operation without a session.

Keep real authz and query predicates in the path. A fixture may provide validated dummy sessions, but must not replace the very ownership or role decision under review. If enforcement is delegated to the database, use locally available matching schema and roles or remain pending. Submit all setup and execution through `omgs prove`; never invoke the test runner directly.

## Reject these false positives

- A shared guard, query scope, or effective RLS denies the same principal and operation before any effect.
- A public resource or expressly authorized sharing/admin flow permits the demonstrated behavior under trusted intent.
- An arbitrary internal helper is not reachable by the claimed caller.
- The test changes a mock to return forbidden data instead of exercising the actual enforcement decision.
- Only an identifier is exposed, without a private read or unauthorized effect.

Unclear sharing rules or missing external policies are exact `needs_validation` facts, not grounds for rejection or severity. Identity uses attack class, entry point, sink symbol, and boundary through `omgs fingerprint`.

## Intent questions

When a record turns on intent, set its `intent_id` to one of these library questions instead of writing a new one, so one recorded answer resolves every record that asks it (`omgs intent list` shows them all):

- `web.public-resource`: Is this resource meant to be readable without signing in?
- `web.admin-only-action`: Which roles are allowed to perform this action?
- `web.cross-tenant-read`: May a member of one workspace or tenant ever read another workspace's records through this route?
