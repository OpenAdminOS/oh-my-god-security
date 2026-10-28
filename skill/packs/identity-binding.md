# Identity binding

Hunt a trusted action bound to the wrong identity, resource or destination. Authentication alone does not establish that the selected object belongs to the caller.

## What to hunt

- Request, import or message fields overriding session-derived user, tenant or owner identifiers.
- Verified signatures whose subject, audience or resource does not match the operation being authorized.
- Browser extension messages trusting payload origins or tab identifiers instead of authenticated sender metadata.
- Cache keys, background jobs or delegated credentials that lose the originating principal or resource binding.

## Source patterns that matter

Follow the trusted identity producer through each join, queue, cache and sink. Compare canonical identifiers and authorization scope, including account linking and alternative encodings. Inspect actual sender validation on extension message listeners and the relationship between token audience, requested object and final effect. A signed but caller-editable claim is not trusted membership.

## Proof shape

Inside omgs prove, use two dummy identities and synthetic resources. Exercise the real enforcement chain with an authenticated A claim selecting B's private resource or a mismatched sender/audience. Assert denial and no private result or state change. Include the authorized A-to-A control. Stop at the minimum unauthorized synthetic effect, with no live identity provider or browser account.

## False leads a verifier should kill

- A shared scope or delegated policy binds the selected resource to the trusted principal before the sink.
- Explicit reviewed sharing or administrator intent authorizes the cross-identity operation.
- The claimed caller cannot influence the identifier, or the test mocks away the binding check.

Missing external identity policy remains needs_validation, with the precise missing fact and no severity.

## Intent questions

- `identity.resource-binding`: Must the requested resource belong to the authenticated identity or an explicitly authorized delegate?
- `web.cross-tenant-read`: May a member of one workspace or tenant ever read another workspace's records through this route?
