# Tenant isolation and delegated authorization

Use for `tenant_isolation` and ownership units that delegate to a database or external API. A missing application predicate is a lead. It is not evidence that delegated enforcement is absent.

## What to hunt

- Tenant selectors taken from untrusted parameters instead of verified membership, missing tenant scope in reads/joins/writes, and caches reused across principals or tenants.
- Effective database roles with elevated privileges, views or functions that change execution identity, broad grants, disabled RLS, or policies that authorize the wrong tenant or only one operation.
- Direct browser database access whose safety depends on backend policy, and server API calls forwarding a user token versus substituting a privileged credential.

## Source patterns that matter

Trace `createClient` and server client wrappers to actual request auth headers or session tokens, not just the initialization key's name. Follow `.from()`, `.rpc()`, SQL joins, connection pools, views, and `SECURITY DEFINER` functions. Inspect checked-in migrations for RLS enable/force settings, grants, `USING` read/row selection rules and `WITH CHECK` write rules. Trace tenant claims to verified membership; a signed but user-editable claim is not trusted authorization policy.

Identify delegation outside the repository through remote API base URLs, database client construction, migration gaps, documentation references, generated types without policies, and wrappers whose implementation is elsewhere. Record exactly which table, operation, effective role, policy, or backend authorization behavior is unknown. Never contact that service or load credentials to resolve the question.

Postgres owners and bypass roles can evade ordinary row policies; views and definer functions need their own execution-role trace. See [Postgres row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html). For Supabase, determine the effective request authorization context before concluding that an administrative client bypasses policies; initialization alone can mislead. See [RLS guidance](https://supabase.com/docs/guides/database/postgres/row-level-security).

## Missing intent and read only local checks

Ask: "Should a member of workspace A ever read or change workspace B's private records?" For missing backend evidence, ask: "Is access to this table restricted by database policies managed outside this repository? Please provide the policy definition and intended application role for local review." Keep credentials and connection strings out of the answer. Store reviewed answers as scoped intent in committed policy, not as proof that deployed enforcement works.

Only inspect a synthetic local database through `omgs prove`. Use read only catalog queries for `pg_catalog.pg_class` (`relrowsecurity`, `relforcerowsecurity`, owner), `pg_catalog.pg_policy`/`pg_catalog.pg_policies` (roles, command, expressions), `pg_catalog.pg_roles` (`rolsuper`, `rolbypassrls`), grants, and current/session user. Compare with the committed migration snapshot. Do not change policies or grants, call target stored functions for reconnaissance, install extensions, connect to a hosted database, or claim local metadata proves deployment state. Missing local schema/roles is a blocker.

## Minimal proof test

In the runner's scratch, use the application's existing database test framework and locally available schema/toolchain to create dummy tenants A/B and one private row each. Exercise the actual application path under A's effective non-owner role, with B's selector. Assert no B data is returned and no B row changes; A's control succeeds. For write policies, check the final tenant/owner of the row as well as the response. Fixture setup belongs only in scratch, never a deployed backend.

If backend enforcement is the question, a mocked query or owner-only database connection cannot decide it. Preserve `needs_validation` with the missing role/policy or local dependency. Escalate only through the runner when a test cannot decide and an approved local build can.

## Reject these false positives

- Effective RLS, a shared membership-scoped query, or a trusted backend denies the claimed cross-tenant operation.
- An elevated role is used solely on an authorized administrative path.
- A table is intentionally public or shared under reviewed intent.
- A static migration omission is presented as proof of a remote configuration gap.
- A publishable or anonymous client key is classified as a secret without any unauthorized result.

Missing external evidence stays pending. Never "fix" unknown delegation by disabling RLS, testing a remote endpoint, or broadly replacing backend policy with duplicated application checks.

## Intent questions

When a record turns on intent, set its `intent_id` to one of these library questions instead of writing a new one, so one recorded answer resolves every record that asks it (`omgs intent list` shows them all):

- `web.cross-tenant-read`: May a member of one workspace or tenant ever read another workspace's records through this route?
- `web.public-resource`: Is this resource meant to be readable without signing in?
