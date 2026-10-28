# Reconnaissance

Read source as text. Never import modules, run the framework, discover tests through the test
runner, or execute package scripts outside `omgs prove`. Keep maps and the ledger in the initialized
output directory.

## Build a map that hunters can use

1. Read package metadata and lockfiles as text to record framework, database client, auth library,
   test framework, and pinned versions. Identify `app/` or `src/app/`, workspace packages, path
   aliases, generated code, and checked-in tests. List missing local dependencies without installing
   them.
2. Enumerate `route.ts`/`route.js` handlers per HTTP method, dynamic and catch-all segments,
   exported and inline `'use server'` actions, and server-rendered loaders. Record how each is
   reachable; a route group is not a URL segment. Mark runtime reachability uncertain when build
   behavior is needed to decide it.
3. Trace request params, search params, form/action arguments, JSON, headers, cookies, webhook
   bodies, and integration URLs into shared services, database queries, privileged clients, and
   returned data. Treat caller-supplied user, role, and tenant identifiers as claims until verified
   against trusted state.
4. Map authentication and authorization separately: session validation, membership lookup, object
   ownership, administrative roles, shared wrappers, data access helpers, middleware or
   version-appropriate proxy configuration, and matcher exclusions. Read actual imports and call
   order, not helper names alone.
5. Trace Postgres/Supabase client construction and effective caller credentials. Inspect migrations,
   grants, row level security (RLS) policies, views, functions and execution roles as text. Record
   external API or database enforcement that is not present in the repository as an unresolved
   dependency, not an absent control.
6. List sensitive results: row reads/updates, tenant membership changes, privileged integration
   actions, and private data serialized to the browser. Map caches by principal and tenant where
   they can affect those results. Use the four packs to select relevant attack classes.

For each boundary, write `untrusted principal/input -> enforcement location -> trusted
resource/effect`, with file, symbol, and line references. Typical boundaries are anonymous to
authenticated, member to administrator, owner to another owner, tenant A to tenant B, unsigned
sender to trusted webhook, and caller-chosen URL to authorized integration destination. Record the
application's intended allow/deny behavior and its source; unresolved intent becomes a question.

## Record the architecture map

Write the structured map to `architecture.json` in the output directory, following
[schemas/architecture.schema.json](schemas/architecture.schema.json). Use these exact keys: `stack`
(detected); `zones` (ordered least to most trusted, each `id` + `name`); `components` (each `id`,
`name`, `zone`, optional `kind`/`tech`/`path`, and `entry_point: true` when externally reachable);
`principals`; `boundaries` (each `id`, `name`, `between` of exactly two zone ids, `enforcement`);
`flows` (each `from` and `to` component id, optional `data`/`protocol`/`authn`/`authz` and `crosses`
set to a boundary id when the flow crosses one); `input_surfaces` (each `id`, `component`,
`attacker`); and `unexamined` stated plainly. Unrecognised keys are silently ignored, so match these
names exactly. `omgs audit init` seeds a stub you fill in.

Then render it: `omgs architecture --in architecture.json --out <output-dir>`. This writes a
deterministic `ARCHITECTURE.md` and an offline `ARCHITECTURE.html` with an auto-laid-out flow graph,
so the reviewer can see how the target is built and what its attack surface is. The map is
descriptive only; it never asserts a finding or changes a verdict. Keep all free-text
target-derived; the renderer escapes it.

## Seed the coverage ledger

A unit is one concrete surface, one violated boundary under investigation, and one attack class. Do
not use whole folders as units or multiply by irrelevant classes. Split HTTP methods and materially
different principal/resource operations. Multiple units may share a root cause and later deduplicate
to one fingerprint.

Each unit records:

- `unit_id`, `source_ref`, surface path/method or action symbol, and input selectors.
- Boundary, attack class, relevant pack, expected invariant, and intent source or missing fact.
- Suspected sink and enforcement chain, including backend delegations and evidence locations.
- Assignment owner, call/time budget, status, candidate fingerprints, and reason for the status.

The ledger file stores each unit as `id`, `surface`, `attack_classes`, `status`, plus `evidence`
(finding fingerprints, candidate files, or paths) and `note`; keep the richer planning detail above
in the unit's surface text or the architecture map. Use statuses `planned`, `candidate`, `covered`,
`deferred`, `blocked`, and `out_of_scope`. A covered unit has a trace and disposition even when it
yielded no candidate, and `omgs ledger set` refuses `covered` without at least one `--evidence`
reference. A blocked or deferred unit names its exact missing evidence or capability, and out of
scope needs a reason; the CLI requires `--note` for all three. Out of scope never means safe. Add
units discovered during the run with `omgs ledger add --ledger <run-dir>/coverage-ledger.json --unit
<id> --surface <s> --classes <a,b>`.

Example unit: `GET /api/projects/[id]` by a member of tenant A, tenant A to tenant B project rows,
`tenant_isolation`, sink `loadProject`, invariant that only current-tenant rows can be returned.
Check both the application predicate and the effective database role before proposing a violation.

Seed per-boundary units when a target runs privileged components; one whole-repo unit is too coarse
to hunt a root helper. A macOS updater with a root LaunchDaemon, for example, needs distinct units
for the XPC or IPC service surface, the installer and its signer/version trust decision, the
download and resolver chain, policy and feed loading, and the packaging or lifecycle scripts, each
with its own principal and invariant. Privileged components also shape the proof plan, but not
toward a VM by default: the signer and version decisions in an installer or root helper are pure
logic, so seed a tier 1 sandbox proof of the decision function (synthetic signer and version, no
root), as in `benchmark/fixtures/installer-trust`. The part whose effect genuinely needs real root
has no proof tier; seed it as a `needs_validation` unit with a manual plan rather than any
unsandboxed execution.

Give hunters the map and assigned units, not speculative findings from other hunters. Reconcile new
surfaces back into the ledger under the remaining budget. Finish by listing unexamined boundaries
and external controls that could not be checked. Never compute a coverage percentage or security
score.

Framework background: [Next.js route
handlers](https://nextjs.org/docs/app/api-reference/file-conventions/route) and [authentication
guidance](https://nextjs.org/docs/app/guides/authentication). Match the checked-in framework version
before relying on routing behavior.
