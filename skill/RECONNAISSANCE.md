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
`principals`; `boundaries` (each `id`, `name`, `between` of exactly two zone ids,
`enforcement` as an array of strings);
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

Use [schemas/coverage-ledger.schema.json](schemas/coverage-ledger.schema.json) for the ledger.

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
`idor_tenant_isolation`, sink `loadProject`, invariant that only current-tenant rows can be
returned.
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

## PowerShell, module libraries and other stacks

The earlier HTTP examples are stack examples, not a prerequisite. For PowerShell, read manifests
and `FunctionsToExport`, public/private functions, dot-sourcing and sample consumers as text.
Map parameter binding, pipeline input, JSON conversion, certificate handling, filesystem writes,
privileged cmdlets and external service calls. For Azure Functions, read bindings, authLevel,
HTTP/query inputs, worker conversion and deployment configuration when present. Missing host
configuration and real Graph or Storage semantics remain unexamined dependencies. Do not fetch or
execute them to complete the map. For libraries, exported functions and callers replace routes;
trace caller capabilities and validation before each sensitive return or side effect.

Seeded stack units are mapping checklists, not hunter assignments. Before dispatch, create bounded
surface/boundary/class units. A covered checklist requires `child_units` with 1 to 256 existing
unit ids, all covered or explicitly out of scope. Each child declares `scope_paths`, such as
`[{"path":"app/api/items/route.ts","operation":"GET"}]`, with one attack class per bounded
decision. The critic rejects shared or overlapping path scopes for the same class across different
children. Split a large partition into nested checklists. Parent checklists describe the partition
and own no candidates.

Each scope is an object with a required relative `path` and an optional `operation`. Literal
`#` characters in directory and file names stay in `path`, for example
`{"path":"src#ipc/Decision#read.swift","operation":"read"}`. Omit `operation` to own the whole
path and its descendants. Operation identifiers are case-sensitive ASCII strings matching
`[A-Za-z_][A-Za-z0-9_.:-]{0,127}` (1 to 128 characters). Use a stable identifier for source
symbols whose spelling does not fit this grammar. Unknown fields and null operations are refused.
Legacy string scopes without `#` remain accepted as plain paths with no operation. Any string
containing `#` is refused because it could name a literal path or a path plus operation. Migrate
`"dir/a#b"` to `{"path":"dir/a#b"}` for the literal filename or
`{"path":"dir/a","operation":"b"}` for operation `b` on `dir/a`. No separator is inferred.
All paths resolve against `scope_root` with existence, containment, link and filesystem alias
checks before a partition closes. A legacy ledger without `scope_root` requires target context
before closure.

Route file checklists require `operations`, an object mapping every method/operation name to its
child unit id, and `syntax_review: "complete"`. Enumerate methods by reading source only. Include
reexports, aliases, default handlers, wrappers and delegated operations. Never import target code
or execute a parser supplied by the target. Uncertain syntax means `syntax_review: "uncertain"`
and a blocked checklist until a complete manual enumeration is possible. Do not infer a missing
method from a text search or a failed parse. Keep native operation lists to the same standard.

Use `ledger add` or `ledger set` with `--mapping '<json-object>'` to merge mapping fields under
the ledger lock. For example, add a child with
`--mapping '{"scope_paths":[{"path":"src/route.ts","operation":"GET"}]}'`, then close its parent
with

```sh
--mapping '{"child_units":["route-get"],"operations":{"GET":"route-get"},"syntax_review":"complete"}'
```

Create and reconcile children before closing their checklist. A rejected update writes nothing.

Partial examination is recorded with `partial: true` and `residual_units` naming 1 to 256 separate
units for every unexamined remainder before marking the examined unit covered. A candidate does
not close its residuals. Missing, self, duplicate or cyclic references fail validation. Planned
residuals still fail the critic; blocked/deferred residuals remain disclosed gaps. Never replace a
partial note with a claim that the whole source was examined.

Binary assets have an `assets:excluded` review unit with a count and at most 20 sorted paths.
Scripts under public directories remain code. Exclusion requires examination or the same explicit
reviewed exclusion reason as documentation and dependencies. Classification never removes a path
from accountability. Sensor staging prioritizes discovered first-party source, then other inputs.
`sensors.json` retains up to 128 skipped path/reason records per scanner, with paths bounded to
1024 characters. The summary states omitted record counts; a directory bound describes an
unenumerated subtree, never a count of all its files. Resolve the sensor inventory ledger gap by
reviewing the retained manifest and accounting for unlisted scope. A truncated manifest cannot
establish complete scanning, and zero matches cannot close that gap.

## Native IPC and credential boundaries

Read native sources and launchd property lists as text. Record these checks explicitly:

- Listener creation, Mach service name, launchd `MachServices`, `UserName`, executable path and
  ownership assumptions. Root service effects and installation remain manual validation limits.
- `listener(_:shouldAcceptNewConnection:)`, audit-token identity, signer/team/entitlement checks,
  and whether caller identity stays bound to each connection and operation.
- Exported object and `NSXPCInterface`, protocol methods, argument/reply class allowlists,
  `setClasses` and secure decoding. Enumerate reply payloads as well as inbound objects.
- Per-operation resource authorization, credential getters, disclosure recipients, and downstream
  privileged operations. Admission alone does not authorize all operations or secret readback.

Small map fragment (use existing zone ids in the full map):

```json
{
  "boundaries": [{
    "id": "ipc-callers", "name": "Local caller to privileged service",
    "between": ["local-client", "service"],
    "enforcement": ["Sources/Listener.swift: caller audit-token check",
                    "Sources/Service.swift: per-operation resource check"]
  }],
  "unexamined": ["Live launchd registration and privileged effects"]
}
```

Partition listener/caller authorization as `ipc_authorization`, credential-return policy as
`secret_disclosure`, and privileged effects as `privileged_local_ops`. Source hints seed native
operation checklists but never prove their enumeration complete. Ask `native.accepted-callers`,
`native.secret-disclosure` and `native.privileged-operations` when policy is unresolved.

Sensor hit counts use distinct fingerprints. Repeated observations retain `duplicate_sources` on
the surviving hit: the original `first_source_index`, duplicate `count`, sampled `source_indexes`
and `omitted` count. Indices address the ordered normalized scanner metadata stream before
compaction. Up to 128 duplicate indices are retained across the whole report. The surviving hit
supplies the shared tool, rule, path, line and package identity. Matched values and raw scanner
content remain discarded. Removing duplicate observations never closes their ledger unit.
