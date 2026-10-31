# Hunting

Whenever a hunter or verifier uses a proof recipe, the verifier must declare `--expect-marker
BOUNDARY_ASSERTION_FAILED` on `omgs prove`. Require exit 1 and the runner's full-stream
`contract.boundary_marker_seen` and `contract.authorized_control_seen` fields before claiming recipe
proof support. Harnesses read `OMGS_PROOF_NONCE` and `OMGS_PROOF_CONTRACT` from the environment,
then emit `OMGS_CONTROL_<nonce>` after the authorized control and `OMGS_BOUNDARY_<nonce>_<label>`
immediately before assertion exit 1. Require schema `omgs-proof/3` with `contract.kind: "recipe"`;
missing or null contract fields are invalid. Fixed or wrong-nonce markers earn no support. Hostile
code sharing the harness process can read the nonce, so the independent evaluator remains required.
Exit 2 is a harness or usage error and never supports a proof.

## Assign bounded, isolated work

Assign one hunter a small set of ledger units sharing a surface or enforcement chain. Supply source
identity, architecture map, relevant pack, trusted intent, local evidence paths, exact call/time
allowance, and the candidate contract below. The hunter may read related source, but must record new
surfaces instead of silently expanding scope.

Hunters do not see each other's hypotheses before submitting. Use independent agent contexts when
available. If the host cannot isolate contexts, run sequential bounded passes and disclose that
limitation. Preserve a fresh verification context; do not have the author certify their own
candidate. All target execution still goes through `omgs prove` under the shared safety policy.

Stop on a complete candidate, a traced effective control, a precise blocker, or budget exhaustion.
Return an explicit disposition for every assigned unit, including no-candidate results and the
control that decided them. Secret and dependency sensors are deterministic inputs, not model hunting
assignments.

## Candidate contract

Candidates are hypotheses, not confirmed findings. This is the agent handoff contract, not an
extension to the CLI findings schema. Each hunter writes its candidates as a schema-shaped file
named `candidates-<hunter>.json` into the run directory (an empty `candidates` list when it found
nothing), validated against [schemas/candidates.schema.json](schemas/candidates.schema.json), plus a
short prose summary, so deduplication and fingerprinting are mechanical rather than hand-merged from
free-form reports. Return structured records with these fields and no severity:

| Field | Content |
| --- | --- |
| `hunter` | The hunter's own identity, such as `red-installer`. The record's `hunted_by` repeats it, and the verifier must be someone else. |
| `unit_ids`, `source_ref` | Ledger provenance and exact reviewed source. |
| `title`, `attack_class` | Concrete claimed unauthorized result and stable class identifier. |
| `entry_point` | Repository-relative path plus HTTP method/route or exported action symbol. |
| `sink` | Repository-relative module and stable effect-producing symbol. |
| `boundary` | Principal/resource boundary and invariant allegedly violated. |
| `location` | Relevant repository-relative `path` and one-based `line`. |
| `attacker_capability` | Lowest privilege, controlled inputs, and required state. |
| `trace` | Ordered input, enforcement checks, sink, and returned data or mutation, with source references. |
| `concrete_result` | Specific disclosure, state change, or privileged local effect; distinguish predicted from observed. |
| `counterevidence` | Shared guards, backend policy, middleware, wrappers, and legitimate intent already checked. |
| `missing_fact`, `intent_question` | Exact undecided fact and plain language question if intent matters; null when none. |
| `proof_plan` | Minimum synthetic fixture, safe invariant assertion, expected vulnerable failure and control success, local prerequisites, and stop condition. |
| `fingerprint` | Output from `omgs fingerprint` using the four identity inputs below. |

Use the shared [class registry](intent/classes.json) for attack classes across seeds, packs,
candidates and intent filters. It includes `ssrf`, `artifact_poisoning`, `ipc_authorization` and
`secret_disclosure`. New public classes are added to that registry with tests and relevant intent
questions. Candidate and finding validation and fingerprint creation reject unregistered classes,
listing the registered names. New identifiers require a registry update before use. Classes do
not change accountability or exclusion rules. An intent filter accepts every registered class
and explicitly reports when it has no questions.

A partially examined unit declares `partial: true` and references separate `residual_units` before
closure. Preserve every unexamined operation there. Stack and operation checklists use explicit
`child_units`; never assign their broad scope as duplicate candidate ownership. Read the source to
complete operation enumeration; unknown syntax remains blocked. Declare ownership using
`scope_paths: [{"path":"src#ipc/Decision.swift","operation":"read"}]`. The optional operation
matches `[A-Za-z_][A-Za-z0-9_.:-]{0,127}`; omit it for whole-path ownership. Literal `#`
characters belong in `path`. Migrate ambiguous legacy strings as described in RECONNAISSANCE.md.

## Identity and deduplication

Compute identity only through `omgs fingerprint`, binding **attack class, entry point, sink symbol,
and violated boundary** through the documented interface. Include module identity where symbols
repeat. Keep line numbers and titles as evidence, never identity inputs. Do not handcraft hashes or
substitute an advisory identifier.

Merge duplicate traces into one candidate without discarding unit provenance or counterevidence.
Keep distinct entry points or distinct boundaries separate when their identity inputs differ. Fixes
and line movement alone must not manufacture a new identity. Recompute if verification changes a
semantic identity input, and list the candidate's original fingerprint in the record's `candidates`
so the critic can still trace the record to its hunter.

## Coverage critic

The critic challenges the ledger, not just the candidate list. Check that every discovered handler
method, action, principal transition, data access path, and relevant backend delegation has a unit
and disposition. Look for unassigned units, UI-only assumptions, uncovered middleware matchers,
alternate privileged clients, and unexamined methods behind a reviewed URL.

For each gap, add a bounded unit with `omgs ledger add --ledger <run-dir>/coverage-ledger.json` or
record why it remains unexamined with `omgs ledger set --ledger <run-dir>/coverage-ledger.json
--unit <id> --status deferred|blocked|out_of_scope --note <reason>`. The mechanical half of this
pass is `omgs critic --run <run-dir>`, which fails on unreconciled units, unverified candidates, and
records whose verifier hunted them. Reconcile assignments, evidence, source revisions, duplicate
fingerprints, and exhausted budgets. Send candidates to a fresh verifier with source and
counterevidence. A lead found late (by the critic or the evaluator) still enters as a candidate from
a hunter, never as a record written directly. Do not endorse them by consensus, promote source
traces to confirmed, or claim completeness because all dispatched hunters returned.

## Validate and ingest handoffs

Run `omgs validate --candidates OUTPUT_DIR/candidates-HUNTER.json` and
`omgs validate --dispositions OUTPUT_DIR/dispositions-HUNTER.json`. The disposition schema ships
at `schemas/dispositions.schema.json`. The host ingests a complete handoff atomically with
`omgs ledger ingest --ledger OUTPUT_DIR/coverage-ledger.json
--dispositions OUTPUT_DIR/dispositions-HUNTER.json`. Candidate dispositions map to `covered` with
evidence, meaning examined and handed to verification, never confirmed or safe.

Hunters must not execute any probe, including synthetic non-target probes on the host. Hand all
execution plans to the verifier for `omgs prove`. Context isolation is a host obligation, not an OS
access boundary: shared output directories do not prevent cross-reading. Disclose that limitation;
use host-enforced read scopes where available and never claim technical isolation without them.

Registered classes describe different boundaries. `download_integrity` concerns payload identity
and authenticity; `download_and_execute` concerns the input-to-execution chain. Likewise,
`deletion_path_safety` describes path confinement and `privileged_local_ops` the privileged effect.
Use the same class for the same boundary across runs. Do not rename a class to fit a stack seed.
Existing shipped records use the registered legacy labels `tenant_isolation`, `export_scope` and
`search_control`; retain their identity when comparing those records. Unknown names are rejected,
never silently hashed into a new identity. Hyphen aliases in intent question filters do not change
candidate identity; fingerprint creation requires the registered spelling.
