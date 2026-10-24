# Hunting

## Assign bounded, isolated work

Assign one hunter a small set of ledger units sharing a surface or enforcement chain. Supply source identity, architecture map, relevant pack, trusted intent, local evidence paths, exact call/time allowance, and the candidate contract below. The hunter may read related source, but must record new surfaces instead of silently expanding scope.

Hunters do not see each other's hypotheses before submitting. Use independent agent contexts when available. If the host cannot isolate contexts, run sequential bounded passes and disclose that limitation. Preserve a fresh verification context; do not have the author certify their own candidate. All target execution still goes through `omgs prove` under the shared safety policy.

Stop on a complete candidate, a traced effective control, a precise blocker, or budget exhaustion. Return an explicit disposition for every assigned unit, including no-candidate results and the control that decided them. Secret and dependency sensors are deterministic inputs, not model hunting assignments.

## Candidate contract

Candidates are hypotheses, not confirmed findings. This is the agent handoff contract, not an extension to the CLI findings schema. Each hunter writes its candidates as a schema-shaped file into the run directory, validated against [schemas/candidates.schema.json](../schemas/candidates.schema.json), plus a short prose summary, so deduplication and fingerprinting are mechanical rather than hand-merged from free-form reports. Return structured records with these fields and no severity:

| Field | Content |
| --- | --- |
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

Use stable attack class names across runs, such as `missing_authorization`, `idor`, `tenant_isolation`, `webhook_verification`, `webhook_replay`, `integration_url`, and `client_only_authorization`. Apply the installed CLI's canonicalization and accepted schema; this vocabulary does not invent extra schema fields.

## Identity and deduplication

Compute identity only through `omgs fingerprint`, binding **attack class, entry point, sink symbol, and violated boundary** through the documented interface. Include module identity where symbols repeat. Keep line numbers and titles as evidence, never identity inputs. Do not handcraft hashes or substitute an advisory identifier.

Merge duplicate traces into one candidate without discarding unit provenance or counterevidence. Keep distinct entry points or distinct boundaries separate when their identity inputs differ. Fixes and line movement alone must not manufacture a new identity. Recompute if verification changes a semantic identity input.

## Coverage critic

The critic challenges the ledger, not just the candidate list. Check that every discovered handler method, action, principal transition, data access path, and relevant backend delegation has a unit and disposition. Look for unassigned units, UI-only assumptions, uncovered middleware matchers, alternate privileged clients, and unexamined methods behind a reviewed URL.

For each gap, add a bounded unit or record why it remains unexamined. Reconcile assignments, evidence, source revisions, duplicate fingerprints, and exhausted budgets. Send candidates to a fresh verifier with source and counterevidence. Do not endorse them by consensus, promote source traces to confirmed, or claim completeness because all dispatched hunters returned.
