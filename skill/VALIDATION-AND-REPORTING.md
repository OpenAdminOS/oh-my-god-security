# Validation and reporting

## Disprove first

A fresh verifier receives the candidate contract, relevant source, trusted intent, and proof artifacts, not the hunter's confidence or a proposed severity. In a separate context, reconstruct the path and try to break it: unreachable export, earlier authorization, a trusted identifier, effective RLS, wrapper enforcement, safe return projection, or intended public access. Follow delegation to the limit of locally available evidence.

Reject a candidate only with concrete counterevidence that defeats the claimed result. A missing dependency, external policy, unclear product intent, or unavailable sandbox is `needs_validation`, with the exact missing fact. Never use absence of proof as proof of safety. Before any execution, independently check the proof's minimal scope and all execution controls in [SKILL.md](SKILL.md#execution-safety).

## Proof ladder

| Tier | Machine value | Evidence and verdict |
| --- | --- | --- |
| 0 | `traced` | Complete input-to-sink trace and claimed boundary violation. Candidate only; never confirmed. |
| 1 | `test_proven` | A security invariant test fails because the real target path permits the unauthorized effect, inside `omgs prove`, under the project's own test runner or, when that runner cannot run in the sandbox, an equivalent harness that compiles and exercises the unmodified target code and asserts the same invariant. Decisive evidence earns confirmed. |
| 2 | `sandbox_exploited` | Sandbox verified against a locally built copy of the app on synthetic data. Use only when a test cannot decide, after human approval of the first tier 2 run per repository. |

The deterministic runner selects escalation under the run budget. The agent supplies the missing fact and cheapest proposed decisive proof; it cannot self-award a tier, bypass approval, or escalate merely for a more dramatic demonstration. Evidence that already decides the boundary ends execution. Retain the highest earned tier on blockage; a failed build or timeout earns no new tier. A tier describes evidence, while verdict describes whether that evidence supports the claim.

There is no tier above `sandbox_exploited`. An effect the OS sandbox cannot contain, such as a privileged installer or a root LaunchDaemon or XPC helper that needs real root and Gatekeeper, has no proof tier: it cannot be confirmed, because OMGS has no backend that executes it through `omgs prove`, and running it unsandboxed on a manually chosen machine is never permitted. Keep such a record `needs_validation` with the exact missing fact and a safe manual validation plan; never promote it to confirmed. Most privileged-target findings do not need this anyway: a decision-logic defect such as a nil expected signer disabling verification, or a missing downgrade check, lives in a pure function and is decided at tier 1 by an invariant test on that function with synthetic inputs, no VM and no root (`benchmark/fixtures/installer-trust` is a worked example, and this is the path OMGS expects). A person may separately demonstrate live impact on a throwaway, network-isolated, snapshot-and-discard VM to inform severity, but that is a manual step outside OMGS, not a proof tier, and OMGS never requires a user to stand up a VM.

Non-web and non-sandboxable targets need a documented proof recipe, because the project's own test runner may not run under the sandbox. For a Swift package whose `swift test` cannot run under MXC (SwiftPM spawns a nested sandbox, which a sandboxed process cannot do), compile the unmodified target modules with `swiftc -emit-library` and run the same invariant assertions through a small harness inside `omgs prove`, keeping the XCTest file as the proposed regression test and disclosing the runner substitution in evidence. Such a harness earns `test_proven` as long as it exercises the unmodified target code, asserts the real invariant, and the substitution is disclosed. A harness that reimplements, stubs, or mocks the logic under test does not earn `test_proven`; it is at most a synthetic reproducer for the pack, evidence about the class and not about this target.

Do not rely on the sandbox to contain daemon-mediated effects. Under MXC on macOS, `defaults write`, `open`, `launchctl` and the clipboard are denied and Apple Events are not delivered (observed 2026-10-27), but a proof that needs such an API is testing the daemon, not the target. `NSTemporaryDirectory()` resolves to the real per-user temp dir, which MXC denies, so a harness that uses it fails rather than escaping. Cleaning up afterward never counts as containment: if an effect could leave the sandbox, the escape has already happened. Redirect temp to a scratch-relative path. For preferences, launchd, or similar daemon IPC, avoid the API in the proof or record a blocker and leave the record `needs_validation`; never rely on post-run cleanup as the containment, and never reach for an unsandboxed machine instead. A proof harness that crashes before reaching the code under test (a missing dynamic library, a load error, a build failure) must fail loudly and distinctly: never read a harness abort as the target refusing the operation, or a crash will masquerade as a passing control.

## Write a regression test

1. Use the target's existing test framework and conventions. Write a draft beneath the external output directory, with a proposed target-relative path for later human acceptance. The runner stages the test into the workspace copy; never write audit logs or generated fixture data into the target.
2. Create dummy principals A and B, synthetic resources and local secrets. State the intended invariant as the test assertion, such as B cannot read A's private row. Include an authorized success control so a broken harness cannot look like protection.
3. Exercise the actual route/action/service and enforcement chain. Mock only unrelated external effects. Do not mock out the authorization check, tenant predicate, signature verification, or RLS whose failure is at issue. A mock database that simply returns a forbidden row cannot establish a real RLS bypass.
4. Assert the minimum decisive effect: response contents for a read, unchanged synthetic state for a denied write, or no privileged effect for an invalid event. A status code alone is insufficient when a mutation could occur before the response.
5. Submit the test and exact runner invocation to `omgs prove`. Run test discovery, setup, builds, and prerequisites only there. No installs, downloads, remote credentials, or external endpoints. Record runner exit, assertion output, authorized control, observed effect, backend/policy/limits, and source identity.
6. Confirm only when the invariant fails for the claimed security reason. Syntax errors, missing modules, unrelated assertions, and all-denied fixtures are blockers or harness failures. Preserve the test as the fix acceptance check. A future approved patch should make the same test pass without weakening the invariant, with all reruns still sandboxed.

For tier 2 (Linux only), the runner builds and runs a writable workspace copy with only local synthetic services on the sandbox's private loopback. Tier 2 uses the same convention as tier 1: a named harness or test, passed with `--test`, that fails with an assertion when the unauthorized effect happens and passes when it does not. Approval must cover the local effect and stop condition. Stop after one minimal decisive result; never point the client, app, webhook, or database at a live or third party system. If local dependencies or enforced controls are missing, record the exact blocker and a manual plan with the same safety constraints.

## Missing intent

Ask about expected behavior, not security jargon. Example: "Should a signed-in member of one workspace be able to read a private project from another workspace if they know its ID?" Record the affected surface and the exact missing expectation in `intent_question`; leave verdict pending and omit severity.

Record the owner's answer with `omgs intent answer --target <repo> --id <intent_id> --answer <text> --source <who> [--scope repo|<path>]`. Answers are stored on the reviewer's machine keyed by the target's full path, never in the reviewed repository, and every later `omgs audit init` on that target copies them into the run so the report shows them beside the matching questions. An answer recorded after a run was initialized applies from the next run; for a repository reviewed by URL, `omgs review` creates the clone the answer's `--target` names. The store is trusted only when it lives outside the target and is a regular file with a single link, so stored answers are supported on Unix (macOS, Linux) only. Proposing the same rule as committed project policy through normal owner review stays a separate, optional step. Keep the question and run evidence outside the target. An answer from a PR head cannot change the gate or rewrite trusted base policy. Do not invent an answer, treat a pending proposal as accepted policy, or call a policy answer execution evidence. Reevaluate the candidate and run the necessary proof after intent is resolved.

## Findings record

Serialize the following semantic fields using the installed CLI schema. Fields unavailable for a pending record use the schema's absent or null representation, never fabricated values. Internal hunter context stays in linked evidence rather than adding unsupported fields.

| Field | Requirement |
| --- | --- |
| `fingerprint` | Deterministic `omgs fingerprint` result from attack class, entry point, sink symbol, boundary. |
| `title` | Concrete unauthorized result, without inflated impact. |
| `verdict` | Exactly `confirmed`, `needs_validation`, or `rejected`. |
| `severity` | Required only for confirmed findings, using the CLI's accepted scale and demonstrated impact. Omit for all other verdicts. |
| `proof_tier` | Exactly `traced`, `test_proven`, or `sandbox_exploited`; never exceed runner evidence. |
| `attack_class` | Stable class used for identity. |
| `entry_point` | Stable path and route/method or action symbol. |
| `sink` | Stable module and effect-producing symbol. |
| `boundary` | Principal/resource boundary and violated invariant. |
| `location` | Object containing repository-relative `path` and one-based `line` in the reviewed source. |
| `locations` | Further locations of the same root cause, each with `path` and `line`. One defect copied into several places stays one record and counts once; do not emit one record per copy. |
| `hunted_by` | Identity of the hunter whose candidate produced the record, matching that candidate's `hunter`. Required. |
| `verified_by` | Identity of the independent verifier that decided the record. Required, and `omgs validate` rejects it when it equals `hunted_by`. |
| `candidates` | Fingerprints of further candidates merged into this record: several hunters raising one root cause under different identities, or the original candidate fingerprint when verification changed an identity input. The record's own fingerprint is implicit. |
| `evidence` | Source trace, attacker prerequisites, concrete result, controls/counterevidence, external artifact references and runner evidence. For pending records include the exact missing fact and blocker; for rejection include the decisive refutation. |
| `fix_brief` | Confirmed: invariant, narrowest effective change, proof test acceptance check. Otherwise null or absent per schema. |
| `intent_question` | Unresolved plain language intent question with scope, otherwise null or absent per schema. |
| `intent_id` | Library question the record asks, from `omgs intent list`. Prefer it over a free-text question when one fits: records sharing an id are grouped into one question in the report, and one recorded answer resolves all of them. `omgs validate` rejects an unknown id. |

Severity follows the confirmed boundary and effect, including privilege, data scope, and prerequisites. Do not claim bulk exposure, account takeover, or remote execution from a single unrelated symptom. No severity belongs on unresolved questions or rejected hypotheses.

Fix brief example: **Invariant:** members access only their workspace's private projects. **Narrowest change:** constrain `loadProject` to the trusted workspace membership and project ID before returning data, preserving authorized reads. **Acceptance check:** the saved project test denies cross-workspace access and permits the owner's read. Include the test path and evidence reference; do not auto-apply a fix.

## Validate, render, and hand off

Use `omgs fingerprint` after any identity correction, then `omgs validate --findings <run-dir>/findings.json` over the final records. Then run `omgs critic --run <run-dir>`: it reconciles the ledger, every `candidates*.json`, and `findings.json`, and exits 1 on any gap (a unit still `planned` or `candidate`, a `covered` unit without evidence, a candidate no finding accounts for, a finding whose verifier hunted one of its candidates, a finding no unit cites as evidence). Close each gap in the ledger with `omgs ledger set` (evidence or a note) or by verifying the missing candidate; do not report over open gaps. `omgs report` also runs the critic and prints its result in the report. Resolve schema errors, duplicate identity conflicts, missing evidence, invalid severity/verdict combinations, and inconsistent tiers before `omgs report`. A validator pass checks structure and deterministic consistency, not the truth of an agent's claim.

The CLI renders `findings.json`, SARIF, `REPORT.md`, and `REPORT.html` from the same verified records outside the target. Check that the offline HTML escapes target text, embeds no scripts from the target, makes no external requests, and agrees with the other views. Treat reports as sensitive. Include pending intent, exact blockers, unexamined ledger units, mode, budget and spend, agent/model identity, and sandbox backend/policy. No score or coverage percentage.

In gate mode, only committed proof tests and scanner rules may block a merge. A model verdict, source trace, pending question, or uncommitted proof cannot gate, including a tier 2 demonstration without a committed deterministic guard. Advisory mode blocks nothing. Propose accepted proof tests, intent rules, policy and suppressions for normal review; keep run output external and never silently change the gate mode or policy source.
