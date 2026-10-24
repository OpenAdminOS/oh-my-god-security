# Validation and reporting

## Disprove first

A fresh verifier receives the candidate contract, relevant source, trusted intent, and proof artifacts, not the hunter's confidence or a proposed severity. In a separate context, reconstruct the path and try to break it: unreachable export, earlier authorization, a trusted identifier, effective RLS, wrapper enforcement, safe return projection, or intended public access. Follow delegation to the limit of locally available evidence.

Reject a candidate only with concrete counterevidence that defeats the claimed result. A missing dependency, external policy, unclear product intent, or unavailable sandbox is `needs_validation`, with the exact missing fact. Never use absence of proof as proof of safety. Before any execution, independently check the proof's minimal scope and all execution controls in [SKILL.md](SKILL.md#execution-safety).

## Proof ladder

| Tier | Machine value | Evidence and verdict |
| --- | --- | --- |
| 0 | `traced` | Complete input-to-sink trace and claimed boundary violation. Candidate only; never confirmed. |
| 1 | `test_proven` | A security invariant test fails because the real target path permits the unauthorized effect, under the project's test runner inside `omgs prove`. Decisive evidence earns confirmed. |
| 2 | `sandbox_exploited` | Sandbox verified against a locally built copy of the app on synthetic data. Use only when a test cannot decide, after human approval of the first tier 2 run per repository. |
| 3 | `dedicated_host` | A real exploit on a dedicated disposable host, for the rare target whose decisive proof cannot execute inside the OS sandbox at all (a privileged installer, a root LaunchDaemon or XPC helper). Confirmed only with a disposable-host attestation recorded in `prerequisites`. Lower portability than tier 2, not higher: the proof is bound to a bespoke machine. |

The deterministic runner selects escalation under the run budget. The agent supplies the missing fact and cheapest proposed decisive proof; it cannot self-award a tier, bypass approval, or escalate merely for a more dramatic demonstration. Evidence that already decides the boundary ends execution. Retain the highest earned tier on blockage; a failed build or timeout earns no new tier. A tier describes evidence, while verdict describes whether that evidence supports the claim.

Tier 3 is a narrow exception to the sandbox-only rule, not a convenience, and most privileged-target findings never need it. A decision-logic defect such as a nil expected signer disabling verification, or a missing downgrade check, lives in a pure function and is decided at tier 1 by an invariant test on that function with synthetic inputs, with no VM and no root; `benchmark/fixtures/installer-trust` is a worked example. Reach for tier 3 only after tiers 1 and 2 are shown to be impossible for the specific boundary (for example, demonstrating that the effect actually reaches real root through a real signed installer and Gatekeeper the sandbox cannot provide), and only to show impact a logic proof has already established. OMGS never requires a user to stand up a VM. The dedicated host must be genuinely disposable: a throwaway VM or wiped machine with no real data, no credentials, and no Keychain secrets, snapshotted and discarded after the run. Never a productive machine, and never one shared with real work. Record the host identity, its disposable nature, and the exact manual steps in `prerequisites`; weakening the host (disabling Gatekeeper, enabling passwordless sudo) is part of the attestation and must be reverted when done.

Non-web and non-sandboxable targets need a documented proof recipe, because the project's own test runner may not run under the sandbox. For a Swift package whose `swift test` cannot run inside the Seatbelt profile (SwiftPM spawns a nested sandbox that is denied), compile the unmodified target modules with `swiftc -emit-library` and run the same invariant assertions through a small harness inside `omgs prove`, keeping the XCTest file as the proposed regression test and disclosing the runner substitution in evidence. Executed-invariant evidence without the project's own test runner is honest proof but a known labeling boundary: it does not by itself earn `test_proven`.

The sandbox does not contain every effect. Daemon-mediated writes escape file-based containment: a `defaults write` reaches the real preference domain through `cfprefsd`, and `NSTemporaryDirectory()` resolves to the real per-user temp dir, both outside the scratch area. Use throwaway domains, scratch-relative temp paths, and verify deletion after the run, or avoid the API. Finally, a proof harness that crashes before reaching the code under test (a missing dynamic library, a load error, a build failure) must fail loudly and distinctly: never read a harness abort as the target refusing the operation, or a crash will masquerade as a passing control.

## Write a regression test

1. Use the target's existing test framework and conventions. Write a draft beneath the external output directory, with a proposed target-relative path for later human acceptance. The runner stages the test into scratch; never write audit logs or generated fixture data into the target.
2. Create dummy principals A and B, synthetic resources and local secrets. State the intended invariant as the test assertion, such as B cannot read A's private row. Include an authorized success control so a broken harness cannot look like protection.
3. Exercise the actual route/action/service and enforcement chain. Mock only unrelated external effects. Do not mock out the authorization check, tenant predicate, signature verification, or RLS whose failure is at issue. A mock database that simply returns a forbidden row cannot establish a real RLS bypass.
4. Assert the minimum decisive effect: response contents for a read, unchanged synthetic state for a denied write, or no privileged effect for an invalid event. A status code alone is insufficient when a mutation could occur before the response.
5. Submit the test and exact runner invocation to `omgs prove`. Run test discovery, setup, builds, and prerequisites only there. No installs, downloads, remote credentials, or external endpoints. Record runner exit, assertion output, authorized control, observed effect, backend/policy/limits, and source identity.
6. Confirm only when the invariant fails for the claimed security reason. Syntax errors, missing modules, unrelated assertions, and all-denied fixtures are blockers or harness failures. Preserve the test as the fix acceptance check. A future approved patch should make the same test pass without weakening the invariant, with all reruns still sandboxed.

For tier 2, the runner builds and runs a writable scratch copy with only local synthetic services on isolated loopback. Approval must cover the local effect and stop condition. Stop after one minimal decisive result; never point the client, app, webhook, or database at a live or third party system. If local dependencies or enforced controls are missing, record the exact blocker and a manual plan with the same safety constraints.

## Missing intent

Ask about expected behavior, not security jargon. Example: "Should a signed-in member of one workspace be able to read a private project from another workspace if they know its ID?" Record the affected surface and the exact missing expectation in `intent_question`; leave verdict pending and omit severity.

Store the answer, scope, source, and date as an intent rule in the project's supported committed policy format through normal owner review. Keep the question and run evidence outside the target. An answer from a PR head cannot change the gate or rewrite trusted base policy. Do not invent an answer, treat a pending proposal as accepted policy, or call a policy answer execution evidence. Reevaluate the candidate and run the necessary proof after intent is resolved.

## Findings record

Serialize the following semantic fields using the installed CLI schema. Fields unavailable for a pending record use the schema's absent or null representation, never fabricated values. Internal hunter context stays in linked evidence rather than adding unsupported fields.

| Field | Requirement |
| --- | --- |
| `fingerprint` | Deterministic `omgs fingerprint` result from attack class, entry point, sink symbol, boundary. |
| `title` | Concrete unauthorized result, without inflated impact. |
| `verdict` | Exactly `confirmed`, `needs_validation`, or `rejected`. |
| `severity` | Required only for confirmed findings, using the CLI's accepted scale and demonstrated impact. Omit for all other verdicts. |
| `proof_tier` | Exactly `traced`, `test_proven`, `sandbox_exploited`, or `dedicated_host`; never exceed runner evidence. A `dedicated_host` record must carry a disposable-host attestation in `prerequisites`. |
| `attack_class` | Stable class used for identity. |
| `entry_point` | Stable path and route/method or action symbol. |
| `sink` | Stable module and effect-producing symbol. |
| `boundary` | Principal/resource boundary and violated invariant. |
| `location` | Object containing repository-relative `path` and one-based `line` in the reviewed source. |
| `evidence` | Source trace, attacker prerequisites, concrete result, controls/counterevidence, external artifact references and runner evidence. For pending records include the exact missing fact and blocker; for rejection include the decisive refutation. |
| `fix_brief` | Confirmed: invariant, narrowest effective change, proof test acceptance check. Otherwise null or absent per schema. |
| `intent_question` | Unresolved plain language intent question with scope, otherwise null or absent per schema. |

Severity follows the confirmed boundary and effect, including privilege, data scope, and prerequisites. Do not claim bulk exposure, account takeover, or remote execution from a single unrelated symptom. No severity belongs on unresolved questions or rejected hypotheses.

Fix brief example: **Invariant:** members access only their workspace's private projects. **Narrowest change:** constrain `loadProject` to the trusted workspace membership and project ID before returning data, preserving authorized reads. **Acceptance check:** the saved project test denies cross-workspace access and permits the owner's read. Include the test path and evidence reference; do not auto-apply a fix.

## Validate, render, and hand off

Use `omgs fingerprint` after any identity correction, then `omgs validate` over the final records and required run inputs. Resolve schema errors, duplicate identity conflicts, missing evidence, invalid severity/verdict combinations, and inconsistent tiers before `omgs report`. A validator pass checks structure and deterministic consistency, not the truth of an agent's claim.

The CLI renders `findings.json`, SARIF, `REPORT.md`, and `REPORT.html` from the same verified records outside the target. Check that the offline HTML escapes target text, embeds no scripts from the target, makes no external requests, and agrees with the other views. Treat reports as sensitive. Include pending intent, exact blockers, unexamined ledger units, mode, budget and spend, agent/model identity, and sandbox backend/policy. No score or coverage percentage.

In gate mode, only committed proof tests and scanner rules may block a merge. A model verdict, source trace, pending question, or uncommitted proof cannot gate, including a tier 2 demonstration without a committed deterministic guard. Advisory mode blocks nothing. Propose accepted proof tests, intent rules, policy and suppressions for normal review; keep run output external and never silently change the gate mode or policy source.
