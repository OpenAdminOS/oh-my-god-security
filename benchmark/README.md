# OMGS benchmark

Measure whether agents find real boundary violations, whether fresh verifiers keep true candidates, and what the process costs. The CLI is deterministic and never calls a model. This benchmark evaluates the agent workflow plus its deterministic proof and reporting artifacts, not a model-generated security score.

## Corpus

- **Real vulnerability fix pairs:** pin an authorized repository's vulnerable commit and the commit fixing the same independently confirmed vulnerability, with its CVE/advisory provenance. The vulnerable snapshot must yield a confirmed finding for that defect; the fixed snapshot must not yield that finding. Inspect the fix and regression evidence to exclude partial fixes or unrelated changes. Other findings require separate adjudication.
- **AI generated sample apps:** retain generation prompt hash, agent/model configuration and seed when supported. A human independently confirms each deliberately present defect using local synthetic fixtures and a regression test. A generation prompt or model label is not ground truth. Include repaired versions and realistic distractors.
- **Clean negatives:** humans inspect and test specific surfaces with effective shared authorization, intentional public data, correct RLS, verified webhooks and UI guards backed by server controls. Record exactly which units are negative. A fixed commit is negative for its repaired defect, not automatically clean for every attack class.

Stay within TypeScript, Next.js App Router, and Postgres or Supabase. No live targets, real user data, or external service validation. An unavailable local dependency, sandbox control, or external policy is a recorded blocker, not evidence of absence or a reason to execute elsewhere.

For the real post-cutoff cohort, record the latest known training knowledge cutoff for every model used in hunting, criticism, and verification. The vulnerability's earliest known public disclosure and public fix availability must both be later than that cutoff. Include dates and sources, not just the CVE assignment date. Unknown cutoff or earlier disclosure makes the case ineligible for a post-cutoff claim for that configuration; report it in a separate cohort. Post-cutoff selection reduces leakage risk, but does not prove absence of training contamination.

## Split and run protocol

Group every version of a defect, repository family, and generated template family in the same cohort. Assign cohorts, not individual commits, to development and held-out evaluation. Rotate the held-out split on a declared schedule, version each rotation, and publish aggregate results. Once a held-out case is exposed for tuning, retire it from future held-out use and replace it. Keep labels, patches, advisory identities, paired versions, proof solutions, and repository history out of agent context.

1. Freeze the corpus revision, split rotation, complete agent/model configurations, pack and CLI versions, tools/dependency snapshot, trusted base policy, mode, and per-run budget. Predeclare repetition count `k`, sampling settings, seed handling, and the identity matching/adjudication rules.
2. Prepare authorized source snapshots and already available dependencies separately from execution. Do not execute target hooks during preparation. Network fetching or dependency installation is never part of a proof. If a required offline fixture cannot be provisioned safely under the sandbox contract, mark the run blocked.
3. Give agents only the blinded target, trusted policy, source identity, and task. Run each snapshot in a fresh run directory outside the target and a fresh agent context, without prior findings, paired source, or external lookup of the case. Sandbox all target tests, builds, and local apps through `omgs prove` with network denied, dummy data, and explicit limits. Tier 2 retains its first-run human approval requirement per repository.
4. Use the skill's full six-phase flow, including fresh verification, `omgs fingerprint`, `omgs validate`, and `omgs report`. Both gate and advisory modes must be exercised. Only committed proof tests and scanner rules can gate; a benchmark label or model verdict cannot gate.
5. Save pre-verifier candidates and final verdicts, runner-attested proof tiers, assertions and counterevidence, blockers, examined/unexamined units, agent call/token counts, monetary cost, and elapsed times. Redact real secrets if accidentally encountered and stop the affected proof. Keep run output external and sensitive.
6. Repeat `k` independent complete runs at the same per-run budget. Do not feed earlier candidates into later runs or select the best run as the single-run result. Record stochastic seeds where supported and disclose unsupported seeds.

The evaluator matches confirmed records to ground-truth attack class, entry point, sink and boundary, using `omgs fingerprint` and reviewed semantic aliases for genuine refactors. A path/line match, advisory name, or keyword hit is insufficient. Confirmed results require at least `test_proven`; traced candidates do not count as recovered defects. Keep alias adjudication independent of the hunter and record all disputed matches.

## Metrics

Use human-confirmed, eligible positive defects as the recall denominator. Show numerators, denominators, cohort, stack, proof tiers, budget, configuration, blockers and sample counts alongside every metric. Do not silently remove blocked or budget-exhausted cases from the primary denominator. A secondary executable-subset result may be shown with its exclusions.

| Metric | Definition |
| --- | --- |
| Single run recall | Distinct eligible defects confirmed in one complete run divided by all eligible positive defects. Report each run and the mean. |
| Union of `k` runs recall | Distinct eligible defects confirmed in at least one of the predeclared `k` independent runs divided by that same denominator. Publish total `k`-run cost. |
| False positives | Count of independently refuted confirmed findings, with false discovery fraction `FP / (TP + FP)` and negative-unit rate `negative units with at least one FP / adjudicated negative units`. Include repeated detections on fixed snapshots. Pending records are reported separately. |
| Verifier false rejection rate | Ground-truth-positive candidate groups explicitly rejected by the verifier divided by all ground-truth-positive candidate groups submitted to it. Deduplicate within each run. Report true candidates left pending separately so deferral cannot hide lost recall. |
| Cost per run | Agent input/output tokens, calls and actual currency cost across hunters, critics, verifiers and retries; proof/tool resource cost and wall time separately. Mark unavailable billing data unknown. CLI model-call count is always zero. |
| Run to run variance | Distribution, range and standard deviation of recall, false positives, cost and time over independent runs; include per-defect detection frequency. Do not claim determinism of agent output because the CLI is deterministic. |

Use `null`/not applicable for zero denominators. Unexpected confirmed findings receive independent adjudication before being scored; they are neither automatically false positives nor silently added to the frozen recall denominator. Publish an amended corpus version if ground truth changes. Include needs-validation volume, verifier deferrals, sandbox blockers, and paired vulnerable/fixed outcomes with the primary metrics. No coverage percentage or security score.

## Manifest format

[cases.example.json](cases.example.json) is valid JSON with **fictional, non-runnable examples only**. It is a proposed benchmark manifest, not the CLI findings schema. Never include `examples_only` or `example_only` cases in scored results. Invalid domains, synthetic hashes and reviewer names in that file are illustrative, not provenance.

All fields shown are required for a case manifest; use null only where noted. Keep truth-bearing fields in evaluator storage outside blinded target snapshots.

| Field | Meaning |
| --- | --- |
| `format_version`, `examples_only`, `cases` | Manifest format revision, global example exclusion, and case list. |
| `id`, `example_only`, `kind`, `description` | Unique case ID, case exclusion, `real_fix_pair`, `generated_app`, or `clean_negative`, and scope. |
| `source` | Repository URL, authorization basis, and license object (`spdx_id`, `redistribution_status`, `note`). URL may be null for private local fixtures. |
| `stack` | Language, pinned Next.js version, and database stack. Pin additional tools in the fixture toolchain manifest. |
| `provenance` | Advisory ID/URL, first public disclosure/fix dates and evidence URLs (null for generated cases); generator agent/model, prompt SHA-256 and seed (null for nongenerated cases); human confirmation reviewer/date and private evidence path. |
| `cutoff` | Latest participating model cutoff, status (`eligible`, `ineligible`, `unknown`, or `not_applicable`) and reason. Null date with `not_applicable` is allowed for generated/clean cases; `unknown` cannot support post-cutoff claims. |
| `split` | Cohort ID, `development` or `held_out` partition, and rotation ID. |
| `snapshots` | Unique snapshot IDs, `vulnerable`, `fixed`, or `clean` role, immutable source ref, local fixture path and toolchain manifest path. All family snapshots share a split. |
| `fixtures` | Reviewed policy path, synthetic setup manifest, dependency snapshot SHA-256, `network: denied`, `data: synthetic_only`, and tier 2 first-run approval requirement. Setup runs only through `omgs prove`. |
| `expected_findings` | Ground-truth defect ID, four identity inputs, source location, invariant, positive/negative snapshot IDs, minimum proof tier, and evaluator-only proof test path. Empty for wholly clean cases. Compute actual fingerprints with `omgs fingerprint`, never invent them here. |
| `known_clean_units` | Snapshot IDs, surface, boundary, class and invariant for independently checked negative units. |
| `budget` | Maximum agent calls, model tokens, currency cost in USD, wall seconds and proof runs. These are benchmark per-run limits, bound to supported policy fields by the harness; do not assume CLI flags with these names. |

Paths are relative to an authorized local fixture bundle outside evaluated targets unless they identify source locations. Check all references, full immutable source IDs, artifact hashes and dates before admitting a real case. The manifest never embeds secrets, production connection details, or executable shell commands.

## Add a case

1. Establish authorization and record license/provenance without redistributing material whose rights are unresolved. Select the in-scope boundary and smallest synthetic reproducer. For a real pair, independently confirm both revisions and record the disclosure/fix timeline against the evaluated configuration's cutoff.
2. Pin immutable snapshots, local dependencies, toolchain and policy. Write the invariant test in the target framework as an evaluator-only artifact. Run only through `omgs prove`; observe the security assertion fail on the vulnerable snapshot and pass on the fixed snapshot, with authorized controls passing on both. No proof can depend on a remote backend.
3. Have a human confirm the defect, the fix and scoped negative units from the trace and sandbox artifacts. Generated defect labels need the same review. Record exact pending facts instead of admitting unverified positives.
4. Fill every manifest field, mark real cases `example_only: false`, validate JSON and all fixture/hash/reference relationships, and assign the entire family to a cohort/rotation before evaluation. Keep held-out labels and solution tests separate from agent-visible inputs.
5. Run the complete workflow under the frozen protocol, adjudicate unexpected findings independently, and publish paired outcomes, all required metrics, costs, variance and limitations. Keep raw vulnerability reports in external run output. Do not accept a release based on a handpicked successful run.

## Licensing: open decision

Benchmark corpus licensing is explicitly deferred in [DECISIONS.md](../DECISIONS.md). This design does not choose a corpus license or authorize copying upstream source, advisories, patches, or generated app dependencies. Track rights per case; retain required notices. Until the decision and rights are resolved, keep restricted material in authorized local fixtures and publish only metadata whose redistribution is permitted. Example license identifiers are illustrative, not a licensing decision.
