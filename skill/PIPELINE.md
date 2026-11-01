# Pipeline

## The pipeline (multi-agent by default)

OMGS is a multi-agent pipeline by default, not a single review pass. Red hunts in isolation, blue
verifies independently, a separate evaluator adjudicates, and green proposes fixes. Each stage runs
in its own fresh context so that no agent certifies its own work: the verifier never sees the
hunters reasoning before submitting, and the evaluator is independent of both hunt and verify. A
single combined pass that hunts, verifies, and reports in one context is not an OMGS review and must
not be labelled as one, because it cannot deliver the adversarial separation the verdicts depend on.
Where the host cannot isolate contexts, run sequential bounded passes with distinct instructions and
disclose that limitation.

Hand each role brief over **verbatim**, plus its explicit scope and resolved inputs. Do not
paraphrase or summarize a brief. Use one shared red brief for every hunter, varying only boundary,
units and packs:

- Red: [agents/red-hunter.md](agents/red-hunter.md).
- Blue: [agents/blue-verifier.md](agents/blue-verifier.md).
- Evaluator: [agents/evaluator.md](agents/evaluator.md).
- Green, only for explicitly approved fixes: [agents/green-fixer.md](agents/green-fixer.md).

For initialization, `omgs audit init --target TARGET --persona builder|inheritor|team` selects
defaults, report depth and budget profile. There is one shared pool for dispatch calls, original
proofs and replays. Builder defaults to 24 combined units, inheritor to 64, and team to 96.
An explicit `--budget 40` replaces that default with 40 combined units. The effective profile is
`custom` when a persona's selected cap differs from its default; metadata separately retains
`persona_budget_profile` and `persona_budget_default`. Without committed base policy, all
default to advisory and explicit --mode and --budget override defaults. With --base, committed
policy takes precedence and conflicting overrides fail. The persona is recorded in run metadata and
never changes the evidence bar, sandbox rules or verdict semantics. Without --persona, the existing
unbounded budget remains unless --budget is supplied.

Every inventory class stays accountable. Test, docs, data, assets and vendored groups each get a
`planned` exclusion unit with their total count and first 20 sorted paths across all files.
This includes `assets:excluded`, which blocks the critic until resolved. Assign these units
to hunters to skim or sample, then hunt with `covered` plus evidence or record `out_of_scope` with
`--note "reviewed, not security relevant: <reason>"`. For out_of_scope, cite at least one displayed
sampled path with --evidence. Describe the review and why the group is irrelevant; classification
alone cannot justify exclusion. Blocked or deferred exclusions remain critic failures. The first 20
paths are a sample, not the entire scope. Resolution reasons appear in ledger output and reports.

Optional sensors are installed tools executed only inside pinned Microsoft MXC, including Gitleaks
and Semgrep. MXC denies external egress, inbound connections and host loopback on every supported
OS. Missing MXC, failed preflight and a Windows augmentation-tier refusal are gaps; never fall back
to host execution. Target copies, scanner runtime roots, rules and the OSV database are read-only.
Private scratch is outside run artifacts and removed after supervised cleanup on every exit path;
cleanup failures remain gaps. Linux requests a 2 GiB cgroup memory limit and 128 tasks where the
user scope is available. Elsewhere no total memory cap is claimed. Source input is bounded to 16
MiB/file, 64 MiB total, 100,000 enumerated entries, 10,000 staged files and 64 directory levels.
Omissions retain bounded per path skip records and omitted record counts as gaps. A skipped
directory describes an unenumerated subtree, not a count of its files. Every sensor has
a 120 second deadline and 4 MiB output cap. See README for the teardown margin.

TruffleHog uses `--no-verification --no-update --no-ignore-tag`. OSV-Scanner uses
`--offline-vulnerabilities --offline --no-call-analysis --no-resolve --no-ignore` and an OMGS-owned
empty `--config`, bypassing repository suppression files. Semgrep requires local
`OMGS_SEMGREP_CONFIG` rules; registry fetching is disabled. The copied `.semgrepignore` and
`.gitleaksignore` files are removed in any letter case, `.gitignore` and inline `nosemgrep` are
disabled. Tool-reported skipped input and
diagnostics remain gaps.

A missing `OMGS_OSV_DB` cache (default `<OMGS data dir>/osv-db`) is a gap, never permission to
fetch. Database download remains a separate explicit network opt-in using the README command,
outside MXC only because this is a network fetch the user has opted into. OMGS never runs it
automatically.

Read `sensor-hits.json` and `sensors.json` during mapping. Raw secret values are not retained. Each
code-class hit seeds a `sensor:<tool>:<fingerprint>` candidate unit. OSV package name, version and
ecosystem participate in that fingerprint and appear in reports; each affected version requires its
own resolution. Assign it to a hunter and record `covered` with evidence, or resolve it with a
specific reason. The critic rejects unaccounted or missing hit units. Test, docs, data and vendored
hits stay visible in reports and belong in their existing exclusion group review. Scanner matches
are leads, not confirmations. Retain sensor gaps, including missing tools, malformed output, absent
databases and unapplied resource limits, in the handoff.


## Required reading by role

Read required sections once per fresh role context. Reuse those reads within that context while
its bundle identity remains unchanged. A new role context reads its own required sections.
The host passes each role brief verbatim; the matrix supplements and never replaces that brief.
Every role reads all of [EXECUTION-SAFETY.md](EXECUTION-SAFETY.md), including artifact containment
and platform limits. [PROOF-CONTRACT.md](PROOF-CONTRACT.md) is the authoritative proof contract;
phase text links to it instead of maintaining a second exit, marker or replay specification.

| Role | Required pipeline sections | Additional required reading |
| --- | --- | --- |
| Host | Preamble, progress, and current phase | SETUP, budgets before dispatch, handoff before artifact consumption |
| Red hunter | Preamble, Hunt, and progress | Its verbatim brief, decision rules, hunting, assigned packs; proof contract only when planning a recipe |
| Blue verifier | Preamble, Challenge, Prove, and progress | Its verbatim brief, validation, full proof contract, matching recipe |
| Evaluator | Preamble, Adjudicate, Prove, and progress | Its verbatim brief, validation, full proof contract, matching recipe |
| Green fixer | Preamble, Prove, and progress | Its verbatim brief, approved scope, full proof contract, matching recipe |

Unassigned phases, unrelated packs and other stack recipes are optional. Required safety content,
role separation, independent replay, budget charging and stop conditions are never optional.

## Required progress at every transition

Status recording is required for every run, independently of the optional browser view. Before
initialization, read [HANDOFF-AND-PROGRESS.md](HANDOFF-AND-PROGRESS.md)
and ask once whether to open the live view. Never open a browser without that explicit yes.

Immediately after `audit init` resolves `OUTPUT_DIR`, run the Initialize status command below and
verify that `OUTPUT_DIR/pipeline-status.json` exists. If status fails, report and resolve the error;
never silently continue a full run with no status file. Do this even when live view is declined.
At every transition, mark the outgoing stage `done` (or `failed` with the actual blocker), then
mark the incoming stage `active`, always with a short, plain-language `--detail`. Record completion
or failure of the final stage too. Use `omgs status`, not hand-written JSON. The commands below
show entry updates; use the same stage id and a result detail for the corresponding exit update.
Keep only the currently running stages active. For parallel hunters, record each child's entry and
exit with `--parent hunt`, a useful `--label` and a plain-language detail.

Before **every** sandbox proof or replay, including evaluator replays, run the Prove status
command below. Mark `prove` done or failed afterward with the actual outcome, and reactivate the
calling stage if more work remains.
A blocked proof remains `needs_validation`; progress states never change verdicts. Do not leave
`prove` active during later adjudication or reporting. Update cumulative counters as decisions are
recorded, using the existing keys `candidates`, `confirmed`, `needs_validation`, and `rejected`.


### Initialize

1. **Initialize.** Run `omgs audit init` with the resolved setup values through the documented
   interface. Record source identity, trusted base policy, mode, limits, and locally available
   tools. Let deterministic sensors inspect secrets and supply chain data; do not spend model calls
   duplicating those sensors or execute target code for reconnaissance.

   Once `OUTPUT_DIR` exists, create the mandatory status file before starting optional watch:

   ```sh
   omgs status --run OUTPUT_DIR --stage initialize --state active --detail "Preparing the review"
   ```

### Map

2. **Map.** Read [RECONNAISSANCE.md](RECONNAISSANCE.md). Map architecture, principals, input
   surfaces, enforcement and delegated controls. Seed coverage ledger units as surface by boundary
   by attack class, with evidence paths and unexamined areas. Record the structured map in
   `architecture.json` per [schemas/architecture.schema.json](schemas/architecture.schema.json) and
   render it with `omgs architecture --in architecture.json --out OUTPUT_DIR`; the resulting
   `ARCHITECTURE.md` and offline `ARCHITECTURE.html` show how the target is built, its trust
   boundaries and attack surface, and what was not examined. This map is descriptive and never
   changes a verdict.

   ```sh
   omgs status --run OUTPUT_DIR --stage map --state active --detail "Mapping the project"
   ```

### Hunt

3. **Hunt.** Read [HUNTING.md](HUNTING.md), hand each hunter the matching [proof
   recipe](PROOF-RECIPES.md#proof-by-default-per-stack-recipes), and read only the relevant [attack
   packs](DECISION-RULES.md#attack-packs). Dispatch several isolated hunters, normally one per
   boundary unit (for a privileged target, for example, one each for the installer trust decision,
   the IPC or XPC surface, and the download and resolver chain). Hunters hand proof plans and drafts
   to the verifier and never execute proofs. Each hunter runs in its own fresh context, reads only
   its scope, cannot see the other hunters, and writes its structured candidates without severity to
   `OUTPUT_DIR/candidates-<hunter>.json`, with its own identity in each candidate's `hunter`. Use
   `omgs fingerprint` with attack class, entry point, sink symbol, and violated boundary for
   identity and deduplication.

   ```sh
   omgs status --run OUTPUT_DIR --stage hunt --state active --detail "Looking for leads"
   ```

### Challenge

4. **Challenge.** Read [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md). A fresh,
   independent verifier that did not do the hunting dedupes the candidates by fingerprint and
   adversarially tries to disprove each one, following shared and delegated controls, rejecting the
   leads a control defeats, and recording exact missing facts. Run `omgs validate` on the records
   before proof; keep valid unresolved candidates pending. Parallel verifiers each write
   `OUTPUT_DIR/findings-<verifier>.json`; combine them with `omgs findings merge --run OUTPUT_DIR
   --from <file>...`, which refuses conflicting records for the same fingerprint.

   ```sh
   omgs status --run OUTPUT_DIR --stage verify --state active --detail "Checking each lead"
   ```

### Prove

5. **Prove.** The independent verifier submits its minimal proof plan and test drafts to `omgs
   prove`. The runner selects the cheapest decisive tier under budget. Tier 1 runs the project's
   test runner, or an equivalent harness over the unmodified target code, in the sandbox. Tier 2
   exercises a locally built app on dummy data only when a test cannot decide, with explicit human
   approval for its first run per repository. No approval is implied by a general audit request. Run
   each proof as `omgs prove --run OUTPUT_DIR --finding <fingerprint> --test <target-relative test
   path> [--test-from <draft outside the target>] --expect-marker BOUNDARY_ASSERTION_FAILED --cmd
   "<command>"` (add `--tier 2` for a local app; tier 2 runs only on Linux, elsewhere it exits 3
   with the reason). The runner copies the target into a per-run workspace, executes only inside the
   SHA-256 pinned Microsoft MXC executor, and writes `OUTPUT_DIR/proofs/<n>.json` with the executor
   and config digests, every enforced control and every gap, the exit code, any surviving processes,
   and redacted output. Exit 3 means nothing ran: record the printed blocker. Tier 2 approval is
   given only by a person at a terminal with `omgs approve --target <repo>`; never run that command
   yourself. The verifier then folds each proof result back into its record (verdict, proof tier,
   evidence, and `proof_ref` set to the printed `proofs/<n>.json`, because `omgs validate` rejects a
   `test_proven` or `sandbox_exploited` record without a matching clean proof record).
   Apply the authoritative [proof contract](PROOF-CONTRACT.md) for assertion support, markers,
   cleanliness, timeout and replay identity. Missing evidence cannot earn a tier. The evaluator in
   step 6 replays every proof it upholds with `omgs prove --run OUTPUT_DIR --replay <n>` instead of
   trusting the record file, and checks that the real target and intended assertion executed.
   A replay that is not reproduced overturns the tier. Recompute identities with `omgs fingerprint`
   after any semantic change so records are final before adjudication.

   ```sh
   omgs status --run OUTPUT_DIR --stage prove --state active --detail "Testing a lead safely"
   ```

### Adjudicate

6. **Adjudicate.** A separate evaluator, independent of both the hunt and the verify, reviews every
   finalized record against the source and the proof artifacts: it upholds, adjusts, or overturns
   each verdict, checks that each proof exercises the real target code and that the proof tier
   matches the evidence reached, and catches over- and under-statement. It is never the author of a
   record it judges. When it surfaces a lead no hunter raised, that lead goes back through a fresh
   hunter as a new candidate (and then the verifier), because every record must trace to a hunter
   candidate and be verified by someone else; the evaluator never adds a record directly. This pass
   is load-bearing: it is where overclaimed confirmations and mislabelled proofs are caught.
   Adjudication is the last step that may change a record; any semantic change after it (a new
   verdict, severity, proof tier, or fingerprint) requires another adjudication pass on the changed
   record before reporting. Each uphold records the verdict, tier, severity and proof_ref it
   upheld, and the critic and report flag any record that no longer matches as changed after
   adjudication.

   ```sh
   omgs status --run OUTPUT_DIR --stage adjudicate --state active --detail "Reviewing the evidence"
   ```

   The evaluator's gaps describe the run as it saw it. When the host later closes a ledger
   placeholder or fixes a record the evaluator flagged, run the evaluator again so evaluation.json
   reflects the current run; never edit or delete its gaps by hand.

### Report

7. **Report.** Let the coverage critic reconcile every ledger unit against the adjudicated records
   (reconciliation adds coverage dispositions, it does not change a verdict). Record each unit's
   disposition with `omgs ledger set --ledger OUTPUT_DIR/coverage-ledger.json --unit <id> --status
   <status> --evidence <fingerprint or path>` (a `covered` unit needs evidence; `deferred`,
   `blocked`, and `out_of_scope` need `--note`). Run `omgs validate`, then `omgs critic --run
   OUTPUT_DIR` until it passes, then `omgs report` with `--hunters <n> --verifier <id> --agent-calls
   <n>` so the run metadata (and any batch index) records who ran the review and at what cost.
   Verify `findings.json`, SARIF, `REPORT.md`, and offline `REPORT.html` agree and all live under
   `OUTPUT_DIR`, alongside the `ARCHITECTURE.md` and `ARCHITECTURE.html` map from the Map phase.
   Report confirmed findings with tier and severity, pending questions, exact blockers, what was not
   examined, and mode/budget/model/sandbox metadata. Do not publish a score or coverage percentage.

   ```sh
   omgs status --run OUTPUT_DIR --stage report --state active --detail "Preparing your report"
   ```

   After rendering and checking the outputs, record the final transition:

   ```sh
   omgs status --run OUTPUT_DIR --stage report --state done --detail "Report saved"
   ```

If budget or a provider block prevents resolving a late lead, record a blocked or deferred ledger
unit and preserve the pending fact. Render a partial handoff with the critic gaps visible rather
than losing completed evidence. A partial report is not a completed review or a critic pass;
`run_status: partial` marks artifact delivery only. Resume in a follow-up run with explicit scope.
