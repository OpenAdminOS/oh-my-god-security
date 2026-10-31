# Budgets and routing

### Model routing on refusal

A model may refuse security review work mid-task. Configure an ordered model list per role in
`~/.local/share/omgs/models.json` (`{"roles": {"hunter": ["primary", "fallback"], "verifier": [...],
"evaluator": [...], "guard": [...]}}`), ask `omgs route --run OUTPUT_DIR --role <role>` which model
to start each role with, and on a refusal run `omgs route --run OUTPUT_DIR --role <role> --refused
<model> --reason <what happened>`. Selection records availability only. For a safety stop, first
record the affected attempt and follow the controlled recovery contract below. Relaunch only when
the existing host or user authority permits it, with a fresh attempt and the same brief. Every
reroute is recorded in the run metadata and the report. A
reroute never merges roles: a hunter rerouted to the verifier's model still runs as a separate agent
from the verifier. When `omgs route` exits 1 the role has no usable model (every fallback refused,
or none is configured for it); the blocker is recorded in the run metadata, so stop that role
instead of stalling. Exit 2 means the command itself failed, for example a missing or malformed
`models.json`.

### Batch reviews

To review many repositories, write their https URLs one per line to a file and run `omgs batch init
--list <file> --out <batch-dir>`, where `<batch-dir>` is new or empty. It exits 1 when any
repository failed to initialize (the failures are recorded in `batch.json`). It clones each
repository (https only, validated), initializes one run directory per repository under
`<batch-dir>`, records failures in `batch.json` without stopping, and prints one agent brief per
run. Run the full pipeline above in each run directory separately; never share hunters, verifiers,
or findings across repositories. Finish with `omgs batch index --batch <batch-dir>/batch.json --out
<batch-dir>` for an offline `INDEX.md` and `INDEX.html` with per-repository counts, blockers, agent
calls, and reroutes.

## Agent budgets

Before dispatch, allocate the total call, token/cost, wall clock, and proof limits exposed by policy
and reserve capacity for verification and reporting. Each hunter gets explicit scope, context size,
call/time allowance, output contract, and a stop condition. Count retries, critics, verifier calls,
and repeated runs against the same run budget. The agent accounts for reasoning calls; the CLI
enforces its deterministic limits. Do not hide model calls behind CLI commands.

Use focused text reads and shared maps instead of repeatedly loading the whole repository. Prefer
one decisive test to more speculation. Stop when a boundary is decided, evidence cannot be obtained
safely, or the next call would exceed budget. Record exhausted units and unfinished candidates as
unexamined or blocked. Never silently reset or expand a budget, or claim an unreviewed area is
clean. Fix runs inherit the original persona and only the remaining combined call/proof allowance,
as specified in [agents/green-fixer.md](agents/green-fixer.md); pause spending in the original run
until that reservation is reconciled.

Host accounting is optional and cumulative per role. Supply `--accounting
red-hunter=12000,0.32,45000` on `omgs status` or `omgs report`, repeating the option for
host, blue-verifier, evaluator and green-fixer. Values are tokens, USD cost and duration in
milliseconds.
Use `unknown` or an empty field for unavailable values. Omitted roles and values stay unknown, never
zero; resubmission replaces that role's totals. Report reads saved status accounting. Never estimate
missing usage from stage clocks.

## Clone placement and live accounting

Use `omgs review --repo-url https://github.com/example/project --persona inheritor
--clone-root /private/campaign/clones --out /private/campaign/run` for one repository.
Use `omgs batch init --list repos.txt --out /private/campaign/runs --persona inheritor
--clone-root /private/campaign/clones` for a batch. Clone root contains host/owner/name paths;
`--out` chooses run storage. Both must remain outside the reviewed target after symlink resolution.
The persona is applied on initial creation, so no run deletion or recreation is needed.
`OMGS_HOME` still relocates all state, including models, answers, scratch and offline database;
prefer the explicit placement flags when isolating only clones and runs. `execution_profile`
describes sandbox settings. `budget_profile` records the effective budget selection, while
`persona_budget_profile` and `persona_budget_default` retain the persona defaults separately.

Before every dispatch, charge exactly once using a dispatch receipt below or the legacy
`omgs budget --run OUTPUT_DIR --charge-calls 1` command. Never use both for the same turn.
Proofs charge themselves. Report `--agent-calls` is an absolute local cumulative count, never a
delta;
it cannot reduce recorded usage. Reports, indexes and handoffs show calls plus proofs and remaining
family allowance. Do not charge the same calls again during reporting.

`omgs route --run OUTPUT_DIR --role verifier --refused MODEL --reason "provider block: reason"`
records the event even without models.json. Exit 1 means recorded with no route available, not lost
metadata. Refusal history and blockers remain visible even if a later call succeeds. A provider
block can leave complete or partial artifacts; quarantine stopped output and use a fresh authorized
replacement for decisions. Record the exact reason without credentials. Retrying or switching
requires the host's existing authorization and consumes the same budget; no automatic provider
retry occurs.

Supply known identities with repeated `omgs report --model hunter=NAME --model verifier=NAME
--model evaluator=NAME ...`. These labels disclose host facts and never authorize a model change.

With no routing file and no refusal, `route` returns `host-default` to retain the host selection.
After a refusal it stays blocked until an explicit configured fallback is available.

## Retained attempts and stops

The host records each dispatch with `omgs attempt --run OUTPUT_DIR --event EVENT_FILE`.
The event file follows `schemas/attempt-event.schema.json`. Events append under the run
lock to `run-metadata.json`; previous events are retained. The host records observed
transcript events, rather than accepting a worker's description of its own stop.
These records are host assertions, not authenticated attestations. Protect the run
metadata and event files with the same private storage rules as other run evidence.

Before dispatch, record a `start` with a unique `id`, role (`host`, `hunter`, `verifier`,
`evaluator` or `guard`), `identity`, fresh `context`, explicit `inputs` and `outputs`
manifests, and `isolation` (`procedural` or `host_enforced`). Manifests enumerate
allowed paths, not permission grants. Shared directories provide procedural context
isolation only. Set `host_enforced` only when the host actually supplies private
input/output views and denies sibling access. Separate identities do not prove
separate contexts. Disclose shared role configurations as an independence limit.
The host still charges each dispatch and continuation before it starts.

After inspecting the finished output, the host records `complete` with the attempt
`id`, observing `actor` and a `reason`. A draft cannot be finalized by adding an
identity alone. A verifier record needs `verification: {"state":"final",
"attempt":"ATTEMPT_ID"}` and its completed verifier attempt. The evaluation file
also names its completed `attempt`. Legacy files without completion records remain
incomplete; do not manufacture completion to make validation pass.

On a safety stop, stop the affected work and record `stop` with `id`, observing
`actor`, `kind` (`provider` or `policy`), exact `reason`, affected `artifacts` and
`disposition` (`quarantined`, `discarded` or `pending_review`). One stopped worker
does not imply that every worker in its role stopped. An attempt may be stopped even
after completion if transcript inspection reveals an earlier stop. Its output then
loses eligibility for finalized decisions. Never complete or reuse a stopped attempt.
Do not retry a blocked action in another form or interpret route selection as permission
to bypass a stop. Preserve artifacts for review without consuming them as decisions.

Resume only within the existing host or user authority and the applicable stop policy.
If that authority does not permit resumption, leave the run blocked. After the
responsible authority reviews the stop and artifact disposition, record a fresh
replacement `start`, then `resolve` naming the old `id`, observing `actor`,
`authority` (`host` or `user`), authorization `reason` and `replacement` id.
Resolution retains the stopped attempt; it does not accept or finalize its output.
The replacement must independently finish and be completed before its decisions count.

Routing exhaustion appends a blocker event. Successful route selection alone does
not establish recovery. After an authorized replacement is recorded, use
```text
omgs attempt --run OUTPUT_DIR --resolve-blocker BLOCKER_ID --actor ACTOR --reason REASON --replacement ATTEMPT_ID
```
This appends resolution without deleting refusal history. Legacy blocker strings
have stable ids `legacy-0`, `legacy-1`, and so on. Reports show active blockers and
retain their event history. Reconcile linked ledger dispositions after recovery.

Usage may be supplied as `--accounting blue-verifier@ATTEMPT_ID=tokens,cost-usd,duration-ms`
(and the equivalent role keys for other roles). Starting an attempt records unknown
components automatically. A continuation replaces that attempt's cumulative usage;
never add cumulative continuation totals together. Each submission records the latest
dispatched turn it covers. A later dispatch retains the known subtotal but marks
unreported continuation usage unknown, including after a safety stop. Submit fresh
cumulative usage to cover that turn. Distinct attempts remain distinct.
Reports show known subtotals, the unknown count for each component, and whether the
aggregate is complete. Legacy role totals remain supported; once attempt entries
exist, they are historical totals and are excluded from attempt subtotals to avoid
double counting. Unknown usage must remain unknown after a stop.


## Role identity and continuation receipts

Record observed identities before reporting with
`omgs route --run OUTPUT_DIR --role host --model LABEL`, repeating for hunter, verifier,
evaluator and guard. This records an observation, without dispatching work, choosing a retry or
resolving blockers. Report accepts the same roles with `--model role=LABEL`; invalid-role errors
list them. Host usage can be reported with the `host` accounting role.

For an initial dispatch or an authorized continuation, the host may submit a `dispatch` event
with attempt `id`, a stable unique `turn` id, observing `actor` and authorization `reason`.
This appends a receipt and charges exactly one unit in the same locked transaction. A continuation
reopens a completed attempt until the host inspects its output and records completion again.
An identical repeated receipt returns `already recorded; do not dispatch again`, with no second
charge. Conflicting reuse of a turn id fails. A stopped attempt cannot dispatch again, even using
an old receipt; authorized recovery still requires a fresh replacement under the stop contract.
A host-side safety stop is recorded with the host role and follows the same rule.

Use either these charged receipts or the legacy manual call-charge command for a given turn,
never both. Start records registration and unknown usage, without charging. Record the latest
cumulative usage for a continued attempt; do not add cumulative continuation figures together.
The shared budget includes these calls, original proofs and replays, all drawing from one pool.
Persona defaults are 24, 64 and 96 combined units for builder, inheritor and team respectively.
An explicit smaller or larger cap replaces that default; it does not create a second allowance.
The historical `budget_agent_calls` key names this single combined cap. It does not allocate a
second proof pool. `budget_semantics` explicitly identifies calls, original proofs and replays.
