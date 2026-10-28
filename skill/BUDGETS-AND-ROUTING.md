# Budgets and routing

### Model routing on refusal

A model may refuse security review work mid-task. Configure an ordered model list per role in
`~/.local/share/omgs/models.json` (`{"roles": {"hunter": ["primary", "fallback"], "verifier": [...],
"evaluator": [...], "guard": [...]}}`), ask `omgs route --run OUTPUT_DIR --role <role>` which model
to start each role with, and on a refusal run `omgs route --run OUTPUT_DIR --role <role> --refused
<model> --reason <what happened>`. Relaunch the same role, in a fresh context and with the same
brief, on the model it prints. Every reroute is recorded in the run metadata and the report. A
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
blue-verifier, evaluator and green-fixer. Values are tokens, USD cost and duration in milliseconds.
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
describes sandbox settings; `budget_profile` describes persona defaults and is independently named.

Before every dispatch, charge its calls with `omgs budget --run OUTPUT_DIR --charge-calls 1`.
Proofs charge themselves. Report `--agent-calls` is an absolute local cumulative count, never a
delta;
it cannot reduce recorded usage. Reports, indexes and handoffs show calls plus proofs and remaining
family allowance. Do not charge the same calls again during reporting.

`omgs route --run OUTPUT_DIR --role verifier --refused MODEL --reason "provider block: reason"`
records the event even without models.json. Exit 1 means recorded with no route available, not lost
metadata. Refusal history and blockers remain visible even if a later call succeeds. A provider
block can leave complete or partial artifacts; validate them and obtain independent adjudication
before using them. Record the exact reason without credentials. Retrying or switching still requires
the host's existing authorization and consumes the same budget; no automatic provider retry occurs.

Supply known identities with repeated `omgs report --model hunter=NAME --model verifier=NAME
--model evaluator=NAME ...`. These labels disclose host facts and never authorize a model change.
