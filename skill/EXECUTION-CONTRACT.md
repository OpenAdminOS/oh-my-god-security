# Execution agreement, pilot and cleanup

Before reading target source into a model, resolve the user's approved provider, exact model,
execution location, scope, exclusions and retention. A coordinator may prepare storage without
reviewing target content when only a remote local model is authorized. Never send target content
to another provider for convenience or independent evaluation. Independence means fresh contexts,
not necessarily different models.

## Lock before dispatch

Initialize new workflow reviews with `--require-contract` on `audit init`, `review`, or `batch
init`.
This marker prevents dispatch, route selection and proofs until a contract is locked. Unmarked
CLI runs retain legacy behavior for compatibility; the workflow must not omit this flag.
Then write a private JSON file and run:

```text
omgs contract lock --run OUTPUT_DIR --from contract.json
omgs contract show --run OUTPUT_DIR
```

Example (replace the source ref and approved identity):

```json
{
  "version": 1,
  "source_ref": "exact initialized commit",
  "scope": ["repository source review"],
  "exclusions": ["Windows runtime validation", "live services"],
  "roles": {
    "hunter": {"provider": "ollama", "model": "approved-model", "location": "macmini"},
    "verifier": {"provider": "ollama", "model": "approved-model", "location": "macmini"},
    "evaluator": {"provider": "ollama", "model": "approved-model", "location": "macmini"}
  },
  "verification": "source_only",
  "retention": "reports_only",
  "pilot_call_limit": 3,
  "accepted_by": "user instruction"
}
```

`verification` is `source_only` or `sandbox_tests`; `retention` is `reports_only` or `evidence`.
Pilot limits range from 3 to 12 charged dispatches. The total call budget must also reserve at least
three calls for verification/reporting. Locking is refused after calls have been spent or proof
artifacts created. Once locked the
agreement cannot change. A separately
approved new run is needed for a legitimate scope change; it never erases a stop or permits routing
around a provider restriction. Historical runs without contracts remain usable, but do not claim
that their model selection was locked. These are host declarations enforced at CLI dispatch,
not authenticated proof of where inference occurred or a host network sandbox. Standalone
`prove --target` without `--run` has no run contract; never use it to bypass a contracted review.

## Readiness and a small pilot

Record `omgs contract readiness --run OUTPUT_DIR --from readiness.json` with `source_ref` and
`checks`. Required keys are `model`, `storage`, `source`, `validation`, `cleanup`. Each value
contains
`state` (`passed` or `blocked`) and nonempty `evidence`. Check actual model availability, durable
host-side result storage, source identity, authorized validation capability and resource ownership.
For source-only scope, validation readiness must explicitly explain the runtime exclusion. An
exclusion is not a passed runtime test. Readiness is immutable after the first dispatch. Changed
infrastructure requires a stop and a
separately authorized run; it cannot reset the pilot allowance.

Register each role using an attempt start event, then bind it before its charged dispatch:

```text
omgs contract bind --run OUTPUT_DIR --from binding.json
```

A binding contains `attempt`, `execution` (provider/model/location exactly matching that role),
`phase` (`pilot` or `review`), and nonempty `boundary`, `actor`, `entry`, `effect`, `invariant`.
Ask one bounded boundary question with exact inputs and a stop condition. Avoid giant file lists.
Every call uses an `attempt` dispatch event; a duplicate receipt is not permission to call again.
Legacy manual budget charging does not replace contract dispatch admission.

Run hunter, verifier and evaluator in distinct contexts and identities on the approved backend.
Persist request, output, timestamps and terminal outcome on the execution host before fetching it.
Distinguish success, refusal, timeout, invalid output and transport loss. Retrieve completed durable
results after a disconnect; never automatically retry an uncertain or failed request. Record failed
or stopped work without coverage credit. Preserve existing safety stops across runs.

Check source citations against the pinned source, counterevidence and structured output. Accept
using `omgs contract pilot --run OUTPUT_DIR --from pilot.json` only when all pass. The input names
`hunter`, `verifier`, `evaluator` attempt IDs, booleans `source_accuracy`, `counterevidence`,
`structured_output`, a nonempty `evidence` list of private run-relative files, and optional
`proof_ref`. Roles must be completed and have charged pilot dispatches. For `sandbox_tests`, a
clean runner-attested proof for this source is mandatory. Pilot success is a host quality judgment,
not a vulnerability confirmation. All finding proof and adjudication rules still apply.

Failed pilot decisions are persisted, revoke previous approval and stop further calls. Positive
resubmission cannot clear the stop; recovery needs a separately authorized new run.
Failed pilot: stop, report why, spend no additional calls. Do not silently choose a larger model,
cloud provider, extra budget or narrower question until authorized. Source-only review remains
explicitly incomplete for runtime assurance, even when all authorized source units are covered.

## Resource ledger and final-report retention

Before creating a checkout, evidence directory, scratch area, process, tunnel or remote job,
record its ownership plan. Once created, register it with:

```text
omgs cleanup register --run OUTPUT_DIR --from resource.json
```

Fields: `id`, `kind` (`checkout`, `evidence`, `scratch`, `process`, `tunnel`, `remote_job`),
`location`, `owner`, `locator`. Use run-specific directories and durable job identifiers. A PID
alone is insufficient ownership evidence. Do not register shared runtimes/models as disposable.

Proof admission atomically checks the contract and charges the shared allowance, including proofs
and linked runs. Admitted proofs keep cleanup closed. After sandbox preparation, the runner checks
stops and the locked target revision again before each workload launch, including replay. A crash or
uncertified cleanup leaves an active proof record for host investigation; do not delete that record
to make cleanup pass. An in-flight stop still requires the host to stop its owned execution process.

After reporting, end active attempts and call `omgs cleanup begin --run OUTPUT_DIR`. New attempts,
dispatches and run-associated proofs are then closed. The host stops owned jobs, checks no survivors
remain and deletes owned disposable resources. Never kill unrelated PIDs, follow replaced symlinks,
or recursively delete an unverified shared directory. The CLI deliberately does not execute
locator strings, kill processes, or delete directories.

For each observed removal/termination submit `omgs cleanup release --run OUTPUT_DIR --from
release.json` with `id`, `actor`, `evidence`. Evidence is a concise host observation, not a copied
secret or raw target evidence. Then `omgs cleanup finish --run OUTPUT_DIR` requires all registered
resources released. An empty ledger can produce a receipt, but attests to no registered resources.
`omgs cleanup show --run OUTPUT_DIR` provides the host-attested receipt. It
covers registered resources only and is not independent deletion verification.

For `reports_only`, first export and inspect final reports outside every disposable resource.
Remove checkout, raw evidence and disposable artifacts on every execution host. Keep a temporary
control directory for the run metadata until resource releases are recorded, export the cleanup
receipt with the final reports, then remove that control directory and verify absence. Record the
last removal in the final report's cleanup note. Retain no raw source/evidence to make this note.
If anything cannot be removed, report its exact location and reason instead of claiming cleanup.
Report start/finish times, elapsed review and test durations separately, scope, method, verification
limits, tools, exact provider/model/location and unresolved work. A finished job is not a complete
audit. Confirmed findings, pending candidates, hardening suggestions and unreviewed areas stay
separate.
