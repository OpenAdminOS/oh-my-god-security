# OMGS technical learnings

Field reviews across web applications, policy automation, desktop applications and
command-line tools informed these capabilities. Target identities, finding titles,
per-target results and private run records are omitted. These learnings are not
security claims about any identifiable project.

## Correctness and trust

1. Stack and surface detection in audit init. Detect at least static HTML and JavaScript, ASP.NET, PowerShell scripts and modules, Swift tools, and binary heavy repositories. Seed ledger units from real entry points and sinks per language. A whole-repository fallback using only web authorization classes can misrepresent non-web targets.
2. First party versus vendored code separation. A field target (desktop app) carried hundreds of vendored binaries and minified libraries. OMGS must inventory first party source, exclude vendored paths from hunting and sensor noise by default, and state exclusions in coverage. Sensor hits in vendored code need separate attribution.
3. Run sensors, do not just detect them. Execute available deterministic tools during init or check, ingest results as candidates with redaction, vendor aware baselines, and stable identities.
4. Report renderer parity with the designed one pager. Show verdict counts, rejected records with their counterevidence, needs validation evidence next to each intent question, sensor results, examined and not examined coverage from the ledger, and run metadata. Today a human must read findings.json to see most of the actual review.
5. One root cause, many locations. A field target (policy updater) produced three records for one copied defect. Support grouped findings with multiple locations, or a family identity above the per location fingerprint, so counts and metrics stay honest.
6. A sandbox backend that exists on user machines today. Without an available executor, candidates remain traced. Ship OS native backends behind the existing sandbox interface so proof tests can actually run, with the report naming the backend used.
7. Run directory hygiene. Create run output with owner only permissions and warn when the output path sits under a shared temp directory. Reports describe vulnerabilities in other people's code.

## Packs and hunting quality

8. Generated script safety pack. Cover the capability to keep untrusted values as data when generating scripts, with synthetic fixtures that check data boundaries and ordinary-value controls.
9. Feed and import to policy pack. External feeds and imported files that write enterprise policy need monotonicity guards (never lower a security minimum automatically), fail closed handling of unsupported filters, and provenance checks before a write.
10. Privileged local operations pack. Deletion through symlinks, path allowlists for recursive removal, executing binaries from user writable locations before dropping privilege, guest to host file extraction, and sandbox shares that expose host project files to guest writes.
11. PowerShell as a first class language. Policy automation commonly uses PowerShell directly or generates it. A PowerShell pack likely outranks a second TypeScript framework for this audience.
12. Enforced hunter and verifier separation. Hunters must not assign final verdicts without independent verification. The CLI or skill flow should require a distinct verifier pass per candidate and record who verified what in run metadata.
13. Ledger update tooling. Hunters need commands to move units between planned, candidate, covered and blocked with evidence links, plus a coverage critic step. Free form architecture notes should not be the only coverage record.
14. Structured prerequisites. Attacker prerequisites currently live in evidence prose with inconsistent quality. Add a dedicated field so triage can sort self inflicted cases from cross principal ones mechanically.

## Workflow and ecosystem

15. One command repo review. Clone shallow to scratch, init the run, run sensors, detect the stack, and print a ready made agent brief. Repeated manual setup makes reviews harder to reproduce.
16. Batch mode for curated lists. Queue many repositories, keep one run directory each, and render an aggregate index with per repo counts, blockers and cost. Directory scale security scanning is a natural OMGS deployment.
17. Benchmark capability cases. Generated script injection is a recurring class worth a benchmark case: values must stay data when a generator emits a script. Synthetic fixtures should assert that quote characters in a value do not become a statement. Dry run safety also merits a synthetic case that checks for unintended side effects. Each case needs human adjudication and a sandbox proof.
18. Model routing resilience. A model refusal can interrupt a review. Per role model selection with recorded fallbacks turns a refusal into a reroute instead of a stalled run.
19. Local run accounting. Record model identity, agent calls, wall time and cost per run in run metadata by default. The benchmark design needs these numbers and hunters currently ignore budget fields they are not forced to update.
20. Intent question library per ecosystem. Recurring questions from this test (may a feed lower a security minimum, who may supply a manifest, which URL schemes may reach managed browsers) should ship as reusable intent prompts that resolve into policy once.

## Proof and reporting lessons

- Keep hunting, verification and evaluation in separate contexts. Rejected
  candidates need counterevidence, and a mechanism proof must not become an
  unsupported end-to-end confirmation.
- Compile unmodified modules into a sandboxed harness when a native test runner
  needs unsupported nested sandboxing. Disclose the runner substitution. A
  synthetic reimplementation proves only a class and cannot promote a target record.
- Avoid daemon-mediated host effects in proofs. Preference services and similar
  IPC can bypass filesystem containment. Post-run cleanup is not containment.
  Use scratch-relative temporary paths and leave unsupported effects unvalidated.
- Seed coverage per trust boundary for privileged software, rather than one
  whole-repository unit. Record installer, service, policy and packaging boundaries.
- Use schema-shaped hunter output, stable identities and explicit merged-candidate
  provenance. Missing metadata and incomplete sensor output must be visible gaps.
- A harness that crashes before reaching target logic is a harness error, never
  evidence that the target refused an operation.
- Host attestation cannot substitute for an enforced sandbox. Live demonstrations
  outside the sandbox are not OMGS proof tiers.
- Deny host reads, writes, network and daemon effects by default. Kill detached
  descendants, bound output capture and check cleanup rather than assuming a
  completed parent process means a completed workload.
- Process markers are consistency evidence, not authentication against hostile
  code sharing the harness. Replay and independent evaluation remain required.

- Protect run artifacts with owner-only storage, bounded reads and no-follow link
  handling. Publish by atomic replacement and serialize updates with OS file locks.
  Sensor failures and malformed results are coverage gaps, never clean zero-hit runs.
- Keep optional progress views offline or loopback-only, with a Host check and
  completion shutdown. They never override deterministic report verdicts.

## Current implementation and evidence limits

The current source includes grouped locations, verifier provenance, typed coverage
ledger transitions, batch initialization and indexes, recorded routing refusals,
an intent library, progress reporting and offline benchmark scoring. Proof drafts
stage into workspace copies; integrating accepted tests requires approval.

MXC 1.0.1 is the sole proof backend. macOS survivor cleanup, Linux PID namespace
teardown and Windows augmentation refusal address platform-specific containment
limits. See [DECISIONS.md](DECISIONS.md) and the
[proof contract](skill/PROOF-CONTRACT.md) for the current guarantees and limitations.

The public tree includes synthetic benchmark fixtures and anonymous
[field-case shapes](benchmark/field-cases.md). It includes no named field reports
or real-project corpus inventory. Paired proofs and published measurements remain
necessary before claiming benchmark recall, false-positive rates, cost or variance.
