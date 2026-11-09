# Changelog

## Unreleased

### Review reliability

- New opt-in execution contracts lock source revision, role provider/model/location, scope,
  exclusions, validation mode and retention before dispatch. The packaged review workflow now
  requires `--require-contract` at initialization for new reviews. Marked runs refuse dispatch,
  routing and proofs until locked. Unmarked CLI runs remain compatible with the legacy API.
  Locking after spent calls or existing proof artifacts is refused.
- Readiness and a bounded three-role quality pilot gate broad dispatch. Refusals do not select
  a fallback in locked runs. Hunter calls preserve a verification/reporting reserve.
- Failed pilot decisions persist and revoke earlier approval. Hunter reserves include charged
  proofs and linked runs. Proof admission tracks active work, blocks cleanup until certified release,
  and rechecks source revision and lifecycle stops immediately before workload launch.
- Reports disclose the execution agreement and retain readiness, pilot and source-only limitations.
- A resource ledger closes dispatch before cleanup and records host-attested resource releases.
  Hosts still perform ownership-checked deletion and process termination; OMGS does not infer
  cleanup from an empty process list or execute arbitrary resource locators.

- Preserve missing-directory errors during macOS storage admission so concurrent job recovery
  can skip directories already retired by their owners without weakening ACL checks.

- Linked fixes inherit the contract requirement and cannot reset parent stops, failed pilots,
  cleanup or source-only scope. Each fix locks its own revision before work.
- Operators can record a host-attested resolution for stranded proofs after checking termination;
  the resolution closes the run and is retained in the cleanup receipt.
- Reports explicitly disclose that source admission compares HEAD, not uncommitted file contents.

### Operational notes

- Contract and resource records are host assertions, not authenticated backend attestations.
- Source-only reviews cannot run target proofs or claim runtime assurance. Windows runtime can
  remain excluded without being counted as tested.
- Failed local pilots stop before scaling; changing providers requires separate authorization.
