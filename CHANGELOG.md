# Changelog

## Unreleased

### Review reliability

- New opt-in execution contracts lock source revision, role provider/model/location, scope,
  exclusions, validation mode and retention before dispatch. The packaged review workflow now
  requires this for new reviews. Existing run directories remain compatible.
- Readiness and a bounded three-role quality pilot gate broad dispatch. Refusals do not select
  a fallback in locked runs. Hunter calls preserve a verification/reporting reserve.
- Reports disclose the execution agreement and retain readiness, pilot and source-only limitations.
- A resource ledger closes dispatch before cleanup and records host-attested resource releases.
  Hosts still perform ownership-checked deletion and process termination; OMGS does not infer
  cleanup from an empty process list or execute arbitrary resource locators.

### Operational notes

- Contract and resource records are host assertions, not authenticated backend attestations.
- Source-only reviews cannot run target proofs or claim runtime assurance. Windows runtime can
  remain excluded without being counted as tested.
- Failed local pilots stop before scaling; changing providers requires separate authorization.
