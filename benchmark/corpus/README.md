# Corpus admission guidance

The public tree contains no named real-project corpus metadata or campaign records.
The [benchmark guide](../README.md) defines case manifests, split handling,
proof requirements and metrics. The shipped scoring fixtures are synthetic.
No real-project recall or false-positive measurement is claimed.

## Cutoff configuration

For each evaluation, record the latest known training cutoff of every participating
hunter, critic and verifier. Use a conservative date when only a month or quarter
is known. Unknown cutoffs cannot support post-cutoff eligibility claims.
Both earliest public disclosure and public fix availability must be later than
the complete participating cutoff. Record source evidence in authorized evaluator
storage, separate from blinded target snapshots.

## Admission requirements

- Establish authorization and review redistribution rights before preparing source.
- Pin vulnerable and fixed snapshots, offline dependencies and synthetic fixtures.
- Independently review the complete fix and run paired sandbox assertions.
- Obtain human confirmation before admitting a case to a frozen denominator.
- Keep case identities, labels and proof solutions outside agent-visible inputs.
- Publish aggregate metrics only with configurations, costs, blockers and limitations.
