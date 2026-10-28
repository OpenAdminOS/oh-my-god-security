# Scorer arithmetic fixture

These artifacts test scoring with synthetic archived source runs. Their
`findings.json`, proof records, saved commands, drafts and MXC configs pass the
same offline validation as `omgs validate`, including recipe contracts. They do
not claim a real security review or actual target execution. No executable
target or source snapshot is included. Paths and provenance labeled fixture are inert test data. This fixture
is separate from both the excluded examples and the real corpus inventory.

Four positive defects are frozen: a, b, c and d. Defect d's snapshot is blocked in
both runs and stays in the denominator. There is one adjudicated negative unit
on the fixed snapshot. All other confirmations require adjudication.

Hand calculation:

- Run 1 recovers a: 1/4 recall. Run 2 recovers b (through its reviewed alias) and
  c: 2/4 recall. Union: 3/4. Mean: 3/8. Recall range: 1/4; population standard
  deviation: 1/8. Frequencies: a, b and c each 1/2; d 0/2.
- Run 1 has one independently refuted confirmation on the fixed snapshot:
  FP = 1; TP = 1; FDR = 1/2; negative-unit rate = 1/1. Run 2: FP = 0;
  TP = 2; FDR = 0/2; negative-unit rate = 0/1. FP population deviation: 1/2.
- Run 1 submits three true candidate groups, rejects b and leaves c pending:
  rejection = 1/3 and pending = 1/3. Run 2 submits and accepts two: both rates
  0/2. The unrelated confirmed finding in run 1 is listed for adjudication.
- Run 1 host accounting supplies four roles at USD 0.50 each: USD 2. Run 2
  supplies no billing, so cost and campaign total are null. Variance cannot be
  computed over the complete cost distribution. Token input/output splits are
  unknown, even when a combined total is supplied. Proof/tool cost is unknown.
- Wall times: 10.1 and 14.4 seconds. Mean 12.25, range 4.3, population deviation 2.15.

[expected.json](expected.json) records those hand-computed metrics. The golden
integration test compares metric structure and counts exactly, with floating point tolerance
`1e-12 + 1e-12 * abs(expected)` for means, ratios and deviations and separately checks paired
outcomes, blocked snapshots, pending volume and unexpected confirmations.
