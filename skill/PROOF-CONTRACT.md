# Proof contract

Whenever a hunter or verifier uses a proof recipe, the verifier must declare `--expect-marker
BOUNDARY_ASSERTION_FAILED` on `omgs prove`. Require exit 1 and the runner's full-stream
`contract.boundary_marker_seen` and `contract.authorized_control_seen` fields before claiming recipe
proof support. Harnesses read `OMGS_PROOF_NONCE` and `OMGS_PROOF_CONTRACT` from the environment,
then emit `OMGS_CONTROL_<nonce>` after the authorized control and `OMGS_BOUNDARY_<nonce>_<label>`
immediately before assertion exit 1. Require schema `omgs-proof/2` with `contract.kind: "recipe"`;
missing or null contract fields are invalid. Fixed or wrong-nonce markers earn no support. Hostile
code sharing the harness process can read the nonce, so the independent evaluator remains required.
Exit 2 is a harness or usage error and never supports a proof.

