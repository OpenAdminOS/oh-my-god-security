# Feature: architecture map of the reviewed target app

A side effect of an OMGS review: emit an architecture map of the TARGET application
(detected stack, components by trust zone, principals, input surfaces, trust
boundaries, data flows, unexamined areas) as ARCHITECTURE.md and a self-contained,
offline ARCHITECTURE.html with a rich auto-laid-out flow graph. Descriptive only;
never changes a verdict.

## Design

- Agent (Map phase) writes `architecture.json` into OUTPUT_DIR per
  `schemas/architecture.schema.json`.
- New deterministic command `omgs architecture --in <architecture.json> --out <dir>`
  renders ARCHITECTURE.md + ARCHITECTURE.html. Rendering is pure/deterministic and
  does not call a model (OMGS invariant).
- The HTML embeds a pre-computed SVG graph laid out in Rust with a deterministic
  layered (Sugiyama-style) algorithm: components are nodes, flows are edges, trust
  zones group/colour nodes; boundary-crossing flows and input-surface nodes are
  highlighted. No external resources, no scripts that fetch.
- `omgs validate` also validates `architecture.json`.
- Skill: RECONNAISSANCE.md / SKILL.md tell the agent to emit architecture.json in
  Map and render it right after recon. README lists the new outputs.

## Layout algorithm (deterministic)

- [ ] Build DAG from flows (from -> to over component ids).
- [ ] Break cycles deterministically (remove back-edges by stable id order).
- [ ] Layer assignment by longest-path from sources (entry points / untrusted zone).
- [ ] Within-layer ordering: barycenter heuristic, fixed iteration count, ties
      broken by component id, so output is byte-stable.
- [ ] Coordinate assignment: fixed box size from label, fixed gaps; zones shown as
      background bands or node accent colour.
- [ ] Edge routing: smooth curves; boundary-crossing edges styled; arrowheads.
- [ ] Emit SVG string (no randomness, no timestamps).

## Tasks

- [x] schemas/architecture.schema.json
- [ ] sample fixture architecture.json (for tests/examples)
- [ ] src/arch.rs: model structs (serde), loader, deterministic layout, MD + HTML render
- [ ] wire `omgs architecture` into main.rs (match existing subcommand pattern)
- [ ] extend `omgs validate` to accept architecture.json
- [ ] tests/core.rs: schema-valid fixture renders; HTML has zero external URLs;
      byte-deterministic across two renders; validate accepts/rejects
- [ ] skill/RECONNAISSANCE.md + skill/SKILL.md: emit + render the map in Map
- [ ] README outputs list mentions ARCHITECTURE.html/.md
- [ ] cargo fmt + cargo test green; actionlint n/a

## Acceptance criteria

- `schemas/architecture.schema.json` is valid JSON Schema; the sample fixture validates.
- `omgs architecture --in fixture --out dir` writes ARCHITECTURE.md and ARCHITECTURE.html.
- ARCHITECTURE.html contains the SVG graph, makes zero external requests (no http/https),
  and is byte-identical across two renders of the same input.
- `omgs validate` accepts a valid architecture.json and rejects an invalid one.
- `cargo test` green including the new tests; existing REPORT tests still pass.
- Docs updated; no em/en dashes; commits without self-mention.
- Branch only; GPT-6.1-Sol review + separate Claude evaluator before any merge; do
  not push to main unless the user says so.

## Review

Implemented on branch feat/architecture-map:
- schemas/architecture.schema.json; examples/architecture.sample.json.
- src/architecture.rs: lenient serde model, validate_architecture, deterministic
  integer-coordinate layered layout, Markdown + self-contained HTML renderers,
  from_json helper. Wired `omgs architecture --in --out` in main.rs; audit now
  seeds architecture.json (replacing the lowercase architecture.md placeholder,
  which avoided a macOS case collision with ARCHITECTURE.md).
- tests/core.rs: 6 new tests (validate accept/reject, determinism, no external
  requests with exactly one trusted <svg>, hostile-field escaping, minimal map
  skips empty sections, lenient from_json). cargo test green (23), clippy clean,
  release builds.
- Docs: SKILL.md (Map + Report), RECONNAISSANCE.md (new section), README.
- Verified render byte-identical across runs, zero external refs; previewed the
  diagram visually (zone columns, boundary-crossing arrows, attack-surface marks).

Acceptance criteria met. Pending: GPT-6.1-Sol review + separate Claude evaluator
before merge; do not push to main unless the user says so.
