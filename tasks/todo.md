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
- [x] src/architecture.rs: model structs (serde), loader, deterministic layout, MD + HTML render
- [x] wire `omgs architecture` into main.rs (match existing subcommand pattern)
- [x] validation runs inside `omgs architecture` (invalid -> `invalid:` lines + exit 1);
      `omgs validate` itself is unchanged (findings only)
- [x] tests/core.rs: schema-valid fixture renders; HTML has zero external URLs;
      byte-deterministic across two renders; validate accepts/rejects; hostile escaping
- [x] skill/RECONNAISSANCE.md + skill/SKILL.md: emit + render the map in Map
- [x] README outputs list mentions ARCHITECTURE.html/.md
- [x] cargo fmt + cargo test green; clippy clean

## Acceptance criteria

- `skill/schemas/architecture.schema.json` is valid JSON Schema; the sample fixture validates.
- `omgs architecture --in fixture --out dir` writes ARCHITECTURE.md and ARCHITECTURE.html;
  invalid input prints `invalid:` lines and exits 1.
- ARCHITECTURE.html contains the SVG graph, makes zero external requests (no http/https),
  and is byte-identical across two renders of the same input.
- `cargo test` green including the new tests; existing REPORT tests still pass.
- Docs updated; no em/en dashes; commits without self-mention.
- Branch only; GPT-6.1-Sol review + separate Claude evaluator before any merge; do
  not push to main unless the user says so.

## Review

Implemented on branch feat/architecture-map (schema lives at
skill/schemas/architecture.schema.json so the installed skill can reach it):
- src/architecture.rs: lenient serde model, validate_architecture, deterministic
  integer-coordinate layered layout, Markdown + self-contained HTML renderers,
  from_json helper. Wired `omgs architecture --in --out` in main.rs; audit now
  seeds architecture.json (replacing the lowercase architecture.md placeholder,
  which avoided a macOS case collision with ARCHITECTURE.md).
- examples/architecture.sample.json.
- tests/core.rs: architecture tests covering validate accept/reject and structural
  gaps, determinism, no-external-request (exactly one trusted <svg>), hostile-field
  and markdown-link escaping, offline byte-contract, notes/principals in HTML,
  minimal maps, wide/uppercased label clamping, single-column gutter, sample
  fixture validity, and cyclic-flow rendering.
- Docs: SKILL.md (Map + Report), RECONNAISSANCE.md (new section with the exact
  keys), README.

Review rounds: 4 GPT-6.1-Sol rounds converged to zero findings; a separate Claude
evaluator then caught an undefined `--blue` CSS var (first-zone accent rendered
black) and a schema link that dangled after skill install, both fixed here, plus
code-span source sanitisation, lanes moved clear of zone headers, and extra tests.
cargo test green (32), clippy clean, output byte-stable. Do not push to main
unless the user says so.
