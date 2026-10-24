# Pre v0.1.0: workflow gaps and sandbox hardening

Full plan: four themed PRs, CI first. Each PR gets GPT-6.1-Sol full-diff review rounds plus a
separate Claude evaluator; merge only when both are green and the user says so.

## PR A: pull request CI (`ci/pr-checks`)

- [x] `.github/workflows/ci.yml`: fmt, clippy `-D warnings`, `cargo test` on macos-14 and
      ubuntu-24.04 (bubblewrap installed), checksum-verified actionlint
- [x] PR opened, CI green, reviews green, merged (#6)

## PR B: finding model, verifier separation, ledger, coverage critic (`feat/verifier-ledger-critic`)

- [x] `Finding.locations` (grouped root cause), rendered in MD/HTML/SARIF, validated
- [x] `hunted_by` + `verified_by` required and distinct; `candidates` list on findings;
      `hunter` required in candidates schema
- [x] typed ledger (`src/ledger.rs`), `ledger add/set/list`, evidence + note, transition rules
- [x] `omgs critic --run <dir>`; report renders the critic result
- [x] fixtures, schemas, skill docs, README, usage(), IMPROVEMENTS.md updated
- [x] tests; reviews green; merged (#9, reopened from #7)

## PR C: run orchestration (`feat/run-orchestration`)

- [x] report writes run metadata back and marks the run complete
- [x] hardened `review` clone; `omgs batch init` + `omgs batch index`
- [x] `omgs status` + `omgs watch` (loopback only, two routes, Host check)
- [x] `omgs route` model fallbacks recorded in run metadata
- [x] intent library (`skill/intent/library.json`), `omgs intent list/answer`, `intent_id`
- [x] tests; docs; reviews green; merged (#8)

## PR D: sandbox hardening (`feat/sandbox-hardening`)

Dropped from the 0.1 scope by decision on 2026-10-24. Spike results and the three open residuals are
recorded in IMPROVEMENTS.md under "Deferred past 0.1".

## Acceptance criteria

See the plan: every PR green on fmt/clippy/test in CI on macOS and Ubuntu; each feature's
criteria (grouped locations count once; equal or missing hunter/verifier rejected; critic exits
1 per gap class; batch index deterministic and offline; watch serves only two loopback routes;
route records reroutes; unknown intent id rejected).

Deferred past 0.1 with PR D, so not part of the 0.1 gate: the deny-by-default profile keeping
the Swift fixture behaviour, setsid and posix_spawn survivors killed and reported, and no
`--ro-bind / /`.

## Review

- #6 CI: one GPT-6.1-Sol round, no findings; Claude evaluator pass.
- #9 (was #7) verifier separation, grouped locations, ledger, critic, strict parsing: 13 GPT-6.1-Sol
  rounds. Rounds 1 to 12 found blocking issues that were almost all one class: malformed input
  (missing or misspelled keys, defaulted fields, arrays for objects, null, duplicate keys, enum
  objects, wrong types, dangling links) parsing into a silent pass. That class is now closed at the
  parser (src/shape.rs). Round 13 was clean; a fresh Claude evaluator passed it and its five minor
  items were fixed. GitHub closed #7 when its stacked base branch was deleted, so it merged as #9
  with an identical tree.
- #8 orchestration: 12 GPT-6.1-Sol rounds, hardening containment (symlinks, hardlinks, FIFOs,
  nested links, target-planted answer stores), concurrency (OS file locks, exclusive claims, clone
  races), and strict parsing of every run file. Rounds 11 and 12 had no blocking findings; a fresh
  Claude evaluator passed it and its three items were fixed before merge. The one remaining
  non-blocking item (Markdown intent answers only on pending records) is fixed in the wrap-up PR.
- Lesson recorded in tasks/lessons.md: never default a required field in a security input, and
  sweep every struct on the same input path before asking for re-review.
