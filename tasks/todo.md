# Pre v0.1.0: workflow gaps and sandbox hardening

Full plan: four themed PRs, CI first. Each PR gets GPT-6.1-Sol full-diff review rounds plus a
separate Claude evaluator; merge only when both are green and the user says so.

## PR A: pull request CI (`ci/pr-checks`)

- [x] `.github/workflows/ci.yml`: fmt, clippy `-D warnings`, `cargo test` on macos-14 and
      ubuntu-24.04 (bubblewrap installed), checksum-verified actionlint
- [ ] PR opened, CI green, reviews green, merged

## PR B: finding model, verifier separation, ledger, coverage critic (`feat/verifier-ledger-critic`)

- [ ] `Finding.locations` (grouped root cause), rendered in MD/HTML/SARIF, validated
- [ ] `hunted_by` + `verified_by` required and distinct; `candidates` list on findings;
      `hunter` required in candidates schema
- [ ] typed ledger (`src/ledger.rs`), `ledger add/set/list`, evidence + note, transition rules
- [ ] `omgs critic --run <dir>`; report renders the critic result
- [ ] fixtures, schemas, skill docs, README, usage(), IMPROVEMENTS.md updated
- [ ] tests; reviews green; merged

## PR C: run orchestration (`feat/run-orchestration`)

- [ ] report writes run metadata back and marks the run complete
- [ ] hardened `review` clone; `omgs batch init` + `omgs batch index`
- [ ] `omgs status` + `omgs watch` (loopback only, two routes, Host check)
- [ ] `omgs route` model fallbacks recorded in run metadata
- [ ] intent library (`skill/intent/library.json`), `omgs intent list/answer`, `intent_id`
- [ ] tests; docs; reviews green; merged

## PR D: sandbox hardening (`feat/sandbox-hardening`)

- [ ] spike: `sandbox_check` nonce identification of survivors (fallback: kqueue tracking)
- [ ] deny-by-default Seatbelt with measured allow set, params instead of interpolation,
      setsid/setpgid syscall deny, survivor sweep
- [ ] waitid WNOWAIT peek before group signal
- [ ] narrowed bubblewrap binds, guarded scratch bind, absolute bwrap path; validated on a
      throwaway Lima Ubuntu VM (deleted afterwards) and CI
- [ ] `tests/sandbox.rs` platform-gated; Swift fixture regression
- [ ] IMPROVEMENTS.md residuals closed or restated; reviews green; merged

## Acceptance criteria

See the plan: every PR green on fmt/clippy/test in CI on macOS and Ubuntu; each feature's
criteria (grouped locations count once; equal or missing hunter/verifier rejected; critic exits
1 per gap class; batch index deterministic and offline; watch serves only two loopback routes;
route records reroutes; unknown intent id rejected; deny-by-default profile keeps the Swift
fixture behaviour; setsid and posix_spawn survivors killed and reported; no `--ro-bind / /`).

## Review

(filled per PR)
