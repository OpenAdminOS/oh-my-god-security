# Corpus research inventory

Research date: 2026-10-28. This directory contains metadata only. No upstream
repository was cloned, built, installed or executed. Full vulnerable and fixed
SHAs in [inventory.json](inventory.json) were resolved independently with the
GitHub commits API. Each vulnerable SHA is the first parent of its fixing commit.
License and stack evidence was read with the contents API at that vulnerable SHA.
No upstream code, patches, advisory text or dependencies are redistributed.

## Cutoff configuration

These are the participating configurations requested for hunting, criticism and
verification. A campaign must freeze exact configurations and roles before use.

| Configuration | Published cutoff | Source | Treatment |
| --- | --- | --- | --- |
| Claude Opus 5.5 | June 2026 | [Official model comparison](https://platform.claude.com/docs/en/models/overview) lists both training data and reliable knowledge cutoffs | Conservatively use 2026-06-30, the last day of the published month |
| GPT-6.1-Sol | April 30, 2026 | [Official model page](https://developers.openai.com/api/docs/models/gpt-6.1-sol) | Use 2026-04-30 |
| Muse Wonder 1.0 | Unknown | [Publisher overview](https://ai.meta.com/tools/muse/) and [publisher developer overview](https://ai.meta.com/llama) | No training or knowledge cutoff found in the available publisher material. Direct overview retrieval also redirected to a login page. A release date cannot substitute for a cutoff |

The latest **known** cutoff is 2026-06-30. The complete configuration cutoff is
**unknown**. Accordingly, zero cases qualify for a post-cutoff claim for this
configuration, regardless of the number of later advisories. This is a research
gap, not evidence that five suitable vulnerabilities do not exist.

## Located pairs and admission gap

| Case | Advisory | Earliest located public disclosure | Public fix available by | Cohort |
| --- | --- | --- | --- | --- |
| Survey custom head script permission bypass | [CVE-2026-105090](https://nvd.nist.gov/vuln/detail/CVE-2026-105090) | 2026-09-29, [public fix PR](https://github.com/formbricks/formbricks/pull/9432) | 2026-09-29, same PR merge | cutoff_unknown |
| Survey response oracle and PIN rate limits | [CVE-2026-14792](https://nvd.nist.gov/vuln/detail/CVE-2026-14792) | 2026-05-21, [public fix PR](https://github.com/formbricks/formbricks/pull/8094) | 2026-05-27, same PR merge | earlier_public_fix |

Both pairs use TypeScript, Next.js App Router and Postgres. All versions of this
repository remain in the same development family. The second advisory's July
publication does not make its May public security fix post-cutoff. For the first,
the researcher's October article is later than the public September PR. Private
report dates are not public disclosure dates. PR creation/merge timestamps are
the earliest located public evidence, not a guarantee that no earlier public
material exists. Commit timestamps alone cannot establish publication time.

The admission gap is **5 eligible cases**, with **2 unadmitted metadata pairs**.
The inventory is deliberately a distinct format, `omgs-corpus-inventory/1`, not a
runnable case manifest. Human confirmation, complete-fix review, local fixture
paths, synthetic setup, dependency digests, proof tests and fingerprints remain
null. The benchmark case format does not allow missing preparation to become
scorable truth. Prepare those fields at campaign time, run the paired assertions
only through `omgs prove`, obtain independent human confirmation, and then create
a fully populated case manifest outside blinded targets. No fingerprints are
invented here. Public upstream test descriptions are not locally verified proof.

## Search record and excluded leads

Searches covered GitHub Security Advisories, OSV and NVD, plus upstream public
fix PRs and commits. Queries included:

```text
site:github.com/advisories Next.js Supabase "2026" "Jul"
site:github.com/advisories "Next.js" "PostgreSQL" "2026"
site:github.com/advisories "TypeScript" "PostgreSQL" "2026"
site:github.com/advisories "Supabase" after:2026-06-30
site:github.com/advisories "Formbricks" "2026" "patch"
site:github.com/advisories "Formbricks" "2026" "August"
site:github.com/advisories "Formbricks" "2026" "Sep"
site:osv.dev/vulnerability Formbricks
site:nvd.nist.gov/vuln/detail "Formbricks" "2026"
site:github.com/advisories "cal.com" "2026" "Jul"
site:github.com/advisories "cal.diy" "2026" "authorization"
site:github.com/advisories "documenso" "2026"
site:github.com/advisories "papermark" "2026"
site:github.com/advisories "docmost" "2026"
```

The GitHub API queries included `repos/formbricks/formbricks/security-advisories`,
`repos/supabase/storage/security-advisories`, and the first 100 reviewed npm
advisories published after 2026-06-30. This is a bounded search, not an exhaustive
registry census. OSV records checked included
[CVE-2026-105090](https://osv.dev/vulnerability/CVE-2026-105090) and
[CVE-2025-59934](https://osv.dev/vulnerability/CVE-2025-59934).

| Excluded lead | Reason |
| --- | --- |
| [GHSA-7229-q9pv-j6p4](https://github.com/formbricks/formbricks/security/advisories/GHSA-7229-q9pv-j6p4) | Public in September 2025, before the known cutoff |
| [CVE-2025-71389](https://github.com/advisories/GHSA-8449-9vw6-7mp5) | July 2026 registry entry refers to an already public December 2025 upstream issue |
| [Documenso issue 3112](https://github.com/documenso/documenso/issues/3112) | Public access-control lead, but fix and current Next.js scope not established; not an admitted fix pair |
| [Cal.diy issue 29802](https://github.com/calcom/cal.diy/issues/29802) | Open authorization lead, no verified fix pair |
| [GHSA-8rrf-w776-x75g](https://github.com/supabase/storage/security/advisories/GHSA-8rrf-w776-x75g), [GHSA-67rp-h2mf-ph72](https://github.com/supabase/storage/security/advisories/GHSA-67rp-h2mf-ph72) | Storage backend advisories, no Next.js App Router target established |
| [GHSA-p9j2-gv94-2wf4](https://github.com/advisories/GHSA-p9j2-gv94-2wf4), [GHSA-h694-7cp9-m8p3](https://github.com/advisories/GHSA-h694-7cp9-m8p3) | Framework fixes, no paired Postgres/Supabase application established |
| [GHSA-4jqv-mc3x-m676](https://github.com/advisories/GHSA-4jqv-mc3x-m676) | Pages Router advisory, outside App Router scope |

These leads are not padding for the five-case requirement. No eligible corpus,
held-out benchmark result or successful vulnerable/fixed proof is claimed.
