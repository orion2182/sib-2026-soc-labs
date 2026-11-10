# SOC Labs 2026 — Spec Kit workspace

Instructor-only builder workspace for **three distinct SOC final-project cases**: API account takeover, suspicious endpoint execution, and DNS/network beaconing. Spec Kit 1.2.3 with Codex skills is installed locally. **The datasets, replay tool, and rules have not been implemented yet.**

| Path | Role |
| --- | --- |
| `.specify/memory/constitution.md` | Shared build and release rules |
| `specs/001-replay-evaluation-harness/spec.md` | Schema, replay/query, metrics, holdout, packaging |
| `specs/002-api-account-takeover/spec.md` | SOC-1 case contract |
| `specs/003-endpoint-execution/spec.md` | SOC-2 case contract |
| `specs/004-dns-network-beacon/spec.md` | SOC-3 case contract |
| `docs/reference/Riset-Lab-SOC-2026.md` | Frozen research/planning source; not a student handout |
| `shared/`, `cases/` | Reserved implementation locations |

## Continue with Spec Kit

Open Codex from this directory. The Spec Kit commands are **Codex skills, not shell commands**. Run for the active feature:

1. `$speckit-plan` — select implementation architecture and data format against its spec.
2. `$speckit-checklist` — review requirement completeness.
3. `$speckit-tasks` — create ordered implementation tasks.
4. `$speckit-analyze` — check spec, plan, and task consistency.
5. `$speckit-implement` — build the feature.
6. `$speckit-converge` — close remaining gaps.

The initial active feature is the replay/evaluation harness. For another case, change `.specify/feature.json` to `{"feature_directory":"specs/002-api-account-takeover"}` (or the corresponding `003`/`004` directory) and repeat. That pointer is local, ignored by Git. Work in this order: harness, SOC-1, SOC-2, SOC-3, then blind pilot and rebalance. Do not rerun `$speckit-specify` for these existing feature specs unless changing their scope intentionally.

## Release gate

Each case needs a schema, labeled training set, unlabeled student holdout, private holdout labels, reference rule, normal-noise counterexamples, answer key, and student card covering Q1–Q12. Freeze the candidate rule before holdout scoring. Verify event/label consistency, reproducible metrics, package separation, no personal data or active callback, and usability on representative laptops before distributing anything.
