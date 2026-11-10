# SOC Labs 2026 — contributor instructions

- Read `.specify/memory/constitution.md` and the active `specs/*/spec.md` before changing implementation.
- This is a public builder workspace, not a student handout. Student packages contain only the assigned case, its data dictionary, training data, student card, and approved tools. Keep holdout labels, ground truth, reference rules, secret seeds, and instructor keys outside this public repository and those packages.
- Build three genuinely different operations: API account takeover, endpoint execution, and DNS/network beacon. Do not create three cosmetic copies of one dataset.
- Use synthetic events and documentation-only addresses/domains. Never collect real campus logs, personal data, credentials, or live network telemetry.
- The required path is replay of static events, rule/query authoring, metric calculation, triage, and escalation. No attack execution or full SIEM installation is required on student laptops.
- Preserve event IDs, source timestamps, UTC offsets, and schema versions. Generated datasets must be deterministic from a recorded seed; labels must be checked against events.
- Freeze a submitted detection version before scoring on instructor-only holdout. Prevent feedback that reveals holdout labels before final evaluation.
- Pilot all three cases on representative 8 GB laptops; the resource limits in specs are design targets until measured.
- The first active feature is `specs/001-replay-evaluation-harness`. Switch `.specify/feature.json` to one `specs/...` path before running Spec Kit skills for another feature.

## OpenCode handoff

- The repository contains specifications, not runnable datasets or scoring tools. Build the replay/evaluation harness first, then SOC-1, SOC-2, and SOC-3. Preserve the 20 November–23 December 2026 calendar and Q1–Q12.
- OpenCode loads this file from the repository root. Use `python3 scripts/select_feature.py --list` and select a feature before the interactive `/speckit.plan`, `/speckit.tasks`, and `/speckit.implement` commands.
- A case is complete only when event/label integrity, normal-noise counterexamples, reproducible metrics, training/holdout separation, package isolation, and a representative-device pilot pass.
