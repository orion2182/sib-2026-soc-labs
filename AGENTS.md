# SOC Labs 2026 — contributor instructions

- Read `.specify/memory/constitution.md` and the active `specs/*/spec.md` before changing implementation.
- This is an instructor-only builder workspace. Student packages contain only the assigned case, its data dictionary, training data, student card, and approved tools. Keep holdout labels, ground truth, reference rules, and instructor keys outside those packages.
- Build three genuinely different operations: API account takeover, endpoint execution, and DNS/network beacon. Do not create three cosmetic copies of one dataset.
- Use synthetic events and documentation-only addresses/domains. Never collect real campus logs, personal data, credentials, or live network telemetry.
- The required path is replay of static events, rule/query authoring, metric calculation, triage, and escalation. No attack execution or full SIEM installation is required on student laptops.
- Preserve event IDs, source timestamps, UTC offsets, and schema versions. Generated datasets must be deterministic from a recorded seed; labels must be checked against events.
- Freeze a submitted detection version before scoring on instructor-only holdout. Prevent feedback that reveals holdout labels before final evaluation.
- Pilot all three cases on representative 8 GB laptops; the resource limits in specs are design targets until measured.
- The first active feature is `specs/001-replay-evaluation-harness`. Switch `.specify/feature.json` to one `specs/...` path before running Spec Kit skills for another feature.
