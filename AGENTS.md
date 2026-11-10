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

- Tiga kasus dan harness replay/evaluasi sudah diimplementasikan. Lihat `docs/BUILD-STATUS.md`, `docs/WINDOWS-SETUP.md`, dan `docs/PILOT-BLIND-2026-11-10.md`; lanjutkan pilot buta manusia dan pemeriksaan rilis. Pertahankan kalender 20 November–23 Desember 2026 dan Q1–Q12.
- OpenCode membaca file ini dari root repo. Pada Windows tanpa Python, gunakan `.\scripts\select-feature.ps1 --list` dan pilih fitur sebelum perintah Spec Kit interaktif. `scripts/select_feature.py` hanya alternatif.
- Perubahan kasus harus menjaga integritas event/label, noise normal, metrik reproduktif, pemisahan holdout, isolasi paket, dan pilot pada perangkat perwakilan.
