# Build status — SOC labs

Updated 2026-11-10.

## Implemented and verified

### Shared harness (`shared/`)

- `lib/soc.php`: JSONL loading, schema/field validation, time-zone checks,
  label referential integrity, a small event/sequence rule engine, event-level
  TP/FP/FN/TN, sequence coverage, manifests.
- `bin/cli.php`: `generate`, `validate`, `evaluate`, `freeze`, `package`,
  `selfcheck`.
- `public/`: local viewer with case/split tabs, filters, raw event detail, and
  `/healthz`. Binds to `127.0.0.1`.
- `tools/soc.ps1`: build, validate, selfcheck, evaluate, freeze, package,
  start/stop/health.
- Python is not required.

### SOC-1 API account takeover (feature 002)

- 49 training events, 27 holdout events, deterministic construction.
- Sources: auth, session, API; explicit source offsets plus normalized UTC.
- Malicious chain, legitimate travel, password retry, scheduled admin, and a
  shared-address false lead.
- Training labels shipped; holdout labels remain in `instructor-private/`
  (gitignored).
- Reference rule: 4-stage chain (`failure → success → object read → token refresh`).
  Training TP=8 FP=0 FN=13 TN=28; holdout TP=7 FP=0 FN=9 TN=11. Repeat run is
  identical.
- Holdout scoring refused without `--instructor`.
- Student package (24 KB) verified standalone: validate, viewer, training
  evaluation all work; no private file is present.

### SOC-2 suspicious endpoint execution (feature 003)

- 24 training and 24 holdout events; endpoint, inventory, and maintenance sources.
- Malicious document-to-PowerShell-to-callback chain, approved helpdesk and
  deployment lookalikes, an orphan process with missing parent telemetry, and PID
  reuse.
- Holdout uses different hosts and a different destination.
- Reference rule: winword → powershell → network by host within 900 s.
  Train and holdout both TP=3 FP=0 FN=2 TN=19; deterministic repeat.
- Student package verified standalone; no instructor files.

## Not built yet

- SOC-3 DNS/network beacon (feature 004): Zeek/Suricata-style records, interval
  analysis, holdout, reference rule, package.
- Blind pilot and cross-case difficulty calibration.
- Sigma mapping document: the engine uses a documented JSON rule format; a Sigma
  translation note is still required by the shared spec where Sigma fits.

## How to verify

```powershell
.\tools\soc.ps1 -Action build
.\tools\soc.ps1 -Action validate
.\tools\soc.ps1 -Action selfcheck
.\tools\soc.ps1 -Action package
```
