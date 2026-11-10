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

- 55 training events, 32 holdout events, deterministic construction.
- Sources: auth, session, API; explicit source offsets plus normalized UTC.
- Malicious chain, legitimate travel, password retry, scheduled admin, and a
  shared-address false lead.
- Training labels shipped; holdout labels remain in `instructor-private/`
  (gitignored).
- Reference rule: 4-stage chain (`failure → success → object read → token refresh`).
  Training TP=8 FP=0 FN=13 TN=34; holdout TP=7 FP=0 FN=9 TN=16. Repeat run is
  identical.
- Holdout scoring refused without `--instructor`.
- Student package (24 KB) verified standalone: validate, viewer, training
  evaluation all work; no private file is present.

### SOC-2 suspicious endpoint execution (feature 003)

- 25 training and 25 holdout events; endpoint, inventory, and maintenance sources.
- Malicious document-to-PowerShell-to-callback chain, approved helpdesk and
  deployment lookalikes, an orphan process with missing parent telemetry, and PID
  reuse.
- Holdout uses different hosts and a different destination.
- Reference rule: winword → powershell → network by host within 900 s.
  Train and holdout both TP=3 FP=0 FN=2 TN=20; deterministic repeat.
- Student package verified standalone; no instructor files.

### SOC-3 DNS/network beacon (feature 004)

- 26 training and 26 holdout events across DNS, connection, and IDS sources.
- Six near-300-second sync lookups followed by small TLS flows, two corroborating
  alerts, hourly vendor update polling, and an alert without corroborating traffic.
- Holdout uses different hosts, domain, address, and flow ids.
- Reference rule: DNS query containing `sync` followed by a TCP connection by host
  within 60 s. Train and holdout both TP=12 FP=0 FN=2 TN=12; deterministic repeat.
- Student package verified standalone; no instructor files.

## Theme status

All three SOC cases are implemented, tested, and packaged. Detection is
reproducible from event IDs and holdout scoring is mentor-only.

## Not built yet

- Blind pilot and cross-case difficulty calibration.
- Sigma mapping document: the engine uses a documented JSON rule format; a Sigma
  translation note is still required by the shared spec where Sigma fits.
- Per-case mentor answer narratives beyond the reference rule and expected metrics.

## How to verify

```powershell
.\tools\soc.ps1 -Action build
.\tools\soc.ps1 -Action validate
.\tools\soc.ps1 -Action selfcheck
.\tools\soc.ps1 -Action package
```
