# Windows setup — SOC labs (no Python required)

## Prerequisites

- Windows 10/11 with PowerShell 5.1+.
- PHP 8.1+ with `json`, `hash`, `mbstring`, `session`. XAMPP PHP
  (`C:\xampp\php\php.exe`) is detected automatically.
- Optional: Git for Windows to clone the repository.

Python, Docker, a SIEM, and internet access are not required.

## Commands

```powershell
cd soc-labs

# Regenerate, validate, and run the reference self-check
.\tools\soc.ps1 -Action build

# Validate only
.\tools\soc.ps1 -Action validate

# Start the viewer at http://127.0.0.1:8091/
.\tools\soc.ps1 -Action start -Port 8091

# Evaluate your rule on training data
.\tools\soc.ps1 -Action evaluate -Rule .\my-rule.json -Split train

# Freeze the rule before mentor holdout scoring
.\tools\soc.ps1 -Action freeze -Rule .\my-rule.json

# Stop the viewer
.\tools\soc.ps1 -Action stop
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `PHP 8.1+ not found` | Add `C:\xampp\php` to `PATH` or install PHP. |
| `running scripts is disabled` | Use `powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 ...`. |
| Port occupied | Use `-Port 8092`. |
| Unknown field error | Check `data/soc-1/schema.json`; undeclared fields are rejected. |
| Holdout refused | Intended. Only a mentor machine may add `--instructor`. |

## Measured footprint (2026-11-10)

- SOC-1 dataset: 76 events total, well under 100 KB.
- Viewer: PHP built-in server, ~22 MB working set in the VAPT pilot on the same
  host; the SOC viewer uses the same runtime model.
- Host used for the check: Windows 11, 7.8 GB RAM, PHP 8.2.4.
