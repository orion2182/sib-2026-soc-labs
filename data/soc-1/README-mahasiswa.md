# SOC-1 — paket latihan API account takeover

Paket ini hanya untuk kelompok SOC-1. Semua event, akun, alamat, dan domain
bersifat sintetis.

## Prasyarat

- Windows 10/11, PowerShell 5.1+.
- PHP 8.1+ dengan ekstensi `pdo_sqlite`, `json`, `hash`, `mbstring`.
  XAMPP PHP (`C:\xampp\php\php.exe`) terdeteksi otomatis.
- Tidak perlu SIEM, Docker, Python, atau internet.

## Isi paket

| Path | Fungsi |
| --- | --- |
| `data/train/events.jsonl` | Event latihan berlabel |
| `data/train/labels.json` | Label dan penjelasan rangkaian latihan |
| `data/holdout/events.jsonl` | Event holdout tanpa label |
| `schema.json` | Skema dan sumber |
| `data-dictionary.md` | Arti field dan gap telemetri |
| `student-card.md` | Kasus dan Q1–Q12 |
| `shared/public/` | Viewer lokal |
| `shared/bin/cli.php` | Validasi, evaluasi, freeze |
| `tools/soc.ps1` | Kendali lokal |
| `manifest-sha256.txt` | Checksum paket |

## Menjalankan

```powershell
# Validasi integritas event, label, dan zona waktu
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action validate

# Buka viewer
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action start -Port 8091
# -> http://127.0.0.1:8091/

# Evaluasi aturan pada data latihan
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action evaluate -Rule .\my-rule.json -Split train

# Bekukan aturan sebelum holdout dinilai mentor
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action freeze -Rule .\my-rule.json

# Hentikan viewer
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action stop
```

Evaluasi holdout ditolak pada mesin peserta. Mentor menilai holdout dengan label
privat dan aturan yang sudah dibekukan.

## Unit evaluasi

Metrik dihitung per **event**:

- **TP** — event malicious yang cocok aturan.
- **FP** — event benign yang cocok aturan.
- **FN** — event malicious yang tidak cocok.
- **TN** — event benign yang tidak cocok.

Laporan juga menampilkan cakupan per rangkaian (`sequence_coverage`) agar Anda
melihat apakah rangkaian utuh terdeteksi atau hanya sebagian.

## Alur kerja yang disarankan

1. Baca `data-dictionary.md` dan `student-card.md`.
2. Buka viewer, filter akun/peristiwa, dan catat baseline normal.
3. Tulis hipotesis rangkaian dan aturan awal.
4. Evaluasi pada latihan; periksa TP/FP/FN beserta event ID.
5. Tuning; bandingkan sebelum/sesudah.
6. Tulis triase, severity, tiket eskalasi, dan runbook.
7. Bekukan aturan, lalu serahkan untuk evaluasi holdout oleh mentor.

## Troubleshooting

| Gejala | Tindakan |
| --- | --- |
| `PHP 8.1+ not found` | Pasang XAMPP/PHP atau tambahkan folder `php` ke `PATH`. |
| `running scripts is disabled` | Gunakan `powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 ...`. |
| Port dipakai | Ganti `-Port 8092`. |
| Evaluasi menolak field | Periksa `schema.json`; field tak dikenal tidak dinilai. |
| Holdout ditolak | Itu disengaja; holdout hanya dinilai mentor. |
| Paket ingin diverifikasi | Bandingkan hash dengan `manifest-sha256.txt`. |
