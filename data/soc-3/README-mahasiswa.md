# SOC-3 - paket latihan beacon DNS/jaringan

Paket ini hanya untuk kelompok SOC-3. Semua host, domain, alamat, dan flow
bersifat sintetis. Tidak ada replay paket atau koneksi keluar.

## Prasyarat

- Windows 10/11, PowerShell 5.1+.
- PHP 8.1+ (`json`, `hash`, `mbstring`, `session`). XAMPP terdeteksi otomatis.
- Tidak perlu SIEM, Docker, Python, atau internet.

## Isi paket

| Path | Fungsi |
| --- | --- |
| `train/events.jsonl` | Event latihan berlabel |
| `train/labels.json` | Label dan penjelasan |
| `holdout/events.jsonl` | Holdout tanpa label |
| `schema.json` | Skema |
| `data-dictionary.md` | Field dan gap |
| `student-card.md` | Kasus dan Q1-Q12 |
| `tools/soc.ps1` | Kendali lokal |

## Menjalankan

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action start -Port 8091
# http://127.0.0.1:8091/?case=soc-3&split=train

powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action validate -Case soc-3
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action evaluate -Case soc-3 -Rule .\my-rule.json -Split train
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action freeze -Case soc-3 -Rule .\my-rule.json
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action stop
```

Holdout hanya dinilai mentor dan ditolak pada mesin peserta.

## Satuan evaluasi

Metrik per event: TP/FP/FN/TN, ditambah cakupan per rangkaian. Hitung interval
antar-query dari `event_time_utc`, bukan dari urutan baris.

## Troubleshooting

| Gejala | Tindakan |
| --- | --- |
| `PHP 8.1+ not found` | Pasang XAMPP/PHP atau tambahkan ke `PATH`. |
| Port dipakai | Ganti `-Port 8092`. |
| Field ditolak | Periksa `schema.json`. |
| Holdout ditolak | Disengaja; hanya mentor. |
| Paket ingin diverifikasi | Bandingkan hash dengan `manifest-sha256.txt`. |
