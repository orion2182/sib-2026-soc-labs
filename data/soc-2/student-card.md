# Kartu kasus SOC-2 - Eksekusi endpoint mencurigakan

**Untuk:** kelompok SOC-2 saja. **Dataset:** `train/` (berlabel) dan
`holdout/` (tanpa label). **Kalender:** 20 November-18 Desember 2026.

## Situasi

Tim Anda menjadi analis SOC untuk KampusNusa. EDR pada workstation mencatat
pembuatan proses, blok script, file, dan koneksi keluar. Tim IT juga menjalankan
deployment helpdesk terjadwal. Manajemen meminta deteksi rangkaian eksekusi
mencurigakan tanpa memblokir pekerjaan IT yang sah.

## Tujuan

1. Memetakan baseline proses normal dan inventaris host.
2. Menyusun hipotesis rangkaian parent-child dan aktivitas lanjutan.
3. Menulis aturan yang tahan terhadap PID reuse dan telemetri induk yang hilang.
4. Mengukur TP/FP/FN/TN dan melakukan tuning.
5. Menulis triase, severity, tiket eskalasi, dan runbook.
6. Membekukan aturan sebelum mentor mengevaluasi holdout.

## Artefak

| Artefak | Isi |
| --- | --- |
| `train/events.jsonl` | Event latihan berlabel |
| `train/labels.json` | Label dan penjelasan rangkaian |
| `holdout/events.jsonl` | Holdout tanpa label |
| `schema.json` | Skema field |
| `data-dictionary.md` | Arti field dan gap |
| `shared/public/` | Viewer lokal |
| `tools/soc.ps1` | Validasi, evaluasi, freeze |

## Menjalankan

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action start -Port 8091
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action validate -Case soc-2
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action evaluate -Case soc-2 -Rule .\my-rule.json -Split train
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action freeze -Case soc-2 -Rule .\my-rule.json
```

## Format aturan

Aturan adalah JSON. Bentuk event-level:

```json
{"name":"x","where":{"all":[{"field":"event_type","op":"eq","value":"process.create"}]}}
```

Bentuk rangkaian:

```json
{"name":"y","group_by":"host","within_seconds":900,
 "stages":[{ "all":[...] },{ "all":[...] }]}
```

Operator: `eq`, `ne`, `in`, `contains`, `startswith`, `gt`, `lt`, `exists`.
Field harus ada di `schema.json`.

Batasan engine: satu event dicocokkan per stage, `group_by` hanya satu field,
tidak ada OR, aritmetika interval, atau join antar-field. Rangkaian yang lebih
panjang dari stage akan menyisakan event sebagai FN; itu batas alat, bukan bukti
deteksi gagal. Anda boleh memakai aturan event-level bila itu lebih tepat.

## Q1-Q12

**Q1.** Sumber log, rentang waktu, field penting, dan gap telemetri?

**Q2.** Kriteria eskalasi dan penerima kasus; alasan severity.

**Q3.** Perilaku normal apa yang terlihat untuk host/akun? Sertakan event ID.

**Q4.** Rangkaian apa yang layak dideteksi dan event apa yang dibutuhkan?

**Q5.** Tulis aturan/query: field, kondisi, window, asumsi skema.

**Q6.** Berapa TP, FP, FN pada data latihan? Jelaskan dua contoh kesalahan.

**Q7.** Tuning apa menurunkan noise tanpa membutakan perilaku penting?

**Q8.** Parent-child process mana paling kuat menunjukkan penyimpangan? Rujuk
`process_guid`, `parent_guid`, host, dan waktu.

**Q9.** Host dan akun mana perlu eskalasi segera? Jelaskan bukti lanjutan.

**Q10.** Bagaimana Anda mengecualikan script helpdesk/deployment yang sah?
Sebut field konteks yang dipakai.

**Q11.** Keputusan eskalasi, containment yang direkomendasikan, dan informasi
untuk IR; bedakan fakta dan dugaan.

**Q12.** Hasil holdout (dinilai mentor), batas deteksi, dan satu perubahan runbook.

## Bukti yang diserahkan

- Aturan/query final dan hash freeze.
- Confusion matrix latihan dengan event ID contoh.
- Tiga triase: satu insiden, satu false positive (helpdesk), satu kasus belum pasti
  (mis. parent hilang).
- Tiket eskalasi dan runbook.
- Pernyataan batas telemetri.

## Batas

- Jangan mengeksekusi script atau menghubungi alamat apa pun.
- Jangan menebak label holdout.
- Nama proses tunggal atau PID tunggal bukan bukti penuh.
