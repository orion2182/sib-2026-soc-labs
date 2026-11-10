# Kartu kasus SOC-1 — API account takeover

**Untuk:** kelompok SOC-1 saja. **Kalender:** 20 November–18 Desember 2026.
**Dataset:** `data/train/` (berlabel) dan `data/holdout/` (tanpa label).
**Alat:** viewer lokal `tools\soc.ps1` dan CLI evaluasi. Tidak perlu SIEM.

## Situasi

Tim Anda menjadi analis SOC untuk KampusNusa, organisasi kampus fiktif. Sebuah
layanan API mahasiswa mencatat autentikasi, pembuatan sesi, dan akses objek.
Manajemen meminta deteksi dini pengambilalihan akun (account takeover) tanpa
membanjiri analis dengan alarm dari perjalanan dinas, salah kata sandi, atau
pemeliharaan terjadwal.

## Tujuan

1. Memahami skema, baseline, dan gap telemetri.
2. Menyusun hipotesis rangkaian perilaku, bukan satu IOC.
3. Menulis aturan/query yang dapat diulang dan mengukur TP/FP/FN/TN.
4. Melakukan tuning dengan mempertahankan contoh sah yang mirip ancaman.
5. Menulis triase, severity, tiket eskalasi, dan runbook singkat.
6. Membekukan aturan sebelum mentor mengevaluasi holdout.

## Artefak yang tersedia

| Artefak | Isi |
| --- | --- |
| `data/train/events.jsonl` | Event latihan, satu JSON per baris |
| `data/train/labels.json` | Label event dan penjelasan rangkaian latihan |
| `data/holdout/events.jsonl` | Event holdout tanpa label |
| `schema.json` | Skema field dan sumber |
| `data-dictionary.md` | Arti field, nilai, dan gap |
| `shared/bin/cli.php` | Validasi, evaluasi aturan, pembekuan, paket |
| `shared/public/` | Viewer lokal (cari, filter, buka raw event) |

## Menjalankan

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action start -Port 8091
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action validate
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action evaluate -Rule .\my-rule.json -Split train
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action freeze -Rule .\my-rule.json
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action stop
```

Buka `http://127.0.0.1:8091/`. Holdout tidak berlabel dan tidak dapat dievaluasi
tanpa izin mentor.

## Format aturan

Aturan adalah JSON. Dua bentuk didukung.

**Per-event:**

```json
{
  "name": "contoh-event",
  "where": {
    "all": [
      { "field": "event_type", "op": "eq", "value": "auth.login" },
      { "field": "outcome", "op": "eq", "value": "failure" }
    ]
  }
}
```

**Rangkaian (sequence):**

```json
{
  "name": "contoh-rangkaian",
  "group_by": "account",
  "within_seconds": 3600,
  "stages": [
    { "all": [{ "field": "event_type", "op": "eq", "value": "auth.login" },
              { "field": "outcome", "op": "eq", "value": "failure" }] },
    { "all": [{ "field": "event_type", "op": "eq", "value": "auth.login" },
              { "field": "outcome", "op": "eq", "value": "success" }] },
    { "all": [{ "field": "event_type", "op": "eq", "value": "api.object.read" }] }
  ]
}
```

Operator: `eq`, `ne`, `in`, `contains`, `startswith`, `gt`, `lt`, `exists`.
Field harus ada di `schema.json`; field tak dikenal atau window tidak valid
menghasilkan error validasi, bukan skor parsial.

## Q1–Q12

**Q1.** Sumber log, rentang waktu, field penting, serta gap telemetri apa yang tersedia?

**Q2.** Apa kriteria menaikkan alert menjadi kasus dan kepada siapa kasus diserahkan?
Tulis alasan severity.

**Q3.** Perilaku normal apa yang terlihat untuk akun pada kasus ini? Sertakan event ID.

**Q4.** Rangkaian perilaku apa yang layak dideteksi, dan event apa yang dibutuhkan
agar hipotesisnya dapat diuji?

**Q5.** Tulis satu aturan/query deteksi yang dapat diulang: field, kondisi, window,
dan asumsi skema.

**Q6.** Pada data latihan berlabel, berapa TP, FP, dan FN? Jelaskan dua contoh kesalahan.

**Q7.** Perubahan tuning apa menurunkan noise tanpa membutakan perilaku penting?
Tunjukkan hasil sebelum/sesudah.

**Q8.** Login mana yang menjadi awal rangkaian, bukan sekadar gagal login? Rujuk event ID.

**Q9.** Akses API mana yang memperkuat dugaan pengambilalihan? Jelaskan konteks sesi,
objek, dan waktu.

**Q10.** Apakah perjalanan sah yang mirip tertangkap aturan Anda? Bedakan alamat,
perangkat, cakupan objek, dan jendela waktu.

**Q11.** Dari alert tervalidasi, apa keputusan eskalasi, containment yang
direkomendasikan, dan informasi yang diserahkan ke IR? Bedakan fakta dan dugaan.

**Q12.** Tunjukkan hasil aturan pada holdout (dinilai mentor), batas deteksi yang
tersisa, dan satu perubahan runbook untuk analis berikutnya.

## Bukti yang diserahkan

- Aturan/query final beserta hash (gunakan `-Action freeze`).
- Confusion matrix latihan dan contoh event ID untuk TP/FP/FN.
- Tiga triase: satu insiden, satu false positive, satu kasus belum pasti.
- Tiket eskalasi dan runbook singkat.
- Pernyataan batas: telemetri yang tidak tersedia dan klaim yang tidak dapat dibuat.

## Batas

- Jangan mengakses sistem, akun, atau jaringan nyata.
- Jangan membuka atau menebak label holdout; evaluasi holdout hanya oleh mentor.
- Satu IOC (alamat atau nama proses) tidak cukup untuk bukti penuh.
