# Kartu kasus SOC-3 - Beacon DNS dan jaringan

**Untuk:** kelompok SOC-3 saja. **Dataset:** `train/` (berlabel) dan
`holdout/` (tanpa label). **Kalender:** 20 November-18 Desember 2026.

## Situasi

Tim Anda menjadi analis SOC untuk KampusNusa. Sensor Zeek mencatat DNS dan
ringkasan koneksi; Suricata mencatat alert. Sebagian host menjalankan pembaruan
terjadwal yang juga periodik. Manajemen meminta penilaian apakah pola periodik
menunjukkan beacon, tanpa menganggap setiap alert sebagai insiden.

## Tujuan

1. Memahami skema DNS/conn/IDS dan gap antar-sensor.
2. Mengukur interval dan pola domain, bukan satu IOC.
3. Mengorelasikan DNS, koneksi, dan alert berdasarkan host/waktu/flow.
4. Memisahkan polling update sah dari beacon.
5. Menulis triase, severity, tiket eskalasi, dan runbook.
6. Membekukan aturan sebelum holdout dinilai mentor.

## Artefak

| Artefak | Isi |
| --- | --- |
| `train/events.jsonl` | Event latihan berlabel |
| `train/labels.json` | Label dan penjelasan |
| `holdout/events.jsonl` | Holdout tanpa label |
| `schema.json` | Skema |
| `data-dictionary.md` | Field dan gap |
| `shared/public/` | Viewer lokal |
| `tools/soc.ps1` | Validasi, evaluasi, freeze |

## Menjalankan

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action start -Port 8091
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action validate -Case soc-3
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action evaluate -Case soc-3 -Rule .\my-rule.json -Split train
powershell -ExecutionPolicy Bypass -File .\tools\soc.ps1 -Action freeze -Case soc-3 -Rule .\my-rule.json
```

## Format aturan

Aturan adalah JSON. Bentuk event-level:

```json
{"name":"x","where":{"all":[{"field":"event_type","op":"eq","value":"dns.query"}]}}
```

Bentuk rangkaian:

```json
{"name":"y","group_by":"host","within_seconds":60,
 "stages":[{ "all":[...] },{ "all":[...] }]}
```

Operator: `eq`, `ne`, `in`, `contains`, `startswith`, `gt`, `lt`, `exists`.
Field harus ada di `schema.json`.

Batasan engine: tidak ada aritmetika interval, OR, atau join antar-field. Untuk
Q8, hitung selisih `event_time_utc` secara manual; aturan hanya menyatakan urutan
dan window. Rangkaian yang lebih panjang dari stage akan menyisakan event sebagai
FN; itu batas alat, bukan bukti deteksi gagal.

## Q1-Q12

**Q1.** Sumber log, rentang waktu, field penting, dan gap telemetri?

**Q2.** Kriteria eskalasi dan penerima kasus; alasan severity.

**Q3.** Perilaku normal apa yang terlihat pada DNS/koneksi? Sertakan event ID.

**Q4.** Pola apa yang layak dideteksi dan event apa yang dibutuhkan?

**Q5.** Tulis aturan/query: field, kondisi, window, asumsi skema.

**Q6.** Berapa TP, FP, FN pada latihan? Jelaskan dua contoh kesalahan.

**Q7.** Tuning apa menurunkan noise tanpa membutakan pola penting?

**Q8.** Pola waktu/domain apa yang membedakan beacon dari update berkala?
Sertakan interval terukur dan event ID.

**Q9.** Event Zeek dan Suricata mana yang saling mendukung? Tunjukkan flow/time.

**Q10.** Pola layanan sah apa yang paling berisiko menjadi false positive, dan
field konteks apa yang memisahkannya?

**Q11.** Keputusan eskalasi, containment yang direkomendasikan, dan informasi
untuk IR; bedakan fakta dan dugaan.

**Q12.** Hasil holdout (dinilai mentor), batas deteksi, dan satu perubahan runbook.

## Bukti yang diserahkan

- Aturan/query final dan hash freeze.
- Confusion matrix latihan dengan event ID.
- Perhitungan interval (mis. selisih waktu antar-query) dan tabel korelasi.
- Tiga triase: satu beacon, satu polling sah, satu alert tanpa dukungan.
- Tiket eskalasi dan runbook.
- Pernyataan batas: sensor yang hilang dan klaim yang tidak dapat dibuat.

## Batas

- Jangan melakukan replay paket atau menghubungi domain/alamat apa pun.
- Jangan menebak label holdout.
- Severity alert IDS saja bukan bukti beacon.
