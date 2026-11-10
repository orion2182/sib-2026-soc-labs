# SOC Labs 2026 — workspace pembangunan deteksi

Repository publik ini menyiapkan lab **SOC/detection engineering untuk 3 kelompok SIB**. Setiap kelompok menerima operasi berbeda dan harus membangun hipotesis, menulis aturan/query, menghitung metrik, men-tune noise, melakukan triase, serta menentukan eskalasi. Kalender: 20 November–23 Desember 2026. Riset pedagogis lengkap berada di `docs/reference/Riset-Lab-SOC-2026.md` dan [repo perencanaan](https://github.com/orion2182/sib-2026-cybersecurity-final-project).

**Status per 10 November 2026:** 3 dataset SOC, viewer, rule engine, evaluator, dan paket peserta telah dibangun dan diuji; dry pilot berbantuan agen sudah dilakukan. Pilot buta manusia dan pemeriksaan rilis masih diperlukan. Lihat `docs/BUILD-STATUS.md` dan `../README-TRANSFER.md` pada salinan lengkap.

## Tiga kasus yang tersedia

| Kasus | Sumber bukti sintetis | Keputusan inti | Noise yang wajib ada |
| --- | --- | --- | --- |
| SOC-1 — Account takeover API | Log autentikasi, sesi, dan audit API | Korelasikan login, perubahan sesi, dan akses objek; tentukan severity | Perjalanan sah, retry login, admin terjadwal |
| SOC-2 — Eksekusi endpoint | Event Windows/Sysmon dalam JSON inert dan inventaris host | Rekonstruksi rantai parent-child process, pilih host/akun untuk eskalasi | Script helpdesk dan deployment IT sah |
| SOC-3 — Beacon DNS/jaringan | Zeek DNS/conn dan Suricata EVE sintetis | Ukur pola periodik dan korelasi lintas sensor | Update otomatis dan polling layanan sah |

Tiap kasus harus memiliki skema, dataset latihan berlabel, holdout tanpa label untuk mahasiswa, label holdout privat mentor, contoh normal, aturan referensi, serta kunci penjelasan berbasis event ID. Kunci dan label privat **tidak boleh di-commit ke repo publik**. Mahasiswa mengerjakan Q1–Q12 dengan raw event, metrik TP/FP/FN/TN, contoh triase, tiket eskalasi, dan runbook. Deteksi satu IOC tanpa konteks tidak cukup.

## Peta file untuk OpenCode

| File/direktori | Fungsi |
| --- | --- |
| `AGENTS.md` | Instruksi proyek otomatis untuk OpenCode |
| `.specify/memory/constitution.md` | Aturan desain, bukti, keselamatan, dan rilis |
| `specs/001-replay-evaluation-harness/spec.md` | Kontrak schema, replay/query, evaluasi, freeze, dan packaging |
| `specs/002-api-account-takeover/spec.md` | Kontrak SOC-1 |
| `specs/003-endpoint-execution/spec.md` | Kontrak SOC-2 |
| `specs/004-dns-network-beacon/spec.md` | Kontrak SOC-3 |
| `docs/reference/Riset-Lab-SOC-2026.md` | Task mahasiswa, rubrik, timeline, dan sumber riset |
| `shared/`, `data/`, `tools/` | Engine, dataset, dan alat yang sudah dibangun |
| `.opencode/commands/` | Perintah Spec Kit untuk OpenCode |
| `scripts/select-feature.ps1` | Pemilih fitur di Windows tanpa Python; `scripts/select_feature.py` opsional |

## Menjalankan dan mengembangkan di Windows

Salinan lengkap dari flashdisk memiliki `README-TRANSFER.md` di direktori induk. Jalankan lab dari disk lokal Windows dengan PowerShell 5.1+ dan PHP 8.1+; **Python dan Docker tidak diperlukan** untuk implementasi sekarang. Instruksi menjalankan, menguji, dan mengemas kasus ada di `docs/WINDOWS-SETUP.md` dan `docs/BUILD-STATUS.md`.

Untuk perubahan spesifikasi di OpenCode, jalankan dari root repo ini:

```powershell
.\scripts\select-feature.ps1 --list
.\scripts\select-feature.ps1 002-api-account-takeover
opencode
```

Perintah `/speckit.plan`, `/speckit.checklist`, `/speckit.tasks`, `/speckit.analyze`, `/speckit.implement`, dan `/speckit.converge` dipakai **di chat OpenCode** ketika mengubah fitur, bukan untuk menjalankan lab. `scripts/select_feature.py` tersedia hanya sebagai alternatif jika Python memang terpasang. Paket peserta harus dibuat melalui perintah packaging dan diperiksa sebelum dibagikan; direktori builder ini memuat bahan instruktur.

## Gerbang rilis mentor

1. Semua event punya ID unik, sumber, timestamp dan zona waktu, schema version, serta hash/manifest yang dapat diverifikasi.
2. Training dan holdout dipisahkan. Aturan mahasiswa dibekukan sebelum evaluasi holdout; label privat tidak muncul pada paket atau feedback dini.
3. Metrik dapat dihitung ulang dari unit evaluasi yang jelas (event atau sequence); noise sah dan gap telemetri terdokumentasi.
4. Tiga paket hanya berisi kasus masing-masing, pertanyaan, data dictionary, training set, holdout tanpa label, dan alat yang diizinkan.
5. Data sepenuhnya sintetis; tidak ada malware aktif, callback internet, log kampus nyata, atau data pribadi nyata.
6. Pilot pada laptop 8 GB mengukur waktu buka, query, RAM, dan kesetaraan tiga kasus. Target awal ukuran dataset <1 GB per kasus harus diverifikasi.

Repository ini adalah bahan pembangun lab, bukan handout mahasiswa. Materi penilaian privat disimpan di luar GitHub publik.
