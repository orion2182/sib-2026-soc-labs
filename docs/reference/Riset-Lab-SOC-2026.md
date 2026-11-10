# Riset dan rancangan final project SOC / detection engineering

**Status:** rancangan instruktur, 26 Oktober 2026. **Peserta:** 3 kelompok, 3 aliran telemetri berbeda.  
**Kalender:** 20 November–23 Desember 2026; semua hari mentorship, gladi, dan presentasi tetap.

## 1. Keputusan desain berbasis riset

SOC perlu menilai **deteksi, triase, korelasi, keputusan eskalasi, dan tuning**, bukan mengulang eksploitasi VAPT. Gunakan format aturan [Sigma](https://github.com/SigmaHQ/sigma-specification) untuk deteksi portabel, dan [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) sebagai referensi hipotesis perilaku. MITRE telah mendepresiasi katalog *Data Sources* lama sejak ATT&CK v18; karena itu materi 2026 mengacu pada strategi/analitik deteksi saat relevan, bukan menganggap daftar data source lama sebagai rujukan terkini. [Catatan pembaruan MITRE](https://attack.mitre.org/resources/updates/updates-october-2025/).

Dataset **replay statis** lebih tepat untuk laptop peserta daripada mewajibkan SIEM besar 24 jam. Satu pencarian log lokal ringan atau dashboard yang disediakan mentor cukup, asal mahasiswa bisa menelusuri raw event, menulis aturan, menguji pada data latihan, lalu menguji ulang pada **holdout** yang kuncinya tetap di mentor. Format JSON dari [Suricata EVE](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) dan [Zeek](https://docs.zeek.org/en/v8.2.0/tutorial/logs.html) dapat dipakai untuk kasus jaringan. Tidak perlu memaksakan chain of custody forensik penuh atau PTES.

## 2. Tiga operasi SOC yang berbeda

| Kelompok | Narasi dan telemetri | Tugas deteksi utama | Noise/false positive yang harus ada |
| --- | --- | --- | --- |
| SOC-1 — **Account takeover API** | Log autentikasi, API, dan audit sesi aplikasi fiktif | Korelasi login tidak biasa → perubahan sesi → akses objek; severity dan eskalasi | Perjalanan sah, retry login pengguna, dan aktivitas admin terjadwal |
| SOC-2 — **Eksekusi mencurigakan endpoint** | Sysmon/Windows event JSON terkurasi dan inventaris host sintetis | Deteksi rangkaian proses/script + aktivitas lanjutan; triase host terdampak | Script helpdesk dan deployment IT yang sah |
| SOC-3 — **Beacon DNS/jaringan** | Zeek DNS/conn dan Suricata EVE sintetis | Deteksi pola periodik/tujuan berulang, korelasi alert jaringan dan konteks host | Telemetri update otomatis dan polling layanan sah |

Setiap kelompok mendapat dataset latihan dengan label mentor, satu dataset holdout tanpa label, dan contoh event normal. Semua IP/domain/akun bersifat dokumentasi atau fiktif; tidak ada callback internet atau serangan langsung. Simpan jawaban insiden dan label holdout di luar paket mahasiswa. Pilot buta menyeimbangkan volume event, tingkat noise, dan waktu investigasi. Target awal per dataset <1 GB; angka ini perlu diukur.

## 3. Lab bertahap dan pertanyaan mahasiswa

### Task 1 — Operasi dan kontrak data (20–23 Nov)

**Situasi:** tim menjadi analis SOC untuk satu organisasi fiktif. Mereka menerima SLA triase, klasifikasi severity, dan data yang boleh diakses.

- **Q1.** Sumber log, rentang waktu, field penting, serta gap telemetri apa yang tersedia?
- **Q2.** Apa kriteria menaikkan alert menjadi kasus dan kepada siapa kasus diserahkan? Tulis alasan severity.

**Bukti:** inventaris data, definisi severity, daftar asumsi. Akses dataset dibuka mentor setelah scope dan aturan pengolahan data dipahami.

### Task 2 — Baseline dan hipotesis (24–27 Nov)

- **Q3.** Perilaku normal apa yang terlihat untuk akun/host/jaringan pada kasus tim? Sertakan contoh event.
- **Q4.** Rangkaian perilaku apa yang layak dideteksi, dan event apa yang dibutuhkan agar hipotesisnya dapat diuji?

**Petunjuk:** satu IOC tunggal mudah menimbulkan false positive. Susun kondisi dengan konteks identitas, host, waktu, atau urutan.

### Task 3 — Aturan dan tuning (30 Nov–8 Des)

- **Q5.** Tulis satu aturan/query deteksi yang dapat diulang, termasuk field, kondisi, window, dan asumsi skema.
- **Q6.** Pada data latihan berlabel, berapa true positive, false positive, dan false negative? Jelaskan dua contoh kesalahan.
- **Q7.** Perubahan tuning apa menurunkan noise tanpa membutakan perilaku penting? Uji hasil sebelum/sesudah.

**Pertanyaan khusus kasus:**

| Kasus | Q8 | Q9 | Q10 |
| --- | --- | --- | --- |
| SOC-1 | Login mana menjadi awal rangkaian, bukan sekadar gagal login? | Akses API mana memperkuat dugaan pengambilalihan? | Apakah perjalanan sah yang mirip tertangkap aturan? |
| SOC-2 | Parent-child process mana paling kuat menunjukkan penyimpangan? | Host dan akun mana perlu eskalasi segera? | Bagaimana mengecualikan script helpdesk yang sah? |
| SOC-3 | Pola waktu/domain apa membedakan beacon dari update berkala? | Event Zeek dan Suricata mana saling mendukung? | Pola layanan sah apa paling berisiko jadi false positive? |

**Bukti Q5–Q10:** aturan/query, potongan raw event tersanitasi, tabel confusion matrix, dan satu kasus triase dengan alasan. Mentor menguji aturan pada holdout setelah tim membekukan versinya.

### Task 4 — Eskalasi dan perbaikan operasi (9–11 Des)

- **Q11.** Dari alert yang tervalidasi, apa keputusan eskalasi, containment yang **direkomendasikan**, dan informasi yang harus diserahkan ke IR? Bedakan fakta dan dugaan.

### Task 5 — Laporan dan demo (14–18 Des)

- **Q12.** Tunjukkan hasil aturan pada holdout, batas deteksi yang tersisa, serta satu perubahan runbook untuk analis berikutnya.

**Serahkan 18 Des:** aturan/query final, test set dan metrik, tiga contoh triase, satu ticket eskalasi, runbook singkat, dan slide. Presentasi 21–23 Des meliputi replay alert dan tanya jawab individu.

## 4. Timeline fase dan gerbang

| Tanggal | Pekerjaan dan gerbang |
| --- | --- |
| 20–23 Nov | Briefing SOC, skema log, SLA, akses dataset; **G0: kontrak data dipahami** |
| 24–27 Nov | Baseline, noise, dan hipotesis deteksi; **G1: hipotesis disetujui mentor** |
| 30 Nov–2 Des | Aturan awal, uji pada latihan berlabel; **G2: definisi metrik dan false positive** |
| 3–8 Des | Tuning, triase kasus, bekukan aturan untuk holdout; **G3: aturan + Q8–Q10** |
| 9–11 Des | Hasil holdout, eskalasi, handoff IR; **G4: keputusan operasional** |
| 14–18 Des | Laporan dan gladi 16–18 Des; **G5: paket final** |
| 21–23 Des | Presentasi/pengujian sesuai slot |

## 5. Rubrik dan persiapan mentor

| Komponen | Poin |
| --- | ---: |
| Pemahaman skema, baseline, dan gap log | 15 |
| Hipotesis dan logika deteksi | 20 |
| Validasi, metrik, false positive, dan tuning | 25 |
| Triase, severity, serta handoff | 20 |
| Runbook, batasan, dan presentasi | 10 |
| Tanya jawab kontribusi individu | 10 |
| **Total** | **100** |

**Checklist mentor sebelum 20 Nov:** buat tiga dataset dan skema field; sisipkan noise sah yang realistis; tetapkan label latihan dan holdout terpisah; validasi aturan referensi pada keduanya; atur waktu dan zona log; sediakan viewer/query ringan; uji ukuran, load time, dan analisis pada laptop 8 GB; siapkan template ticket/eskalasi dan rubrik severity; lakukan pilot buta pada tiga kasus. Tidak perlu memasang SIEM penuh di semua laptop.

**Batas saat ini:** dataset, label holdout, dan aturan referensi belum dibangun. Ambang metrik dan kesetaraan kasus harus dikalibrasi dari pilot, bukan angka yang diada-adakan. Kalender harian terperinci tercantum pada Google Sheets mentor lintas tema.
