# SOC-1 — API account takeover: data dictionary

**Case:** SOC-1 · **Schema:** 1.0.0 · **Unit evaluasi:** event
**Sumber waktu:** setiap `event_time` memuat offset zona sumber; `event_time_utc` adalah instant UTC yang dinormalisasi.

## Sumber log

| Source | Sensor | Isi |
| --- | --- | --- |
| `auth` | `auth-api-1` | Percobaan masuk, keluar, hasil autentikasi |
| `session` | `session-svc-1` | Pembuatan sesi setelah autentikasi |
| `api` | `api-gateway-1` | Akses objek, refresh token, ekspor, perubahan peran |

## Field

| Field | Tipe | Wajib | Keterangan |
| --- | --- | --- | --- |
| `event_id` | string | ya | ID stabil dan unik, mis. `SOC1-T-0007` |
| `case_id` | string | ya | Selalu `SOC-1` |
| `schema_version` | string | ya | `1.0.0` |
| `source` | string | ya | `auth`, `session`, atau `api` |
| `event_time` | string | ya | Waktu sumber dengan offset eksplisit |
| `event_time_utc` | string | ya | Hasil normalisasi ke UTC |
| `sensor` | string | ya | Sensor/servis pengumpul |
| `account` | string | ya | Identitas sintetis |
| `event_type` | string | ya | Kategori peristiwa |
| `outcome` | string | ya | `success`, `failure`, `denied`, `allowed` |
| `session_id` | string | tidak | Referensi sesi sintetis |
| `device_id` | string | tidak | Referensi perangkat sintetis |
| `src_ip` | string | tidak | Alamat dokumentasi (RFC 5737) |
| `geo` | string | tidak | Label geografi kasar |
| `object_type` | string | tidak | Kelas objek API |
| `object_id` | string | tidak | ID objek sintetis |
| `bytes` | integer | tidak | Ukuran respons |
| `role` | string | tidak | Peran saat peristiwa |
| `note` | string | tidak | Konteks singkat |
| `raw` | object | tidak | Payload kecil berbentuk sumber |

## Nilai `event_type`

| Nilai | Arti |
| --- | --- |
| `auth.login` | Percobaan masuk |
| `auth.logout` | Keluar |
| `session.created` | Sesi baru dibuat |
| `api.object.read` | Pembacaan objek |
| `api.token.refresh` | Refresh token sesi |
| `api.export` | Ekspor kumpulan objek |
| `api.role.change` | Perubahan peran |

## Gap telemetri yang diketahui

- Tidak ada log perangkat endpoint; `device_id` hanya penanda sesi.
- Tidak ada isi payload objek, hanya metadata akses.
- `auth` dan `api` berasal dari sensor berbeda; offset clock dapat berbeda beberapa detik.
- Alamat sumber dapat dipakai bersama beberapa akun (NAT).
- Holdout tidak menyertakan label; hanya mentor yang memegang label privat.

## Batas

Semua identitas, alamat, domain, dan objek adalah sintetis. Alamat memakai rentang
dokumentasi. Tidak ada sistem, kredensial, atau telemetri nyata.
