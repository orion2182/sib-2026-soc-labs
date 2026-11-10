# SOC-2 - Suspicious endpoint execution: data dictionary

**Case:** SOC-2 · **Schema:** 1.0.0 · **Unit evaluasi:** event
**Sumber waktu:** `event_time` memuat offset; `event_time_utc` adalah instant UTC.

## Sumber

| Source | Sensor | Isi |
| --- | --- | --- |
| `endpoint` | `edr-win-1` | Proses, script, file, koneksi |
| `inventory` | `cmdb-1` | Informasi host dan pemilik |
| `maintenance` | `change-cal-1` | Jendela perubahan yang disetujui |

## Field

| Field | Tipe | Wajib | Keterangan |
| --- | --- | --- | --- |
| `event_id` | string | ya | ID unik, mis. `SOC2-T-0007` |
| `case_id` | string | ya | Selalu `SOC-2` |
| `schema_version` | string | ya | `1.0.0` |
| `source` | string | ya | `endpoint`, `inventory`, `maintenance` |
| `event_time` | string | ya | Waktu sumber dengan offset |
| `event_time_utc` | string | ya | Normalisasi UTC |
| `sensor` | string | ya | Sensor pengumpul |
| `host` | string | ya | Host sintetis |
| `account` | string | ya | Akun sintetis |
| `event_type` | string | ya | Tipe peristiwa |
| `outcome` | string | ya | `success`, `blocked`, `denied`, `allowed` |
| `pid` | integer | tidak | PID; dapat dipakai ulang |
| `process_guid` | string | tidak | Identitas proses stabil |
| `parent_guid` | string | tidak | Identitas induk; string kosong jika telemetri hilang |
| `process_name` | string | tidak | Nama image |
| `parent_name` | string | tidak | Nama induk bila teramati |
| `command_line` | string | tidak | Representasi command line (inert) |
| `signer` | string | tidak | Signer; kosong jika unsigned |
| `file_path` | string | tidak | Path sintetis |
| `dest_ip` | string | tidak | Alamat dokumentasi |
| `dest_port` | integer | tidak | Port tujuan |
| `bytes` | integer | tidak | Ukuran tulis/kirim |
| `maintenance_id` | string | tidak | Record perubahan |
| `role` | string | tidak | Peran host/akun |
| `note` | string | tidak | Konteks singkat |
| `raw` | object | tidak | Payload kecil |

## Nilai `event_type`

| Nilai | Arti |
| --- | --- |
| `process.create` | Proses dibuat |
| `script.block` | Blok script ditulis/diamati |
| `file.create` | File dibuat |
| `network.connect` | Koneksi keluar |
| `host.info` | Entri inventaris |
| `maintenance.window` | Jendela perubahan disetujui |

## Gap dan jebakan

- `parent_guid` dapat kosong (telemetri induk hilang).
- PID dapat dipakai ulang; gunakan `process_guid`.
- `signer` kosong tidak otomatis jahat; `IT-Approved` adalah konteks sah.
- Jendela maintenance harus dicek terhadap `maintenance_id`.
- Holdout tidak berlabel dan memakai host/tujuan berbeda.

## Batas

Semua record inert. Tidak ada eksekusi script, malware, atau koleksi endpoint nyata.
