# SOC-3 - DNS and network beacon: data dictionary

**Case:** SOC-3 · **Schema:** 1.0.0 · **Unit evaluasi:** event
**Sumber waktu:** `event_time` memuat offset; `event_time_utc` adalah instant UTC.

## Sumber

| Source | Sensor | Isi |
| --- | --- | --- |
| `dns` | `zeek-dns-1` | Query dan jawaban DNS |
| `conn` | `zeek-conn-1` | Ringkasan koneksi |
| `ids` | `suricata-1` | Alert signature |

## Field

| Field | Tipe | Wajib | Keterangan |
| --- | --- | --- | --- |
| `event_id` | string | ya | ID unik, mis. `SOC3-T-0007` |
| `case_id` | string | ya | Selalu `SOC-3` |
| `schema_version` | string | ya | `1.0.0` |
| `source` | string | ya | `dns`, `conn`, `ids` |
| `event_time` | string | ya | Waktu sumber dengan offset |
| `event_time_utc` | string | ya | Normalisasi UTC |
| `sensor` | string | ya | Sensor pengumpul |
| `host` | string | ya | Host sintetis |
| `account` | string | ya | Akun sintetis |
| `event_type` | string | ya | `dns.query`, `conn.flow`, `ids.alert` |
| `outcome` | string | ya | `success`, `allowed`, `denied`, `no_answer` |
| `query` | string | tidak | Nama query DNS |
| `qtype` | string | tidak | Tipe query |
| `rcode` | string | tidak | Kode respons |
| `answers` | string | tidak | Alamat jawaban |
| `dest_ip` | string | tidak | Alamat tujuan dokumentasi |
| `dest_port` | integer | tidak | Port tujuan |
| `proto` | string | tidak | Protokol |
| `duration` | number | tidak | Durasi flow (detik) |
| `orig_bytes` | integer | tidak | Byte dari host |
| `resp_bytes` | integer | tidak | Byte ke host |
| `flow_id` | string | tidak | Referensi flow |
| `signature` | string | tidak | Teks signature IDS |
| `category` | string | tidak | Kategori IDS |
| `severity` | integer | tidak | Severity IDS 1-3 |
| `process_name` | string | tidak | Konteks proses bila ada |
| `role` | string | tidak | Peran sintetis |
| `note` | string | tidak | Konteks singkat |
| `raw` | object | tidak | Payload kecil |

## Gap dan jebakan

- DNS cache dapat membuat query berulang tanpa jawaban baru.
- Interval beacon memiliki jitter; jangan mencari periode eksak.
- Satu alert IDS tanpa `conn`/`dns` yang cocok bukan insiden terkonfirmasi.
- Polling update sah dapat terlihat periodik dan memicu alert severity rendah.
- Sensor DNS dan IDS dapat memiliki offset waktu kecil.
- Holdout memakai host, domain, alamat, dan flow id berbeda.

## Batas

Semua record statis dan sintetis. Tidak ada replay paket atau callback nyata.
