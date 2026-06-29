# Fitur

## Operasi Dataset

Mengelola dataset yang digunakan untuk analisis.

- **get_dataset_status**  
  Mengambil status dataset yang sedang dimuat.

- **list_datasets**  
  Membuat daftar dataset CSV yang tersedia untuk analisis.  
  Mendukung paginasi.

- **switch_dataset**  
  Mengalihkan dataset analisis aktif ke file CSV yang ditentukan.

- **unload_dataset**  
  Membongkar tabel `logs` saat ini.

- **dataset_profile**  
  Mengambil ringkasan dataset, termasuk:
  - jumlah total event
  - rentang waktu
  - tren teratas

  Mendukung paginasi.

---

## Kueri & Pencarian

Mencari dan melakukan kueri pada data log.

- **run_sql**  
  Mengeksekusi kueri `SELECT` baca-saja terhadap tabel `logs`.  
  Mencakup batasan keamanan bawaan.

- **search_all_fields**  
  Melakukan pencarian kata kunci di seluruh kolom atau kolom yang ditentukan.  
  Mendukung paginasi.

- **get_event_detail**  
  Mengambil satu event dalam format `Field / Value` yang diperluas.  
  Mendukung pencarian berdasarkan `RecordID` atau kondisi kueri.

---

## Timeline & Analitik

Menganalisis aktivitas serangan dan timeline event.

- **analyze_mitre_tactics**  
  Melakukan analisis kronologis fase serangan yang dikelompokkan berdasarkan **MITRE ATT&CK tactics**.

- **analyze_host_timeline**  
  Mengekstrak event kronologis untuk host tertentu.  
  Berguna untuk **pelacakan rantai kompromi**.

- **correlate_lateral_movement**  
  Mengorelasikan aktivitas lateral movement antar host dalam rentang waktu yang ditentukan.

- **summarize_events**  
  Mengagregasi event log berdasarkan field yang ditentukan.

- **summarize_by_time_window**  
  Menghitung event berdasarkan jendela waktu:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  Mengagregasi frekuensi kemunculan `RuleTitle` dengan kondisi filter opsional.

---

## Analisis Detail & IOC

Mengekstrak dan menganalisis indikator dari detail log.

- **parse_details_field**  
  Mengekstrak pasangan kunci/nilai dari field `Details`.  
  Mendukung pendaftaran dan agregasi unik.

- **extract_iocs**  
  Mengekstrak **Indicators of Compromise (IOCs)** dari `Details` dan `ExtraFieldInfo`, dikategorikan berdasarkan tipe.

- **decode_powershell_commands**  
  Mendekode perintah PowerShell yang dienkode Base64 yang ditemukan dalam event.
