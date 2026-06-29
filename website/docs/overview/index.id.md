# Tentang

**Mecha Hayabusa** menghubungkan alat analisis log peristiwa Windows **Hayabusa** ke model bahasa besar (LLM) melalui **Model Context Protocol (MCP)**, memungkinkan forensik digital dan threat hunting yang digerakkan oleh bahasa alami. Para analis dapat menyelidiki kumpulan data log peristiwa Windows berbasis CSV menggunakan kemampuan seperti analisis taktik MITRE ATT&CK, ekstraksi IOC, korelasi lateral movement, decoding PowerShell, dan analisis timeline yang berpusat pada host.

Timeline CSV Hayabusa secara otomatis dikonversi menjadi basis data **DuckDB** lokal, memungkinkan LLM melakukan analisis terstruktur yang cepat atas kumpulan data log yang besar. Sistem ini menyediakan kemampuan termasuk pergantian dan pembuatan profil kumpulan data, eksekusi SQL hanya-baca, pencarian lintas bidang, agregasi judul rule, perangkuman jendela waktu, analisis timeline host, penguraian bidang `Details`, ekstraksi IOC, decoding PowerShell yang dienkode Base64, dan korelasi lateral movement.

Mecha Hayabusa juga menyertakan **investigation skill** khusus yang menstandarkan alur kerja DFIR dan mendukung pembuatan laporan insiden terstruktur dalam **bahasa Jepang atau Inggris**.

Inovasi utama dari Mecha Hayabusa adalah memungkinkan LLM untuk menjalankan **alur kerja investigasi DFIR terstruktur melalui MCP**, alih-alih bertindak sebagai antarmuka pencarian sederhana. Pendekatan ini mendukung seluruh siklus hidup investigasi—mulai dari triase kumpulan data dan pengembangan hipotesis hingga analisis fase serangan, investigasi tingkat host, korelasi lateral movement, dan pembuatan laporan akhir—sembari meningkatkan konsistensi dan efisiensi bagi para responder insiden.
