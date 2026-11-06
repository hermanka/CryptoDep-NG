# Rancangan Fitur Berbasis Agent

Catatan rancangan fitur dashboard yang memanfaatkan agent AI di atas hasil CDG. Status per fitur ada di setiap judul.

Prinsip yang berlaku untuk semua fitur:

- Keluaran LLM adalah data tidak tepercaya. ID node divalidasi terhadap graph dan teks ditampilkan sebagai teks biasa.
- Kode dari repository yang dipindai tidak pernah dijalankan.
- Label dan isi graph berasal dari kode pihak ketiga, sehingga prompt memperlakukannya sebagai data, bukan instruksi.

---

## 1. Tanya graph (bahasa alami) — **sudah diimplementasikan**

Pengguna mengetik pertanyaan, misalnya *"Komponen mana yang terdampak jika RSA dibobol?"*. Agent menjawab berdasarkan CDG, lalu dashboard **menyorot node terkait** dan **menganimasikan jalur** di sepanjang edge.

| Bagian | Lokasi |
|---|---|
| Prompt, konteks graph, dan validasi jawaban | `cryptodep/web/ask.py` |
| Endpoint `POST /api/scans/{id}/ask` dengan isi `{question}` | `cryptodep/web/app.py` |
| Chatbox di kiri canvas (dibuka lewat tombol ✦ Tanya graph), sorotan, dan animasi jalur | `cryptodep/web/static/app.js` |
| Balasan mock untuk demo tanpa AI | `cryptodep/web/mock_ai.py` |

Jawaban model berupa `{"answer", "node_ids", "path"}`. ID yang tidak ada di graph dibuang. Batasan: graph di atas 300 node dipotong di prompt (`MAX_NODES`). Pendekatan berbasis retrieval baru diperlukan bila hasil pemindaian nyata melewati batas itu.

---

## 2. Graph yang tumbuh live selama pemindaian — rencana

- Node muncul di canvas saat agent menemukannya, misalnya A2 menemukan RSA dan node merah langsung muncul. A3 kemudian menarik edge ke komponen yang memakainya.
- Panel "jejak pikiran agent" menampilkan satu kalimat per keputusan, misalnya *"A3: `PaymentService` mengimpor `CryptoUtil` → kemungkinan memakai RSA (82%)"*.
- Simulasi gaya yang sudah ada (`runForces`) membuat node baru masuk ke posisinya secara organik.
- Kebutuhan: pipeline menulis temuan sementara melalui callback `progress` yang sudah ada, dan dashboard membacanya lewat polling yang sudah berjalan.
- Risiko: perlu dipastikan penulisan temuan sementara tidak memperlambat tahap A2/A3.

## 3. Simulator roadmap migrasi — rencana

- Rencana dari A5 ditampilkan sebagai slider timeline bertahap, misalnya Q1: RSA di Auth, lalu Q2: ECDSA di Payment.
- Saat slider digeser, node berubah dari merah ke hijau, edge `migrates_to` menyala, dan skor kesiapan kuantum naik.
- Agent menarasikan setiap tahap: apa yang diganti, risikonya, dan alasan urutannya.

## 4. Agent migrasi dan perbaikan kode (patch) — rencana

### Alur pengguna

1. **Node merah**: pengguna memilih algoritma pengganti dari `metadata.migration_suggestions`, misalnya ML-KEM-768 hybrid X25519 atau ML-DSA-65, mencentang lokasi temuan, lalu klik **Buat patch migrasi**.
2. **Node oranye**: tombol **Buat patch perbaikan** dengan target tetap: SHA-256 atau Argon2id untuk password, AES-GCM untuk ECB.
3. Panel progres menampilkan tahapan *menyiapkan konteks → menyusun patch → verifikasi*.
4. Hasil berupa tampilan diff, laporan verifikasi, catatan risiko, dan tombol **Unduh .patch**.

### Komponen

- **A7 FixAgent** (`cryptodep/agents/a7_fixer.py`) berjalan sebagai job worker terpisah, mengikuti pola `launch_scan`.
  1. Konteks: fungsi atau class tempat temuan berada, diambil via AST. Disertakan juga import dan manifest dependensi (`pom.xml`, `requirements.txt`, `package.json`).
  2. Generate: prompt baru di `cryptodep/prompts/`. Keluarannya JSON `{file, unified_diff, dependency_changes, notes}`.
  3. Verifikasi tanpa menjalankan kode repo:
     - `git apply --check`, dan patch hanya boleh menyentuh file temuan serta manifest.
     - Parse ulang dengan tree-sitter.
     - Jalankan ulang Semgrep: temuan lama harus hilang dan tidak ada temuan lemah baru.
     - Bila verifikasi gagal, coba ulang maksimal 1–2 kali dengan umpan balik.
  4. Simpan ke tabel `fixes` di `dashboard.db` dan berkas `fixes/<id>.patch`.
- **API**: `POST /api/scans/{id}/fixes` dengan isi `{node_id, target, finding_refs}`, `GET /api/fixes/{id}`, dan `GET /api/fixes/{id}/download`.
- **Library**:
  - Java: BouncyCastle (ML-KEM/ML-DSA) atau JDK 24+ (JEP 496/497).
  - Python: `liboqs-python`.
  - JavaScript: cukup laporan panduan dulu.

### Risiko yang wajib ditampilkan

- RSA enkripsi → ML-KEM bukan penggantian 1:1. KEM menghasilkan shared secret, sehingga polanya menjadi KEM + AEAD dan format pesan berubah.
- Ukuran kunci dan tanda tangan berubah. Kunci dan data tersimpan perlu migrasi, dan pihak lawan komunikasi harus ikut mendukung.
- Perbaikan oranye juga memutus kompatibilitas data lama:
  - Hash password MD5 perlu di-rehash saat login.
  - Data yang dienkripsi dengan ECB perlu dienkripsi ulang.
- Patch LLM bisa salah secara semantik walaupun lolos verifikasi, sehingga statusnya selalu "perlu review".

### Tahapan

1. **MVP**: perbaikan oranye untuk Java dan Python, berupa patch yang bisa diunduh beserta diff.
2. **Tahap 2**: migrasi merah untuk Java (BouncyCastle, hybrid).
3. **Tahap 3 (opsional)**:
   - Tombol **Buat Pull Request** dengan token GitHub pengguna. Fitur ini menulis ke luar, sehingga selalu perlu konfirmasi.
   - Build/test di container sandbox tanpa jaringan.

Di luar cakupan: push otomatis, perubahan di luar lokasi temuan, dan patch JavaScript.

---

## 5. Ide tambahan

| Ide | Nilai demo | Catatan |
|---|---|---|
| AI Auditor: agent kedua menguji ulang temuan (debat A2 vs auditor) | Pengurangan false positive terlihat | Argumen yang baik untuk paper |
| Skenario HNDL: klik node merah, narasi "harvest now, decrypt later" dengan jalur beranimasi ke data bisnis | Mudah dipahami audiens non-teknis | Bisa memakai ulang sorotan jalur dari fitur 1 |
| Briefing eksekutif sekali klik untuk CISO | Cocok untuk audiens manajemen | Ringkasan dari `report.md` A5 |
| Diff antar pemindaian (sebelum/sesudah migrasi) | Bukti kemajuan yang visual | CLI sudah punya perintah `diff` |
| Gauge skor crypto-agility per repo | Satu angka yang mudah diingat | Dihitung dari `risk_summary`, tanpa LLM |

## Skenario demo yang disarankan

1. Tempel URL repo. Graph tumbuh sambil agent "berpikir" (fitur 2).
2. Tanyakan *"apa yang rusak kalau RSA jatuh?"*. Jalur ke komponen bisnis menyala (fitur 1).
3. Geser timeline roadmap. Graph berubah dari merah ke hijau (fitur 3).
4. Tutup dengan patch migrasi beserta diff dan verifikasinya (fitur 4).
