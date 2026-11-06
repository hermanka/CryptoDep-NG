# Menjalankan CryptoDep Web dan CLI dengan Docker

Dashboard lokal untuk satu operator. Layanan yang sama menyertakan CLI inti, Git, Semgrep, parser Java/Python/JavaScript, SQLite, dan aset GUI lokal. Tidak membutuhkan Neo4j, Node.js, atau CDN saat runtime.

## Mulai

```bash
docker compose up -d --build
```

Buka **http://localhost:8088**. Jika port tersebut terpakai, set `CRYPTODEP_PORT` sebelum menjalankan Compose. Port hanya dipublikasikan ke loopback host.

1. Buka **Pengaturan AI**.
2. Isi endpoint URL, nama model, dan API key jika provider memerlukannya.
3. Klik **Uji koneksi**, lalu **Simpan pengaturan**.
4. Masukkan URL GitHub publik, misalnya `https://github.com/appsecco/dvja`.
5. Klik **Mulai pemindaian**. Progres clone dan A1–A5 ditampilkan per tahap.
6. Jelajahi **Graph** atau **Daftar**. Klik node temuan untuk lokasi/bukti kode, saran migrasi, serta komponen terkait yang perlu ditinjau.
7. Gunakan **Riwayat** untuk membuka hasil lama tanpa scan ulang. CDG, CBOM, dan laporan dapat diunduh dari hasil.

Belum ada fitur penerapan migrasi kode. Merah menandakan migrasi PQC; oranye menandakan peringatan klasik atau peninjauan parameter. Abu-abu mencakup komponen pendukung dan algoritma lain, bukan jaminan keamanan umum. Klasifikasi yang belum diketahui memakai tanda `?` dan garis putus-putus.

## Membaca risiko dan menjelajahi graph

Panel detail memisahkan risiko kuantum, peringatan keamanan klasik, serta kepastian/cakupan analisis. Ia menampilkan asal deteksi, confidence yang dicatat, lokasi/bukti kode, saran tindakan, dan komponen yang perlu ditinjau. Skor dan antrean prioritas PQC inti tidak diubah oleh penilaian tampilan ini.

Aturan klasik awal mencakup MD5/SHA-1 untuk kelemahan collision, serta parameter AES-ECB yang tercatat. Saran membedakan hash integritas dari penyimpanan password: SHA-256 bukan pengganti langsung untuk password hashing; gunakan KDF khusus sesuai kebutuhan. HMAC tidak otomatis diberi label kelemahan collision hanya karena namanya memuat hash tersebut. Aturan ini belum mencakup seluruh kelemahan kriptografi. Rujukan: [RFC 6151](https://www.rfc-editor.org/rfc/rfc6151.html), [kebijakan SHA-1 NIST](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions), [penyimpanan password OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), dan [mode enkripsi OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).

Label `grover_weakened` ditampilkan sebagai peninjauan parameter (oranye), bukan kewajiban universal mengganti AES dengan PQC. Jika satu node memiliki risiko PQC dan klasik sekaligus, merah diprioritaskan tetapi semua peringatan tetap ditampilkan di panel. Hasil lama mendapat penilaian saat dibuka atau diunduh sebagai CDG; tidak perlu scan ulang dan snapshot asli tidak ditulis ulang. CBOM dan laporan inti lama tetap merupakan keluaran scan asal.

Interaksi graph mengambil pola navigasi dari [Obsidian Graph view](https://help.obsidian.md/plugins/graph):

- Hover node untuk menyorot tetangga dan melihat ringkasan; ukuran node mengikuti jumlah hubungan, bukan tingkat risiko.
- Klik node untuk detail; klik garis untuk bukti dan confidence hubungan.
- Klik dua kali node, atau pilih **Fokus lokal**, untuk membatasi graph ke tetangganya. **Tampilan → Kedalaman lokal** memilih 1–4 hop pada graph CDG, bukan hop call graph runtime.
- **Tampilan** menyediakan filter risiko/jenis node, toggle node tanpa hubungan, label, panah, ukuran node, jarak hubungan, dan gaya tolak. Filter dan pencarian juga berlaku pada daftar.
- Drag node untuk memindahkannya; **Sematkan posisi** mempertahankan posisi ketika tata letak diulang. Tombol tata ulang menjalankan layout kembali, sedangkan tombol sesuaikan memusatkan node yang terlihat.
- Layar penuh tersedia dari toolbar. Saat canvas mendapat fokus keyboard, gunakan tombol panah untuk menggeser, `+`/`-` untuk zoom, dan `Escape` untuk keluar dari fokus lokal.
- **Pulihkan tampilan** mengembalikan filter, gaya, dan pin ke keadaan awal. Pengaturan eksplorasi hanya berlaku pada sesi tampilan dan tidak mengubah graph analisis.

## Endpoint AI

Endpoint menerima kontrak OpenAI-compatible Chat Completions. Gunakan base URL beserta prefix API, misalnya `https://provider.example/v1`; aplikasi menambahkan `/chat/completions`. URL lengkap yang berakhir `/chat/completions` juga diterima. Nama model harus sama dengan ID model yang tersedia pada provider.

Untuk server model pada komputer host dari Docker:

```text
http://host.docker.internal:11434/v1
```

Server model host harus menerima koneksi dari Docker. `localhost` di dalam container menunjuk container, bukan komputer host. Aplikasi tidak menjalankan atau mengunduh model AI sendiri.

API key opsional untuk endpoint lokal. Mengosongkan kolom key mempertahankan key tersimpan; centang **Hapus key tersimpan** untuk menghapusnya. Pengaturan baru berlaku pada scan berikutnya; scan yang berjalan menggunakan snapshot konfigurasi saat dimulai. Uji koneksi mengirim permintaan JSON kecil tanpa source repository.

Untuk Gemini, isi endpoint `https://generativelanguage.googleapis.com/v1beta/openai` dan nama model seperti `gemini-flash-latest`, tanpa akhiran `:generateContent`. API native `contents`/`generateContent` tidak dipakai konektor ini. Uji koneksi menggunakan anggaran default 4096 token agar model reasoning memiliki ruang untuk menjawab. Pesan error membedakan HTTP 401 (key), 403 (izin), 404 (endpoint/model), 429 (kuota), dan 503 (layanan/model sibuk); respons error mentah provider tidak ditampilkan.

Potongan kode dikirim ke endpoint yang dipilih saat analisis. API key disimpan dalam SQLite di volume lokal dengan izin file terbatas, **tanpa enkripsi at rest**; key tidak dikirim kembali melalui API dashboard atau dimasukkan ke perintah proses, image, dan hasil unduhan. Perlakukan volume dan backup sebagai data sensitif. Aplikasi ini belum menyediakan autentikasi/multi-user dan tidak ditujukan untuk diekspos ke internet.

## Data dan lifecycle

### API mock lokal sementara

Untuk menguji koneksi dan alur tanpa provider AI nyata:

```bash
docker compose build cryptodep
docker compose --profile mock up -d --no-deps mock-ai
```

Pada **Pengaturan AI** dashboard Docker, isi endpoint `http://mock-ai:8000/v1` dan model `mock-cryptodep`. API key tidak diperlukan. Untuk client yang berjalan langsung di komputer host, gunakan `http://localhost:8090/v1`. Daftar model tersedia di `http://localhost:8090/v1/models`, dan health check di `http://localhost:8090/health`.

Mock mengembalikan JSON uji koneksi, array kosong untuk deteksi/penalaran semantik, dan laporan bertanda mock. Temuan statis dan graph tetap berasal dari scanner; mock tidak menambahkan hasil AI sungguhan. Layanan ini tidak menghubungi provider eksternal, tidak menyimpan API key, dan hanya dipublikasikan pada localhost. Pengaturan Gemini tersimpan tidak otomatis diubah saat mock dijalankan.

Hentikan setelah selesai:

```bash
docker compose --profile mock stop mock-ai
```

### Penyimpanan

Volume Compose `cryptodep_data` dipasang di `/data`. Nama volume aktual memiliki prefix nama project Compose.

```text
/data/
  dashboard.db          # settings dan riwayat pekerjaan
  semgrep/              # konfigurasi scanner
  <scan-id>/
    repo/               # hasil clone
    cdg.db              # penyimpanan inti per scan
    cdg.json            # keluaran inti
    result.json         # CDG dengan bukti dan rekomendasi untuk GUI
    cbom.json
    report.md
    clone.log
    worker.log
```

Riwayat dan hasil bertahan setelah container dibuat ulang. Hasil yang memiliki kegagalan recoverable ditandai **selesai sebagian**, bukan dianggap scan bersih. Kegagalan scanner menghentikan scan. Proses yang terputus ditandai **terputus** pada startup berikutnya; tidak otomatis dilanjutkan.

```bash
docker compose ps
docker compose logs --tail 100 cryptodep
docker compose restart cryptodep
docker compose down
```

`down` tanpa `--volumes` mempertahankan data. Jangan menambahkan `--volumes` jika masih membutuhkan riwayat atau pengaturan. Versi awal belum menyediakan penghapusan otomatis hasil/clone; penggunaan disk bertambah seiring riwayat.

## CLI inti dari image yang sama

```bash
docker compose run --rm --no-deps cryptodep cryptodep --help
```

Untuk memindai source lokal, mount direktori repository sebagai read-only, berikan konfigurasi AI lewat environment, dan tulis hasil ke volume data:

```bash
docker compose run --rm --no-deps \
  -e CRYPTODEP_LLM_PROVIDER=openai_compatible \
  -e CRYPTODEP_LLM_BASE_URL \
  -e CRYPTODEP_LLM_MODEL \
  -e CRYPTODEP_LLM_API_KEY \
  -v /absolute/path/to/repository:/repo:ro \
  cryptodep cryptodep run /repo \
  --output /data/cli_cdg.json --db /data/cli_cdg.db --report /data/cli_report.md
```

Set variabel tersebut di shell sebelumnya; jangan menulis key secara literal di command history. Contoh di atas menggunakan sintaks shell POSIX; PowerShell memakai backtick untuk kelanjutan baris. Pengaturan GUI disimpan terpisah dari environment CLI. Scan CLI ini tidak otomatis ditambahkan ke riwayat dashboard.

## Menjalankan tanpa Docker

```bash
uv sync
uv run uvicorn cryptodep.web.app:app --host 127.0.0.1 --port 8088 --workers 1
```

Data default berada di `web_data/`, yang diabaikan Git. Override dengan `CRYPTODEP_WEB_DATA_DIR`. Windows masih mengikuti runner Semgrep proyek yang menggunakan WSL; Docker direkomendasikan untuk lingkungan scanner yang konsisten. Gunakan **satu worker Uvicorn** dan satu instance aplikasi per direktori data.

## Batas versi ini

- Repository GitHub publik melalui HTTPS; repository privat, submodule, dan Git LFS tidak diunduh secara lengkap.
- Maksimal satu scan aktif, clone 3 menit/512 MB, dan scan keseluruhan 30 menit. Container dibatasi 2 CPU/2 GB RAM. Clone dipantau berkala sehingga batas ukuran bukan kuota disk yang presisi.
- Tidak menjalankan build, dependensi, hook repository, atau kode target. Symlink file target dilewati.
- A6/reachability tidak diaktifkan dari GUI. Dukungan JavaScript berfokus pada import literal dan API kriptografi dasar; TypeScript dan library JS pihak ketiga belum tercakup.
- Graph besar menggunakan layout lingkaran agar browser tetap responsif. Algoritma yang digabung oleh core masih dapat berbagi satu node; panel menyertakan temuan terkait yang tersedia.
- Saran migrasi berasal dari lookup inti dan hasil graph; membutuhkan peninjauan manusia serta tidak membuktikan keamanan runtime.

## Validasi pengembangan

```bash
uv run pytest tests/unit/test_risk.py tests/unit/test_web.py tests/unit/test_javascript_support.py tests/unit/test_pipeline.py -q
node --check cryptodep/web/static/app.js
```

Test API mencakup validasi URL, pembatasan origin/host, perlindungan key, riwayat persisten, koneksi AI kompatibel, kegagalan clone, dan pipeline terisolasi dengan layanan eksternal yang dimock. Pengujian browser menggunakan fixture QA terpisah; fixture tersebut tidak dimasukkan ke riwayat aplikasi produksi.

Untuk memeriksa interaksi graph pada dashboard yang sudah berjalan, instal Playwright secara terpisah beserta Chromium, lalu jalankan:

```bash
uv run python -m tests.integration.graph_browser_smoke --url http://localhost:8088
```

`CRYPTODEP_TEST_BROWSER` dapat menunjuk executable browser yang sudah terpasang. Test ini mengganti respons API di browser dengan fixture; tidak mengubah pengaturan atau riwayat dashboard dan tidak memanggil layanan AI.

Smoke test opsional berikut melakukan clone PyGoat melalui GitHub dan menjalankan Semgrep asli, dengan server AI mock pada loopback container. Data tes berada di direktori sementara, terpisah dari riwayat dashboard. Perintah memerlukan akses jaringan untuk clone; tidak menjalankan aplikasi target dan tidak membutuhkan API key:

```bash
docker compose cp tests/integration/web_smoke.py cryptodep:/tmp/cryptodep-web-smoke.py
docker compose exec -T cryptodep python /tmp/cryptodep-web-smoke.py
docker compose exec -T cryptodep python /tmp/cryptodep-web-smoke.py --repo https://github.com/appsecco/dvja
```

Varian DVJA memeriksa dua pemanggilan MD5 `DigestUtils.md5DigestAsHex` pada source repository asli dan penanda oranye pada graph. Prefilter harus mempertahankan API Spring ini sebelum aturan Semgrep dijalankan. Setelah memperbarui detektor, jalankan scan baru; hasil deteksi pada riwayat lama tidak dihitung ulang otomatis.
