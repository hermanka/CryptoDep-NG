# Contoh output

Output asli CryptoDep dari satu pemindaian [DVJA (Damn Vulnerable Java Application)](https://github.com/appsecco/dvja), untuk melihat bentuk data tanpa menjalankan pipeline.

| Berkas | Isi |
|---|---|
| `dvja_cdg_example.json` | Crypto Dependency Graph (CDG) JSON, format keluaran `cryptodep run --output` |
| `dvja_cbom_example.json` | CBOM CycloneDX v1.6 dari pemindaian yang sama |

**Asal data**

- Repository: `https://github.com/appsecco/dvja`, commit `597ece1ab79ffffea7289d49b0c443bb2ebcbd16`
- Dijalankan lewat dashboard web (Docker) pada 6 November 2026 dengan model `qwen3coder` melalui endpoint kompatibel OpenAI.
- Satu-satunya perubahan setelah pemindaian: path internal container (`/data/<scan-id>/repo/`) diganti path relatif repository, dan `target_repo` diisi URL serta commit.

**Isi temuan**

DVJA hanya memakai MD5 (lewat `org.springframework.util.DigestUtils` di `UserService.java`). Karena itu graph berisi 3 node dan tidak ada algoritma yang rentan kuantum. MD5 tetap merupakan kelemahan klasik: dashboard menandainya oranye ("Tinjau keamanan"), bukan merah (migrasi PQC).

Sebagian deteksi dibantu LLM. Pemindaian ulang dengan model atau waktu berbeda dapat menghasilkan label, confidence, atau edge yang sedikit berbeda.
