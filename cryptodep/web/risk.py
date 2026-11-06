"""Deterministic display assessment; keep core PQC classification and ranking intact."""
from __future__ import annotations

import re


def assess_node(node: dict) -> dict:
    metadata = node.get("metadata") or {}
    findings = metadata.get("findings") or []
    family = str(node.get("algorithm_family", "")).upper().replace("_", "-")
    quantum = str(node.get("quantum_vuln_class", "")).rsplit(".", 1)[-1].lower()
    warnings = []
    if node.get("node_type") == "CryptoAlgorithm" and family in ("MD5", "SHA1", "SHA-1"):
        algorithm = "MD5" if family == "MD5" else "SHA-1"
        warnings.append({
            "code": "weak_hash", "title": f"{algorithm}: kelemahan collision klasik",
            "reason": f"{algorithm} tidak sesuai untuk penggunaan yang membutuhkan ketahanan collision, termasuk tanda tangan digital. Ini risiko klasik, bukan alasan menggantinya langsung dengan algoritma PQC.",
            "action": "Tinjau tujuan penggunaan. Untuk hash integritas yang memerlukan keamanan kriptografis, pertimbangkan SHA-256/SHA-3 sesuai protokol. Untuk password gunakan KDF khusus seperti Argon2id, bukan hash cepat biasa. Rencanakan kompatibilitas dan migrasi data.",
            "sources": ["https://www.rfc-editor.org/rfc/rfc6151.html" if family == "MD5" else "https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
        })
    parameters = [node.get("parameter_set", ""), node.get("label", "")]
    parameters += [f.get("parameter_set", "") for f in findings]
    if node.get("node_type") == "CryptoAlgorithm" and family == "AES" and any(
        re.search(r"(?:^|[-/])ECB(?:$|[-/])", str(value).upper()) for value in parameters
    ):
        warnings.append({
            "code": "ecb_mode", "title": "AES-ECB: pola plaintext dapat terlihat",
            "reason": "Mode ECB dapat memperlihatkan pola blok yang berulang. Masalahnya ada pada mode penggunaan, bukan pada kebutuhan mengganti AES dengan PQC.",
            "action": "Tinjau setidaknya satu temuan ECB terkait. Pertimbangkan mode enkripsi terautentikasi seperti AES-GCM sesuai protokol, dengan pengelolaan nonce yang benar. Jangan mengganti mode tanpa meninjau format data dan interoperabilitas.",
            "sources": ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"],
        })
    pqc = "not_applicable"
    pqc_reason = "Node ini adalah komponen pendukung atau kandidat pengganti, bukan algoritma klasik yang sedang dinilai."
    if node.get("node_type") == "CryptoAlgorithm":
        pqc, pqc_reason = "not_flagged", "Tidak ada penggantian PQC yang ditandai pada cakupan analisis ini. Ini bukan jaminan keamanan umum."
        if quantum == "quantum_vulnerable":
            pqc, pqc_reason = "migration", "Rentan terhadap serangan kuantum pada kriptografi kunci publik. Pilih pengganti berdasarkan fungsi pertukaran kunci atau tanda tangan."
        elif quantum == "grover_weakened":
            pqc, pqc_reason = "parameter_review", "Tinjau ukuran kunci/parameter dan target keamanan. Peningkatan parameter tidak selalu berarti mengganti algoritma dengan PQC; label inti bukan penetapan kewajiban universal."
        elif quantum not in ("quantum_safe_symmetric", "quantum_safe_pqc"):
            pqc, pqc_reason = "unknown", "Klasifikasi kuantum belum cukup diketahui. Diperlukan pemeriksaan manual."
    level = "red" if pqc == "migration" else "orange" if warnings or pqc == "parameter_review" else "unknown" if pqc == "unknown" else "gray"
    labels = {"red": "Migrasi PQC", "orange": "Tinjau keamanan", "gray": "Tidak ada tindakan teridentifikasi", "unknown": "? Belum diketahui"}
    methods = sorted({str(f.get("detected_by")) for f in findings if f.get("detected_by")})
    if not methods and node.get("detected_by"):
        methods = [str(node["detected_by"])]
    return {"level": level, "label": labels[level], "pqc_status": pqc, "pqc_reason": pqc_reason,
            "classical_warnings": warnings, "detection_methods": methods,
            "evidence_status": "Lokasi/bukti tersedia untuk ditinjau" if findings or node.get("source_ref") else "Bukti lokasi belum tersedia",
            "analysis_limit": "Analisis statis; dukungan import tidak membuktikan pemanggilan runtime. Asal/confidence temuan bukan jaminan kelengkapan atau keamanan."}


def annotate_risks(document: dict) -> dict:
    counts = dict.fromkeys(("red", "orange", "gray", "unknown"), 0)
    for node in document.get("nodes", []):
        assessment = assess_node(node)
        node.setdefault("metadata", {})["risk_assessment"] = assessment
        counts[assessment["level"]] += 1
    document["risk_summary"] = counts
    return document
