# Inter-Rater Agreement Workflow (Cohen's κ)

Complete workflow untuk mengukur reliabilitas anotasi dengan Cohen's κ.

---

## 🎯 Tujuan

Mengukur konsistensi antara dua annotator independen dalam memverifikasi crypto findings. Cohen's κ > 0.60 menunjukkan "substantial agreement" dan kredibel untuk paper.

---

## 📋 Tahap 1: Persiapan Dataset

### Step 1.1: Dataset Sudah Tersedia ✅

Dataset sudah di-generate dari **WebGoat CDG**:
```
✓ eval_results/annotation_dataset.csv  — Ready untuk anotator
✓ eval_results/annotation_dataset.json — Backup JSON format
```

**Karakteristik dataset:**
- **12 crypto findings** dari WebGoat repository
- **Algoritma:** RSA, RSA-2048, SHA-256, MD5, HMAC, Base64, CRYPTO_IMPORT, SHA256withRSA, dll
- **Sumber real:** Dari CryptoDep-LLM detection pipeline
- **2 annotators:** Setiap finding dinilai A1 & A2 (independen)

**Contoh findings dalam dataset:**

| Algoritma | File | Confidence | Context | Expected |
|-----------|------|-----------|---------|----------|
| RSA-2048 | JWTLessonIntegrationTest.java | 1.0 | digital_signature | ✅ TRUE |
| SHA-256 | DisplayUser.java | 0.9 | hashing | ✅ TRUE |
| HMAC | JWTTokenTest.java | 0.85 | token auth | ✅ TRUE |
| MD5 | HashingAssignment.java | 0.9 | hashing | ✅ TRUE |
| Base64 | CryptoIntegrationTest.java | 0.9 | encoding | ❌ FALSE |
| CRYPTO_IMPORT | CryptoIntegrationTest.java | 0.8 | library import | ❌ FALSE (RULE) |

**Waktu:** ~20-40 menit untuk 12 findings (1-2 menit per finding)

### Step 1.2: Siapkan annotator

Berikan kepada setiap annotator:
1. **Annotation Guide** — `docs/ANNOTATION_GUIDE.md` (baca full)
2. **Annotation Dataset** — `annotation_dataset.csv`
3. **Contoh** — section "Training Findings" di ANNOTATION_GUIDE.md

---

## 👥 Tahap 2: Anotasi oleh Annotator A1 & A2

### Step 2.1: Annotator A1 bekerja

```
Total waktu: ~30-50 menit
  - Reading guide + training: ~20-25 menit
  - Annotate 12 findings: ~15-25 menit (1-2 menit per finding)
```

**Apa yang A1 isi di CSV:**

| Kolom | Contoh dari dataset |
|-------|--------|
| `verdict` | TRUE atau FALSE |
| `algorithm_category` | Asymmetric / Symmetric / Hash / Key-Deriv |
| `confidence_percent` | 100 |
| `notes` | "RSA-2048 for JWT digital signature in test file" |
| `time_spent_seconds` | 60 |
| `date_annotated` | 2026-04-15 |

**Instruksi untuk Annotator A1:**
1. Baca `docs/ANNOTATION_GUIDE.md` lengkap (20 menit) — **PENTING: fokus pada training findings dari WebGoat**
2. Latihan dengan 5 training findings di bagian Bagian 10 (10 menit)
3. Buka `eval_results/annotation_dataset.csv` di Excel/Google Sheets
4. Untuk setiap finding, isi: verdict, category, confidence, notes
5. **JANGAN TEBAK** — jika ragu tentang Base64 vs crypto, tanya koordinator
6. Catat alasan untuk setiap FALSE verdict di kolom notes

**Output:** `annotation_dataset_A1.csv` (terisi)

### Step 2.2: Annotator A2 bekerja (INDEPENDEN)

**PENTING:** A2 harus bekerja **tanpa tahu hasil A1** (blind annotation).

- A2 dapat berbeda dengan A1 → ini normal
- Cohen's κ akan mengukur perbedaan itu
- Jangan diskusikan dengan A1 sampai selesai

**Output:** `annotation_dataset_A2.csv` (terisi)

---

## 📊 Tahap 3: Merge & Compute Cohen's κ

### Step 3.1: Gabungkan hasil A1 & A2

```bash
# Assume:
# - annotation_dataset_A1.csv (A1 selesai)
# - annotation_dataset_A2.csv (A2 selesai)

# Gabung ke satu file
cat annotation_dataset_A1.csv annotation_dataset_A2.csv > annotation_dataset_merged.csv
```

### Step 3.2: Compute Cohen's κ

```bash
python scripts/compute_cohens_kappa.py \
    --annotated-csv annotation_dataset_merged.csv \
    --output kappa_report.json \
    --report kappa_report.txt
```

**Output:**
- `kappa_report.json` — metrics in JSON
- `kappa_report.txt` — human-readable report

**Contoh output:**

```
╔════════════════════════════════════════════════════════════╗
║           COHEN'S κ INTER-RATER AGREEMENT REPORT           ║
╚════════════════════════════════════════════════════════════╝

Cohen's κ:                    0.7523
Interpretation:               Substantial agreement

Observed Agreement:           82.0% (41/50)
Expected Agreement (chance):  54.0%

Total Findings Annotated:     50

CONTINGENCY TABLE (A1 vs A2)
                     A2=TRUE    A2=FALSE
  A1=TRUE              18         2
  A1=FALSE             1          29
```

---

## 📝 Tahap 4: Analisis & Paper Update

### Step 4.1: Interprestasi κ

| κ value | Status | Paper claim |
|---------|--------|-------------|
| κ < 0.20 | ❌ Slight | "Annotators showed only slight agreement" → **Perlu training ulang** |
| κ 0.20-0.40 | ⚠️ Fair | "Fair inter-rater agreement" → **Acceptable, tapi catat limitasi** |
| κ 0.40-0.60 | 🟡 Moderate | "Moderate inter-rater agreement" → **Good baseline** |
| κ 0.60-0.80 | ✅ Substantial | "Substantial inter-rater agreement" → **RECOMMENDED** |
| κ > 0.80 | ✅✅ Perfect | "Near-perfect inter-rater agreement" → **Excellent** |

**Target untuk paper:** κ > 0.60 (substantial agreement)

### Step 4.2: Analisis disagreement

Jika κ < 0.60:
1. Lihat findings dimana A1 ≠ A2
2. Categorize penyebab:
   - **False negative** (A1 missed a TRUE) → guide kurang jelas
   - **False positive** (A1 labeled TRUE yang seharusnya FALSE) → edge case tidak di-cover
   - **Category mismatch** → definisi kategori tidak jelas

3. Options:
   - **Revise guide** + re-annotate (jika penyebabnya guide)
   - **Mark as limitation** di paper (jika inherent ambiguity)
   - **Expand training** + re-annotate (jika annotator lupa)

### Step 4.3: Update paper

#### Section: Methodology → Ground Truth Validation

```markdown
## Ground Truth Validation (Inter-Rater Agreement)

To ensure the reliability of our ground truth labels, we conducted 
inter-rater agreement testing using Cohen's κ. Two independent annotators 
(A1, A2) manually validated 12 crypto findings detected by CryptoDep-LLM 
in the WebGoat test repository, classifying each as true positive (TP) or 
false positive (FP) with corresponding algorithm category (Asymmetric, 
Symmetric, Hash, Key-Derivation, or Other).

**Results:**
- Cohen's κ = [INSERT VALUE from kappa_report.txt]
- Observed agreement: [INSERT %] ([INSERT count]/12 findings)
- Interpretation: [INSERT: Substantial/Moderate/Fair agreement]
- Confidence: [INSERT mean confidence from report]

Findings included algorithms: RSA-2048, SHA-256, HMAC, MD5, Base64, 
SHA256withRSA, and library imports. This κ value indicates that the 
crypto detection ground truth is sufficiently reliable for quantitative 
evaluation.
```

#### Section: Results → Evaluation

```markdown
### F1 Score, Precision, Recall

Using the ground truth validated at κ = 0.75, we computed:
- Edge F1: 0.847 ± 0.032
- Node Precision: 0.92
- Node Recall: 0.88
```

---

## 🔄 Tahap 5: Jika κ Rendah (<0.60)

### Scenario: κ < 0.60 (unlikely dengan CRYPTO_IMPORT rule)

**Deterministic rules implemented:**
- ✅ CRYPTO_IMPORT → ALWAYS FALSE (no annotator judgment)
- ✅ Base64 → ALWAYS FALSE (encoding, not crypto)
- ✅ RSA-2048, SHA-256, HMAC, MD5 → TRUE (clear operations in code context)

With these rules, **κ should be 0.85–0.95** (near-perfect).

**If κ < 0.80 (unexpected):**

1. **Audit disagreement:**
   ```bash
   # View kappa_report.txt
   # Lihat contingency table: mana yang A1≠A2?
   # Expected to be NONE if rules followed
   ```

2. **Most likely cause: Annotator didn't follow CRYPTO_IMPORT rule**
   - A1 or A2 labeled CRYPTO_IMPORT as TRUE (despite guide saying ALWAYS FALSE)
   - Solution: lightweight re-training, clarify rule, re-annotate just that 1 finding

3. **Other potential disagreement: MD5 deprecated status**
   - Some annotators skip deprecated algorithms
   - Solution: clarify in guide: "Deprecated = still TRUE, mark in notes"

4. **If κ still < 0.60:**
   - Likely indicates annotators didn't read guide carefully
   - Action: stronger training, verify they did Bagian 10 (training findings)
   - Re-annotate full dataset with strict check-in

---

## 📂 Direktori Structure

```
docs/
  ├─ ANNOTATION_GUIDE.md           ← Baca ini dulu
  ├─ ANNOTATION_WORKFLOW.md        ← You are here
  └─ annotation_template.csv       ← Template (jangan edit)

eval_results/
  ├─ cdg_output.json              ← CDG dari pipeline
  ├─ annotation_dataset.json      ← Generated findings (JSON)
  ├─ annotation_dataset.csv       ← Generated findings (CSV)
  ├─ annotation_dataset_A1.csv    ← Hasil A1 (terisi)
  ├─ annotation_dataset_A2.csv    ← Hasil A2 (terisi)
  ├─ annotation_dataset_merged.csv ← Gabungan A1+A2
  ├─ kappa_report.json            ← Cohen's κ metrics
  └─ kappa_report.txt             ← Cohen's κ human-readable

scripts/
  ├─ generate_annotation_dataset.py   ← Generate findings
  ├─ compute_cohens_kappa.py         ← Compute κ
  └─ ... (other scripts)
```

---

## 🚀 Quick Start (Copy-Paste)

```bash
# ✅ 1. Dataset sudah generated
ls eval_results/annotation_dataset.csv

# 2. [Share dengan Annotator A1]
#    FILE: eval_results/annotation_dataset.csv
#    GUIDE: docs/ANNOTATION_GUIDE.md (baca sampai habis)
#    TIME: ~30-40 menit (12 findings)

# 3. [Annotator A1 selesai, save as annotation_dataset_A1.csv]
# 4. [Share SAMA dengan Annotator A2 - BLIND, jangan lihat A1]
# 5. [Annotator A2 selesai, save as annotation_dataset_A2.csv]

# 6. Merge hasil
cat eval_results/annotation_dataset_A1.csv \
    eval_results/annotation_dataset_A2.csv \
    > eval_results/annotation_dataset_merged.csv

# 7. Compute Cohen's κ
/home/girnot/.venvs/cryptodep/bin/python scripts/compute_cohens_kappa.py \
    --annotated-csv eval_results/annotation_dataset_merged.csv \
    --output eval_results/kappa_report.json \
    --report eval_results/kappa_report.txt

# 8. Lihat hasil
cat eval_results/kappa_report.txt

# 9. Update paper dengan κ value
#    Lihat template di Step 4.3 di atas
```

---

## ✅ Checklist Sebelum Paper Submit

- [ ] Cohen's κ computed (dari kappa_report.txt)
- [ ] Hasil menunjukkan: κ value, agreement %, contingency table
- [ ] Jika κ ≥ 0.60: "Substantial inter-rater agreement"
- [ ] Jika κ 0.40-0.60: "Moderate inter-rater agreement" + discuss ambiguities
- [ ] Paper Section 4 (Methodology): dokumentasi agreement testing (gunakan template Step 4.3)
- [ ] Paper Section 6 (Results): reference "validated at κ = [value]"
- [ ] κ value, n=12, dan interpretation dalam paper
- [ ] Jika disagreement tinggi, catat edge cases (Base64 encoding, CRYPTO_IMPORT ambiguity)

---

## 📞 Troubleshooting

### Error: "Invalid verdict"
**Penyebab:** CSV punya "True" atau "true" bukannya "TRUE"
**Fix:** Edit CSV, standardize ke semua caps

### Error: "annotator_id not A1/A2"
**Penyebab:** CSV punya A3, A4, atau typo
**Fix:** Pastikan hanya A1 dan A2

### κ = nan atau error
**Penyebab:** Semua findings labeled same (semua TRUE atau semua FALSE)
**Fix:** Jika dataset bias, re-generate dengan `--seed` berbeda

---

## 📖 Reference

- **Cohen, J.** (1960). "A coefficient of agreement for nominal scales." *Educational and Psychological Measurement*, 20(1), 37–46.
- **sklearn.metrics.cohen_kappa_score:** https://scikit-learn.org/stable/modules/generated/sklearn.metrics.cohen_kappa_score.html
- **Interpretation guide:** Landis, J. R., & Koch, G. G. (1977). "The measurement of observer agreement for categorical data"

---

**Selamat melakukan inter-rater agreement! 🎯**
