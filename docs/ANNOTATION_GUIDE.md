# Annotation Guide — CryptoDep-LLM Ground Truth Inter-Rater Agreement

**Version:** 2.0 (aligned with paper §6.1)
**Purpose:** Two domain experts independently annotate ground truth items to measure
inter-rater reliability via Cohen's κ. Results are reported in Section 6.1 of the paper.

---

## Overview: Two Annotation Tasks

| Task | What to annotate | Label options | Items |
|------|-----------------|---------------|-------|
| **Task 1** | `quantum_vuln_class` for each `CryptoAlgorithmNode` | QV / GW / QSS / QSPQC | 10 nodes |
| **Task 2** | Edge presence in ground truth | PRESENT / ABSENT | 32 candidate edges |

Annotators work **independently** — do not discuss verdicts until both finish.
A third expert adjudicates all disagreements.

---

## Task 1: Quantum Vulnerability Classification

### Label Definitions

| Label | Full name | When to use | Examples |
|-------|-----------|-------------|---------|
| **QV** | `quantum_vulnerable` | Public-key algorithm broken by Shor's algorithm | RSA, ECDH, ECDSA, DSA, DH, ECC |
| **GW** | `grover_weakened` | Symmetric/hash algorithm whose effective security is halved by Grover's algorithm AND key/digest size is below PQ-safe threshold | AES-128, SHA-1, HMAC-SHA1 |
| **QSS** | `quantum_safe_symmetric` | Symmetric or hash algorithm that is quantum-safe at current key size, OR already considered broken classically (MD5, SHA-1) but not susceptible to Shor's | AES-256, SHA-256, SHA-3, HMAC-SHA256, BCrypt, MD5 |
| **QSPQC** | `quantum_safe_pqc` | Already a NIST-standardized PQC algorithm | ML-KEM, ML-DSA, SLH-DSA, FN-DSA |

### Decision Tree

```
Is it a public-key algorithm (RSA / ECC / ECDH / ECDSA / DSA / DH)?
  YES → QV

Is it already a NIST PQC standard (ML-KEM / ML-DSA / SLH-DSA / FN-DSA)?
  YES → QSPQC

Is it symmetric or hash-based AND key/digest size below PQ threshold?
  (AES < 256-bit, SHA < 384-bit, HMAC with SHA-1 base)
  YES → GW

Otherwise (quantum-safe symmetric, hash, or KDF):
  → QSS
```

### Boundary Cases (where annotators may disagree)

| Algorithm | Boundary reason | Paper's classification |
|-----------|----------------|----------------------|
| HMAC (generic) | Depends on underlying hash; HMAC-SHA1 is GW, HMAC-SHA256 is QSS | QSS (when context is JWT HS256 = SHA-256 based) |
| SHA-256 | Grover halves from 256→128 bits; 128-bit PQ security is still acceptable | QSS |
| MD5 | Already broken classically; quantum risk is secondary | QSS |
| SHA-1 | Already broken classically; technically GW if used in HMAC | QSS (classical break dominates) |

> **Adjudication rule:** When annotators disagree on a boundary case, the adjudicator
> applies the decision tree strictly. The `quantum_vuln_class` field in CDG Schema v1.0
> (§4.3 of paper) is the authoritative reference.

---

## Task 2: Edge Presence Annotation

### What is an "edge" in this context?

A dependency edge represents a directed relationship in the Crypto Dependency Graph:

```
AppComponent  --uses-->         CryptoLibrary
CryptoLibrary --implements-->   CryptoAlgorithm
CryptoAlgorithm --migrates_to--> PQCAlgorithm
```

### Label Definitions

| Label | When to use |
|-------|-------------|
| **PRESENT** | The dependency relationship genuinely exists in the source code — there is an import statement, API call, or direct usage that creates this relationship |
| **ABSENT** | The relationship does not exist or cannot be verified from source code — the edge would be speculative, skip a layer, or use the wrong edge type |

### Decision Criteria

Mark **PRESENT** if ALL of the following hold:
- ✓ The source file/class **imports or directly calls** the target library or algorithm
- ✓ The edge type correctly describes the relationship (uses / implements / migrates_to)
- ✓ The dependency chain does not skip a layer (e.g., AppComponent directly --implements--> Algorithm skips the Library layer)

Mark **ABSENT** if ANY of the following:
- ✗ No import statement in source file for the target
- ✗ The edge skips a layer in the dependency chain
- ✗ Wrong edge type used (e.g., `uses` where `implements` is correct)
- ✗ The dependency is transitive/indirect with no direct import evidence

### Decoy Edge Examples (ABSENT)

These are candidate edges that look plausible but are structurally incorrect:

```
# ABSENT — skips library layer (should go via java.security)
HashingAssignment --implements--> MD5

# ABSENT — wrong edge type (AppComponent does not "implement" algorithms)
DisplayUser --implements--> SHA-256

# ABSENT — indirect dependency, no direct import in views.py
views --uses--> jwt   (if views.py imports hashlib but not jwt directly)
```

---

## Annotation Procedure

### Step 1 — Task 1 (Node Classification)
For each `CryptoAlgorithmNode` in the annotation dataset:
1. Read the algorithm name and benchmark context
2. Apply the decision tree above
3. Record your `quantum_vuln_class` label

### Step 2 — Task 2 (Edge Presence)
For each candidate edge in the annotation dataset:
1. Read the source, edge type, and target
2. Check: does this import/call relationship exist in the source code?
3. Record PRESENT or ABSENT

### Step 3 — Adjudication
After both annotators finish:
1. Compare verdicts item by item
2. For each disagreement, the third expert reviews the source code and CDG schema
3. The adjudicated verdict becomes the official GT label

---

## Cohen's κ Interpretation (Landis & Koch 1977)

| κ range | Interpretation |
|---------|---------------|
| < 0.00 | Poor (worse than chance) |
| 0.00–0.20 | Slight |
| 0.21–0.40 | Fair |
| 0.41–0.60 | Moderate |
| 0.61–0.80 | Substantial ← minimum acceptable for this annotation |
| 0.81–1.00 | Almost perfect |

**Target for this study:** κ > 0.75 for each task (above "substantial" threshold).

---

## Reference

Landis, J.R. and Koch, G.G. (1977). The measurement of observer agreement for
categorical data. *Biometrics*, 33(1), 159–174.
