# CryptoDep-NG

Based on [https://github.com/girnot/CryptoDep-LLM](https://github.com/girnot/CryptoDep-LLM)
> **LLM-Powered Crypto Dependency Graph Construction for Automated PQC Migration Planning**

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![LangGraph 0.2](https://img.shields.io/badge/langgraph-0.2-green.svg)](https://github.com/langchain-ai/langgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0--alpha-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-361%20passing-brightgreen.svg)]()

CryptoDep-LLM is a multi-agent agentic framework that **automatically discovers, maps, and prioritizes classical cryptographic dependencies** in enterprise source code. It produces a structured **Crypto Dependency Graph (CDG)** and an AI-generated **Post-Quantum Cryptography (PQC) migration roadmap** — addressing a critical gap confirmed by NIST SP 1800-38B and Checkmarx (2025).

---

## The Problem

Existing CBOM tools (IBM CBOMkit, CycloneDX) produce **flat asset inventories**. They do not answer:

- *Which business components depend on RSA-2048?*
- *Which crypto libraries are at the highest HNDL risk?*
- *What is the optimal migration order given system dependencies?*

CryptoDep-LLM constructs a **queryable dependency graph** — capturing these relationships — and generates a prioritized PQC migration plan aligned with NIST FIPS 203/204/205.

---

## Architecture

```
Repo Input
    │
    ▼
[A1: CodeIngestion]       — Tree-sitter AST parsing, file index, import graph
    │
    ▼
[A2: CryptoDetection]     — Semgrep rules + LLM escalation, finds crypto API usage
    │
    ▼
[A3: DependencyReasoning] — LLM-powered edge extraction (uses / implements / calls)
    │
    ▼
[A6: Reachability]        — BFS call graph tracer from entry points (optional, --reachability)
    │
    ▼
[A4: CDGBuilder]          — Assembles CDGDocument, writes to SQLite (primary), Neo4j (optional), CBOM export
    │
    ▼
[A5: MigrationPlanner]    — Urgency scoring, priority queue, migration report
    │
    ▼
CDG Output (JSON) + Migration Report (Markdown) + CBOM (CycloneDX v1.6)
    │
    ▼
[analyze]                 — Post-run: CBOM → human-readable Markdown report (sections A–E)
```

All agents share a typed `CDGState` (LangGraph StateGraph). No agent holds internal state between runs.

---

## Technology Stack

| Layer                 | Technology                        | Version |
| --------------------- | --------------------------------- | ------- |
| Agent orchestration   | LangGraph                         | 0.2.x   |
| LLM — primary         | Anthropic API (claude-sonnet-4-6) | latest  |
| LLM — local fallback  | Ollama + Qwen2.5-Coder-7B         | latest  |
| Static analysis       | Tree-sitter                       | 0.22.x  |
| Static analysis (opt) | Semgrep                           | 1.70+   |
| Primary storage       | SQLite (embedded)                 | 3.x     |
| Graph database (opt)  | Neo4j Community                   | 5.x     |
| Data models           | Pydantic v2                       | 2.7+    |
| CBOM export           | cyclonedx-python-lib              | 7.0+    |
| CLI framework         | Typer                             | 0.12+   |
| Package management    | uv                                | latest  |

**Supported languages:** Java 11+, Python 3.8+, and initial JavaScript support (`.js`, `.mjs`, `.cjs`).

JavaScript uses Tree-sitter for ES module/CommonJS import extraction and literal relative-module resolution. Initial Semgrep rules target Node.js `crypto`/`node:crypto` and standard Web Crypto calls with recognized literal algorithms. Findings flow through A2–A5 into the CDG, CBOM, and migration report; `node_modules` is excluded. Third-party crypto packages, TypeScript, bundler aliases, and JavaScript reachability are not yet supported. With `--reachability`, JavaScript findings remain unevaluated and use baseline priority weights rather than receiving an unreachable score.

JavaScript files are included by default; use the existing command after configuring the LLM and storage:

```bash
cryptodep run /path/to/javascript-repo --output javascript_cdg.json --report javascript_report.md
```

Targeted checks:

```bash
pytest tests/unit/test_javascript_support.py -q
semgrep --test --config cryptodep/rules/crypto-javascript.yaml tests/fixtures/javascript/crypto-javascript.js
```

---

## Prerequisites

| Requirement                                   | Version | Notes                                                           |
| --------------------------------------------- | ------- | --------------------------------------------------------------- |
| Python                                        | 3.12+   | Required                                                        |
| [uv](https://docs.astral.sh/uv/)              | latest  | Package manager                                                 |
| [Docker](https://docs.docker.com/get-docker/) | 20+     | For Neo4j (optional)                                            |
| Anthropic API key                             | —       | [Get one here](https://console.anthropic.com/)                  |
| Neo4j Community                               | 5.x     | Via Docker — **optional**; pipeline writes to SQLite by default |

---

## Installation

### Web dashboard with Docker

```bash
docker compose up -d --build
```

Open **http://localhost:8088**, configure an OpenAI-compatible endpoint, model, and optional API key in **Pengaturan AI**, then enter a public GitHub repository URL. The dashboard shows stage progress, an interactive CDG, a node list, evidence and migration suggestions, and persistent scan history. It follows [the design reference](docs/DESIGN.md); all browser assets are served locally.

The same image includes the core CLI. SQLite and scan files persist in a Docker volume; Neo4j is not required. This is a local, single-operator application. See [the Docker and dashboard guide](docs/WEB_DOCKER.md) for setup, endpoint configuration, CLI usage, data handling, and limits.

```bash
# 1. Clone the repository
git clone https://github.com/girnot/CryptoDep-LLM.git
cd CryptoDep-LLM

# 2. Install dependencies
uv sync

# 3. Configure environment
cp .env.example .env
# Edit .env and set your ANTHROPIC_API_KEY and NEO4J_PASSWORD

# 4. (Optional) Start Neo4j — pipeline writes to cdg_store.db without Neo4j
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/neo4j1234 \
  -e NEO4J_server_memory_heap_initial__size=512m \
  -e NEO4J_server_memory_heap_max__size=1G \
  -e NEO4J_server_memory_pagecache_size=512m \
  --memory=2G --memory-swap=2G \
  neo4j:5-community

# 5. Verify installation
cryptodep --help
```

---

## Quick Start — Scan a Repository

### OWASP WebGoat (Java benchmark)

```bash
git clone https://github.com/WebGoat/WebGoat.git /tmp/webgoat

# Run the full pipeline
CRYPTODEP_SKIP_NEO4J=1 cryptodep run /tmp/webgoat --output webgoat_cdg.json --verbose

# Analyze the CBOM output — human-readable report
cryptodep analyze cbom_*.json

# Evaluate against expert ground truth
cryptodep eval /tmp/webgoat \
  tests/eval/ground_truth/webgoat_gt.json \
  --predicted-cdg webgoat_cdg.json
```

### Rakshak (Java hybrid-encryption challenge test)

```bash
git clone https://github.com/GauravChaddha1996/Rakshak test_repos/rakshak

CRYPTODEP_SKIP_NEO4J=1 cryptodep run ./test_repos/rakshak --verbose
cryptodep analyze cbom_*.json --deep   # LLM-generated deep narrative
```

Expected pipeline output (Rakshak):
```
[A1] Ingested 49 files (5,012 LOC) in 1.9s
[A2] Detected 145 validated findings (RSA-2048, AES-128-ECB, SHA-1 ...)
[A4] CDG written → 22 nodes, 36 edges
[A5] Migration plan: 3 items | top priority: RSA-2048 → ML-KEM-768
[analyze] Report written → cbom_xxx_analysis.md
```

---

## CLI Reference

### `cryptodep run`

Run the full A1→A5 pipeline on a repository.

```bash
cryptodep run <REPO_PATH> [OPTIONS]

Options:
  --output PATH       CDG output JSON path          [default: cdg_output.json]
  --report PATH       Migration report Markdown path
  --db PATH           SQLite CDG store path          [default: cdg_store.db]
  --lang TEXT         Report language: en | id       [default: en]
  --local-llm         Use Ollama instead of Anthropic API
  --neo4j-uri TEXT    Neo4j connection URI           [default: bolt://localhost:7687]
  --reachability      Enable A6 crypto reachability analysis
  --skip-codeql       Skip optional CodeQL analysis
  --verbose           Show per-agent progress and token counts
```

#### A6 Reachability Analysis (`--reachability`)

A6 inserts a **call graph traversal** step between A3 and A4. It detects public entry points (REST endpoints, servlet handlers, `main()`) and traces BFS paths from each entry point to each detected crypto finding — then assigns a `reachability_score`:

| Score | Meaning |
|-------|---------|
| `1.0` | Called directly from a public entry point (1 hop) |
| `0.5` | Reached in 2 hops |
| `0.0` | Not reachable from any detected entry point |

**Why this matters — the office building analogy:**

Think of the codebase as an office building. Every visitor enters through a public door (a REST endpoint, a servlet, `main()`). `migration_urgency_score` tells you *how dangerous the contents of a safe are*. `reachability_score` tells you *whether any visitor can actually reach the room the safe is in*.

- **RSA-2048 — vault in a locked back room.** RSA-2048 scores urgency 90 because it is broken by Shor's algorithm. But A6 finds no public path leading to it — no REST endpoint, no exposed method that eventually calls this code. Like a vault full of classified documents in a room with no door for visitors. The theoretical threat is real; the practical exploitability is not.

- **MD5 — documents on the reception desk.** MD5 is called directly from a public-facing method (1 hop from an entry point). Like sensitive files left on the front desk — anyone who walks in can see them. It is not quantum-vulnerable, so urgency stays low, but it is immediately reachable.

**A6 adds a second axis:** not just *"how dangerous is the algorithm"* but *"how easily can an attacker reach it from outside."* Both dimensions are necessary for accurate prioritization.

Example — WebGoat with `--reachability`:

| Algorithm | Urgency | Reachability | Interpretation |
|-----------|---------|--------------|----------------|
| RSA-2048  | 90.0    | 0.00 | Vault in a locked room — high theoretical risk, not directly exploitable |
| MD5       | 0.0     | 1.00 | On the reception desk — not quantum-vulnerable, but immediately exposed |
| HMAC      | 0.0     | 1.00 | Quantum-safe and reachable — no action needed |

Reachability scores are embedded in each CDG node's `metadata.reachability_score` field and the entry point call chain is in `metadata.entry_point_paths`. When `--reachability` is not used, all scores default to `1.0` (neutral) — A5 priority ranking is identical to baseline.

> **Note:** A6 is only available in `cryptodep run`. The `cryptodep analyze` command works on a finished CBOM file and does not have access to the source code AST and call graph that A6 requires.

---

### `cryptodep analyze`

Analyze a CBOM JSON file and produce a human-readable Markdown report. Automatically reads `cdg_store.db` alongside the CBOM for component-level edge data.

> **Scope:** `analyze` is a post-processing command — it reads a CBOM that was already generated by `cryptodep run`. It does not re-run any agents and does not include A6 reachability data. For reachability-enriched output, use `cryptodep run --reachability` first.

```bash
cryptodep analyze <CBOM_PATH> [OPTIONS]

Options:
  --output PATH   Output Markdown path    [default: <cbom>_analysis.md]
  --db PATH       SQLite store path       [default: auto-detect cdg_store.db]
  --deep          Add LLM-generated deep analysis (section E)

# Examples
cryptodep analyze cbom_cf9e3305.json
cryptodep analyze cbom_cf9e3305.json --deep
cryptodep analyze cbom_cf9e3305.json --output reports/rakshak.md
```

**Report sections generated:**

| Section | Content                                                         | Requires |
| ------- | --------------------------------------------------------------- | -------- |
| A       | Executive summary — algo count, PQC readiness %, risk level     | CBOM     |
| B       | Algorithm risk table sorted by priority (enum-normalized)       | CBOM     |
| C       | Component → Algorithm map with edge types and confidence        | SQLite   |
| D       | PQC migration recommendations from NIST FIPS 203/204            | CBOM     |
| E       | LLM-generated narrative — risk interpretation + migration steps | `--deep` |

> **Anti-poisoning:** SQLite data is matched by exact `run_id` prefix from the CBOM filename. There is no fallback to the latest run — a CBOM from repo A will never read edge data from repo B.

### `cryptodep validate`

Validate a CDG JSON file against schema v1.0.

```bash
cryptodep validate <CDG_PATH>

cryptodep validate cdg_output.json
# ✓ CDG is valid.
```

### `cryptodep diff`

Compare two CDG snapshots — shows added/removed nodes and edges.

```bash
cryptodep diff <OLD_CDG> <NEW_CDG>

cryptodep diff cdg_v1.json cdg_v2.json
# Added nodes   (1):  ['ML-DSA-65']
# Added edges   (1):  ['ECDSA-256 --[migrates_to]--> ML-DSA-65']
```

### `cryptodep export-cbom`

Export a CDG as CycloneDX CBOM v1.6 JSON.

```bash
cryptodep export-cbom <CDG_PATH> [--output PATH]

cryptodep export-cbom cdg_output.json --output output.cdx.json
# CBOM written → output.cdx.json
```

### `cryptodep export-neo4j`

Re-export a CDG from SQLite into Neo4j.

```bash
cryptodep export-neo4j [OPTIONS]

Options:
  --db PATH           SQLite CDG store path          [default: cdg_store.db]
  --run-id UUID       Specific run to export (default: latest)
  --neo4j-uri TEXT    Neo4j connection URI           [default: bolt://localhost:7687]
```

### `cryptodep query`

Run an arbitrary Cypher query on the CDG in Neo4j.

```bash
cryptodep query "MATCH (n:CryptoAlgorithm {quantum_vuln_class: 'quantum_vulnerable'}) RETURN n.label, n.migration_urgency_score ORDER BY n.migration_urgency_score DESC"
```

### `cryptodep eval`

Run F1/MPQS evaluation against expert ground truth (5-run robustness mode by default).

```bash
cryptodep eval <REPO_PATH> <GROUND_TRUTH_PATH> [OPTIONS]

Options:
  --predicted-cdg PATH   Use a pre-generated CDG (skips pipeline run)
  --output PATH          Save evaluation results as JSON
  --runs N               Number of evaluation runs for mean ± std  [default: 5]
  --verbose              Show per-agent progress
```

---

## Evaluation Results (WebGoat, Anthropic Sonnet 4.6, N=5 runs mean ± std)

| Metric             | Mean      | Std   | Target | Status |
| ------------------ | --------- | ----- | ------ | ------ |
| Node F1            | **0.991** | 0.017 | ≥ 0.80 | ✅      |
| Edge F1            | **0.818** | 0.036 | ≥ 0.75 | ✅      |
| Multi-hop Recall   | **1.000** | 0.000 | ≥ 0.70 | ✅      |
| Spearman ρ         | **1.000** | 0.000 | ≥ 0.75 | ✅      |
| Critical Recall    | **1.000** | 0.000 | = 1.00 | ✅      |
| Hallucination Rate | **0.080** | 0.075 | < 0.15 | ✅      |

> Primary provider: Anthropic claude-sonnet-4-6. Hallucination Rate re-evaluated N=5 (2026-04-25) with corrected `scan_stats` instrumentation — individual runs: 0.091, 0.000, 0.000, 0.200, 0.111; all hallucinated edges rejected by the import-graph gate before CDG construction. Edge F1 std = 0.036 reflects residual API-level non-determinism at `temperature=0` on a 26,320-LOC multi-file repository.

### Cross-Provider Hallucination Rate (WebGoat, N=5 runs each)

| Provider / Model            | Node F1       | Edge F1           | Critical Recall   | Hallucin. Rate       | Targets |
| --------------------------- | ------------- | ----------------- | ----------------- | -------------------- | ------- |
| Anthropic Sonnet 4.6        | 0.947 ± 0.019 | 0.911 ± 0.044     | **1.000 ± 0.000** | 0.080 ± 0.075 ✅     | **6/6** |
| Ollama Cloud Gemma 4 31B    | 0.938 ± 0.023 | **0.933 ± 0.054** | **1.000 ± 0.000** | **0.000 ± 0.000** ✅ | **6/6** |
| Ollama Cloud qwen3-next:80b | 0.965 ± 0.017 | 0.827 ± 0.087     | 0.800 ± 0.400     | 0.195 ± 0.079 ❌     | 4/6     |
| Anthropic Haiku 4.5         | 0.937 ± 0.037 | 0.838 ± 0.096     | 0.600 ± 0.490     | 0.150 ± 0.200 ❌     | 3/6     |

> Hallucination Rate target: < 0.15. All hallucinated edges are rejected by A3's import-graph gate before CDG construction, regardless of provider. Gemma 4 31B achieves 6/6 targets with the highest Edge F1 (0.933) and zero hallucinations across all 5 runs. qwen3-next:80b fails Critical Recall due to consistently hallucinating `io.jsonwebtoken.SignatureAlgorithm` (absent from the repository's import graph). Haiku 4.5 fails Critical Recall on 2 of 5 runs (insufficient dependency edges). *(qwen3-next:80b: 2026-04-18; Sonnet 4.6 + Haiku 4.5 + Gemma 4 31B: 2026-04-25)*

---

## CDG Schema

### Node Types

| Node Type         | Key Attributes                                                                    | Description                                       |
| ----------------- | --------------------------------------------------------------------------------- | ------------------------------------------------- |
| `AppComponent`    | `component_type`, `language`, `file_path`, `quantum_ready`                        | Business logic component using crypto             |
| `CryptoLibrary`   | `library_name`, `package_manager`, `language`, `version`, `is_quantum_safe`       | Crypto library (javax.crypto, cryptography, etc.) |
| `CryptoAlgorithm` | `algorithm_family`, `parameter_set`, `quantum_vuln_class`, `hndl_risk`, `urgency_score` | Detected classical crypto algorithm          |
| `KeyMaterial`     | `key_type`, `key_size_bits`, `storage_type`, `hndl_risk`                          | Key material associated with an algorithm         |
| `BusinessProcess` | `criticality`, `data_lifetime_years`                                              | Business process protected by cryptography        |
| `Protocol`        | `protocol_name`, `version`, `quantum_vulnerable_handshake`, `entry_point`         | Network/app protocol (TLS, SSH, JWT)              |
| `PQCAlgorithm`    | `algorithm_id`, `fips_standard`, `nist_security_level`, `hybrid_classical_pair`   | NIST-standardized PQC replacement target          |

### Edge Types

| Edge Type     | Source → Target                    | Meaning                                         |
| ------------- | ---------------------------------- | ----------------------------------------------- |
| `uses`        | AppComponent → CryptoLibrary       | Component imports/uses a crypto library         |
| `implements`  | CryptoLibrary → CryptoAlgorithm    | Library exposes a specific algorithm            |
| `depends_on`  | AppComponent → AppComponent        | Multi-hop import graph dependency               |
| `relies_on`   | AppComponent → Protocol            | Component uses a network protocol               |
| `protects`    | KeyMaterial/Algorithm → BusinessProcess | Algorithm or key protects a business process |
| `exposes_via` | AppComponent → Protocol            | Component exposes functionality via a protocol  |
| `migrates_to` | CryptoAlgorithm → PQCAlgorithm     | Classical algorithm → NIST PQC replacement      |

### Quantum Vulnerability Classes

| Class                    | Description                              | Examples                         |
| ------------------------ | ---------------------------------------- | -------------------------------- |
| `quantum_vulnerable`     | Broken by Shor's algorithm               | RSA, ECC, ECDSA, DH, DSA, ECDH  |
| `grover_weakened`        | Weakened by Grover (key < 256 bits)      | AES-128 → upgrade to AES-256     |
| `quantum_safe_symmetric` | Secure at ≥ 256-bit key/output size      | AES-256, SHA-256, HMAC, BCRYPT   |
| `quantum_safe_pqc`       | NIST-standardized PQC target state       | ML-KEM, ML-DSA, SLH-DSA, FN-DSA |

---

## PQC Migration Recommendations

| Classical Algorithm     | NIST PQC Replacement | FIPS Standard | Hybrid Recommendation      |
| ----------------------- | -------------------- | ------------- | -------------------------- |
| RSA (key encapsulation) | ML-KEM-768           | FIPS 203      | X25519 + ML-KEM-768        |
| ECDH / DH               | ML-KEM-768           | FIPS 203      | X25519 + ML-KEM-768 (HPKE) |
| ECDSA                   | ML-DSA-65            | FIPS 204      | Ed25519 + ML-DSA-65        |
| DSA                     | ML-DSA-65            | FIPS 204      | —                          |
| RSA (signature)         | ML-DSA-65            | FIPS 204      | Ed25519 + ML-DSA-65        |

---

## Migration Urgency Score

Every `CryptoAlgorithm` node receives a `migration_urgency_score` ∈ [0, 100] computed by A4:

```
migration_urgency_score = (V + Gv) × C × D × 100 + centrality_bonus + hndl_bonus
```

| Factor             | Meaning                                    | Values                                              |
| ------------------ | ------------------------------------------ | --------------------------------------------------- |
| `V`                | Quantum vulnerability (Shor susceptibility) | 1.0 if `quantum_vulnerable`, else 0.0              |
| `Gv`               | Grover reduction (symmetric key-size < 256) | 0.4 if AES/SHA with key < 256 bits, else 0.0       |
| `C`                | Business criticality                        | critical=1.0, high=0.75, medium=0.5, low=0.25      |
| `D`                | Data lifetime exposure (Mosca's inequality) | ≥10y=1.0, ≥5y=0.8, ≥1y=0.5, <1y=0.2               |
| `centrality_bonus` | Graph betweenness centrality boost (A4)     | `graph_centrality × 20` (up to +20)                |
| `hndl_bonus`       | Harvest-Now-Decrypt-Later exposure          | +10 if `hndl_risk` and algorithm is vulnerable     |

Formula grounded in NIST SP 800-30 Rev. 1 (threat × impact × exposure) and Mosca's inequality. The multiplicative core ensures quantum-safe algorithms always score zero regardless of criticality. A5 normalizes this score to [0,1] and combines it with an additive weighted composite for final priority ranking.

---

## Configuration

Copy `.env.example` to `.env` and fill in:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...       # Anthropic API key
NEO4J_PASSWORD=password             # Neo4j password (match Docker setup)

# Optional
NEO4J_URI=bolt://localhost:7687    # Neo4j connection URI
CRYPTODEP_DEBUG=0                   # Set to 1 to dump LLM prompts/responses to logs/
CRYPTODEP_LLM_PROVIDER=anthropic   # anthropic | ollama | openrouter | groq
CRYPTODEP_ANTHROPIC_MODEL=claude-sonnet-4-6  # override default model

# Skip Neo4j preflight hard-abort (use when Docker is unavailable)
CRYPTODEP_SKIP_NEO4J=0             # Set to 1 to skip
```

### Using Local LLM (offline / privacy mode)

```bash
ollama pull qwen2.5-coder:7b
cryptodep run /path/to/repo --local-llm
```

---

## Development

```bash
# Run unit tests
pytest tests/unit/ -v

# Run targeted tests for a specific agent
pytest tests/unit/test_a2_detection.py -v

# Run full test suite
pytest tests/unit/ -q
# 361 passing, 2 warnings (Semgrep env warnings in test_spring_rules)
```

> **WSL2 note:** If `pytest` is not on PATH, use the full venv path: `~/.venvs/cryptodep/bin/pytest`

### Project Structure

```
cryptodep/
├── agents/
│   ├── a1_ingestion.py      # Code parsing, AST, import graph
│   ├── a2_detection.py      # Crypto API detection (Semgrep + LLM)
│   ├── a3_reasoning.py      # Dependency edge extraction (LLM)
│   ├── a4_builder.py        # CDG assembly, Neo4j import, CBOM export
│   ├── a5_planner.py        # Migration prioritization, report generation
│   └── a6_reachability.py   # BFS call graph tracer (--reachability)
├── analysis/
│   └── analyzer.py          # CBOMAnalyzer — CBOM → Markdown report
├── schema/
│   ├── cdg_models.py        # Pydantic models: CDGNode, CDGEdge, CDGDocument
│   ├── cdg_schema_v1.json   # JSON Schema Draft 2020-12
│   └── pqc_lookup.py        # PQC_MIGRATION_TABLE, compute_urgency_score()
├── tools/
│   ├── llm_tools.py         # call_llm() — all LLM calls go through here
│   ├── neo4j_tools.py       # Neo4j upsert, Cypher, centrality
│   ├── sqlite_tools.py      # SQLite CDG persistence
│   └── cbom_tools.py        # CycloneDX CBOM v1.6 export
├── cli.py                   # Typer CLI entry points
├── pipeline.py              # LangGraph StateGraph assembly
├── state.py                 # CDGState TypedDict definition
└── config.py                # CryptoDependConfig

tests/
├── unit/                    # Per-agent unit tests (361 passing)
├── integration/             # Full A1→A5 pipeline test
└── eval/
    ├── eval_metrics.py      # 6 PRD metrics + 5-run robustness
    └── ground_truth/
        ├── fixture_gt.json  # Synthetic fixture ground truth
        └── webgoat_gt.json  # OWASP WebGoat 8.x ground truth

test_repos/                  # Not included — clone benchmarks manually (see Quick Start)
```

---

## Known Limitations (Phase 1)

- **Languages:** Java and Python, plus initial JavaScript detection/import support. JavaScript reachability and TypeScript remain unsupported. Go, PHP, Rust, and C/C++ are future work.
- **Analysis scope:** Static analysis only — no runtime, network traffic, or binary analysis.
- **CodeQL:** Optional; requires separate CodeQL CLI installation.
- **Neo4j:** Optional. Pipeline writes to SQLite by default; Neo4j export is best-effort. Set `CRYPTODEP_SKIP_NEO4J=1` to skip the Neo4j preflight check when Docker is unavailable.
- **LLM dependency:** Semantic edge reasoning (A3) and migration planning (A5) require either Anthropic API access or a local Ollama model.
- **Custom crypto:** Hand-rolled crypto implementations (e.g., raw `BigInteger` RSA) may be missed by Semgrep rules targeting standard API calls; LLM escalation partially compensates.

---

## Roadmap

| Phase             | Features                                                                               |
| ----------------- | -------------------------------------------------------------------------------------- |
| Phase 1 (current) | Java + Python, initial JavaScript detection/imports, A1–A6 pipeline (A6: Java/Python), `analyze`, CDG, CBOM, evaluation |
| Phase 2           | JavaScript reachability; Go/PHP/Rust/C/C++ support; CI/CD integration; parallel agent execution |
| Phase 3           | Web UI, automated PQC code generation, real-time monitoring                            |

---

## Citation

If you use CryptoDep-LLM in your research, please cite:

```bibtex
@article{girinoto2026cryptodep,
  title   = {CryptoDep-LLM: Automated Cryptographic Dependency Graph Construction
              for Post-Quantum Migration Planning},
  author  = {Girinoto, Girinoto and Limbong, David Sam and Susanti, Bety Hayat},
  journal = {under review},
  year    = {2026},
  url     = {https://github.com/girnot/CryptoDep-LLM}
}
```

---

## Acknowledgments

- **NIST** — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) standards
- **OWASP WebGoat** — primary Java benchmark repository
- **Politeknik Siber dan Sandi Negara (Poltek SSN)** — Research Pillar 1: Quantum-Ready Cryptography
- **Calf Coffee Industry** Instagram: @kopicalf support this research 

---

## License

MIT License — see [LICENSE](LICENSE) for details.
