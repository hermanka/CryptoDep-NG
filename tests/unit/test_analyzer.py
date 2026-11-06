from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from cryptodep.analysis.analyzer import CBOMAnalyzer

FIXTURE_CBOM = {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
    "version": 1,
    "metadata": {"timestamp": "2026-04-23T10:00:00+00:00"},
    "components": [
        {
            "bom-ref": "cdg:node:aaaa-rsa",
            "name": "RSA-2048",
            "type": "cryptographic-asset",
            "properties": [
                {"name": "cryptodep:algorithm_family", "value": "RSA"},
                {"name": "cryptodep:migration_priority", "value": "MigrationPriority.CRITICAL"},
                {"name": "cryptodep:quantum_vuln_class", "value": "NistQuantumVulnClass.QUANTUM_VULNERABLE"},
            ],
        },
        {
            "bom-ref": "cdg:node:bbbb-aes",
            "name": "AES-128",
            "type": "cryptographic-asset",
            "properties": [
                {"name": "cryptodep:algorithm_family", "value": "AES"},
                {"name": "cryptodep:migration_priority", "value": "MigrationPriority.HIGH"},
                {"name": "cryptodep:quantum_vuln_class", "value": "NistQuantumVulnClass.GROVER_WEAKENED"},
            ],
        },
        {
            "bom-ref": "cdg:node:cccc-app",
            "name": "AuthService",
            "type": "library",
            "properties": [],
        },
        {
            "bom-ref": "cdg:node:pqc:ML-KEM-768",
            "name": "ML-KEM-768",
            "type": "cryptographic-asset",
            "properties": [
                {"name": "cryptodep:algorithm_id", "value": "PQCAlgorithmId.ML_KEM_768"},
                {"name": "cryptodep:fips_standard", "value": "FIPS 203"},
            ],
        },
    ],
    "dependencies": [
        {"ref": "cdg:node:aaaa-rsa"},
        {"ref": "cdg:node:bbbb-aes"},
        {"ref": "cdg:node:cccc-app"},
    ],
}


def make_cbom_file(tmp_path: Path, run_id_prefix: str = "abcd1234") -> Path:
    """Write fixture CBOM to a temp file named cbom_{prefix}.json."""
    p = tmp_path / f"cbom_{run_id_prefix}.json"
    p.write_text(json.dumps(FIXTURE_CBOM))
    return p


def make_sqlite_db(tmp_path: Path, run_id: str = "abcd1234-0000-0000-0000-000000000000") -> Path:
    """Create SQLite db with fixture nodes + edges."""
    db_path = tmp_path / "cdg_store.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE cdg_runs (
        run_id TEXT, repo_path TEXT, created_at TEXT, node_count INTEGER,
        edge_count INTEGER, cdg_json TEXT)""")
    conn.execute("""CREATE TABLE cdg_nodes (
        run_id TEXT, node_id TEXT, node_type TEXT, label TEXT,
        algorithm_family TEXT, quantum_vuln_class TEXT,
        migration_urgency_score REAL, source_ref TEXT, confidence REAL, node_json TEXT)""")
    conn.execute("""CREATE TABLE cdg_edges (
        run_id TEXT, edge_id TEXT, source_id TEXT, target_id TEXT,
        edge_type TEXT, confidence REAL, evidence TEXT)""")
    conn.execute(
        "INSERT INTO cdg_runs VALUES (?,?,?,?,?,?)",
        (run_id, "/test/repo", "2026-04-23T10:00:00", 3, 1, "{}"),
    )
    conn.execute(
        "INSERT INTO cdg_nodes VALUES (?,?,?,?,?,?,?,?,?,?)",
        (run_id, "cdg:node:cccc-app", "AppComponent", "AuthService", None, None, None, "src/Auth.java:10", 0.9, "{}"),
    )
    conn.execute(
        "INSERT INTO cdg_nodes VALUES (?,?,?,?,?,?,?,?,?,?)",
        (run_id, "cdg:node:aaaa-rsa", "CryptoAlgorithm", "RSA-2048", "RSA", "quantum_vulnerable", 90.0, "src/Auth.java:15", 0.95, "{}"),
    )
    conn.execute(
        "INSERT INTO cdg_edges VALUES (?,?,?,?,?,?,?)",
        (run_id, "edge-001", "cdg:node:cccc-app", "cdg:node:aaaa-rsa", "uses", 0.9, "AuthService uses RSA-2048"),
    )
    conn.commit()
    conn.close()
    return db_path


# ── Task 2: load() tests ──────────────────────────────────────────────────────

def test_load_parses_cbom(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    assert len(analyzer._components) == 4
    assert analyzer._run_id == "abcd1234"


def test_load_opens_sqlite_by_run_id(tmp_path):
    run_id = "abcd1234-0000-0000-0000-000000000000"
    cbom_path = make_cbom_file(tmp_path, run_id_prefix="abcd1234")
    db_path = make_sqlite_db(tmp_path, run_id=run_id)
    analyzer = CBOMAnalyzer(cbom_path, db_path=db_path)
    analyzer.load()
    assert analyzer._has_sqlite is True
    assert len(analyzer._nodes) == 2
    assert len(analyzer._edges) == 1


def test_load_no_sqlite_fallback_skipped(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    assert analyzer._has_sqlite is False


def test_load_anti_poisoning_wrong_run_id(tmp_path):
    cbom_path = make_cbom_file(tmp_path, run_id_prefix="abcd1234")
    db_path = make_sqlite_db(tmp_path, run_id="deadbeef-0000-0000-0000-000000000000")
    analyzer = CBOMAnalyzer(cbom_path, db_path=db_path)
    analyzer.load()
    assert analyzer._has_sqlite is False
    assert analyzer._nodes == []
    assert analyzer._edges == []


# ── Task 3: Sections A + B ────────────────────────────────────────────────────

def test_section_a_executive_summary(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert "# CryptoDep Analysis Report" in report
    assert "Algorithms detected" in report
    assert "CRITICAL" in report


def test_section_b_risk_table_enum_normalized(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert "MigrationPriority.CRITICAL" not in report
    assert "NistQuantumVulnClass.QUANTUM_VULNERABLE" not in report
    assert "CRITICAL" in report
    assert "QUANTUM_VULNERABLE" in report
    assert "RSA-2048" in report


def test_section_b_sorted_by_priority(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert report.index("RSA-2048") < report.index("AES-128")


# ── Task 4: Section C ─────────────────────────────────────────────────────────

def test_section_c_component_map_with_sqlite(tmp_path):
    run_id = "abcd1234-0000-0000-0000-000000000000"
    cbom_path = make_cbom_file(tmp_path, run_id_prefix="abcd1234")
    db_path = make_sqlite_db(tmp_path, run_id=run_id)
    analyzer = CBOMAnalyzer(cbom_path, db_path=db_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert "## Component Map" in report
    assert "AuthService" in report
    assert "RSA-2048" in report
    assert "uses" in report


def test_section_c_absent_without_sqlite(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert "## Component Map" not in report


def test_section_c_absent_when_run_id_mismatch(tmp_path):
    cbom_path = make_cbom_file(tmp_path, run_id_prefix="abcd1234")
    db_path = make_sqlite_db(tmp_path, run_id="deadbeef-0000-0000-0000-000000000000")
    analyzer = CBOMAnalyzer(cbom_path, db_path=db_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert "## Component Map" not in report
    assert "AuthService" not in report


# ── Task 5: Section D ─────────────────────────────────────────────────────────

def test_section_d_rsa_recommendation(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    report = analyzer.build_base_report()
    assert "## PQC Migration Recommendations" in report
    assert "RSA-2048" in report
    assert "ML-KEM-768" in report


def test_section_d_not_required_excluded(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    report = analyzer.build_base_report()
    section_d_start = report.find("## PQC Migration Recommendations")
    assert section_d_start != -1
    section_d = report[section_d_start:]
    # AES-128 is HIGH — should appear with action
    assert "AES-128" in section_d


# ── Task 6: enrich_with_llm ───────────────────────────────────────────────────

from unittest.mock import AsyncMock, patch


def test_enrich_with_llm_returns_section_e(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    with patch(
        "cryptodep.analysis.analyzer.call_llm",
        new_callable=AsyncMock,
        return_value="## Deep Analysis\n\nThis is the LLM narrative.",
    ):
        section_e = analyzer.enrich_with_llm(object())
    assert "## Deep Analysis" in section_e
    assert "LLM narrative" in section_e


def test_enrich_with_llm_failure_returns_warning(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    analyzer.load()
    with patch(
        "cryptodep.analysis.analyzer.call_llm",
        new_callable=AsyncMock,
        side_effect=Exception("API error"),
    ):
        section_e = analyzer.enrich_with_llm(object())
    assert "Deep analysis unavailable" in section_e


# ── Task 7: write() orchestrator ─────────────────────────────────────────────

def test_write_creates_default_output(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    result_path = analyzer.write()
    expected = cbom_path.parent / "cbom_abcd1234_analysis.md"
    assert result_path == expected
    assert result_path.exists()
    assert "# CryptoDep Analysis Report" in result_path.read_text()


def test_write_custom_output_path(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    out = tmp_path / "my_report.md"
    result_path = analyzer = CBOMAnalyzer(cbom_path)
    result_path = analyzer.write(output_path=out)
    assert result_path == out
    assert out.exists()


def test_write_deep_appends_section_e(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    analyzer = CBOMAnalyzer(cbom_path)
    with patch(
        "cryptodep.analysis.analyzer.call_llm",
        new_callable=AsyncMock,
        return_value="## Deep Analysis\n\nNarrative here.",
    ):
        result_path = analyzer.write(deep=True, config=object())
    content = result_path.read_text()
    assert "## Deep Analysis" in content
    assert "# CryptoDep Analysis Report" in content


# ── Task 8: CLI command ───────────────────────────────────────────────────────

from typer.testing import CliRunner
from cryptodep.cli import app


def test_cli_analyze_basic(tmp_path):
    cbom_path = make_cbom_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["analyze", str(cbom_path)])
    assert result.exit_code == 0, result.output
    out_file = cbom_path.parent / "cbom_abcd1234_analysis.md"
    assert out_file.exists()
    assert "# CryptoDep Analysis Report" in out_file.read_text()


def test_cli_analyze_missing_file(tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["analyze", str(tmp_path / "missing.json")])
    assert result.exit_code != 0
