"""Unit tests for cryptodep/tools/sqlite_tools.py"""
from __future__ import annotations

import sqlite3

import pytest

from cryptodep.tools.sqlite_tools import (
    get_connection,
    init_schema,
    save_cdg,
    load_latest_cdg,
    load_cdg_by_run_id,
    list_runs,
)
from cryptodep.schema.cdg_models import (
    CDGDocument,
    CDGEdge,
    CDGEdgeType,
    CryptoAlgorithmNode,
    MigrationPlan,
    MigrationPriority,
    NistQuantumVulnClass,
)


def _make_doc(run_id: str = "run-1", repo: str = "repo/a") -> CDGDocument:
    node = CryptoAlgorithmNode(
        label="RSA-2048",
        algorithm_family="RSA",
        parameter_set="RSA-2048",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
        migration_priority=MigrationPriority.CRITICAL,
    )
    edge = CDGEdge(
        edge_type=CDGEdgeType.MIGRATES_TO,
        source_id=node.node_id,
        target_id="cdg:node:pqc:ML-KEM-768",
        confidence=1.0,
    )
    return CDGDocument(
        target_repo={"path": repo},
        scan_stats={"run_id": run_id},
        nodes=[node.model_dump(mode="json")],
        edges=[edge],
        migration_plan=MigrationPlan(total_vulnerable_assets=1),
    )


@pytest.fixture
def conn():
    """In-memory SQLite connection with schema initialized."""
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_schema(c)
    yield c
    c.close()


def test_init_schema_idempotent(conn):
    """Calling init_schema twice must not raise and must create all 3 tables."""
    init_schema(conn)  # second call
    tables = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"cdg_runs", "cdg_nodes", "cdg_edges"}.issubset(tables)


def test_save_and_load_round_trip(conn):
    """Save a CDGDocument then load it back — nodes, edges, migration_plan survive."""
    doc = _make_doc(run_id="run-abc", repo="repo/webgoat")
    save_cdg(conn, "run-abc", doc, "repo/webgoat")

    loaded = load_cdg_by_run_id(conn, "run-abc")
    assert loaded.nodes == doc.nodes
    assert len(loaded.edges) == len(doc.edges)
    assert loaded.migration_plan.total_vulnerable_assets == 1


def test_load_latest_by_repo(conn):
    """load_latest_cdg with repo_path returns only that repo's latest run."""
    doc_a = _make_doc(run_id="run-1", repo="repo/a")
    doc_b = _make_doc(run_id="run-2", repo="repo/b")
    save_cdg(conn, "run-1", doc_a, "repo/a")
    save_cdg(conn, "run-2", doc_b, "repo/b")

    loaded = load_latest_cdg(conn, repo_path="repo/a")
    assert loaded.scan_stats["run_id"] == "run-1"


def test_load_by_run_id_not_found(conn):
    """load_cdg_by_run_id raises ValueError for unknown run_id."""
    with pytest.raises(ValueError, match="No CDG run found"):
        load_cdg_by_run_id(conn, "nonexistent-id")


def test_upsert_overwrites(conn):
    """Saving the same run_id twice leaves exactly one row in cdg_runs."""
    doc = _make_doc(run_id="run-dup")
    save_cdg(conn, "run-dup", doc, "repo/x")
    save_cdg(conn, "run-dup", doc, "repo/x")

    count = conn.execute(
        "SELECT COUNT(*) FROM cdg_runs WHERE run_id = 'run-dup'"
    ).fetchone()[0]
    assert count == 1
