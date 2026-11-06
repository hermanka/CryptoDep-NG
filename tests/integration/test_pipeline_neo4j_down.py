"""Integration test: pipeline completes successfully when Neo4j is unreachable.

This test verifies AC: A4 writes CDG to SQLite even when Neo4j is down.
Neo4j is pointed at a port that is guaranteed to be closed (19999).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cryptodep.config import CryptoDependConfig
from cryptodep.pipeline import build_pipeline
from cryptodep.tools.sqlite_tools import get_connection, load_latest_cdg

_SAMPLE_REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


@pytest.fixture
def config_neo4j_down(tmp_path):
    """Config pointing Neo4j at a dead port, SQLite in a temp dir."""
    return CryptoDependConfig(
        llm_provider="anthropic",
        neo4j_uri="bolt://localhost:19999",   # guaranteed unreachable
        neo4j_password="irrelevant",
        sqlite_db_path=str(tmp_path / "cdg_store.db"),
    )


@pytest.mark.integration
def test_pipeline_succeeds_when_neo4j_down(config_neo4j_down, tmp_path):
    """Pipeline exits with cdg_document in state and SQLite store populated,
    even when Neo4j is unreachable."""
    pipeline = build_pipeline(config_neo4j_down)
    output_path = str(tmp_path / "cdg_output.json")

    # Should NOT raise even though Neo4j is down
    final_state = pipeline.run(str(_SAMPLE_REPO), output_path=output_path)

    # Pipeline produced a CDG document
    assert final_state.get("cdg_document") is not None

    # SQLite store was written
    db_path = config_neo4j_down.sqlite_db_path
    assert Path(db_path).exists(), f"cdg_store.db not found at {db_path}"

    conn = get_connection(db_path)
    cdg_doc = load_latest_cdg(conn)
    conn.close()
    assert cdg_doc is not None

    # Neo4j failure was logged as recoverable error, not a hard failure
    errors = final_state.get("errors", [])
    neo4j_errors = [e for e in errors if e.get("error_type") == "neo4j_unavailable"]
    assert all(e["recoverable"] for e in neo4j_errors), "Neo4j errors must be recoverable"
