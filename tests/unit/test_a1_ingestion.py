from __future__ import annotations

import asyncio
import pathlib
import pytest

from cryptodep.config import CryptoDependConfig
from cryptodep.agents.a1_ingestion import CodeIngestionAgent

FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"


def _make_state(repo_path: str) -> dict:
    config = CryptoDependConfig(neo4j_password="test")
    return {
        "repo_path": repo_path,
        "config": config,
        "run_id": "test-run-a1",
        "file_index": {},
        "ast_cache": {},
        "import_graph": {},
        "repo_stats": {"total_files": 0, "total_loc": 0, "languages": {}},
        "raw_crypto_findings": [],
        "validated_findings": [],
        "candidate_edges": [],
        "validated_edges": [],
        "cdg_document": None,
        "neo4j_import_stats": {},
        "cbom_export_path": "",
        "migration_plan": None,
        "report_md": "",
        "errors": [],
        "agent_timings": {},
        "total_llm_tokens": 0,
    }


def test_a1_populates_file_index():
    config = CryptoDependConfig(neo4j_password="test")
    agent = CodeIngestionAgent(config)
    state = _make_state(str(FIXTURES))
    result = asyncio.run(agent.run(state))
    # 9 fixture files total (5 java + 4 python; 2 added in M6 for reachability fixtures)
    assert len(result["file_index"]) == 9


def test_a1_file_index_has_correct_fields():
    config = CryptoDependConfig(neo4j_password="test")
    agent = CodeIngestionAgent(config)
    state = _make_state(str(FIXTURES))
    result = asyncio.run(agent.run(state))
    for fi in result["file_index"].values():
        assert "path" in fi
        assert "language" in fi
        assert "size_bytes" in fi
        assert "loc" in fi
        assert fi["language"] in ("java", "python")


def test_a1_populates_repo_stats():
    config = CryptoDependConfig(neo4j_password="test")
    agent = CodeIngestionAgent(config)
    state = _make_state(str(FIXTURES))
    result = asyncio.run(agent.run(state))
    stats = result["repo_stats"]
    assert stats["total_files"] == 9
    assert stats["total_loc"] > 0
    assert "java" in stats["languages"]
    assert "python" in stats["languages"]


def test_a1_populates_import_graph():
    config = CryptoDependConfig(neo4j_password="test")
    agent = CodeIngestionAgent(config)
    state = _make_state(str(FIXTURES))
    result = asyncio.run(agent.run(state))
    assert set(result["import_graph"].keys()) == set(result["file_index"].keys())
    # AuthService.java has >=3 imports
    auth_key = next(k for k in result["import_graph"] if "AuthService" in k)
    assert len(result["import_graph"][auth_key]) >= 3


def test_a1_graceful_skip_on_bad_file(tmp_path):
    """A1 must not crash when a file can't be parsed — AC-A1-01."""
    config = CryptoDependConfig(neo4j_password="test")
    agent = CodeIngestionAgent(config)
    bad = tmp_path / "Bad.java"
    bad.write_bytes(b"\x00\x01\x02\x03")
    (tmp_path / "Good.java").write_text("public class Good {}")

    state = _make_state(str(tmp_path))
    result = asyncio.run(agent.run(state))
    assert isinstance(result["file_index"], dict)


def test_a1_records_agent_timing():
    config = CryptoDependConfig(neo4j_password="test")
    agent = CodeIngestionAgent(config)
    state = _make_state(str(FIXTURES))
    result = asyncio.run(agent.run(state))
    assert "A1:CodeIngestion" in result["agent_timings"]
    assert result["agent_timings"]["A1:CodeIngestion"] > 0
