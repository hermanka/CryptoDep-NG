"""Tests for pipeline node wiring."""
from __future__ import annotations
from unittest.mock import patch


def _minimal_state(cfg):
    """Return a minimal valid CDGState dict for testing."""
    return {
        "repo_path": "/tmp",
        "config": cfg,
        "run_id": "x",
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
        "sqlite_db_path": "",
        "migration_plan": None,
        "report_md": "",
        "errors": [],
        "agent_timings": {},
        "total_llm_tokens": 0,
        "entry_points": [],
        "call_graph": {},
        "reachability_map": {},
        "reachability_paths": {},
        "reachability_mode": "disabled",
    }


def test_make_validated_node_wraps_agent():
    """_make_validated_node must return a coroutine that calls validate_state after agent.run."""
    from cryptodep.pipeline import CryptoDependPipeline
    from cryptodep.config import CryptoDependConfig

    cfg = CryptoDependConfig(neo4j_password="test")
    call_log = []

    async def fake_run(state):
        call_log.append("run")
        return state

    with patch("cryptodep.pipeline.validate_state") as mock_validate:
        wrapped = CryptoDependPipeline._make_validated_node(fake_run, "TestAgent")
        import asyncio
        state = _minimal_state(cfg)
        asyncio.run(wrapped(state))

    assert "run" in call_log, "Agent run() must be called"
    mock_validate.assert_called_once_with(state, "TestAgent")


def test_build_graph_uses_validated_nodes():
    """All graph.add_node() calls in _build_graph must use _make_validated_node."""
    from cryptodep.pipeline import CryptoDependPipeline
    from cryptodep.config import CryptoDependConfig

    cfg = CryptoDependConfig(neo4j_password="test")
    validated_calls = []

    original_make = CryptoDependPipeline._make_validated_node

    def tracking_make(agent_run, agent_name):
        validated_calls.append(agent_name)
        return original_make(agent_run, agent_name)

    with patch.object(CryptoDependPipeline, "_make_validated_node",
                      staticmethod(tracking_make)):
        pipe = CryptoDependPipeline(cfg)

    assert len(validated_calls) >= 5, (
        f"Expected at least 5 agents wrapped, got {len(validated_calls)}: {validated_calls}"
    )
    assert "A1:CodeIngestion" in validated_calls
    assert "A2:CryptoDetection" in validated_calls
    assert "A3:DependencyReasoning" in validated_calls
    assert "A4:CDGBuilder" in validated_calls
    assert "A5:MigrationPlanner" in validated_calls


def test_build_graph_wraps_a6_when_reachability_enabled():
    """A6:Reachability must also be wrapped when enable_reachability=True."""
    from cryptodep.pipeline import CryptoDependPipeline
    from cryptodep.config import CryptoDependConfig

    cfg = CryptoDependConfig(neo4j_password="test", enable_reachability=True)
    validated_calls = []
    original_make = CryptoDependPipeline._make_validated_node

    def tracking_make(agent_run, agent_name):
        validated_calls.append(agent_name)
        return original_make(agent_run, agent_name)

    with patch.object(CryptoDependPipeline, "_make_validated_node",
                      staticmethod(tracking_make)):
        pipe = CryptoDependPipeline(cfg)

    assert "A6:Reachability" in validated_calls, (
        f"A6 not wrapped; got: {validated_calls}"
    )
