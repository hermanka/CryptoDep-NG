"""Integration test: full A1 → A5 pipeline on fixture repo, all external services mocked."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_FIXTURE_REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config():
    """Return a CryptoDependConfig suitable for testing (no real neo4j password needed)."""
    from cryptodep.config import CryptoDependConfig

    return CryptoDependConfig(neo4j_password="test-password")


def _a3_mock_response() -> str:
    """Minimal valid A3 LLM response — empty edge list (safe fallback)."""
    return "[]"


def _a5_mock_response() -> str:
    """Minimal valid A5 LLM response — Markdown report stub."""
    return "# PQC Migration Report\n\n## Executive Summary\nAll findings processed."


# ---------------------------------------------------------------------------
# Module-scoped fixture: run pipeline ONCE, share results across all tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pipeline_result(tmp_path_factory):
    """Run the full A1→A5 pipeline on the sample_repo fixture with mocked externals.

    Returns (final_state, output_path).
    """
    tmp = tmp_path_factory.mktemp("pipeline_run")
    output_path = str(tmp / "cdg_output.json")

    config = _make_config()

    # Build the pipeline
    from cryptodep.pipeline import CryptoDependPipeline

    pipeline = CryptoDependPipeline(config)

    # Patch LLM calls in each agent module that imports call_llm directly.
    # Patch neo4j.GraphDatabase.driver so A4 skips real Neo4j (it wraps in try/except).
    mock_a3_llm = AsyncMock(side_effect=[_a3_mock_response()])
    mock_a5_llm = AsyncMock(side_effect=[_a5_mock_response()])
    mock_a2_llm = AsyncMock(side_effect=["[]"] * 20)  # A2 escalation (low-conf findings)

    # Neo4j driver mock — A4 calls driver(), then close()
    mock_driver = MagicMock()
    mock_neo4j_module = MagicMock()
    mock_neo4j_module.GraphDatabase.driver.return_value = mock_driver

    async def _run_pipeline():
        # Use the pipeline's own initial-state factory so CDGState key changes
        # are automatically reflected here without needing to update this test.
        initial_state = pipeline._make_initial_state(str(_FIXTURE_REPO))
        with (
            patch("cryptodep.agents.a2_detection.call_llm", mock_a2_llm),
            patch("cryptodep.agents.a3_reasoning.call_llm", mock_a3_llm),
            patch("cryptodep.agents.a5_planner.call_llm", mock_a5_llm),
            patch.dict("sys.modules", {"neo4j": mock_neo4j_module}),
        ):
            return await pipeline._graph.ainvoke(initial_state)  # type: ignore[union-attr]

    final_state = asyncio.run(_run_pipeline())

    # Write CDG output if produced (mirrors pipeline.run() behaviour)
    import json as _json
    if final_state.get("cdg_document"):
        doc = final_state["cdg_document"]
        with open(output_path, "w") as f:
            _json.dump(doc.model_dump(mode="json"), f, indent=2, default=str)

    return final_state, output_path


# ---------------------------------------------------------------------------
# Tests (all share the module-scoped fixture)
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    def test_pipeline_completes_without_error(self, pipeline_result):
        """State errors list must be empty (no fatal errors from any agent)."""
        state, _ = pipeline_result
        # Filter out recoverable warnings (neo4j_unavailable, cbom_export_failed are OK)
        fatal_errors = [
            e for e in state["errors"]
            if not e.get("recoverable", True)
        ]
        assert fatal_errors == [], f"Fatal pipeline errors: {fatal_errors}"

    def test_pipeline_produces_cdg_document(self, pipeline_result):
        """CDGDocument must be populated after A4 completes."""
        state, _ = pipeline_result
        assert state["cdg_document"] is not None, "cdg_document is None — A4 failed to build CDG"

    def test_pipeline_cdg_has_crypto_algorithm_node(self, pipeline_result):
        """CDG must contain at least one CryptoAlgorithm node (RSA/AES detected in fixture)."""
        state, _ = pipeline_result
        doc = state["cdg_document"]
        assert doc is not None
        from cryptodep.schema.cdg_models import CDGNodeType

        crypto_nodes = [
            n for n in doc.nodes
            if n.get("node_type") in (
                CDGNodeType.CRYPTO_ALGORITHM,
                CDGNodeType.CRYPTO_ALGORITHM.value,
                "crypto_algorithm",
                "CryptoAlgorithm",
            )
        ]
        assert len(crypto_nodes) >= 1, (
            f"No CryptoAlgorithm nodes found. All node types: "
            f"{[n.get('node_type') for n in doc.nodes]}"
        )

    def test_pipeline_cdg_has_migrates_to_edge(self, pipeline_result):
        """A4 always adds migrates_to edges for quantum_vulnerable nodes (RSA in fixture)."""
        state, _ = pipeline_result
        doc = state["cdg_document"]
        assert doc is not None

        # Flexible edge_type check (may be enum or string depending on model_dump mode)
        def _is_migrates_to(e) -> bool:
            et = getattr(e, "edge_type", None) or e.get("edge_type", "") if isinstance(e, dict) else e.edge_type
            return str(et) in ("migrates_to", "CDGEdgeType.MIGRATES_TO")

        migrates_edges = [e for e in doc.edges if _is_migrates_to(e)]
        assert len(migrates_edges) >= 1, (
            f"No migrates_to edges found — expected ≥1 for RSA-2048→ML-KEM-768. "
            f"All edge types: {[getattr(e,'edge_type',e.get('edge_type','?') if isinstance(e,dict) else '?') for e in doc.edges]}"
        )

    def test_pipeline_migration_plan_populated(self, pipeline_result):
        """Migration plan must contain at least 1 item (RSA-2048 is quantum-vulnerable)."""
        state, _ = pipeline_result
        plan = state["migration_plan"]
        assert plan is not None, "migration_plan is None"
        assert plan.total_vulnerable_assets >= 1, (
            "No vulnerable assets detected — expected RSA-2048 from AuthService.java"
        )
        assert len(plan.priority_queue) >= 1, (
            "priority_queue is empty — A5 failed to rank migration items"
        )

    def test_pipeline_all_agents_recorded_timing(self, pipeline_result):
        """Every agent must record its execution time in agent_timings."""
        state, _ = pipeline_result
        timings = state["agent_timings"]
        expected_agents = [
            "A1:CodeIngestion",
            "A2:CryptoDetection",
            "A3:DependencyReasoning",
            "A4:CDGBuilder",
            "A5:MigrationPlanner",
        ]
        missing = [name for name in expected_agents if name not in timings]
        assert missing == [], f"Missing timing keys: {missing}. Present: {list(timings.keys())}"
