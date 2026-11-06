"""Integration test: A1 → A2 → A3 → A6 → A4 → A5 with --reachability on fixture repo."""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cryptodep.config import CryptoDependConfig
from cryptodep.pipeline import CryptoDependPipeline

_FIXTURE_REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides):
    defaults = {
        "neo4j_password": "test-password",
        "enable_reachability": True,
    }
    defaults.update(overrides)
    return CryptoDependConfig(**defaults)


def _a3_mock_response() -> str:
    return "[]"


def _a5_mock_response() -> str:
    return "# PQC Migration Report\n\n## Executive Summary\nAll findings processed."


def _semgrep_mock_findings():
    """Return synthetic Semgrep raw results that look like real RSA/AES detections."""
    return [
        {
            "path": str(_FIXTURE_REPO / "AuthService.java"),
            "start": {"line": 8},
            "extra": {
                "message": "RSA key generation detected",
                "lines": 'KeyPairGenerator.getInstance("RSA");',
                "metadata": {"category": "crypto-java-api"},
            },
        },
        {
            "path": str(_FIXTURE_REPO / "crypto_utils.py"),
            "start": {"line": 5},
            "extra": {
                "message": "AES cipher usage detected",
                "lines": "AES.new(key, AES.MODE_CBC)",
                "metadata": {"category": "crypto-python-api"},
            },
        },
    ]


def _entry_points_mock():
    """Synthetic entry points matching the sample_repo fixture."""
    return [
        {
            "file": str(_FIXTURE_REPO / "LoginController.java"),
            "method": "login",
            "type": "rest_endpoint",
            "line": 12,
        },
    ]


def _call_graph_mock():
    """Synthetic call graph: LoginController.login calls AuthService.generateRSAKey."""
    return {
        "LoginController.login": ["AuthService.generateRSAKey"],
        "AuthService.generateRSAKey": [],
    }


# ---------------------------------------------------------------------------
# Module-scoped fixture: run full pipeline with reachability ONCE
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pipeline_result_with_reachability(tmp_path_factory):
    """Run the full A1→A2→A3→A6→A4→A5 pipeline on sample_repo with mocked externals.

    Returns (final_state, output_path).
    """
    tmp = tmp_path_factory.mktemp("pipeline_a6")
    output_path = str(tmp / "cdg_output.json")
    config = _make_config()
    pipeline = CryptoDependPipeline(config)

    mock_a2_llm = AsyncMock(side_effect=["[]"] * 20)  # A2 escalation (low-conf findings)
    mock_a3_llm = AsyncMock(return_value=_a3_mock_response())
    mock_a5_llm = AsyncMock(return_value=_a5_mock_response())

    # Neo4j driver mock — A4 calls driver(), then close()
    mock_driver = MagicMock()
    mock_neo4j_module = MagicMock()
    mock_neo4j_module.GraphDatabase.driver.return_value = mock_driver

    async def _run():
        initial_state = pipeline._make_initial_state(str(_FIXTURE_REPO))
        with (
            patch("cryptodep.agents.a2_detection.run_semgrep", return_value=_semgrep_mock_findings()),
            patch("cryptodep.agents.a2_detection.call_llm", mock_a2_llm),
            patch("cryptodep.agents.a3_reasoning.call_llm", mock_a3_llm),
            patch("cryptodep.agents.a5_planner.call_llm", mock_a5_llm),
            patch("cryptodep.agents.a6_reachability.detect_entry_points", return_value=_entry_points_mock()),
            patch("cryptodep.agents.a6_reachability.build_call_graph", return_value=_call_graph_mock()),
            patch.dict("sys.modules", {"neo4j": mock_neo4j_module}),
        ):
            return await pipeline._graph.ainvoke(initial_state)  # type: ignore[union-attr]

    final_state = asyncio.run(_run())

    # Write CDG output if produced (mirrors pipeline.run() behaviour)
    if final_state.get("cdg_document"):
        doc = final_state["cdg_document"]
        with open(output_path, "w") as f:
            json.dump(doc.model_dump(mode="json"), f, indent=2, default=str)

    return final_state, output_path


# ---------------------------------------------------------------------------
# Tests (all share the module-scoped fixture)
# ---------------------------------------------------------------------------

def test_a6_ran_and_populated_state(pipeline_result_with_reachability):
    """A6 timing key must be recorded in agent_timings."""
    state, _ = pipeline_result_with_reachability
    assert "A6:ReachabilityAnalyzer" in state["agent_timings"], (
        f"A6 timing not found. Present keys: {list(state['agent_timings'].keys())}"
    )


def test_entry_points_detected(pipeline_result_with_reachability):
    """At least one entry point of a known type must be present after A6 runs."""
    state, _ = pipeline_result_with_reachability
    eps = state["entry_points"]
    assert len(eps) >= 1, "No entry points detected by A6"
    types = {ep["type"] for ep in eps}
    assert "rest_endpoint" in types or "main" in types, (
        f"Expected rest_endpoint or main entry point, got: {types}"
    )


def test_call_graph_populated(pipeline_result_with_reachability):
    """Call graph must have at least one node after A6 runs on sample_repo."""
    state, _ = pipeline_result_with_reachability
    cg = state["call_graph"]
    assert len(cg) >= 1, "call_graph is empty — A6 did not build call graph"


def test_reachability_map_has_entries(pipeline_result_with_reachability):
    """reachability_map must be populated when validated_findings are present."""
    state, _ = pipeline_result_with_reachability
    rmap = state["reachability_map"]
    if state["validated_findings"]:
        assert len(rmap) >= 1, (
            "validated_findings non-empty but reachability_map is empty"
        )


def test_cdg_output_written(pipeline_result_with_reachability):
    """CDG JSON output file must exist and contain a 'nodes' key."""
    _, output_path = pipeline_result_with_reachability
    assert Path(output_path).exists(), f"CDG output file not found: {output_path}"
    data = json.loads(Path(output_path).read_text())
    assert "nodes" in data, f"CDG output missing 'nodes' key. Keys: {list(data.keys())}"


def test_all_agents_recorded_timing_with_reachability(pipeline_result_with_reachability):
    """All agents including A6 must record execution time in agent_timings."""
    state, _ = pipeline_result_with_reachability
    timings = state["agent_timings"]
    expected_agents = [
        "A1:CodeIngestion",
        "A2:CryptoDetection",
        "A3:DependencyReasoning",
        "A6:ReachabilityAnalyzer",
        "A4:CDGBuilder",
        "A5:MigrationPlanner",
    ]
    missing = [name for name in expected_agents if name not in timings]
    assert missing == [], f"Missing timing keys: {missing}. Present: {list(timings.keys())}"


def test_pipeline_completes_without_fatal_errors(pipeline_result_with_reachability):
    """No fatal (non-recoverable) errors should occur in the reachability pipeline."""
    state, _ = pipeline_result_with_reachability
    fatal_errors = [e for e in state["errors"] if not e.get("recoverable", True)]
    assert fatal_errors == [], f"Fatal pipeline errors: {fatal_errors}"


def test_existing_pipeline_without_reachability_unchanged():
    """Pipeline without --reachability should NOT have A6 in timings."""
    config = _make_config(enable_reachability=False)
    pipeline = CryptoDependPipeline(config)

    mock_a2_llm = AsyncMock(side_effect=["[]"] * 20)
    mock_a3_llm = AsyncMock(return_value="[]")
    mock_a5_llm = AsyncMock(return_value="# Report")

    mock_driver = MagicMock()
    mock_neo4j_module = MagicMock()
    mock_neo4j_module.GraphDatabase.driver.return_value = mock_driver

    async def _run():
        initial_state = pipeline._make_initial_state(str(_FIXTURE_REPO))
        with (
            patch("cryptodep.agents.a2_detection.run_semgrep", return_value=_semgrep_mock_findings()),
            patch("cryptodep.agents.a2_detection.call_llm", mock_a2_llm),
            patch("cryptodep.agents.a3_reasoning.call_llm", mock_a3_llm),
            patch("cryptodep.agents.a5_planner.call_llm", mock_a5_llm),
            patch.dict("sys.modules", {"neo4j": mock_neo4j_module}),
        ):
            return await pipeline._graph.ainvoke(initial_state)  # type: ignore[union-attr]

    state = asyncio.run(_run())

    assert "A6:ReachabilityAnalyzer" not in state["agent_timings"], (
        "A6 timing unexpectedly present when enable_reachability=False"
    )
    assert state["reachability_map"] == {}, (
        "reachability_map should be empty when enable_reachability=False"
    )
