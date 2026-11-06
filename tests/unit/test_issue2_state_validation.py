"""Tests for Issue 2: State validation after agent writes.

RED tests — all should fail before the fix.
"""
from __future__ import annotations

import pytest
from cryptodep.config import CryptoDependConfig


def _base_state() -> dict:
    return {
        "repo_path": "/tmp/repo",
        "config": CryptoDependConfig(neo4j_password="test"),
        "run_id": "abc123",
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


# ── validate_state utility exists ────────────────────────────────────────────

def test_validate_state_module_exists():
    """cryptodep.tools.state_validation must be importable."""
    from cryptodep.tools import state_validation  # noqa: F401


def test_validate_state_callable():
    """validate_state(state, agent_name) must be a callable."""
    from cryptodep.tools.state_validation import validate_state
    assert callable(validate_state)


# ── valid state passes without error ─────────────────────────────────────────

def test_validate_state_passes_for_valid_state():
    """A well-formed state must pass validation without raising."""
    from cryptodep.tools.state_validation import validate_state
    state = _base_state()
    # Should not raise
    validate_state(state, "A1:CodeIngestion")


# ── wrong types are detected ─────────────────────────────────────────────────

def test_validate_state_detects_wrong_type_for_validated_findings():
    """validated_findings must be a list; a string value must raise ValueError."""
    from cryptodep.tools.state_validation import validate_state
    state = _base_state()
    state["validated_findings"] = "oops"  # wrong type
    with pytest.raises((ValueError, TypeError)) as exc_info:
        validate_state(state, "A2:CryptoDetection")
    assert "validated_findings" in str(exc_info.value).lower() or "A2" in str(exc_info.value)


def test_validate_state_detects_none_file_index():
    """file_index must be a dict; None must raise."""
    from cryptodep.tools.state_validation import validate_state
    state = _base_state()
    state["file_index"] = None  # wrong type
    with pytest.raises((ValueError, TypeError)):
        validate_state(state, "A1:CodeIngestion")


def test_validate_state_detects_wrong_total_llm_tokens():
    """total_llm_tokens must be int; a float that isn't int-like must raise."""
    from cryptodep.tools.state_validation import validate_state
    state = _base_state()
    state["total_llm_tokens"] = "four thousand"  # wrong type
    with pytest.raises((ValueError, TypeError)):
        validate_state(state, "A3:DependencyReasoning")


def test_validate_state_detects_invalid_reachability_mode():
    """reachability_mode must be one of 'disabled'|'absent'|'analyzed'."""
    from cryptodep.tools.state_validation import validate_state
    state = _base_state()
    state["reachability_mode"] = "active"  # invalid value
    with pytest.raises((ValueError, TypeError)):
        validate_state(state, "A6:ReachabilityAnalyzer")


# ── error message attributes the originating agent ───────────────────────────

def test_validate_state_error_includes_agent_name():
    """Validation error message must include the agent name for traceability."""
    from cryptodep.tools.state_validation import validate_state
    state = _base_state()
    state["validated_findings"] = 42  # wrong type
    agent = "A2:CryptoDetection"
    with pytest.raises((ValueError, TypeError)) as exc_info:
        validate_state(state, agent)
    assert agent in str(exc_info.value)


# ── pipeline wraps agents with validation ────────────────────────────────────

def test_pipeline_has_validated_node_wrapper():
    """CryptoDependPipeline must expose a _make_validated_node static/class method."""
    from cryptodep.pipeline import CryptoDependPipeline
    assert hasattr(CryptoDependPipeline, "_make_validated_node"), (
        "CryptoDependPipeline must have _make_validated_node for wrapping agent.run()"
    )
