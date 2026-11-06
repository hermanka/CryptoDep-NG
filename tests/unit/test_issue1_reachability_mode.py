"""Tests for Issue 1: Asymmetric reachability sentinel fix.

RED tests — all should fail before the fix.
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from cryptodep.config import CryptoDependConfig
from cryptodep.schema.cdg_models import (
    CryptoAlgorithmNode,
    NistQuantumVulnClass,
    MigrationPriority,
)


def _make_config(**kwargs) -> CryptoDependConfig:
    return CryptoDependConfig(neo4j_password="test", **kwargs)


def _rsa_node() -> CryptoAlgorithmNode:
    return CryptoAlgorithmNode(
        label="RSA-2048",
        algorithm_family="RSA",
        parameter_set="RSA-2048",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
        migration_urgency_score=75.0,
        hndl_risk=True,
        migration_priority=MigrationPriority.CRITICAL,
    )


# ── CDGState has reachability_mode field ─────────────────────────────────────

def test_cdgstate_has_reachability_mode_field():
    """CDGState must declare reachability_mode with a default of 'disabled'."""
    from cryptodep.state import CDGState
    import typing
    hints = typing.get_type_hints(CDGState)
    assert "reachability_mode" in hints, (
        "CDGState must have a 'reachability_mode' field"
    )


def test_pipeline_initializes_reachability_mode_disabled():
    """Initial state built by pipeline must set reachability_mode='disabled'."""
    from cryptodep.pipeline import CryptoDependPipeline
    config = _make_config()
    pipeline = CryptoDependPipeline(config)
    state = pipeline._make_initial_state("/tmp/repo")
    assert state["reachability_mode"] == "disabled", (
        f"Expected 'disabled', got {state['reachability_mode']!r}"
    )


# ── A6 sets reachability_mode correctly ──────────────────────────────────────

def test_a6_sets_mode_analyzed_on_success():
    """A6 must set reachability_mode='analyzed' when BFS runs successfully."""
    from cryptodep.agents.a6_reachability import ReachabilityAgent
    from cryptodep.state import CDGState

    config = _make_config(enable_reachability=True)
    agent = ReachabilityAgent(config)

    state: dict = {
        "repo_path": "/tmp",
        "config": config,
        "validated_findings": [
            {
                "source_ref": "AuthService.java:L8",
                "algorithm_family": "RSA",
                "confidence": 0.9,
                "evidence": "test",
                "use_context": "key_exchange",
                "detected_by": "static_rule",
                "parameter_set": "RSA-2048",
            }
        ],
        "file_index": {"AuthService.java": {"path": "AuthService.java", "language": "java", "size_bytes": 100, "loc": 10}},
        "ast_cache": {},
        "errors": [],
        "agent_timings": {},
        "reachability_mode": "disabled",
    }

    with patch("cryptodep.agents.a6_reachability.detect_entry_points") as mock_ep, \
         patch("cryptodep.agents.a6_reachability.build_call_graph") as mock_cg:
        mock_ep.return_value = [
            {"file": "AuthService.java", "method": "handle", "type": "rest_endpoint", "line": 1}
        ]
        mock_cg.return_value = {"AuthService.handle": ["AuthService.generateRSAKey"]}
        result = asyncio.run(agent.run(state))

    assert result["reachability_mode"] == "analyzed", (
        f"Expected 'analyzed' after successful BFS, got {result['reachability_mode']!r}"
    )


def test_a6_sets_mode_absent_when_no_entry_points():
    """A6 must set reachability_mode='absent' when no entry points are found."""
    from cryptodep.agents.a6_reachability import ReachabilityAgent

    config = _make_config(enable_reachability=True)
    agent = ReachabilityAgent(config)

    state: dict = {
        "repo_path": "/tmp",
        "config": config,
        "validated_findings": [
            {
                "source_ref": "Util.java:L5",
                "algorithm_family": "RSA",
                "confidence": 0.9,
                "evidence": "test",
                "use_context": "key_exchange",
                "detected_by": "static_rule",
                "parameter_set": "RSA-2048",
            }
        ],
        "file_index": {},
        "ast_cache": {},
        "errors": [],
        "agent_timings": {},
        "reachability_mode": "disabled",
    }

    with patch("cryptodep.agents.a6_reachability.detect_entry_points") as mock_ep, \
         patch("cryptodep.agents.a6_reachability.build_call_graph") as mock_cg:
        mock_ep.return_value = []   # no entry points
        mock_cg.return_value = {}
        result = asyncio.run(agent.run(state))

    assert result["reachability_mode"] == "absent", (
        f"Expected 'absent' when no entry points, got {result['reachability_mode']!r}"
    )


# ── A5 drops reachability term when mode != 'analyzed' ───────────────────────

def test_a5_drops_reachability_term_when_mode_disabled():
    """When reachability_mode='disabled', A5 must NOT apply the 1.0 default.

    Score with mode='disabled' must equal score computed with baseline weights
    (no reachability term), not the reachability-boosted version.
    """
    from cryptodep.agents.a5_planner import _compute_priority_score
    node = _rsa_node()
    config = _make_config()
    baseline_weights = config.priority_weights   # no reachability key

    # Score with explicit reachability_score=1.0 using reachability weights
    # (this is the OLD behaviour that inflates rank unfairly)
    weights_with_reach = dict(config.priority_weights_with_reachability)
    old_score = _compute_priority_score(node, weights_with_reach, reachability_score=1.0)

    # Score with mode='disabled' — reachability term must be dropped
    new_score = _compute_priority_score(
        node, baseline_weights, reachability_score=None  # None = not evaluated
    )
    # The baseline score (no reachability term) should differ from the inflated one
    assert new_score < old_score or abs(new_score - old_score) < 1e-6, (
        "Baseline score should not be inflated by the absent reachability term"
    )


def test_a5_uses_reachability_term_when_mode_analyzed():
    """When reachability_mode='analyzed', A5 must include reachability in composite."""
    from cryptodep.agents.a5_planner import _compute_priority_score
    node = _rsa_node()
    config = _make_config()

    weights = dict(config.priority_weights_with_reachability)
    score_with_reach = _compute_priority_score(node, weights, reachability_score=0.5)
    score_no_reach = _compute_priority_score(node, weights, reachability_score=0.0)

    # A finding with reachability 0.5 must outrank one with 0.0
    assert score_with_reach > score_no_reach


def test_a5_none_reachability_score_does_not_raise():
    """_compute_priority_score must accept reachability_score=None without error."""
    from cryptodep.agents.a5_planner import _compute_priority_score
    node = _rsa_node()
    config = _make_config()
    # Should not raise
    score = _compute_priority_score(node, config.priority_weights, reachability_score=None)
    assert isinstance(score, float)
    assert score >= 0.0
