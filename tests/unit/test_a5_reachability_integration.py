from __future__ import annotations
import pytest
from cryptodep.agents.a5_planner import _compute_priority_score
from cryptodep.schema.cdg_models import (
    CryptoAlgorithmNode, NistQuantumVulnClass, MigrationPriority,
)

def _make_vuln_node(urgency: float = 50.0, hndl: bool = True) -> CryptoAlgorithmNode:
    return CryptoAlgorithmNode(
        label="RSA-2048", algorithm_family="RSA", parameter_set="RSA-2048",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
        migration_priority=MigrationPriority.CRITICAL,
        migration_urgency_score=urgency, hndl_risk=hndl,
    )

def test_priority_with_reachability_score_boosts_ranking():
    weights_with_reach = {"urgency": 0.35, "hndl": 0.20, "boundary": 0.12, "lifetime": 0.08, "reachability": 0.25}
    node = _make_vuln_node(urgency=50.0)
    score_reachable = _compute_priority_score(node, weights_with_reach, reachability_score=1.0)
    score_unreachable = _compute_priority_score(node, weights_with_reach, reachability_score=0.0)
    assert score_reachable > score_unreachable
    assert score_reachable - score_unreachable == pytest.approx(0.25, abs=0.01)

def test_priority_without_reachability_key_uses_neutral_default():
    original_weights = {"urgency": 0.50, "hndl": 0.25, "boundary": 0.15, "lifetime": 0.10}
    node = _make_vuln_node(urgency=50.0)
    score = _compute_priority_score(node, original_weights)
    # 0.50*(50/100) + 0.25*(1.0) + 0.15*(0.0) + 0.10*(0.7) = 0.25 + 0.25 + 0 + 0.07 = 0.57
    assert score == pytest.approx(0.57, abs=0.01)

def test_priority_non_vulnerable_returns_zero():
    node = CryptoAlgorithmNode(
        label="AES-256", algorithm_family="AES",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC,
    )
    weights = {"urgency": 0.35, "hndl": 0.20, "boundary": 0.12, "lifetime": 0.08, "reachability": 0.25}
    score = _compute_priority_score(node, weights, reachability_score=1.0)
    assert score == 0.0
