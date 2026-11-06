"""TDD tests for Figure 4 Quantum Vulnerability Classification Decision Tree.

Tests are written first and must fail before implementation begins.
Run: /home/girnot/.venvs/cryptodep/bin/pytest tests/unit/test_fig4_classification.py -v
"""
from __future__ import annotations
import pytest
from cryptodep.schema.cdg_models import NistQuantumVulnClass


def test_grover_weakened_enum_exists():
    """GROVER_WEAKENED must exist as a distinct enum value (not QUANTUM_SAFE_SYMMETRIC)."""
    assert hasattr(NistQuantumVulnClass, "GROVER_WEAKENED")
    assert NistQuantumVulnClass.GROVER_WEAKENED.value == "grover_weakened"
    assert NistQuantumVulnClass.GROVER_WEAKENED != NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC


def test_nist_pqc_families_frozenset_exists():
    """NIST_PQC_FAMILIES must be importable from pqc_lookup."""
    from cryptodep.schema.pqc_lookup import NIST_PQC_FAMILIES
    assert isinstance(NIST_PQC_FAMILIES, frozenset)
    assert "ML-KEM" in NIST_PQC_FAMILIES
    assert "ML-DSA" in NIST_PQC_FAMILIES
    assert "SLH-DSA" in NIST_PQC_FAMILIES
    assert "FN-DSA" in NIST_PQC_FAMILIES


def test_classify_vuln_q2_nist_pqc():
    """Q2: ML-KEM, ML-DSA, SLH-DSA, FN-DSA → quantum_safe_pqc."""
    from cryptodep.agents.a4_builder import _classify_vuln
    assert _classify_vuln("ML-KEM") == NistQuantumVulnClass.QUANTUM_SAFE_PQC
    assert _classify_vuln("ML-KEM-768") == NistQuantumVulnClass.QUANTUM_SAFE_PQC
    assert _classify_vuln("ML-DSA") == NistQuantumVulnClass.QUANTUM_SAFE_PQC
    assert _classify_vuln("SLH-DSA") == NistQuantumVulnClass.QUANTUM_SAFE_PQC
    assert _classify_vuln("FN-DSA-512") == NistQuantumVulnClass.QUANTUM_SAFE_PQC


def test_classify_vuln_q1_public_key():
    """Q1: RSA, ECC, DH, ECDH, ECDSA, DSA → quantum_vulnerable."""
    from cryptodep.agents.a4_builder import _classify_vuln
    assert _classify_vuln("RSA") == NistQuantumVulnClass.QUANTUM_VULNERABLE
    assert _classify_vuln("RSA-2048") == NistQuantumVulnClass.QUANTUM_VULNERABLE
    assert _classify_vuln("ECC") == NistQuantumVulnClass.QUANTUM_VULNERABLE
    assert _classify_vuln("ECDSA") == NistQuantumVulnClass.QUANTUM_VULNERABLE
    assert _classify_vuln("ECDH") == NistQuantumVulnClass.QUANTUM_VULNERABLE
    assert _classify_vuln("DH") == NistQuantumVulnClass.QUANTUM_VULNERABLE
    assert _classify_vuln("DSA") == NistQuantumVulnClass.QUANTUM_VULNERABLE


def test_classify_vuln_dhkem_not_vulnerable():
    """DHKEM (HPKE KEM, not classic DH) must not match 'DH' prefix-vulnerable."""
    from cryptodep.agents.a4_builder import _classify_vuln
    result = _classify_vuln("DHKEM")
    assert result != NistQuantumVulnClass.QUANTUM_VULNERABLE, (
        "DHKEM falsely matched 'DH' via loose prefix — delimiter-safe matching required"
    )


def test_classify_vuln_q4_symmetric():
    """Q4: AES, SHA, HMAC → quantum_safe_symmetric (when family alone, no key size)."""
    from cryptodep.agents.a4_builder import _classify_vuln
    assert _classify_vuln("AES") == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC
    assert _classify_vuln("SHA") == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC
    assert _classify_vuln("HMAC") == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC
    assert _classify_vuln("MD5") == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC


def test_build_algo_nodes_q3_grover_weakened():
    """Q3: AES-128 node must get grover_weakened, AES-256 must get quantum_safe_symmetric."""
    from cryptodep.agents.a4_builder import _build_algo_nodes
    findings_128 = [{"algorithm_family": "AES", "parameter_set": "AES-128",
                     "confidence": 1.0, "source_ref": "Test.java:1"}]
    findings_256 = [{"algorithm_family": "AES", "parameter_set": "AES-256",
                     "confidence": 1.0, "source_ref": "Test.java:2"}]
    nodes_128 = _build_algo_nodes(findings_128)
    nodes_256 = _build_algo_nodes(findings_256)
    assert list(nodes_128.values())[0].quantum_vuln_class == NistQuantumVulnClass.GROVER_WEAKENED
    assert list(nodes_256.values())[0].quantum_vuln_class == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC


def test_recompute_urgency_grover_weakened_gets_nonzero_score():
    """GROVER_WEAKENED nodes must receive a non-zero urgency score from _recompute_urgency."""
    from cryptodep.agents.a4_builder import _recompute_urgency
    from cryptodep.schema.cdg_models import CryptoAlgorithmNode, NistQuantumVulnClass, MigrationPriority
    node = CryptoAlgorithmNode(
        label="AES-128",
        algorithm_family="AES",
        parameter_set="AES-128",
        key_size_bits=128,
        quantum_vuln_class=NistQuantumVulnClass.GROVER_WEAKENED,
        migration_priority=MigrationPriority.HIGH,
        hndl_risk=True,
    )
    updated = _recompute_urgency(node, centrality_score=0.0)
    assert updated.migration_urgency_score > 0.0, (
        f"GROVER_WEAKENED AES-128 must have non-zero urgency; got {updated.migration_urgency_score}"
    )


def test_total_vulnerable_assets_includes_grover_weakened():
    """total_vulnerable_assets in CDG document must count GROVER_WEAKENED nodes."""
    from cryptodep.agents.a4_builder import _build_algo_nodes
    from cryptodep.schema.cdg_models import NistQuantumVulnClass
    findings = [
        {"algorithm_family": "RSA", "parameter_set": "RSA-2048",
         "confidence": 1.0, "source_ref": "Auth.java:1"},
        {"algorithm_family": "AES", "parameter_set": "AES-128",
         "confidence": 1.0, "source_ref": "Enc.java:2"},
    ]
    nodes = _build_algo_nodes(findings)
    vuln_count = sum(
        1 for n in nodes.values()
        if n.quantum_vuln_class in {
            NistQuantumVulnClass.QUANTUM_VULNERABLE,
            NistQuantumVulnClass.GROVER_WEAKENED,
        }
    )
    assert vuln_count == 2, f"Expected 2 migration-needed assets (RSA + AES-128), got {vuln_count}"


def test_compute_priority_score_grover_weakened_nonzero():
    """GROVER_WEAKENED nodes must receive a non-zero priority score from A5."""
    from cryptodep.agents.a5_planner import _compute_priority_score
    from cryptodep.schema.cdg_models import CryptoAlgorithmNode, NistQuantumVulnClass, MigrationPriority
    node = CryptoAlgorithmNode(
        label="AES-128",
        algorithm_family="AES",
        parameter_set="AES-128",
        key_size_bits=128,
        quantum_vuln_class=NistQuantumVulnClass.GROVER_WEAKENED,
        migration_priority=MigrationPriority.HIGH,
        migration_urgency_score=28.0,
        hndl_risk=True,
    )
    score = _compute_priority_score(node, is_boundary=False, data_lifetime_years=7.0)
    assert score > 0.0, (
        f"GROVER_WEAKENED AES-128 must enter A5 priority queue; got score={score}"
    )


def test_quantum_readiness_counts_grover_weakened():
    """Quantum readiness score must count GROVER_WEAKENED as vulnerable (reduces score)."""
    from cryptodep.agents.a5_planner import _compute_quantum_readiness
    from cryptodep.schema.cdg_models import CryptoAlgorithmNode, NistQuantumVulnClass, MigrationPriority
    nodes = [
        CryptoAlgorithmNode(
            label="AES-256",
            algorithm_family="AES",
            quantum_vuln_class=NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC,
        ),
        CryptoAlgorithmNode(
            label="AES-128",
            algorithm_family="AES",
            quantum_vuln_class=NistQuantumVulnClass.GROVER_WEAKENED,
            migration_priority=MigrationPriority.HIGH,
        ),
    ]
    readiness = _compute_quantum_readiness(nodes)
    assert readiness < 100.0, (
        f"Readiness must be < 100 when GROVER_WEAKENED node present; got {readiness}"
    )
