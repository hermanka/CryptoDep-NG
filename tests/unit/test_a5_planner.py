from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch

from cryptodep.agents.a5_planner import (
    _compute_priority_score,
    _build_migration_item,
    _compute_quantum_readiness,
    _build_migration_prompt,
)
from cryptodep.schema.cdg_models import (
    CDGDocument,
    CryptoAlgorithmNode,
    PQCAlgorithmNode,
    CDGEdge,
    CDGEdgeType,
    MigrationItem,
    MigrationPlan,
    NistQuantumVulnClass,
    PQCAlgorithmId,
    NistSecurityLevel,
    MigrationPriority,
)
from cryptodep.config import CryptoDependConfig


def _make_config() -> CryptoDependConfig:
    return CryptoDependConfig(neo4j_password="test")


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


def _aes_node() -> CryptoAlgorithmNode:
    return CryptoAlgorithmNode(
        label="AES-256",
        algorithm_family="AES",
        parameter_set="AES-256",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC,
        migration_urgency_score=0.0,
        hndl_risk=False,
        migration_priority=MigrationPriority.NOT_REQUIRED,
    )


def _make_cdg_doc(algo_nodes, pqc_nodes=None, edges=None) -> CDGDocument:
    pqc_nodes = pqc_nodes or []
    edges = edges or []
    all_node_dicts = (
        [n.model_dump(mode="python") for n in algo_nodes]
        + [n.model_dump(mode="python") for n in pqc_nodes]
    )
    return CDGDocument(nodes=all_node_dicts, edges=edges,
                       migration_plan=MigrationPlan())


# ── _compute_priority_score ───────────────────────────────────────────────────

def test_priority_score_zero_for_safe_algo():
    node = _aes_node()
    weights = {"urgency": 0.5, "hndl": 0.25, "boundary": 0.15, "lifetime": 0.10}
    score = _compute_priority_score(node, weights)
    assert score == 0.0


def test_priority_score_nonzero_for_vulnerable():
    node = _rsa_node()
    weights = {"urgency": 0.5, "hndl": 0.25, "boundary": 0.15, "lifetime": 0.10}
    score = _compute_priority_score(node, weights)
    assert score > 0.0


def test_priority_score_hndl_adds_weight():
    node_hndl = _rsa_node()  # hndl_risk=True
    node_no_hndl = _rsa_node().model_copy(update={"hndl_risk": False})
    weights = {"urgency": 0.5, "hndl": 0.25, "boundary": 0.15, "lifetime": 0.10}
    score_hndl = _compute_priority_score(node_hndl, weights)
    score_no_hndl = _compute_priority_score(node_no_hndl, weights)
    assert score_hndl > score_no_hndl


def test_priority_score_boundary_adds_weight():
    node = _rsa_node()
    weights = {"urgency": 0.5, "hndl": 0.25, "boundary": 0.15, "lifetime": 0.10}
    score_base = _compute_priority_score(node, weights, is_boundary=False)
    score_bnd = _compute_priority_score(node, weights, is_boundary=True)
    assert score_bnd >= score_base


# ── _build_migration_item ─────────────────────────────────────────────────────

def test_build_migration_item_correct_pqc():
    node = _rsa_node()
    item = _build_migration_item(rank=1, algo_node=node, config=_make_config())
    assert item.rank == 1
    assert item.algo_node_id == node.node_id
    assert item.current_algorithm == "RSA-2048"
    assert item.recommended_pqc == PQCAlgorithmId.ML_KEM_768


def test_build_migration_item_hybrid_recommended():
    node = _rsa_node()
    item = _build_migration_item(rank=1, algo_node=node, config=_make_config())
    assert item.hybrid_mode_recommended is True


# ── _compute_quantum_readiness ────────────────────────────────────────────────

def test_quantum_readiness_all_vulnerable():
    score = _compute_quantum_readiness([_rsa_node()])
    assert score == 0.0


def test_quantum_readiness_all_safe():
    score = _compute_quantum_readiness([_aes_node()])
    assert score == 100.0


def test_quantum_readiness_mixed():
    score = _compute_quantum_readiness([_rsa_node(), _aes_node()])
    assert 0.0 < score < 100.0


def test_quantum_readiness_empty():
    score = _compute_quantum_readiness([])
    assert score == 100.0


# ── _build_migration_prompt ───────────────────────────────────────────────────

def test_build_migration_prompt_returns_strings():
    node = _rsa_node()
    plan = MigrationPlan(
        priority_queue=[
            MigrationItem(
                rank=1,
                algo_node_id=node.node_id,
                current_algorithm="RSA-2048",
                recommended_pqc=PQCAlgorithmId.ML_KEM_768,
                urgency_score=75.0,
            )
        ],
        total_vulnerable_assets=1,
        quantum_readiness_score=0.0,
    )
    doc = _make_cdg_doc([node])
    system, user = _build_migration_prompt(plan, doc, _make_config())
    assert isinstance(system, str) and len(system) > 0
    assert isinstance(user, str) and "RSA" in user


def test_build_migration_prompt_bahasa():
    node = _rsa_node()
    plan = MigrationPlan(priority_queue=[], total_vulnerable_assets=1)
    doc = _make_cdg_doc([node])
    config = CryptoDependConfig(neo4j_password="test", report_language="id")
    system, user = _build_migration_prompt(plan, doc, config)
    assert "Bahasa Indonesia" in system or "Indonesia" in user


# ── MigrationPlannerAgent.run() ───────────────────────────────────────────────

from cryptodep.agents.a5_planner import MigrationPlannerAgent


def _make_state_with_cdg() -> dict:
    node = _rsa_node()
    cdg_doc = _make_cdg_doc([node])
    migration_plan = MigrationPlan(
        total_vulnerable_assets=1,
        quantum_readiness_score=0.0,
    )
    return {
        "repo_path": "/test/repo",
        "config": _make_config(),
        "run_id": "test-run-002",
        "file_index": {},
        "ast_cache": {},
        "import_graph": {},
        "repo_stats": {"total_files": 1, "total_loc": 100, "languages": {}},
        "raw_crypto_findings": [],
        "validated_findings": [],
        "candidate_edges": [],
        "validated_edges": [],
        "cdg_document": cdg_doc,
        "neo4j_import_stats": {"nodes": 2, "edges": 1},
        "cbom_export_path": "cbom_test.json",
        "migration_plan": migration_plan,
        "report_md": "",
        "errors": [],
        "agent_timings": {},
        "total_llm_tokens": 0,
    }


@pytest.mark.asyncio
async def test_run_produces_migration_plan():
    agent = MigrationPlannerAgent(_make_config())
    state = _make_state_with_cdg()
    llm_response = "## PQC Migration Report\n\nRSA-2048 must migrate to ML-KEM-768.\n"
    with patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock(return_value=llm_response)):
        result = await agent.run(state)
    assert result["migration_plan"] is not None
    assert len(result["migration_plan"].priority_queue) >= 1


@pytest.mark.asyncio
async def test_run_produces_report_md():
    agent = MigrationPlannerAgent(_make_config())
    state = _make_state_with_cdg()
    llm_response = "## PQC Migration Report\n\nRSA-2048 must migrate to ML-KEM-768.\n"
    with patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock(return_value=llm_response)):
        result = await agent.run(state)
    assert "PQC Migration Report" in result["report_md"]


@pytest.mark.asyncio
async def test_run_records_timing():
    agent = MigrationPlannerAgent(_make_config())
    state = _make_state_with_cdg()
    with patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock(return_value="# Report")):
        result = await agent.run(state)
    assert "A5:MigrationPlanner" in result["agent_timings"]


@pytest.mark.asyncio
async def test_run_rsa_ranked_critical():
    """RSA node with hndl_risk=True must appear as first item in priority queue."""
    agent = MigrationPlannerAgent(_make_config())
    state = _make_state_with_cdg()
    with patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock(return_value="# Report")):
        result = await agent.run(state)
    first_item = result["migration_plan"].priority_queue[0]
    assert first_item.current_algorithm == "RSA-2048"


@pytest.mark.asyncio
async def test_run_no_cdg_document():
    """No CDG document → empty migration plan, no LLM call, no crash."""
    agent = MigrationPlannerAgent(_make_config())
    state = _make_state_with_cdg()
    state["cdg_document"] = None
    with patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock()) as mock_llm:
        result = await agent.run(state)
    mock_llm.assert_not_called()
    assert result["migration_plan"] is not None
    assert result["migration_plan"].priority_queue == []


@pytest.mark.asyncio
async def test_run_empty_graph_skips_llm_with_deterministic_report():
    """CDG without crypto algorithms → no LLM call, honest 'nothing found' report, no error."""
    config = _make_config()
    config.report_language = "id"
    agent = MigrationPlannerAgent(config)
    state = _make_state_with_cdg()
    state["cdg_document"] = _make_cdg_doc([])
    with patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock()) as mock_llm:
        result = await agent.run(state)
    mock_llm.assert_not_called()
    assert "Tidak ada algoritma kriptografi" in result["report_md"]
    assert result["migration_plan"].priority_queue == [] and result["errors"] == []
