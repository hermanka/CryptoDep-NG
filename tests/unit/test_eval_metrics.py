"""Unit tests for eval_metrics.py (M5)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.eval.eval_metrics import (
    _node_key,
    _edge_key,
    resolve_edge_labels,
    compute_f1,
    evaluate_nodes,
    evaluate_edges,
    compute_multihop_recall,
    _rank,
    _spearman_rho,
    evaluate_migration_priority,
    compute_hallucination_rate,
    compute_token_efficiency,
    compute_throughput,
    evaluate_all,
)

FIXTURE_GT = json.loads(
    Path("tests/eval/ground_truth/fixture_gt.json").read_text()
)


# ── helpers ──────────────────────────────────────────────────────────────────

def test_node_key_crypto_algorithm():
    node = {"node_type": "CryptoAlgorithm", "label": "RSA-2048"}
    assert _node_key(node) == ("CryptoAlgorithm", "RSA-2048")


def test_node_key_library():
    node = {"node_type": "CryptoLibrary", "label": "javax.crypto"}
    assert _node_key(node) == ("CryptoLibrary", "javax.crypto")


def test_edge_key():
    edge = {"edge_type": "uses", "source_label": "AuthService", "target_label": "javax.crypto"}
    assert _edge_key(edge) == ("AuthService", "uses", "javax.crypto")


def test_resolve_edge_labels():
    nodes = [
        {"node_id": "n1", "label": "AuthService"},
        {"node_id": "n2", "label": "javax.crypto"},
    ]
    edges = [{"source_id": "n1", "target_id": "n2", "edge_type": "uses"}]
    resolved = resolve_edge_labels(edges, nodes)
    assert resolved[0]["source_label"] == "AuthService"
    assert resolved[0]["target_label"] == "javax.crypto"


def test_resolve_edge_labels_unknown_id():
    """Edges referencing unknown node ids get label 'unknown'."""
    nodes = [{"node_id": "n1", "label": "A"}]
    edges = [{"source_id": "n1", "target_id": "MISSING", "edge_type": "uses"}]
    resolved = resolve_edge_labels(edges, nodes)
    assert resolved[0]["target_label"] == "unknown"


# ── compute_f1 ───────────────────────────────────────────────────────────────

def test_compute_f1_perfect():
    result = compute_f1(tp=5, fp=0, fn=0)
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0


def test_compute_f1_zero_division():
    result = compute_f1(tp=0, fp=0, fn=0)
    assert result["f1"] == 0.0


def test_compute_f1_partial():
    result = compute_f1(tp=4, fp=1, fn=1)
    assert abs(result["precision"] - 0.8) < 1e-9
    assert abs(result["recall"] - 0.8) < 1e-9
    assert abs(result["f1"] - 0.8) < 1e-9


# ── evaluate_nodes ───────────────────────────────────────────────────────────

def test_evaluate_nodes_perfect():
    gt = FIXTURE_GT["nodes"]
    result = evaluate_nodes(gt, gt)  # predicted == ground truth
    assert result["f1"] == 1.0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0


def test_evaluate_nodes_one_missing():
    gt = FIXTURE_GT["nodes"]
    predicted = gt[:-1]  # drop last node
    result = evaluate_nodes(predicted, gt)
    assert result["recall"] < 1.0
    assert result["f1"] < 1.0


def test_evaluate_nodes_one_extra():
    gt = FIXTURE_GT["nodes"]
    extra = {"node_type": "CryptoAlgorithm", "label": "DES-56"}
    predicted = gt + [extra]
    result = evaluate_nodes(predicted, gt)
    assert result["precision"] < 1.0
    assert result["recall"] == 1.0


def test_evaluate_nodes_empty_predicted():
    gt = FIXTURE_GT["nodes"]
    result = evaluate_nodes([], gt)
    assert result["f1"] == 0.0


# ── evaluate_edges ───────────────────────────────────────────────────────────

def test_evaluate_edges_perfect():
    gt_edges = FIXTURE_GT["edges"]
    # gt edges already have source_label/target_label
    result = evaluate_edges(gt_edges, gt_edges)
    assert result["f1"] == 1.0


def test_evaluate_edges_one_missing():
    gt_edges = FIXTURE_GT["edges"]
    predicted = gt_edges[:-1]  # drop last edge
    result = evaluate_edges(predicted, gt_edges)
    assert result["recall"] < 1.0


def test_evaluate_edges_hallucinated():
    gt_edges = FIXTURE_GT["edges"]
    extra = {"edge_type": "uses", "source_label": "FakeService", "target_label": "javax.crypto"}
    predicted = gt_edges + [extra]
    result = evaluate_edges(predicted, gt_edges)
    assert result["precision"] < 1.0
    assert result["recall"] == 1.0


# ── compute_multihop_recall ───────────────────────────────────────────────────

def test_compute_multihop_recall_perfect():
    # fixture has chain: AuthService -> uses -> javax.crypto -> implements -> RSA-2048 -> migrates_to -> ML-KEM-768
    gt_edges = FIXTURE_GT["edges"]
    result = compute_multihop_recall(predicted_edges=gt_edges, ground_truth_edges=gt_edges)
    assert result == 1.0


def test_compute_multihop_recall_no_multihop():
    """When no 3+-hop chains exist in GT, return 1.0 (vacuously true)."""
    gt_edges = [
        {"edge_type": "uses", "source_label": "A", "target_label": "B"},
        {"edge_type": "uses", "source_label": "C", "target_label": "D"},
    ]
    result = compute_multihop_recall(predicted_edges=gt_edges, ground_truth_edges=gt_edges)
    assert result == 1.0


def test_compute_multihop_recall_missing_hop():
    gt_edges = FIXTURE_GT["edges"]
    # drop the 'implements' edge that completes the 3-hop chain
    predicted = [e for e in gt_edges if not (
        e["edge_type"] == "implements" and e["source_label"] == "javax.crypto" and e["target_label"] == "RSA-2048"
    )]
    result = compute_multihop_recall(predicted_edges=predicted, ground_truth_edges=gt_edges)
    assert result < 1.0


# ── _rank and _spearman_rho ───────────────────────────────────────────────────

def test_rank_no_ties():
    assert _rank([3.0, 1.0, 2.0]) == [3.0, 1.0, 2.0]


def test_rank_with_ties():
    # two items tied at 1.0 → average rank 1.5
    result = _rank([1.0, 1.0, 3.0])
    assert result[0] == result[1] == 1.5
    assert result[2] == 3.0


def test_spearman_rho_perfect():
    assert abs(_spearman_rho([3, 1, 2], [3, 1, 2]) - 1.0) < 1e-9


def test_spearman_rho_inverse():
    assert abs(_spearman_rho([1, 2, 3], [3, 2, 1]) - (-1.0)) < 1e-9


def test_spearman_rho_too_short():
    # n=1 with matching values → trivially perfect correlation
    assert _spearman_rho([1.0], [1.0]) == 1.0
    # n=0 → undefined, returns 0.0
    assert _spearman_rho([], []) == 0.0


# ── evaluate_migration_priority ───────────────────────────────────────────────

def test_evaluate_migration_priority_perfect():
    plan = FIXTURE_GT["migration_plan"]
    result = evaluate_migration_priority(plan, plan)
    assert abs(result["spearman_rho"] - 1.0) < 1e-9
    assert result["critical_recall"] == 1.0


def test_evaluate_migration_priority_reversed_ranking():
    gt_plan = FIXTURE_GT["migration_plan"]
    # swap ranks in predicted
    pred_plan = {
        "priority_queue": [
            {"rank": 1, "current_algorithm": "AES-CBC", "urgency_score": 20.0, "migration_priority": "low"},
            {"rank": 2, "current_algorithm": "RSA-2048", "urgency_score": 90.0, "migration_priority": "critical"},
        ]
    }
    result = evaluate_migration_priority(pred_plan, gt_plan)
    assert result["spearman_rho"] < 0  # anti-correlated
    # critical_recall: RSA-2048 is in predicted (even if rank 2) → recall = 1.0
    assert result["critical_recall"] == 1.0


def test_evaluate_migration_priority_missing_critical():
    gt_plan = FIXTURE_GT["migration_plan"]
    pred_plan = {
        "priority_queue": [
            {"rank": 1, "current_algorithm": "AES-CBC", "urgency_score": 20.0, "migration_priority": "low"},
        ]
    }
    result = evaluate_migration_priority(pred_plan, gt_plan)
    assert result["critical_recall"] < 1.0


def test_evaluate_migration_priority_empty_predicted():
    gt_plan = FIXTURE_GT["migration_plan"]
    result = evaluate_migration_priority({"priority_queue": []}, gt_plan)
    assert result["spearman_rho"] == 0.0
    assert result["critical_recall"] == 0.0


# ── compute_hallucination_rate ────────────────────────────────────────────────

def test_compute_hallucination_rate_zero():
    gt_edges = FIXTURE_GT["edges"]
    assert compute_hallucination_rate(proposed_edges=gt_edges, validated_edges=gt_edges) == 0.0


def test_compute_hallucination_rate_partial():
    # 4 proposed, 3 validated → 1 hallucinated → rate = 0.25
    gt_edges = FIXTURE_GT["edges"]
    validated = gt_edges[:3]
    assert abs(compute_hallucination_rate(proposed_edges=gt_edges, validated_edges=validated) - 0.25) < 1e-9


def test_compute_hallucination_rate_empty_proposed():
    assert compute_hallucination_rate(proposed_edges=[], validated_edges=[]) == 0.0


# ── compute_token_efficiency ─────────────────────────────────────────────────

def test_compute_token_efficiency_average():
    # 3 chains, total 9000 tokens → avg 3000
    assert compute_token_efficiency(total_tokens=9000, num_chains=3) == 3000.0


def test_compute_token_efficiency_zero_chains():
    assert compute_token_efficiency(total_tokens=0, num_chains=0) == 0.0


# ── compute_throughput ────────────────────────────────────────────────────────

def test_compute_throughput():
    # 10000 LOC in 2 minutes → 5000 LOC/min
    assert compute_throughput(total_loc=10_000, elapsed_seconds=120.0) == 5000.0


def test_compute_throughput_zero_time():
    assert compute_throughput(total_loc=1000, elapsed_seconds=0.0) == 0.0


# ── evaluate_all ─────────────────────────────────────────────────────────────

def test_evaluate_all_returns_all_keys():
    gt = FIXTURE_GT
    predicted_cdg = {
        "nodes": gt["nodes"],
        "edges": gt["edges"],
        "migration_plan": gt["migration_plan"],
    }
    result = evaluate_all(
        predicted_cdg=predicted_cdg,
        ground_truth=gt,
        total_llm_tokens=6000,
        elapsed_seconds=60.0,
        proposed_edges=gt["edges"],
        validated_edges=gt["edges"],
    )
    expected_keys = {
        "node_f1", "edge_f1", "multihop_recall",
        "spearman_rho", "critical_recall",
        "hallucination_rate", "token_efficiency", "throughput",
    }
    assert expected_keys.issubset(result.keys())


def test_evaluate_all_perfect_cdg_passes_targets():
    gt = FIXTURE_GT
    predicted_cdg = {
        "nodes": gt["nodes"],
        "edges": gt["edges"],
        "migration_plan": gt["migration_plan"],
    }
    result = evaluate_all(
        predicted_cdg=predicted_cdg,
        ground_truth=gt,
        total_llm_tokens=9000,
        elapsed_seconds=60.0,
        proposed_edges=gt["edges"],
        validated_edges=gt["edges"],
    )
    assert result["node_f1"] >= 0.80
    assert result["edge_f1"] >= 0.75
    assert result["spearman_rho"] >= 0.75
    assert result["critical_recall"] == 1.0
    assert result["hallucination_rate"] < 0.15


# ── CLI eval command ──────────────────────────────────────────────────────────

def test_cli_eval_command_exists():
    """The 'eval' command must be registered in the Typer app."""
    from cryptodep.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(app, ["eval", "--help"])
    assert result.exit_code == 0
    assert "--predicted-cdg" in result.output or "predicted" in result.output.lower()


# ── scan_stats fallback warning ───────────────────────────────────────────────

def test_eval_hallucination_fallback_emits_warning():
    """When scan_stats lacks a3_proposed_edges, evaluate_all should emit a UserWarning."""
    import warnings

    cdg_without_field = {"nodes": [], "edges": [], "scan_stats": {}}
    gt = {"nodes": [], "edges": [], "scan_stats": {}, "migration_plan": {}}

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = evaluate_all(
            predicted_cdg=cdg_without_field,
            ground_truth=gt,
            total_llm_tokens=0,
            elapsed_seconds=1.0,
            proposed_edges=[],
            validated_edges=[],
        )
    fallback_warnings = [x for x in w if "a3_proposed_edges absent" in str(x.message)]
    assert len(fallback_warnings) == 1
    assert result["hallucination_rate"] == 0.0


def test_eval_hallucination_no_warning_when_scan_stats_present():
    """When scan_stats has a3_proposed_edges, no fallback warning should be emitted."""
    import warnings

    cdg_with_field = {
        "nodes": [], "edges": [],
        "scan_stats": {"a3_proposed_edges": 5, "a3_validated_edges": 4},
    }
    gt = {"nodes": [], "edges": [], "scan_stats": {}, "migration_plan": {}}

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        evaluate_all(
            predicted_cdg=cdg_with_field,
            ground_truth=gt,
            total_llm_tokens=0,
            elapsed_seconds=1.0,
            proposed_edges=[{}] * 5,
            validated_edges=[{}] * 4,
        )
    fallback_warnings = [x for x in w if "a3_proposed_edges absent" in str(x.message)]
    assert len(fallback_warnings) == 0
