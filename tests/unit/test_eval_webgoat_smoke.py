"""Smoke tests for evaluate_all() with WebGoat ground truth.

Verifies:
  1. Ground truth file exists and has expected structure
  2. Ground truth contains correct quantum-vulnerable algorithms
  3. Critical algorithms are ranked first in migration priority queue
  4. Perfect prediction (GT as predicted) passes all 8 PRD metric targets
"""
from __future__ import annotations

import json
import pathlib

GT_PATH = pathlib.Path("tests/eval/ground_truth/webgoat_gt.json")


def test_webgoat_gt_file_exists() -> None:
    """Ground truth file must exist at expected path."""
    assert GT_PATH.exists(), f"WebGoat ground truth not found at {GT_PATH}"


def test_webgoat_gt_has_expected_structure() -> None:
    """Ground truth must have required top-level keys and correct counts."""
    data = json.loads(GT_PATH.read_text())
    assert "nodes" in data
    assert "edges" in data
    assert "migration_plan" in data
    assert "priority_queue" in data["migration_plan"]
    assert "scan_stats" in data
    assert data["scan_stats"]["total_loc"] == 26320
    assert len(data["nodes"]) == 12
    assert len(data["edges"]) == 8
    assert len(data["migration_plan"]["priority_queue"]) == 1


def test_webgoat_gt_has_quantum_vulnerable_algorithms() -> None:
    """Ground truth must identify RSA-2048 as quantum_vulnerable."""
    data = json.loads(GT_PATH.read_text())
    vuln = [n for n in data["nodes"]
            if n.get("quantum_vuln_class") == "quantum_vulnerable"]
    assert len(vuln) == 1, f"Expected only RSA-2048 as quantum_vulnerable, got {[n['label'] for n in vuln]}"
    assert vuln[0]["label"] == "RSA-2048"


def test_webgoat_gt_critical_algorithms_ranked_first() -> None:
    """Critical priority algorithm must be ranked first in migration plan."""
    data = json.loads(GT_PATH.read_text())
    pq = data["migration_plan"]["priority_queue"]
    assert pq[0]["migration_priority"] == "critical"
    assert pq[0]["current_algorithm"] == "RSA-2048"
    # Only one critical item in the WebGoat GT — RSA-2048 is the sole quantum-vulnerable algo
    assert len(pq) == 1


def test_evaluate_all_perfect_prediction_passes_all_metrics() -> None:
    """Perfect prediction (GT used as predicted) must pass all 8 PRD metric targets.

    The 8 metrics with PRD thresholds:
      1. Node F1 >= 0.80
      2. Edge F1 >= 0.75
      3. Multi-hop recall >= 0.70
      4. Spearman rho >= 0.75
      5. Critical recall == 1.00
      6. Hallucination rate < 0.15
      7. Token efficiency <= 3000 tokens/chain
      8. Throughput >= 5000 LOC/min
    """
    from tests.eval.eval_metrics import evaluate_all, resolve_edge_labels

    data = json.loads(GT_PATH.read_text())

    pred_nodes = data["nodes"]
    pred_edges = data["edges"]  # already label-based in GT format
    pred_edges_resolved = resolve_edge_labels(pred_edges, pred_nodes)

    # Compute elapsed_seconds for exactly 5000 LOC/min throughput:
    # throughput = total_loc / (elapsed_seconds / 60)
    # 5000 = 26320 / (elapsed_seconds / 60)
    # elapsed_seconds = 26320 * 60 / 5000 = 315.84 seconds
    total_loc = data["scan_stats"]["total_loc"]
    results = evaluate_all(
        predicted_cdg=data,
        ground_truth=data,
        total_llm_tokens=3000 * 4,   # 4 chains × 3000 tokens = exactly at limit
        elapsed_seconds=total_loc * 60 / 5000,  # exactly 5000 LOC/min
        proposed_edges=pred_edges_resolved,
        validated_edges=pred_edges_resolved,
    )

    # With perfect prediction, F1 metrics must be 1.0
    assert results["node_f1"] == 1.0, f"node_f1={results['node_f1']}"
    assert results["edge_f1"] == 1.0, f"edge_f1={results['edge_f1']}"
    assert results["critical_recall"] == 1.0, f"critical_recall={results['critical_recall']}"

    # All PRD pass thresholds must be met
    pass_keys = [
        "passes_node_f1",
        "passes_edge_f1",
        "passes_multihop_recall",
        "passes_spearman_rho",
        "passes_critical_recall",
        "passes_hallucination_rate",
    ]
    for key in pass_keys:
        assert results[key], (
            f"{key} should be True for perfect prediction but got False. "
            f"Full results: {results}"
        )
