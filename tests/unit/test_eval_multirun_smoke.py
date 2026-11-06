"""Smoke tests for multi-run evaluation output format (M7 Tasks 1 & 6)."""
from __future__ import annotations

import math

from tests.eval.eval_metrics import aggregate_multirun_results


def _fake_result(node_f1: float = 0.9, edge_f1: float = 0.8) -> dict:
    return {
        "node_f1": node_f1,
        "node_precision": node_f1,
        "node_recall": node_f1,
        "edge_f1": edge_f1,
        "edge_precision": edge_f1,
        "edge_recall": edge_f1,
        "multihop_recall": 1.0,
        "spearman_rho": 0.9,
        "critical_recall": 1.0,
        "hallucination_rate": 0.05,
        "token_efficiency": 2000.0,
        "throughput": 6000.0,
        "passes_node_f1": node_f1 >= 0.80,
        "passes_edge_f1": edge_f1 >= 0.75,
        "passes_multihop_recall": True,
        "passes_spearman_rho": True,
        "passes_critical_recall": True,
        "passes_hallucination_rate": True,
    }


def test_aggregate_has_required_keys() -> None:
    result = aggregate_multirun_results([_fake_result(), _fake_result(0.85, 0.77)])
    assert "runs" in result
    assert "metrics" in result
    assert "passes" in result
    assert "individual_runs" in result


def test_aggregate_metrics_have_mean_and_std() -> None:
    result = aggregate_multirun_results([_fake_result(), _fake_result(0.85, 0.77)])
    for metric_name, metric_val in result["metrics"].items():
        assert "mean" in metric_val, f"Missing 'mean' in {metric_name}"
        assert "std" in metric_val, f"Missing 'std' in {metric_name}"


def test_aggregate_passes_derived_from_mean() -> None:
    """passes_* must be derived from mean values, not individual run booleans."""
    # Run 1 node_f1=0.9 (pass), Run 2 node_f1=0.5 (fail) → mean=0.7 < 0.80 → False
    result = aggregate_multirun_results([_fake_result(node_f1=0.9), _fake_result(node_f1=0.5)])
    assert math.isclose(result["metrics"]["node_f1"]["mean"], 0.7, abs_tol=1e-6)
    assert result["passes"]["passes_node_f1"] is False


def test_aggregate_individual_runs_preserved() -> None:
    runs = [_fake_result(), _fake_result(0.85, 0.77)]
    result = aggregate_multirun_results(runs)
    assert result["runs"] == 2
    assert len(result["individual_runs"]) == 2


def test_aggregate_std_computation() -> None:
    """Population std: sqrt(((0.8-0.9)^2 + (1.0-0.9)^2) / 2) = 0.1."""
    result = aggregate_multirun_results([_fake_result(node_f1=0.8), _fake_result(node_f1=1.0)])
    assert math.isclose(result["metrics"]["node_f1"]["mean"], 0.9, abs_tol=1e-6)
    assert math.isclose(result["metrics"]["node_f1"]["std"], 0.1, abs_tol=1e-6)


def test_aggregate_runs_count() -> None:
    runs = [_fake_result() for _ in range(5)]
    result = aggregate_multirun_results(runs)
    assert result["runs"] == 5
