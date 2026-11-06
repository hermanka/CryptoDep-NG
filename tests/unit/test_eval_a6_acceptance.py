"""Acceptance criteria tests for M6 A6 Crypto Reachability Analyzer.

AC-A6-01: Entry point detection precision >= 0.90 on WebGoat crypto lesson files
AC-A6-02: A5 Spearman rho improvement >= +0.05 with reachability scoring (synthetic data)
"""
from __future__ import annotations

import pytest
from pathlib import Path

from cryptodep.tools.ast_tools import parse_file_ast
from cryptodep.tools.callgraph_tools import detect_entry_points
from cryptodep.agents.a5_planner import _compute_priority_score
from cryptodep.schema.cdg_models import (
    CryptoAlgorithmNode,
    MigrationPriority,
    NistQuantumVulnClass,
)
from tests.eval.eval_metrics import _spearman_rho

# ── Paths ─────────────────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).parent.parent.parent
_WEBGOAT_CRYPTO = (
    _REPO_ROOT
    / "test_repos"
    / "webgoat"
    / "src"
    / "main"
    / "java"
    / "org"
    / "owasp"
    / "webgoat"
    / "lessons"
    / "cryptography"
)

# Ground truth: filename -> set of method names that are genuine REST entry points.
# Derived by inspecting @GetMapping / @PostMapping / @RequestMapping on methods
# inside @RestController classes.
_CRYPTO_GT_ENDPOINTS: dict[str, set[str]] = {
    "EncodingAssignment.java": {"getBasicAuth", "completed"},
    "HashingAssignment.java": {"getMd5", "getSha256", "completed"},
    "SecureDefaultsAssignment.java": {"completed"},
    "SigningAssignment.java": {"getPrivateKey", "completed"},
    "XOREncodingAssignment.java": {"completed"},
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_webgoat_crypto_cache() -> tuple[dict, dict]:
    """Build file_index and ast_cache for the 5 WebGoat crypto lesson files."""
    file_index: dict = {}
    ast_cache: dict = {}
    for filename in _CRYPTO_GT_ENDPOINTS:
        path = _WEBGOAT_CRYPTO / filename
        if not path.exists():
            continue
        result = parse_file_ast(path, "java")
        if result:
            key = str(path)
            ast_cache[key] = result
            file_index[key] = {
                "path": key,
                "language": "java",
                "size_bytes": path.stat().st_size,
                "loc": 50,
            }
    return file_index, ast_cache


def _scores_to_ranks(scores: list[float]) -> list[int]:
    """Convert a list of scores to ranks where rank 1 = highest score.

    Ties are broken arbitrarily (first occurrence wins lower rank number).
    The test data is designed to have no ties.
    """
    n = len(scores)
    order = sorted(range(n), key=lambda i: scores[i], reverse=True)
    ranks = [0] * n
    for rank_pos, idx in enumerate(order, 1):
        ranks[idx] = rank_pos
    return ranks


# ── AC-A6-01: Entry point detection precision ─────────────────────────────────

def test_ac_a6_01_entry_point_detection_precision():
    """AC-A6-01: detect_entry_points() precision >= 0.90 on WebGoat crypto lessons.

    Runs Tree-sitter based entry point detection on 5 known @RestController
    files and checks that ≥ 90% of detected entry points are genuinely REST
    endpoints (defined by the ground-truth mapping above).
    """
    file_index, ast_cache = _build_webgoat_crypto_cache()

    if not ast_cache:
        pytest.skip("WebGoat test repo not available at test_repos/webgoat/")

    detected = detect_entry_points(file_index, ast_cache)

    # Build (filename, method) pairs for comparison
    detected_set: set[tuple[str, str]] = {
        (Path(ep["file"]).name, ep["method"]) for ep in detected
    }
    gt_set: set[tuple[str, str]] = {
        (filename, method)
        for filename, methods in _CRYPTO_GT_ENDPOINTS.items()
        for method in methods
    }

    tp = len(detected_set & gt_set)
    fp = len(detected_set - gt_set)
    fn = len(gt_set - detected_set)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    assert precision >= 0.90, (
        f"AC-A6-01 FAIL: entry point detection precision {precision:.3f} < 0.90\n"
        f"  Detected: {sorted(detected_set)}\n"
        f"  Ground truth: {sorted(gt_set)}\n"
        f"  False positives: {sorted(detected_set - gt_set)}\n"
        f"  False negatives: {sorted(gt_set - detected_set)}\n"
        f"  TP={tp}, FP={fp}, FN={fn}, Recall={recall:.3f}"
    )


# ── AC-A6-02: Spearman rho improvement ────────────────────────────────────────

def test_ac_a6_02_spearman_rho_improvement():
    """AC-A6-02: Adding reachability scoring improves Spearman rho by >= +0.05.

    Synthetic scenario: 4 quantum-vulnerable nodes where urgency-only ranking
    disagrees with expert ranking.  Reachability scores (aligned with expert
    exposure knowledge) correct the ranking and lift Spearman rho.

    Without reachability: urgency alone ranks DSA first (highest urgency=90),
    disagreeing with expert who ranks RSA first (most exposed, reachability=1.0).
    Computed baseline Spearman rho = 0.0 (see design comments in PROGRESS.md).

    With reachability: RSA floats to the top → predicted ranking matches expert
    → Spearman rho = 0.8, improvement = +0.8 >= +0.05.
    """
    # Columns: label, urgency (0-100), hndl_risk, expert_rank, reachability_score
    scenarios = [
        ("RSA", 30, True,  1, 1.0),   # Most critical: widely exposed REST endpoint
        ("MD5", 50, True,  2, 0.5),   # Moderate exposure
        ("DH",  70, False, 3, 0.2),   # Low exposure (internal service)
        ("DSA", 90, False, 4, 0.0),   # Unreachable from any public entry point
    ]

    weights_baseline = {
        "urgency": 0.50, "hndl": 0.25, "boundary": 0.15, "lifetime": 0.10,
    }
    weights_with_reach = {
        "urgency": 0.35, "hndl": 0.20, "boundary": 0.12, "lifetime": 0.08,
        "reachability": 0.25,
    }

    algo_nodes = []
    for label, urgency, hndl, expert_rank, reach in scenarios:
        node = CryptoAlgorithmNode(
            label=label,
            algorithm_family=label,
            quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
            migration_priority=MigrationPriority.CRITICAL,
            migration_urgency_score=float(urgency),
            hndl_risk=hndl,
        )
        algo_nodes.append((node, expert_rank, reach))

    # Baseline: urgency + hndl only (reachability uses default=1.0 neutral weight=0)
    scores_baseline = [
        _compute_priority_score(node, weights_baseline)
        for node, _expert_rank, _reach in algo_nodes
    ]
    pred_ranks_baseline = _scores_to_ranks(scores_baseline)
    expert_ranks = [exp for _node, exp, _reach in algo_nodes]

    rho_baseline = _spearman_rho(
        [float(r) for r in expert_ranks],
        [float(r) for r in pred_ranks_baseline],
    )

    # With reachability: reachability_score aligned with expert exposure ranking
    scores_with_reach = [
        _compute_priority_score(node, weights_with_reach, reachability_score=reach)
        for node, _expert_rank, reach in algo_nodes
    ]
    pred_ranks_with_reach = _scores_to_ranks(scores_with_reach)

    rho_with_reach = _spearman_rho(
        [float(r) for r in expert_ranks],
        [float(r) for r in pred_ranks_with_reach],
    )

    improvement = rho_with_reach - rho_baseline

    assert improvement >= 0.05, (
        f"AC-A6-02 FAIL: Spearman rho improvement {improvement:.3f} < +0.05\n"
        f"  Baseline rho (urgency only): {rho_baseline:.3f}\n"
        f"  With reachability rho:       {rho_with_reach:.3f}\n"
        f"  Baseline scores:   {[round(s, 3) for s in scores_baseline]}\n"
        f"  Reachable scores:  {[round(s, 3) for s in scores_with_reach]}\n"
        f"  Expert ranks:      {expert_ranks}\n"
        f"  Predicted (base):  {pred_ranks_baseline}\n"
        f"  Predicted (reach): {pred_ranks_with_reach}"
    )
