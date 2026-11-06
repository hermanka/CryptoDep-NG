"""Evaluation metrics for CryptoDep-LLM (PRD Section 10.2).

Metrics:
  - Node F1 (target >= 0.80)
  - Edge F1 (target >= 0.75)
  - Multi-hop Recall on 3+-hop chains (target >= 0.70)
  - MPQS Spearman rho vs. expert ranking (target >= 0.75)
  - Critical Recall (target = 1.00)
  - Throughput (target >= 5000 LOC/min)
  - Hallucination rate (target < 15%)
  - Token efficiency (<= 3000 tokens / dependency chain)

Usage:
  python tests/eval/eval_metrics.py --repo webgoat --gt tests/eval/ground_truth/webgoat_gt.json
"""
from __future__ import annotations

import argparse
import json
import networkx as nx
from pathlib import Path
from typing import Any


def compute_f1(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _node_key(node: dict) -> tuple[str, str]:
    """Canonical identity key for a CDG node: (node_type, label)."""
    return (node["node_type"], node["label"])


def _edge_key(edge: dict) -> tuple[str, str, str]:
    """Canonical identity key for a CDG edge: (source_label, edge_type, target_label)."""
    return (edge["source_label"], edge["edge_type"], edge["target_label"])


def resolve_edge_labels(edges: list[dict], nodes: list[dict]) -> list[dict]:
    """Add source_label / target_label to each edge dict by resolving node_id references.

    Edges in CDGDocument use source_id / target_id (UUIDs). Ground truth uses labels
    directly. Unknown node_ids produce label 'unknown'. If source_label/target_label
    already exist, they are preserved (idempotent).
    """
    id_to_label: dict[str, str] = {n["node_id"]: n["label"] for n in nodes}
    resolved = []
    for edge in edges:
        e = dict(edge)
        # If labels already exist, preserve them; otherwise resolve from IDs
        if "source_label" not in e:
            e["source_label"] = id_to_label.get(e.get("source_id", ""), "unknown")
        if "target_label" not in e:
            e["target_label"] = id_to_label.get(e.get("target_id", ""), "unknown")
        resolved.append(e)
    return resolved


def evaluate_nodes(predicted: list[dict], ground_truth: list[dict]) -> dict[str, float]:
    """Compute Node F1 against ground truth. Nodes matched by (node_type, label)."""
    def _node_key_relaxed(node: dict) -> tuple[str, str]:
        label = node["label"]
        if node["node_type"] == "CryptoAlgorithm":
            # Normalize RSA-2048 <-> RSA for matching
            label = label.split("-")[0]
        return (node["node_type"], label)

    pred_keys = {_node_key_relaxed(n) for n in predicted}
    gt_keys = {_node_key_relaxed(n) for n in ground_truth}
    tp = len(pred_keys & gt_keys)
    fp = len(pred_keys - gt_keys)
    fn = len(gt_keys - pred_keys)
    return compute_f1(tp=tp, fp=fp, fn=fn)


def evaluate_edges(predicted: list[dict], ground_truth: list[dict]) -> dict[str, float]:
    """Compute Edge F1 against ground truth.

    Both predicted and ground_truth must have source_label / target_label fields.
    Use resolve_edge_labels() on predicted CDG edges first.
    Edges matched by (source_label, edge_type, target_label).
    """
    def _edge_key_relaxed(edge: dict) -> tuple[str, str, str]:
        src = edge["source_label"]
        tgt = edge["target_label"]
        # Normalize RSA-2048 <-> RSA in edge targets
        if "-" in tgt and any(f in tgt.upper() for f in ["RSA", "EC", "DH"]):
             tgt = tgt.split("-")[0]
        return (src, edge["edge_type"], tgt)

    pred_keys = {_edge_key_relaxed(e) for e in predicted}
    gt_keys = {_edge_key_relaxed(e) for e in ground_truth}
    tp = len(pred_keys & gt_keys)
    fp = len(pred_keys - gt_keys)
    fn = len(gt_keys - pred_keys)
    return compute_f1(tp=tp, fp=fp, fn=fn)


def compute_multihop_recall(
    predicted_edges: list[dict],
    ground_truth_edges: list[dict],
    min_hops: int = 3,
) -> float:
    """Compute Multi-hop Recall: fraction of 3+-edge GT chains present in predicted.

    A chain is fully recalled if every edge in it exists in predicted.
    Returns 1.0 vacuously when no chains of min_hops length exist in ground truth.
    """
    def _build_graph(edges: list[dict]) -> nx.MultiDiGraph:
        g = nx.MultiDiGraph()
        for e in edges:
            edge_key = _edge_key(e)
            g.add_edge(e["source_label"], e["target_label"], edge_key=edge_key)
        return g

    gt_graph = _build_graph(ground_truth_edges)
    pred_edge_keys = {
        (e["source_label"], e["edge_type"], e["target_label"].split("-")[0] if "-" in e["target_label"] else e["target_label"])
        for e in predicted_edges
    }

    gt_chains: list[list[tuple[str, str, str]]] = []
    for source in gt_graph.nodes:
        for target in gt_graph.nodes:
            if source == target:
                continue
            # cutoff=min_hops + 2 caps the path enumeration at (min_hops + 2) edges
            for path_nodes in nx.all_simple_paths(gt_graph, source, target, cutoff=min_hops + 2):
                if len(path_nodes) - 1 >= min_hops:
                    chain = []
                    for i in range(len(path_nodes) - 1):
                        u, v = path_nodes[i], path_nodes[i + 1]
                        # For MultiDiGraph, g[u][v] is a dict of {edge_index: attr_dict}
                        edge_attrs = next(iter(gt_graph[u][v].values()))
                        key = edge_attrs["edge_key"]
                        # Normalize for matching
                        chain.append((key[0], key[1], key[2].split("-")[0] if "-" in key[2] else key[2]))
                    gt_chains.append(chain)

    if not gt_chains:
        return 1.0

    recalled = sum(
        1 for chain in gt_chains if all(ek in pred_edge_keys for ek in chain)
    )
    return recalled / len(gt_chains)


def _rank(values: list[float]) -> list[float]:
    """Assign average ranks to a list of values, handling ties (Spearman method)."""
    n = len(values)
    indexed = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n - 1 and values[indexed[j + 1]] == values[indexed[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[indexed[k]] = avg
        i = j + 1
    return ranks


def _spearman_rho(x: list[float], y: list[float]) -> float:
    """Compute Spearman rank correlation coefficient.

    For n=1: returns 1.0 if ranks agree (trivially), 0.0 otherwise.
    For n<1: returns 0.0.
    """
    n = len(x)
    if n < 2:
        return 1.0 if n == 1 and x == y else 0.0
    rx = _rank(x)
    ry = _rank(y)
    mean_rx = sum(rx) / n
    mean_ry = sum(ry) / n
    num = sum((rx[i] - mean_rx) * (ry[i] - mean_ry) for i in range(n))
    den_x = sum((rx[i] - mean_rx) ** 2 for i in range(n)) ** 0.5
    den_y = sum((ry[i] - mean_ry) ** 2 for i in range(n)) ** 0.5
    if den_x == 0 or den_y == 0:
        return 0.0
    return num / (den_x * den_y)


def evaluate_migration_priority(
    predicted_plan: dict[str, Any],
    ground_truth_plan: dict[str, Any],
) -> dict[str, float]:
    """Compute MPQS Spearman rho and Critical Recall.

    spearman_rho: rank correlation between predicted and GT urgency rankings.
    critical_recall: fraction of GT 'critical' items present in predicted plan.
    """
    gt_queue: list[dict] = ground_truth_plan.get("priority_queue", [])
    pred_queue: list[dict] = predicted_plan.get("priority_queue", [])

    if not gt_queue:
        rho = 1.0 if not pred_queue else 0.0
        return {"spearman_rho": rho, "critical_recall": 1.0}

    max_pred_rank = len(pred_queue) + 1
    pred_rank_by_algo: dict[str, int] = {
        item["current_algorithm"]: item["rank"] for item in pred_queue
    }

    # Helper to resolve algorithm family from a node label (e.g., "RSA-2048" -> "RSA")
    def _get_family(label: str) -> str:
        return label.split("-")[0].split(" ")[0].upper()

    pred_rank_by_family: dict[str, int] = {
        _get_family(item["current_algorithm"]): item["rank"] for item in pred_queue
    }

    # Helper to resolve node labels for Node F1 matching
    def _get_node_label(node: dict) -> str:
        label = node["label"]
        if node["node_type"] == "CryptoAlgorithm":
            # Normalize RSA-2048 <-> RSA for matching
            return label.split("-")[0]
        return label

    gt_ranks = list(range(1, len(gt_queue) + 1))
    pred_ranks = []
    for item in gt_queue:
        label = item["current_algorithm"]
        # Try exact label match first, then family match as fallback
        rank = pred_rank_by_algo.get(label)
        if rank is None:
            rank = pred_rank_by_family.get(_get_family(label), max_pred_rank)
        pred_ranks.append(rank)

    rho = _spearman_rho(
        [float(r) for r in gt_ranks],
        [float(r) for r in pred_ranks],
    )

    critical_algos_gt = {
        item["current_algorithm"]
        for item in gt_queue
        if item.get("migration_priority") == "critical"
    }
    if not critical_algos_gt:
        critical_recall = 1.0
    else:
        pred_algos = {item["current_algorithm"] for item in pred_queue}
        recalled_critical = critical_algos_gt & pred_algos
        critical_recall = len(recalled_critical) / len(critical_algos_gt)

    return {"spearman_rho": rho, "critical_recall": critical_recall}


def compute_hallucination_rate(
    proposed_edges: list[dict],
    validated_edges: list[dict],
) -> float:
    """Compute hallucination rate: FP edges / total proposed edges.  # PRD §10.2.5

    A hallucinated edge was proposed by the LLM but failed import-graph validation.
    PRD target: < 0.15.
    """
    total = len(proposed_edges)
    if total == 0:
        return 0.0
    validated_count = len(validated_edges)
    fp = total - validated_count
    return max(fp, 0) / total


def compute_token_efficiency(total_tokens: int, num_chains: int) -> float:
    """Compute average LLM tokens per dependency chain. Informational metric."""
    if num_chains == 0:
        return 0.0
    return total_tokens / num_chains


def compute_throughput(total_loc: int, elapsed_seconds: float) -> float:
    """Compute pipeline throughput in LOC/minute. Informational metric."""
    if elapsed_seconds <= 0:
        return 0.0
    return total_loc / (elapsed_seconds / 60.0)


def evaluate_all(
    predicted_cdg: dict[str, Any],
    ground_truth: dict[str, Any],
    total_llm_tokens: int,
    elapsed_seconds: float,
    proposed_edges: list[dict],
    validated_edges: list[dict],
) -> dict[str, float]:
    """Run all 8 evaluation metrics and return a single result dict.

    Args:
        predicted_cdg: CDGDocument-like dict with 'nodes', 'edges' (source_id/target_id),
            and 'migration_plan'.
        ground_truth: expert GT dict with 'nodes', 'edges' (source_label/target_label),
            'migration_plan', and 'scan_stats.total_loc'.
        total_llm_tokens: CDGState.total_llm_tokens from the pipeline run.
        elapsed_seconds: wall-clock seconds for the pipeline run.
        proposed_edges: all LLM-proposed edges before validation (pre-resolved with labels).
        validated_edges: edges that survived import-graph validation (pre-resolved with labels).

    Returns dict with keys:
        node_f1, node_precision, node_recall,
        edge_f1, edge_precision, edge_recall,
        multihop_recall, spearman_rho, critical_recall,
        hallucination_rate, token_efficiency, throughput,
        passes_node_f1, passes_edge_f1, passes_multihop_recall,
        passes_spearman_rho, passes_critical_recall, passes_hallucination_rate.
        token_efficiency and throughput are informational only (no passes_* key).
    """
    import warnings as _warnings

    pred_nodes: list[dict] = predicted_cdg.get("nodes", [])
    pred_edges_raw: list[dict] = predicted_cdg.get("edges", [])
    pred_edges = resolve_edge_labels(pred_edges_raw, pred_nodes)

    _scan_stats = predicted_cdg.get("scan_stats", {})
    if "a3_proposed_edges" not in _scan_stats:
        _warnings.warn(
            "scan_stats.a3_proposed_edges absent — hallucination_rate will be 0.0 via fallback "
            "(CDG pre-dates scan_stats instrumentation). Re-run with current pipeline to get real data.",
            stacklevel=2,
        )

    gt_nodes: list[dict] = ground_truth.get("nodes", [])
    gt_edges: list[dict] = ground_truth.get("edges", [])
    gt_plan: dict = ground_truth.get("migration_plan", {})
    pred_plan: dict = predicted_cdg.get("migration_plan", {})
    total_loc: int = ground_truth.get("scan_stats", {}).get("total_loc", 0)

    num_chains = len(validated_edges)

    node_metrics = evaluate_nodes(pred_nodes, gt_nodes)
    edge_metrics = evaluate_edges(pred_edges, gt_edges)
    multihop = compute_multihop_recall(pred_edges, gt_edges)
    migration = evaluate_migration_priority(pred_plan, gt_plan)
    halluc = compute_hallucination_rate(proposed_edges, validated_edges)
    tok_eff = compute_token_efficiency(total_llm_tokens, num_chains)
    throughput = compute_throughput(total_loc, elapsed_seconds) if elapsed_seconds > 0 else None

    return {
        "node_f1": node_metrics["f1"],
        "node_precision": node_metrics["precision"],
        "node_recall": node_metrics["recall"],
        "edge_f1": edge_metrics["f1"],
        "edge_precision": edge_metrics["precision"],
        "edge_recall": edge_metrics["recall"],
        "multihop_recall": multihop,
        "spearman_rho": migration["spearman_rho"],
        "critical_recall": migration["critical_recall"],
        "hallucination_rate": halluc,
        "token_efficiency": tok_eff,
        "throughput": throughput if throughput is not None else 0.0,
        # PRD targets (bool stored as bool, not float)
        "passes_node_f1": node_metrics["f1"] >= 0.80,
        "passes_edge_f1": edge_metrics["f1"] >= 0.75,
        "passes_multihop_recall": multihop >= 0.70,
        "passes_spearman_rho": migration["spearman_rho"] >= 0.75,
        "passes_critical_recall": migration["critical_recall"] == 1.0,
        "passes_hallucination_rate": halluc < 0.15,
    }


def _print_report(repo: str, results: dict[str, Any]) -> None:
    """Print a human-readable evaluation report to stdout."""
    def status(key: str) -> str:
        return "PASS" if results.get(f"passes_{key}") else "FAIL"

    print(f"\n{'='*60}")
    print(f"CryptoDep-LLM Evaluation Report — {repo}")
    print(f"{'='*60}")
    print(f"  Node F1:            {results['node_f1']:.3f}  (target >= 0.80)  [{status('node_f1')}]")
    print(f"  Edge F1:            {results['edge_f1']:.3f}  (target >= 0.75)  [{status('edge_f1')}]")
    print(f"  Multi-hop Recall:   {results['multihop_recall']:.3f}  (target >= 0.70)  [{status('multihop_recall')}]")
    print(f"  Spearman rho:       {results['spearman_rho']:.3f}  (target >= 0.75)  [{status('spearman_rho')}]")
    print(f"  Critical Recall:    {results['critical_recall']:.3f}  (target = 1.00)  [{status('critical_recall')}]")
    print(f"  Hallucination rate: {results['hallucination_rate']:.3f}  (target < 0.15)  [{status('hallucination_rate')}]")
    print(f"  Token efficiency:   {results['token_efficiency']:.0f} tok/chain  (informational)")
    tp_val = results["throughput"]
    tp_str = f"{tp_val:.0f} LOC/min" if tp_val > 0 else "N/A (no pipeline run)"
    print(f"  Throughput:         {tp_str}  (informational)")
    passes = sum(1 for k in results if k.startswith("passes_") and results[k])
    total = sum(1 for k in results if k.startswith("passes_"))
    print(f"\n  Targets met: {passes}/{total}")
    print(f"{'='*60}\n")


_PASS_THRESHOLDS: dict[str, tuple[str, float]] = {
    "passes_node_f1":          ("node_f1",          0.80),
    "passes_edge_f1":          ("edge_f1",           0.75),
    "passes_multihop_recall":  ("multihop_recall",   0.70),
    "passes_spearman_rho":     ("spearman_rho",      0.75),
    "passes_hallucination_rate": ("hallucination_rate", 0.15),
}


def aggregate_multirun_results(individual_runs: list[dict]) -> dict:
    """Aggregate N independent eval result dicts into mean ± std per metric.

    Returns dict with keys:
        runs (int), metrics (dict metric→{mean,std}),
        passes (dict passes_*→bool derived from means),
        individual_runs (list of original dicts).
    """
    import math

    n = len(individual_runs)
    numeric_keys = [k for k in individual_runs[0] if not k.startswith("passes_")]

    metrics: dict[str, dict[str, float]] = {}
    for key in numeric_keys:
        values = [float(r[key]) for r in individual_runs]
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        metrics[key] = {"mean": mean, "std": math.sqrt(variance)}

    passes: dict[str, bool] = {}
    for pass_key, (metric_key, threshold) in _PASS_THRESHOLDS.items():
        mean_val = metrics[metric_key]["mean"]
        if pass_key == "passes_hallucination_rate":
            passes[pass_key] = mean_val < threshold
        else:
            passes[pass_key] = mean_val >= threshold
    # critical_recall: mean must equal exactly 1.0
    passes["passes_critical_recall"] = math.isclose(
        metrics["critical_recall"]["mean"], 1.0, abs_tol=1e-9
    )

    return {
        "runs": n,
        "metrics": metrics,
        "passes": passes,
        "individual_runs": individual_runs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CryptoDep-LLM evaluation")
    parser.add_argument("--repo", required=True, help="Repository name")
    parser.add_argument("--gt", required=True, help="Ground truth CDG JSON path")
    parser.add_argument("--predicted", required=True, help="Predicted CDG JSON path")
    parser.add_argument("--output", default=None, help="Results JSON output path")
    parser.add_argument("--total-tokens", type=int, default=0, help="Total LLM tokens used")
    parser.add_argument("--elapsed", type=float, default=0.0, help="Pipeline elapsed seconds")
    args = parser.parse_args()

    gt_path = Path(args.gt)
    if not gt_path.exists():
        print(f"Ground truth file not found: {gt_path}")
        raise SystemExit(1)

    pred_path = Path(args.predicted)
    if not pred_path.exists():
        print(f"Predicted CDG file not found: {pred_path}")
        raise SystemExit(1)

    ground_truth = json.loads(gt_path.read_text())
    predicted_cdg = json.loads(pred_path.read_text())
    predicted_edges_raw = predicted_cdg.get("edges", [])
    predicted_nodes = predicted_cdg.get("nodes", [])
    resolved_edges = resolve_edge_labels(predicted_edges_raw, predicted_nodes)

    # Read A3 proposed/validated counts from scan_stats (written by A4).
    # Falls back to len(resolved_edges) for both if not present (legacy CDGs → rate=0.0).
    scan_stats = predicted_cdg.get("scan_stats", {})
    a3_proposed = scan_stats.get("a3_proposed_edges", len(resolved_edges))
    a3_validated = scan_stats.get("a3_validated_edges", len(resolved_edges))

    # Build synthetic edge lists of the right length for compute_hallucination_rate.
    proposed_edges_proxy = [{}] * a3_proposed
    validated_edges_proxy = [{}] * a3_validated

    results = evaluate_all(
        predicted_cdg=predicted_cdg,
        ground_truth=ground_truth,
        total_llm_tokens=args.total_tokens,
        elapsed_seconds=args.elapsed,
        proposed_edges=proposed_edges_proxy,
        validated_edges=validated_edges_proxy,
    )

    _print_report(args.repo, results)

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
