"""Agent 6 — Reachability Analyzer (PRD Section 5.6 / M6).

Responsibility:
  Given validated crypto findings and the AST-derived call graph, perform a
  BFS traversal from each detected entry point to determine which findings are
  reachable at runtime and how many hops away they are.

  Reachability score formula: 1.0 / hop_count  (0.0 if unreachable)

  Outputs:
  - entry_points     — list of EntryPoint dicts detected in the repo
  - call_graph       — qualified "Class.method" → [callee, ...] map
  - reachability_map — finding source_ref → reachability_score float
  - reachability_paths — finding source_ref → list[str] shortest path

Acceptance criteria (M6):
  AC-A6-01: Direct finding scores 1.0
  AC-A6-02: Two-hop finding scores 0.5
  AC-A6-03: Unreachable finding scores 0.0
  AC-A6-04: BFS terminates on cycles
  AC-A6-05: max_hops cap is enforced
"""
from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

from cryptodep.agents import BaseAgent
from cryptodep.config import CryptoDependConfig
from cryptodep.tools.ast_tools import source_ref_path
from cryptodep.state import CDGState, CryptoFinding, EntryPoint
from cryptodep.tools.callgraph_tools import build_call_graph, detect_entry_points

log = structlog.get_logger().bind(agent_name="A6:ReachabilityAnalyzer")


# ── Pure helper functions ─────────────────────────────────────────────────────

def _compute_reachability_score(hop_count: int) -> float:
    """Return 1.0 / hop_count for hop_count > 0, else 0.0."""
    if hop_count <= 0:
        return 0.0
    return 1.0 / hop_count


def _finding_stems(findings: List[CryptoFinding]) -> Dict[str, str]:
    """Map each finding's source_ref to its file stem (without extension/path).

    E.g. "AuthService.java:L8" → "AuthService"
    """
    stem_map: Dict[str, str] = {}
    for f in findings:
        ref = f["source_ref"]
        # Strip the ":L..." suffix to get the filename, then take the stem
        filename = source_ref_path(ref)          # "AuthService.java"
        stem = Path(filename).stem            # "AuthService"
        stem_map[ref] = stem
    return stem_map


def _entry_point_cg_key(ep: EntryPoint, call_graph: Dict[str, List[str]]) -> Optional[str]:
    """Return the call-graph key that best matches an EntryPoint.

    Heuristic: look for a key whose basename (after ".") matches ep['method']
    and whose class prefix contains the file stem of ep['file'].
    Falls back to any key whose method matches.
    """
    ep_method = ep["method"]
    ep_file_stem = Path(ep["file"]).stem  # "a" from "a.java"

    # Try exact stem.method match first
    for key in call_graph:
        parts = key.split(".", 1)
        if len(parts) == 2:
            cls, meth = parts
            if meth == ep_method and ep_file_stem.lower() in cls.lower():
                return key

    # Looser: any key whose method name matches
    for key in call_graph:
        parts = key.split(".", 1)
        if len(parts) == 2 and parts[1] == ep_method:
            return key

    return None


def _trace_reachability(
    entry_points: List[EntryPoint],
    call_graph: Dict[str, List[str]],
    findings: List[CryptoFinding],
    max_hops: int = 6,
) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
    """BFS from each entry point; assign shortest-path reachability score per finding.

    Matching logic:
    - A finding with source_ref "Foo.java:L42" matches any call-graph node whose
      key or callee string contains the file stem "Foo".
    - The stem match is case-sensitive against the exact file stem extracted.

    Args:
        entry_points: List of EntryPoint dicts (file, method, type, line).
        call_graph:   "Class.method" → [callee, ...] mapping.
        findings:     Validated crypto findings with source_ref strings.
        max_hops:     Maximum BFS depth; findings beyond this are unreachable.

    Returns:
        (reachability_map, reachability_paths) where
          reachability_map[source_ref] = score (0.0 if unreachable)
          reachability_paths[source_ref] = list of node keys on shortest path
    """
    # Build stem → [source_ref, ...] index
    stem_to_refs: Dict[str, List[str]] = {}
    for finding in findings:
        ref = finding["source_ref"]
        stem = Path(source_ref_path(ref)).stem
        stem_to_refs.setdefault(stem, []).append(ref)

    # Results: source_ref → (best_hop_count, path)
    best_hops: Dict[str, int] = {}
    best_paths: Dict[str, List[str]] = {}

    for ep in entry_points:
        # Find the starting node in the call graph
        start_key = _entry_point_cg_key(ep, call_graph)
        if start_key is None:
            # Try to build a synthetic key from file stem + method
            ep_file_stem = Path(ep["file"]).stem
            synthetic = f"{ep_file_stem}.{ep['method']}"
            if synthetic in call_graph:
                start_key = synthetic
            else:
                # Try matching by method name in callees — seed BFS from any
                # matching top-level key. Last resort: skip this entry point.
                continue

        # BFS: queue entries are (current_node_key, hop_count, path_so_far)
        # hop_count represents the depth at which the *current* node was reached.
        # The entry point is at hop 0; its direct callees are at hop 1 (score 1.0).
        visited: set[str] = set()
        queue: deque[Tuple[str, int, List[str]]] = deque()
        queue.append((start_key, 0, [start_key]))

        while queue:
            node, hops, path = queue.popleft()

            if node in visited:
                continue
            visited.add(node)

            # Check if this node (reached at `hops` depth) matches any finding stem.
            # Entry point itself (hops=0) can also be a crypto site, score would be
            # 1/1 = 1.0 is not applicable here — the entry point is the caller, not
            # the finding. We check callees below.
            # For nodes deeper than the start, hops >= 1 → valid score.
            if hops >= 1:
                for stem, refs in stem_to_refs.items():
                    if stem in node:
                        for ref in refs:
                            prev_best = best_hops.get(ref, max_hops + 1)
                            if hops < prev_best:
                                best_hops[ref] = hops
                                best_paths[ref] = list(path)

            if hops >= max_hops:
                continue

            # Enqueue callees at depth hops+1
            next_hops = hops + 1
            for callee in call_graph.get(node, []):
                if callee not in visited:
                    next_path = path + [callee]
                    queue.append((callee, next_hops, next_path))

                    # Also score callee strings that are not graph keys themselves
                    # (bare method names like "AuthService.generateRSAKey" that appear
                    # as callee values but have no outgoing edges in the graph).
                    for stem, refs in stem_to_refs.items():
                        if stem in callee:
                            for ref in refs:
                                prev_best = best_hops.get(ref, max_hops + 1)
                                if next_hops < prev_best:
                                    best_hops[ref] = next_hops
                                    best_paths[ref] = next_path

    # Build output maps
    reachability_map: Dict[str, float] = {}
    reachability_paths: Dict[str, List[str]] = {}

    for finding in findings:
        ref = finding["source_ref"]
        hop = best_hops.get(ref, 0)
        reachability_map[ref] = _compute_reachability_score(hop)
        reachability_paths[ref] = best_paths.get(ref, [])

    return reachability_map, reachability_paths


# ── Agent class ───────────────────────────────────────────────────────────────

class ReachabilityAgent(BaseAgent):
    """A6: Reachability Analyzer — BFS call-graph traversal + scoring."""

    agent_name = "A6:ReachabilityAnalyzer"

    def __init__(self, config: CryptoDependConfig) -> None:
        super().__init__(config)

    async def run(self, state: CDGState) -> CDGState:  # type: ignore[override]
        """Run reachability analysis and update CDGState.

        Early-exit conditions:
        - No validated findings → skip, set empty defaults.
        - No entry points detected → log warning, skip.

        On success, state is updated with:
          entry_points, call_graph, reachability_map, reachability_paths,
          agent_timings, (errors on exception).
        """
        t_start = time.perf_counter()

        findings: List[CryptoFinding] = state.get("validated_findings", [])
        unsupported = [f for f in findings if Path(source_ref_path(f["source_ref"])).suffix in (".js", ".mjs", ".cjs")]
        if unsupported:
            self.log.warning("javascript_reachability_unsupported", findings=len(unsupported))
            findings = [f for f in findings if f not in unsupported]
            state["errors"] = state.get("errors", []) + [{
                "agent": self.agent_name,
                "error_type": "unsupported_language",
                "message": "JavaScript reachability is not implemented; its findings were not evaluated.",
                "recoverable": True,
            }]

        if not findings:
            self.log.info("no_findings_skip", reason="validated_findings is empty")
            elapsed = time.perf_counter() - t_start
            state.update({
                "entry_points": [],
                "call_graph": {},
                "reachability_map": {},
                "reachability_paths": {},
                "reachability_mode": "absent",
                "agent_timings": {
                    **state.get("agent_timings", {}),
                    self.agent_name: elapsed,
                },
            })
            return state

        try:
            file_index: Dict[str, Any] = state.get("file_index", {})
            ast_cache: Dict[str, Any] = state.get("ast_cache", {})

            self.log.info("detecting_entry_points")
            entry_points: List[EntryPoint] = detect_entry_points(file_index, ast_cache)

            self.log.info("building_call_graph")
            call_graph: Dict[str, List[str]] = build_call_graph(file_index, ast_cache)

            if not entry_points:
                self.log.warning(
                    "no_entry_points",
                    reason="No entry points found; reachability scores will be 0",
                )
                elapsed = time.perf_counter() - t_start
                state.update({
                    "entry_points": [],
                    "call_graph": call_graph,
                    "reachability_map": {f["source_ref"]: 0.0 for f in findings},
                    "reachability_paths": {f["source_ref"]: [] for f in findings},
                    "reachability_mode": "absent",
                    "agent_timings": {
                        **state.get("agent_timings", {}),
                        self.agent_name: elapsed,
                    },
                })
                return state

            max_hops: int = getattr(self.config, "max_hop_depth", 6)

            self.log.info(
                "tracing_reachability",
                entry_points=len(entry_points),
                call_graph_nodes=len(call_graph),
                findings=len(findings),
                max_hops=max_hops,
            )

            reachability_map, reachability_paths = _trace_reachability(
                entry_points, call_graph, findings, max_hops=max_hops
            )

            reachable_count = sum(1 for v in reachability_map.values() if v > 0.0)
            self.log.info(
                "reachability_complete",
                reachable=reachable_count,
                total=len(findings),
            )

        except Exception as exc:
            self.log.error("reachability_failed", error=str(exc), exc_info=True)
            elapsed = time.perf_counter() - t_start
            state.update({
                "entry_points": [],
                "call_graph": {},
                "reachability_map": {},
                "reachability_paths": {},
                "errors": state.get("errors", []) + [{
                    "agent": self.agent_name,
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                    "recoverable": True,
                }],
                "agent_timings": {
                    **state.get("agent_timings", {}),
                    self.agent_name: elapsed,
                },
            })
            return state

        elapsed = time.perf_counter() - t_start
        state.update({
            "entry_points": entry_points,
            "call_graph": call_graph,
            "reachability_map": reachability_map,
            "reachability_paths": reachability_paths,
            "reachability_mode": "analyzed",
            "agent_timings": {
                **state.get("agent_timings", {}),
                self.agent_name: elapsed,
            },
        })
        return state
