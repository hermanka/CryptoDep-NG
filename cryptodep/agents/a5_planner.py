"""Agent 5 — Migration Planner Agent (PRD Section 5.5).

Responsibility:
  Traverse the completed CDG using graph queries and LLM reasoning to generate
  a prioritized, human-readable PQC migration roadmap.
  Priority scoring: priority_score = w1*urgency + w2*hndl_risk + w3*is_boundary + w4*data_lifetime

  Outputs:
  - MigrationPlan JSON (structured)
  - Markdown migration report (English or Bahasa Indonesia)

Acceptance criteria (M4):
  AC-A5-01: Migration plan Spearman rho >= 0.75 vs. expert-ranked ground truth
  AC-A5-02: All critical-priority items correctly identified (Recall = 1.0)
  AC-A5-03: Report generation completes in < 60 seconds
  AC-A5-04: Bahasa Indonesia report passes grammatical review (manual eval)
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import structlog

from cryptodep.agents import BaseAgent
from cryptodep.schema.cdg_models import (
    CDGDocument,
    CryptoAlgorithmNode,
    MigrationItem,
    MigrationPlan,
    MigrationPriority,
    NistQuantumVulnClass,
    PQCAlgorithmId,
)
from cryptodep.schema.pqc_lookup import (
    PQC_MIGRATION_TABLE,
    HYBRID_RECOMMENDATIONS,
)
from cryptodep.state import CDGState
from cryptodep.tools.llm_tools import call_llm

log = structlog.get_logger().bind(agent_name="A5:MigrationPlanner")

# All quantum-vulnerability classes that require migration planning.
# Keeps _compute_priority_score, _compute_quantum_readiness, and the
# vuln_nodes list comprehension consistent.
_MIGRATION_CLASSES: frozenset = frozenset({
    NistQuantumVulnClass.QUANTUM_VULNERABLE,
    NistQuantumVulnClass.GROVER_WEAKENED,
})

_SYSTEM_EN = (
    "You are a post-quantum cryptography migration expert writing a technical migration report.\n"
    "Write clear, actionable guidance for enterprise security engineers.\n"
    "Be concise and precise. Use Markdown formatting with headers and tables."
)

_SYSTEM_ID = (
    "Anda adalah pakar migrasi kriptografi pasca-kuantum yang menulis laporan teknis dalam Bahasa Indonesia.\n"
    "Tulis panduan yang jelas dan dapat ditindaklanjuti untuk insinyur keamanan enterprise.\n"
    "Gunakan format Markdown dengan heading dan tabel. Pastikan tata bahasa Indonesia yang baik dan benar."
)


def _compute_priority_score(
    algo_node: CryptoAlgorithmNode,
    weights: Optional[Dict[str, float]] = None,
    is_boundary: bool = False,
    data_lifetime_years: float = 7.0,
    reachability_score: Optional[float] = None,
) -> float:
    """Compute composite priority score for a CryptoAlgorithmNode.

    priority_score = w1*urgency_norm + w2*hndl_flag + w3*boundary_flag
                   + w4*lifetime_norm [+ w5*reachability_score if evaluated]

    Where:
      urgency_norm       = algo_node.migration_urgency_score / 100
      hndl_flag          = 1.0 if hndl_risk else 0.0
      boundary_flag      = 1.0 if is_boundary else 0.0
      lifetime_norm      = min(data_lifetime_years / 10.0, 1.0)
      reachability_score = 0.0–1.0 from A6, or None when A6 was not run.
                           When None, the reachability term is DROPPED (not
                           substituted with 1.0) to avoid inflating scores
                           relative to a run where A6 found no entry points.

    Returns 0.0 for algorithms that do not require migration planning.
    """
    if algo_node.quantum_vuln_class not in _MIGRATION_CLASSES:
        return 0.0
    if weights is None:
        weights = {}

    w1 = weights.get("urgency", 0.50)
    w2 = weights.get("hndl", 0.25)
    w3 = weights.get("boundary", 0.15)
    w4 = weights.get("lifetime", 0.10)
    w5 = weights.get("reachability", 0.0)

    urgency_norm = algo_node.migration_urgency_score / 100.0
    hndl_flag = 1.0 if algo_node.hndl_risk else 0.0
    boundary_flag = 1.0 if is_boundary else 0.0
    lifetime_norm = min(data_lifetime_years / 10.0, 1.0)

    score = (
        w1 * urgency_norm
        + w2 * hndl_flag
        + w3 * boundary_flag
        + w4 * lifetime_norm
    )
    # Only add the reachability term when A6 actually produced a score.
    # reachability_score=None means "not evaluated" — drop the term entirely
    # rather than substituting 1.0 (which would inflate rank when A6 is off).
    if reachability_score is not None and w5 > 0.0:
        score += w5 * reachability_score

    return round(score, 4)


def _build_migration_item(
    rank: int,
    algo_node: CryptoAlgorithmNode,
    config: Any,
) -> MigrationItem:
    """Create a ranked MigrationItem for a quantum-vulnerable CryptoAlgorithmNode."""
    mapping = PQC_MIGRATION_TABLE.get(algo_node.algorithm_family, {})

    # Resolve context-specific sub-mapping (key_exchange vs digital_signature).
    use_ctx = algo_node.use_context or "key_exchange"
    sub = mapping.get(use_ctx) or mapping.get("key_exchange") or mapping.get("digital_signature") or {}
    pqc_id: PQCAlgorithmId = sub.get("replacement", PQCAlgorithmId.ML_KEM_768)
    hybrid_rec = sub.get("hybrid") or HYBRID_RECOMMENDATIONS.get(algo_node.algorithm_family)

    rationale = mapping.get("rationale", "")
    notes = f"{rationale} Hybrid: {hybrid_rec}" if hybrid_rec else rationale

    return MigrationItem(
        rank=rank,
        algo_node_id=algo_node.node_id,
        current_algorithm=algo_node.label,
        recommended_pqc=pqc_id,
        urgency_score=algo_node.migration_urgency_score,
        hybrid_mode_recommended=hybrid_rec is not None,
        migration_notes=notes.strip(),
    )


def _compute_quantum_readiness(algo_nodes: List[CryptoAlgorithmNode]) -> float:
    """Compute quantum readiness score (0–100) from the list of CryptoAlgorithmNodes.

    Score = 100 * (safe + unknown) / total.
    An empty list returns 100.0 (no vulnerabilities found).
    """
    if not algo_nodes:
        return 100.0
    total = len(algo_nodes)
    vuln_count = sum(
        1 for n in algo_nodes
        if n.quantum_vuln_class in _MIGRATION_CLASSES
    )
    return round(100.0 * (total - vuln_count) / total, 1)


def _build_migration_prompt(
    migration_plan: MigrationPlan,
    cdg_doc: CDGDocument,
    config: Any,
) -> Tuple[str, str]:
    """Return (system_prompt, user_prompt) for the A5 LLM report generation call."""
    import json

    system_prompt = _SYSTEM_ID if config.report_language == "id" else _SYSTEM_EN

    plan_json = json.dumps(
        [item.model_dump(mode="json") for item in migration_plan.priority_queue],
        indent=2,
    )

    lang_instruction = (
        "Write the report in Bahasa Indonesia."
        if config.report_language == "id"
        else "Write the report in English."
    )

    bssn_instruction = (
        "\nInclude a BSSN/SPBE Compliance section referencing PP_82_2023 and CNSA 2.0 requirements."
        if getattr(config, "bssn_mode", False)
        else ""
    )

    user_prompt = (
        f"Generate a PQC migration report for the scanned repository.\n\n"
        f"Quantum Readiness Score: {migration_plan.quantum_readiness_score}/100\n"
        f"Total Vulnerable Assets: {migration_plan.total_vulnerable_assets}\n\n"
        f"Priority Queue (ranked, most urgent first):\n{plan_json}\n\n"
        f"Generate a complete Markdown migration report with these sections:\n"
        f"1. Executive Summary (quantum readiness score, key findings)\n"
        f"2. Priority Migration Queue (table: Rank | Algorithm | Recommended PQC | Urgency | Notes)\n"
        f"3. Per-Item Migration Details (one subsection per critical/high item)\n"
        f"4. Implementation Roadmap (Phase 1: Inventory, Phase 2: Hybrid, Phase 3: Full PQC)\n"
        f"{bssn_instruction}\n\n"
        f"{lang_instruction}"
    )

    return system_prompt, user_prompt


def _extract_algo_nodes(cdg_doc: CDGDocument) -> List[CryptoAlgorithmNode]:
    """Reconstruct CryptoAlgorithmNode objects from CDGDocument.nodes."""
    from cryptodep.schema.cdg_models import CDGNodeType

    nodes: List[CryptoAlgorithmNode] = []
    for node_dict in cdg_doc.nodes:
        if node_dict.get("node_type") == CDGNodeType.CRYPTO_ALGORITHM.value:
            try:
                nodes.append(CryptoAlgorithmNode.model_validate(node_dict))
            except Exception as exc:  # noqa: BLE001
                log.warning("a5_node_parse_fail", reason=str(exc)[:80])
    return nodes


def _fallback_report(plan: MigrationPlan) -> str:
    """Generate a minimal Markdown report without LLM (used on LLM failure)."""
    lines = [
        "# PQC Migration Report (LLM Unavailable)\n\n",
        f"**Quantum Readiness Score:** {plan.quantum_readiness_score}/100\n",
        f"**Total Vulnerable Assets:** {plan.total_vulnerable_assets}\n\n",
        "## Priority Queue\n\n",
        "| Rank | Algorithm | Recommended PQC | Urgency |\n",
        "|---|---|---|---|\n",
    ]
    for item in plan.priority_queue:
        lines.append(
            f"| {item.rank} | {item.current_algorithm} "
            f"| {item.recommended_pqc.value} | {item.urgency_score:.1f} |\n"
        )
    return "".join(lines)


def _empty_report(language: str) -> str:
    """Report for a scan with no crypto algorithms; states the limits instead of claiming the code is safe."""
    if language == "id":
        return ("# Laporan Migrasi PQC\n\n"
                "Tidak ada algoritma kriptografi yang terdeteksi dalam cakupan analisis, sehingga tidak ada rencana migrasi yang disusun.\n\n"
                "Ini bukan jaminan bahwa kode bebas dari penggunaan atau kelemahan kriptografi. Analisis bersifat statis dan "
                "terbatas pada bahasa serta pola API yang didukung; kriptografi lewat library pihak ketiga, konfigurasi, atau "
                "komponen di luar repository dapat tidak terdeteksi.\n")
    return ("# PQC Migration Report\n\n"
            "No cryptographic algorithms were detected within the analysis scope, so no migration plan was produced.\n\n"
            "This does not guarantee the code is free of cryptographic usage or weaknesses. The analysis is static and "
            "limited to supported languages and API patterns; crypto via third-party libraries, configuration, or "
            "components outside the repository may go undetected.\n")


class MigrationPlannerAgent(BaseAgent):
    agent_name = "A5:MigrationPlanner"

    async def run(self, state: CDGState) -> CDGState:
        t0 = time.time()
        cdg_doc: Optional[CDGDocument] = state.get("cdg_document")
        errors = list(state.get("errors", []))
        weights: Dict[str, float] = self.config.priority_weights

        if cdg_doc is None:
            self.log.warning("a5_skip_no_cdg")
            state.update({
                "migration_plan": MigrationPlan(),
                "report_md": "",
                "agent_timings": {**state.get("agent_timings", {}), self.agent_name: 0.0},
            })
            return state

        self.log.info("a5_start", node_count=len(cdg_doc.nodes))

        # ── 1. Extract CryptoAlgorithmNodes from CDGDocument ─────────────────
        algo_nodes = _extract_algo_nodes(cdg_doc)
        vuln_nodes = [n for n in algo_nodes
                      if n.quantum_vuln_class in _MIGRATION_CLASSES]

        # ── 2. Score and rank ─────────────────────────────────────────────────
        reachability_map: Dict[str, float] = state.get("reachability_map", {})
        reachability_mode: str = state.get("reachability_mode", "disabled")
        reach_analyzed = reachability_mode == "analyzed" and bool(reachability_map)
        if reach_analyzed:
            weights = self.config.priority_weights_with_reachability
        scored = sorted(
            [
                (
                    _compute_priority_score(
                        n, weights if n.source_ref in reachability_map else self.config.priority_weights,
                        is_boundary=n.metadata.get("is_boundary", False),
                        # Pass None when A6 was not run or found no entry points —
                        # this drops the reachability term rather than inflating with 1.0.
                        reachability_score=reachability_map.get(n.source_ref)
                        if reach_analyzed else None,
                    ),
                    n,
                )
                for n in vuln_nodes
            ],
            key=lambda t: t[0],
            reverse=True,
        )

        priority_queue: List[MigrationItem] = [
            _build_migration_item(rank=i + 1, algo_node=node, config=self.config)
            for i, (_, node) in enumerate(scored)
        ]

        # ── 3. Compute readiness score ────────────────────────────────────────
        readiness = _compute_quantum_readiness(algo_nodes)

        migration_plan = MigrationPlan(
            priority_queue=priority_queue,
            total_vulnerable_assets=len(vuln_nodes),
            quantum_readiness_score=readiness,
        )

        self.log.info("a5_plan_built", items=len(priority_queue),
                      readiness=readiness, vulnerable=len(vuln_nodes))

        # ── 4. Generate narrative report via LLM ─────────────────────────────
        report_md = ""
        token_estimate = 0
        if not algo_nodes:
            # Nothing to plan: a deterministic report avoids an LLM call that could only invent content.
            self.log.info("a5_skip_llm_no_algorithms")
            report_md = _empty_report(self.config.report_language)
        else:
            try:
                system_prompt, user_prompt = _build_migration_prompt(
                    migration_plan, cdg_doc, self.config
                )
                llm_response = await call_llm(
                    self.config,
                    [{"role": "user", "content": user_prompt}],
                    system_prompt=system_prompt,
                    response_format=None,  # free-form Markdown, not JSON
                )
                report_md = llm_response.strip()
                token_estimate = (len(user_prompt) + len(report_md)) // 4
                self.log.info("a5_report_generated", length=len(report_md))
            except Exception as exc:  # noqa: BLE001
                self.log.warning("a5_llm_fail", reason=str(exc)[:120])
                report_md = _fallback_report(migration_plan)
                errors.append({
                    "agent": self.agent_name,
                    "error_type": "llm_report_failed",
                    "message": str(exc)[:200],
                    "recoverable": True,
                })

        elapsed = time.time() - t0
        state.update({
            "migration_plan": migration_plan,
            "report_md": report_md,
            "agent_timings": {**state.get("agent_timings", {}), self.agent_name: elapsed},
            "total_llm_tokens": state.get("total_llm_tokens", 0) + token_estimate,
            "errors": errors,
        })
        self.log.info("a5_complete", elapsed=round(elapsed, 2))
        return state
