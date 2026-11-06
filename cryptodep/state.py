"""CDGState — shared LangGraph state contract (PRD Section 6).

All agents read from and write to CDGState.
Never use global variables or agent-local state between runs.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict

from cryptodep.schema.cdg_models import CDGDocument, CDGEdge, MigrationPlan


class FileInfo(TypedDict):
    path: str
    language: str
    size_bytes: int
    loc: int


class RepoStats(TypedDict):
    total_files: int
    total_loc: int
    languages: Dict[str, int]


class CryptoFinding(TypedDict):
    algorithm_family: str
    parameter_set: Optional[str]
    use_context: str
    source_ref: str        # "file.java:L42"
    confidence: float
    evidence: str
    detected_by: str       # "static_rule" | "llm_semantic" | "hybrid"


class PipelineError(TypedDict):
    agent: str
    error_type: str
    message: str
    recoverable: bool


class EntryPoint(TypedDict):
    file: str
    method: str
    type: str     # "rest_endpoint" | "servlet" | "main" | "async_task" | "framework_view"
    line: int


class CDGState(TypedDict):
    # ── Config (set at pipeline init) ────────────────────────────────────────
    repo_path: str
    config: Any                           # CryptoDependConfig (avoid circular import)
    run_id: str                           # UUID

    # ── A1: CodeIngestion outputs ─────────────────────────────────────────────
    file_index: Dict[str, FileInfo]       # path → FileInfo
    ast_cache: Dict[str, Any]             # path → Tree-sitter Tree
    import_graph: Dict[str, List[str]]    # path → list of imported paths
    repo_stats: RepoStats

    # ── A2: CryptoDetection outputs ───────────────────────────────────────────
    raw_crypto_findings: List[CryptoFinding]
    validated_findings: List[CryptoFinding]

    # ── A3: DependencyReasoning outputs ──────────────────────────────────────
    candidate_edges: List[CDGEdge]
    validated_edges: List[CDGEdge]

    # ── A4: CDGBuilder outputs ────────────────────────────────────────────────
    cdg_document: Optional[CDGDocument]
    neo4j_import_stats: Dict[str, int]    # {"nodes": N, "edges": M}
    cbom_export_path: str
    sqlite_db_path: str                   # path to cdg_store.db written by A4

    # ── A5: MigrationPlanner outputs ─────────────────────────────────────────
    migration_plan: Optional[MigrationPlan]
    report_md: str

    # ── Pipeline metadata ─────────────────────────────────────────────────────
    errors: List[PipelineError]
    agent_timings: Dict[str, float]       # agent_name → seconds
    total_llm_tokens: int

    # ── A6: ReachabilityAnalyzer outputs (opt-in via --reachability) ────────
    entry_points: List[EntryPoint]
    call_graph: Dict[str, List[str]]         # "Class.method" → ["Called.method", ...]
    reachability_map: Dict[str, float]       # finding source_ref → reachability_score
    reachability_paths: Dict[str, List[str]] # finding source_ref → [path strings]
    reachability_mode: str                   # "disabled" | "absent" | "analyzed"
