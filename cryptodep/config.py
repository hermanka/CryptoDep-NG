"""CryptoDependConfig — pipeline configuration model (PRD Section 11)."""
from __future__ import annotations

from typing import Dict, List, Literal

from pydantic import BaseModel, Field, SecretStr


class CryptoDependConfig(BaseModel):
    # ── LLM ──────────────────────────────────────────────────────────────────
    llm_provider: Literal["anthropic", "ollama", "openrouter", "groq", "openai_compatible"] = "anthropic"
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-sonnet-4-6"
    ollama_model: str = "qwen2.5-coder:7b"
    openrouter_model: str = "stepfun/step-3.5-flash:free"
    groq_model: str = "llama-3.3-70b-versatile"
    llm_temperature: float = 0.0  # deterministic
    llm_max_tokens: int = 4096
    llm_confidence_threshold: float = 0.75
    min_edge_support: float = 0.25  # A3: minimum BFS support score to accept a validated edge
                                    # 0.25 = reject 4-hop inferences (1/4); 0.5 = reject 3-hop+

    # ── Analysis ─────────────────────────────────────────────────────────────
    languages: List[str] = ["java", "python", "javascript"]
    exclude_patterns: List[str] = ["**/test/**", "**/build/**", "**/.git/**"]
    max_hop_depth: int = 4
    max_file_tokens: int = 2000  # CPG slice size
    max_import_graph_entries: int = 50   # A3 prompt: max files in import graph excerpt (50 stays within Groq 32K limit)
    use_codeql: bool = False
    enable_reachability: bool = False  # opt-in via --reachability CLI flag
    max_escalation_calls: int = 50    # A2: max LLM calls for low-confidence escalation (per run)

    # ── Neo4j ────────────────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    enable_neo4j: bool = True
    neo4j_user: str = "neo4j"
    neo4j_password: str = Field(..., description="Neo4j password (set via NEO4J_PASSWORD env var)")

    # ── Output ───────────────────────────────────────────────────────────────
    report_language: Literal["en", "id"] = "en"
    bssn_mode: bool = False
    export_cbom: bool = True

    # ── Storage ──────────────────────────────────────────────────────────────
    sqlite_db_path: str = "cdg_store.db"

    # ── Scoring weights (A5) ─────────────────────────────────────────────────
    priority_weights: Dict[str, float] = {
        "urgency": 0.50,
        "hndl": 0.25,
        "boundary": 0.15,
        "lifetime": 0.10,
    }

    priority_weights_with_reachability: Dict[str, float] = {
        "urgency": 0.35,
        "hndl": 0.20,
        "boundary": 0.12,
        "lifetime": 0.08,
        "reachability": 0.25,
    }

    model_config = {"env_prefix": "CRYPTODEP_"}
