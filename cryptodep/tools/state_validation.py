"""State validation utility — catches type corruption in CDGState after agent writes.

Called by CryptoDependPipeline._make_validated_node after each agent.run().
Converts silent data corruption into loud, agent-attributed errors.
"""
from __future__ import annotations

from typing import Any

# Critical CDGState fields and their expected Python types.
# Only scalar/container types checked here — Pydantic model fields are trusted
# to be validated by their own constructors.
_FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "repo_path": str,
    "run_id": str,
    "file_index": dict,
    "ast_cache": dict,
    "import_graph": dict,
    "repo_stats": dict,
    "raw_crypto_findings": list,
    "validated_findings": list,
    "candidate_edges": list,
    "validated_edges": list,
    "neo4j_import_stats": dict,
    "cbom_export_path": str,
    "sqlite_db_path": str,
    "report_md": str,
    "errors": list,
    "agent_timings": dict,
    "total_llm_tokens": (int, float),
    "entry_points": list,
    "call_graph": dict,
    "reachability_map": dict,
    "reachability_paths": dict,
    "reachability_mode": str,
}

_VALID_REACHABILITY_MODES = {"disabled", "absent", "analyzed"}


def validate_state(state: Any, agent_name: str) -> None:
    """Validate critical CDGState fields after an agent write.

    Args:
        state: The CDGState dict returned by an agent.
        agent_name: Name of the agent that just wrote the state.

    Raises:
        TypeError: If a field has the wrong type.
        ValueError: If a field has an invalid value (e.g., bad reachability_mode).
    """
    for field, expected_type in _FIELD_TYPES.items():
        if field not in state:
            # Missing field — not an error here; TypedDict allows optional defaults.
            continue
        value = state[field]
        # None is only acceptable for Optional fields (cdg_document, migration_plan, config).
        # All other fields must be non-None with the declared type.
        _nullable = {"cdg_document", "migration_plan", "config"}
        if field in _nullable and value is None:
            continue
        if value is None or not isinstance(value, expected_type):
            raise TypeError(
                f"[{agent_name}] CDGState field '{field}' has wrong type: "
                f"expected {expected_type}, got {type(value).__name__!r} "
                f"(value: {value!r:.80})"
            )

    # Domain-specific checks
    mode = state.get("reachability_mode")
    if mode is not None and mode not in _VALID_REACHABILITY_MODES:
        raise ValueError(
            f"[{agent_name}] CDGState field 'reachability_mode' has invalid value: "
            f"{mode!r}. Must be one of {sorted(_VALID_REACHABILITY_MODES)}."
        )
