from __future__ import annotations

from cryptodep.state import CDGState, EntryPoint


def test_entry_point_typeddict():
    ep: EntryPoint = {
        "file": "LoginController.java",
        "method": "login",
        "type": "rest_endpoint",
        "line": 15,
    }
    assert ep["file"] == "LoginController.java"
    assert ep["type"] == "rest_endpoint"


def test_cdgstate_has_reachability_keys():
    """CDGState type must accept the four new A6 keys."""
    state: CDGState = {
        "repo_path": "/tmp",
        "config": None,
        "run_id": "test",
        "file_index": {},
        "ast_cache": {},
        "import_graph": {},
        "repo_stats": {"total_files": 0, "total_loc": 0, "languages": {}},
        "raw_crypto_findings": [],
        "validated_findings": [],
        "candidate_edges": [],
        "validated_edges": [],
        "cdg_document": None,
        "neo4j_import_stats": {},
        "cbom_export_path": "",
        "migration_plan": None,
        "report_md": "",
        "errors": [],
        "agent_timings": {},
        "total_llm_tokens": 0,
        # ── A6 fields ──
        "entry_points": [],
        "call_graph": {},
        "reachability_map": {},
        "reachability_paths": {},
    }
    assert state["entry_points"] == []
    assert state["reachability_map"] == {}
