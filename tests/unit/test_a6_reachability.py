from __future__ import annotations
import asyncio
from unittest.mock import patch
import pytest
from cryptodep.config import CryptoDependConfig


def test_trace_direct_reachability():
    from cryptodep.agents.a6_reachability import _trace_reachability
    entry_points = [{"file": "a.java", "method": "handle", "type": "rest_endpoint", "line": 1}]
    call_graph = {"Controller.handle": ["AuthService.generateRSAKey"]}
    findings = [{"source_ref": "AuthService.java:L8", "algorithm_family": "RSA",
                 "confidence": 0.9, "evidence": "test", "use_context": "key_exchange",
                 "detected_by": "static_rule", "parameter_set": "RSA-2048"}]
    rmap, rpaths = _trace_reachability(entry_points, call_graph, findings, max_hops=6)
    matching = [v for k, v in rmap.items() if "AuthService" in k]
    assert len(matching) >= 1
    assert matching[0] == 1.0


def test_trace_two_hop_reachability():
    from cryptodep.agents.a6_reachability import _trace_reachability
    entry_points = [{"file": "a.java", "method": "handle", "type": "rest_endpoint", "line": 1}]
    call_graph = {
        "Controller.handle": ["Service.process"],
        "Service.process": ["CryptoUtil.rsaEncrypt"],
    }
    findings = [{"source_ref": "CryptoUtil.java:L10", "algorithm_family": "RSA",
                 "confidence": 0.9, "evidence": "test", "use_context": "encryption",
                 "detected_by": "static_rule", "parameter_set": "RSA-2048"}]
    rmap, rpaths = _trace_reachability(entry_points, call_graph, findings, max_hops=6)
    matching = [v for k, v in rmap.items() if "CryptoUtil" in k]
    assert len(matching) >= 1
    assert matching[0] == 0.5


def test_trace_unreachable():
    from cryptodep.agents.a6_reachability import _trace_reachability
    entry_points = [{"file": "a.java", "method": "handle", "type": "rest_endpoint", "line": 1}]
    call_graph = {"Controller.handle": ["Unrelated.method"]}
    findings = [{"source_ref": "CryptoUtil.java:L10", "algorithm_family": "RSA",
                 "confidence": 0.9, "evidence": "test", "use_context": "encryption",
                 "detected_by": "static_rule", "parameter_set": "RSA-2048"}]
    rmap, rpaths = _trace_reachability(entry_points, call_graph, findings, max_hops=6)
    assert rmap.get("CryptoUtil.java:L10", 0.0) == 0.0


def test_trace_max_hops_respected():
    from cryptodep.agents.a6_reachability import _trace_reachability
    entry_points = [{"file": "a.java", "method": "handle", "type": "rest_endpoint", "line": 1}]
    call_graph = {
        "Controller.handle": ["A.call"],
        "A.call": ["B.call"],
        "B.call": ["CryptoUtil.rsaEncrypt"],
    }
    findings = [{"source_ref": "CryptoUtil.java:L10", "algorithm_family": "RSA",
                 "confidence": 0.9, "evidence": "test", "use_context": "encryption",
                 "detected_by": "static_rule", "parameter_set": "RSA-2048"}]
    rmap, _ = _trace_reachability(entry_points, call_graph, findings, max_hops=2)
    assert rmap.get("CryptoUtil.java:L10", 0.0) == 0.0


def test_trace_handles_cycles():
    from cryptodep.agents.a6_reachability import _trace_reachability
    entry_points = [{"file": "a.java", "method": "handle", "type": "rest_endpoint", "line": 1}]
    call_graph = {
        "Controller.handle": ["A.call"],
        "A.call": ["Controller.handle", "CryptoUtil.rsaEncrypt"],
    }
    findings = [{"source_ref": "CryptoUtil.java:L10", "algorithm_family": "RSA",
                 "confidence": 0.9, "evidence": "test", "use_context": "encryption",
                 "detected_by": "static_rule", "parameter_set": "RSA-2048"}]
    rmap, rpaths = _trace_reachability(entry_points, call_graph, findings, max_hops=6)
    matching = [v for k, v in rmap.items() if "CryptoUtil" in k]
    assert len(matching) >= 1
    assert matching[0] == 0.5


def test_scorer_direct():
    from cryptodep.agents.a6_reachability import _compute_reachability_score
    assert _compute_reachability_score(1) == 1.0

def test_scorer_multi_hop():
    from cryptodep.agents.a6_reachability import _compute_reachability_score
    assert _compute_reachability_score(4) == 0.25

def test_scorer_unreachable():
    from cryptodep.agents.a6_reachability import _compute_reachability_score
    assert _compute_reachability_score(0) == 0.0


def _make_config(**overrides):
    defaults = {"neo4j_password": "test", "enable_reachability": True}
    defaults.update(overrides)
    return CryptoDependConfig(**defaults)

def _make_state(findings=None, ast_cache=None, file_index=None, import_graph=None):
    return {
        "repo_path": "/tmp/test", "config": _make_config(), "run_id": "test-run",
        "file_index": file_index or {}, "ast_cache": ast_cache or {},
        "import_graph": import_graph or {},
        "repo_stats": {"total_files": 0, "total_loc": 0, "languages": {}},
        "raw_crypto_findings": [], "validated_findings": findings or [],
        "candidate_edges": [], "validated_edges": [],
        "cdg_document": None, "neo4j_import_stats": {}, "cbom_export_path": "",
        "migration_plan": None, "report_md": "",
        "errors": [], "agent_timings": {}, "total_llm_tokens": 0,
        "entry_points": [], "call_graph": {},
        "reachability_map": {}, "reachability_paths": {},
    }


def test_a6_run_populates_reachability_map():
    from cryptodep.agents.a6_reachability import ReachabilityAgent
    config = _make_config()
    agent = ReachabilityAgent(config)
    state = _make_state(findings=[
        {"source_ref": "CryptoUtil.java:L10", "algorithm_family": "RSA",
         "confidence": 0.9, "evidence": "test", "use_context": "encryption",
         "detected_by": "static_rule", "parameter_set": "RSA-2048"},
    ])
    mock_eps = [{"file": "a.java", "method": "handle", "type": "rest_endpoint", "line": 1}]
    mock_cg = {"Controller.handle": ["CryptoUtil.rsaEncrypt"]}
    with patch("cryptodep.agents.a6_reachability.detect_entry_points", return_value=mock_eps), \
         patch("cryptodep.agents.a6_reachability.build_call_graph", return_value=mock_cg):
        result = asyncio.run(agent.run(state))
    assert result["reachability_map"] != {}
    assert result["entry_points"] == mock_eps
    assert result["call_graph"] == mock_cg


def test_a6_run_no_findings_skips():
    from cryptodep.agents.a6_reachability import ReachabilityAgent
    config = _make_config()
    agent = ReachabilityAgent(config)
    state = _make_state(findings=[])
    result = asyncio.run(agent.run(state))
    assert result["reachability_map"] == {}
    assert result["entry_points"] == []


def test_a6_records_timing():
    from cryptodep.agents.a6_reachability import ReachabilityAgent
    config = _make_config()
    agent = ReachabilityAgent(config)
    state = _make_state(findings=[])
    result = asyncio.run(agent.run(state))
    assert "A6:ReachabilityAnalyzer" in result["agent_timings"]
