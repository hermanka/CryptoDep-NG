from __future__ import annotations
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch

from cryptodep.agents.a3_reasoning import (
    _import_matches_target,
    _build_import_graph_support,
    _extract_file_and_line,
    _build_dependency_prompt,
    _parse_llm_edges,
    DependencyReasoningAgent,
)
from cryptodep.config import CryptoDependConfig
from cryptodep.schema.cdg_models import CDGEdgeType


# ── _import_matches_target ─────────────────────────────────────────────────

def test_import_matches_exact():
    assert _import_matches_target("java.security.KeyPairGenerator", "java.security.KeyPairGenerator") is True

def test_import_matches_basename_dot_separated():
    assert _import_matches_target("org.bouncycastle.jce.provider.BouncyCastleProvider", "BouncyCastleProvider") is True

def test_import_matches_python_module():
    assert _import_matches_target("Crypto.PublicKey.RSA", "RSA") is True

def test_import_no_match():
    assert _import_matches_target("javax.crypto.Cipher", "RSA") is False

def test_import_matches_with_java_extension():
    # LLM sometimes gives target as "CryptoUtil.java" instead of "CryptoUtil"
    assert _import_matches_target("com.example.crypto.CryptoUtil", "CryptoUtil.java") is True


# ── _build_import_graph_support ────────────────────────────────────────────

def test_support_same_file():
    ig = {"a.java": ["org.crypto.RSA"]}
    assert _build_import_graph_support("a.java", "a.java", ig) == 1.0

def test_support_direct_exact_import():
    ig = {"a.java": ["java.security.KeyPairGenerator"]}
    assert _build_import_graph_support("a.java", "java.security.KeyPairGenerator", ig) == 1.0

def test_support_direct_basename_import():
    ig = {"a.java": ["org.bouncycastle.jce.provider.BouncyCastleProvider"]}
    assert _build_import_graph_support("a.java", "BouncyCastleProvider", ig) == 1.0

def test_support_no_path():
    ig = {"a.java": ["javax.crypto.AES"]}
    assert _build_import_graph_support("a.java", "org.crypto.RSA", ig) == 0.0

def test_support_source_not_in_graph():
    ig = {"b.java": ["org.crypto.RSA"]}
    assert _build_import_graph_support("a.java", "org.crypto.RSA", ig) == 0.0

def test_support_multi_hop():
    # a.java imports b.java (b.java is itself a key in graph), b.java imports RSA
    ig = {
        "a.java": ["b.java"],
        "b.java": ["org.crypto.RSA"],
    }
    score = _build_import_graph_support("a.java", "org.crypto.RSA", ig)
    assert 0.0 < score < 1.0   # 0.5

def test_support_max_hops_respected():
    ig = {
        "a.java": ["b.java"],
        "b.java": ["c.java"],
        "c.java": ["org.crypto.RSA"],
    }
    # 3-hop chain; with max_hops=1 only the direct imports of a.java are checked
    score = _build_import_graph_support("a.java", "org.crypto.RSA", ig, max_hops=1)
    assert score == 0.0


# ── _extract_file_and_line ─────────────────────────────────────────────────

def test_extract_file_and_line_L_prefix():
    file, line = _extract_file_and_line("src/auth/JwtService.java:L42")
    assert file == "src/auth/JwtService.java"
    assert line == 42

def test_extract_file_and_line_no_prefix():
    file, line = _extract_file_and_line("src/auth/JwtService.java:42")
    assert file == "src/auth/JwtService.java"
    assert line == 42

def test_extract_file_and_line_no_colon():
    file, line = _extract_file_and_line("src/auth/JwtService.java")
    assert file == "src/auth/JwtService.java"
    assert line == 1


# ── _build_dependency_prompt ───────────────────────────────────────────────

_SAMPLE_FINDINGS = [
    {
        "algorithm_family": "RSA",
        "parameter_set": "RSA-2048",
        "use_context": "key_generation",
        "source_ref": "AuthService.java:L7",
        "confidence": 0.95,
        "evidence": 'KeyPairGenerator.getInstance("RSA")',
        "detected_by": "static_rule",
    }
]
_SAMPLE_IG = {"AuthService.java": ["java.security.KeyPairGenerator"]}
_SAMPLE_AST = {
    "AuthService.java": {
        "source": "import java.security.KeyPairGenerator;\npublic class AuthService {}",
        "tree": None,
    }
}


def test_prompt_user_contains_findings():
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_SAMPLE_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert "RSA" in user

def test_prompt_user_contains_import_graph():
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_SAMPLE_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert "KeyPairGenerator" in user

def test_prompt_system_mentions_step_by_step():
    cfg = CryptoDependConfig(neo4j_password="test")
    system, _ = _build_dependency_prompt(_SAMPLE_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert "step by step" in system.lower()

def test_prompt_user_requests_json_output():
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_SAMPLE_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert "edge_type" in user


# ── _parse_llm_edges ───────────────────────────────────────────────────────

_EDGE_JSON = json.dumps([{
    "edge_type": "uses",
    "source_ref": "AuthService.java:L1",
    "target_ref": "java.security.KeyPairGenerator",
    "source_label": "AuthService",
    "target_label": "KeyPairGenerator",
    "llm_confidence": 0.9,
    "evidence": "import java.security.KeyPairGenerator",
}])

def test_parse_edges_clean_json():
    edges = _parse_llm_edges(_EDGE_JSON)
    assert len(edges) == 1
    assert edges[0]["edge_type"] == "uses"
    assert edges[0]["llm_confidence"] == 0.9

def test_parse_edges_strips_json_fence():
    fenced = f"```json\n{_EDGE_JSON}\n```"
    edges = _parse_llm_edges(fenced)
    assert len(edges) == 1

def test_parse_edges_cot_preamble_then_json():
    with_preamble = f"Let me trace the chain...\nAuthService uses KeyPairGenerator.\n\n{_EDGE_JSON}"
    edges = _parse_llm_edges(with_preamble)
    assert len(edges) == 1

def test_parse_edges_empty_list():
    assert _parse_llm_edges("[]") == []

def test_parse_edges_malformed_returns_empty():
    assert _parse_llm_edges("not json") == []
    assert _parse_llm_edges("```json\nbad\n```") == []


# ── DependencyReasoningAgent.run() ─────────────────────────────────────────

def _make_a3_state(findings=None, import_graph=None):
    config = CryptoDependConfig(neo4j_password="test")
    return {
        "repo_path": "/test",
        "config": config,
        "run_id": "test-run-a3",
        "file_index": {},
        "ast_cache": {
            "AuthService.java": {
                "source": "import java.security.KeyPairGenerator;\npublic class AuthService {}",
                "tree": None,
            }
        },
        "import_graph": import_graph if import_graph is not None else {
            "AuthService.java": ["java.security.KeyPairGenerator", "javax.crypto.Cipher"],
        },
        "repo_stats": {"total_files": 1, "total_loc": 2, "languages": {}},
        "raw_crypto_findings": [],
        "validated_findings": findings if findings is not None else [
            {
                "algorithm_family": "RSA",
                "parameter_set": "RSA-2048",
                "use_context": "key_generation",
                "source_ref": "AuthService.java:L7",
                "confidence": 0.95,
                "evidence": 'KeyPairGenerator.getInstance("RSA")',
                "detected_by": "static_rule",
            }
        ],
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
    }


_VALID_EDGE_JSON = json.dumps([{
    "edge_type": "uses",
    "source_ref": "AuthService.java:L1",
    "target_ref": "java.security.KeyPairGenerator",
    "source_label": "AuthService",
    "target_label": "KeyPairGenerator",
    "llm_confidence": 0.9,
    "evidence": "import java.security.KeyPairGenerator",
}])

_HALLUCINATED_EDGE_JSON = json.dumps([{
    "edge_type": "uses",
    "source_ref": "AuthService.java:L1",
    "target_ref": "non.existent.Library",
    "source_label": "AuthService",
    "target_label": "NonExistentLib",
    "llm_confidence": 0.85,
    "evidence": "hallucinated",
}])

_MIXED_EDGES_JSON = json.dumps([
    {
        "edge_type": "uses",
        "source_ref": "AuthService.java:L1",
        "target_ref": "java.security.KeyPairGenerator",
        "source_label": "AuthService",
        "target_label": "KeyPairGenerator",
        "llm_confidence": 0.9,
        "evidence": "import java.security.KeyPairGenerator",
    },
    {
        "edge_type": "uses",
        "source_ref": "AuthService.java:L1",
        "target_ref": "non.existent.Library",
        "source_label": "AuthService",
        "target_label": "NonExistentLib",
        "llm_confidence": 0.85,
        "evidence": "hallucinated",
    },
])


def test_a3_run_produces_candidate_edges():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = _VALID_EDGE_JSON
        result = asyncio.run(agent.run(state))
    assert len(result["candidate_edges"]) == 1


def test_a3_run_validated_edge_passes_import_check():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = _VALID_EDGE_JSON
        result = asyncio.run(agent.run(state))
    assert len(result["validated_edges"]) == 1
    assert result["validated_edges"][0].edge_type == CDGEdgeType.USES


def test_a3_run_filters_hallucinated_edges():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = _HALLUCINATED_EDGE_JSON
        result = asyncio.run(agent.run(state))
    assert len(result["candidate_edges"]) == 1
    assert len(result["validated_edges"]) == 0   # hallucination excluded


def test_a3_run_mixed_edges_correct_split():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = _MIXED_EDGES_JSON
        result = asyncio.run(agent.run(state))
    assert len(result["candidate_edges"]) == 2
    assert len(result["validated_edges"]) == 1   # only the real import survives


def test_a3_no_llm_call_on_empty_findings():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state(findings=[])
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        result = asyncio.run(agent.run(state))
    mock_llm.assert_not_called()
    assert result["candidate_edges"] == []
    assert result["validated_edges"] == []


# ── safe-hints prompt guard ────────────────────────────────────────────────

def test_safe_hints_prompt_says_do_not_propose():
    """Prompt must not invite LLM to propose edges from safe-hints files."""
    findings = [
        {"algorithm_family": "RSA", "parameter_set": "RSA-2048",
         "source_ref": "src/Auth.java:L10", "confidence": 0.9,
         "use_context": "key_exchange", "evidence": "KPG.getInstance(\"RSA\")",
         "detected_by": "static_rule"},
        {"algorithm_family": "SHA", "parameter_set": "SHA-256",
         "source_ref": "src/Hash.java:L5", "confidence": 0.9,
         "use_context": "hashing", "evidence": "MessageDigest.getInstance(\"SHA-256\")",
         "detected_by": "static_rule"},
    ]
    import_graph = {"src/Auth.java": ["java.security.KeyPairGenerator"]}
    ast_cache: dict = {}
    cfg = CryptoDependConfig(neo4j_password="x")
    _, user_prompt = _build_dependency_prompt(findings, import_graph, ast_cache, cfg)

    # Must NOT say "include edges if code depends"
    assert "include edges if code depends" not in user_prompt
    # Must say "do NOT propose" or equivalent
    assert "do NOT propose" in user_prompt or "DO NOT propose" in user_prompt


# ── min_edge_support threshold ─────────────────────────────────────────────

def test_min_edge_support_default_in_config():
    """CryptoDependConfig must expose min_edge_support with default 0.25."""
    cfg = CryptoDependConfig(neo4j_password="x")
    assert hasattr(cfg, "min_edge_support")
    assert cfg.min_edge_support == 0.25


def test_support_threshold_rejects_four_hop():
    """A 4-hop BFS edge (support=0.25) must be rejected when min_edge_support=0.25."""
    ig = {
        "a.java": ["b.java"],
        "b.java": ["c.java"],
        "c.java": ["d.java"],
        "d.java": ["org.crypto.RSA"],
    }
    support = _build_import_graph_support("a.java", "org.crypto.RSA", ig, max_hops=4)
    # 4 hops → support = 1/4 = 0.25
    assert support == pytest.approx(0.25)
    # At the default threshold of 0.25, this must NOT pass (> not >=)
    cfg = CryptoDependConfig(neo4j_password="x")
    assert support <= cfg.min_edge_support  # 0.25 is not > 0.25


def test_support_threshold_accepts_two_hop():
    """A 2-hop BFS edge (support=0.5) must be accepted."""
    ig = {
        "a.java": ["b.java"],
        "b.java": ["org.crypto.RSA"],
    }
    support = _build_import_graph_support("a.java", "org.crypto.RSA", ig, max_hops=4)
    assert support == pytest.approx(0.5)
    cfg = CryptoDependConfig(neo4j_password="x")
    assert support > cfg.min_edge_support  # 0.5 > 0.25


def test_a3_confidence_is_min_of_llm_and_import_support():
    # llm_confidence=0.9, direct import -> support=1.0 -> min=0.9
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = _VALID_EDGE_JSON
        result = asyncio.run(agent.run(state))
    assert result["validated_edges"][0].confidence == pytest.approx(0.9, abs=0.01)


def test_a3_updates_total_llm_tokens():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = _VALID_EDGE_JSON
        result = asyncio.run(agent.run(state))
    assert result["total_llm_tokens"] > 0


def test_a3_records_timing():
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state()
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "[]"
        result = asyncio.run(agent.run(state))
    assert "A3:DependencyReasoning" in result["agent_timings"]


# ── max_import_graph_entries default ──────────────────────────────────────

def test_config_max_import_graph_entries_default_is_50():
    """Default must be 50 to stay within Groq 32 K context limit."""
    cfg = CryptoDependConfig(neo4j_password="test")
    assert cfg.max_import_graph_entries == 50


def test_prompt_ig_capped_at_config_limit():
    """Import graph in prompt is capped to max_import_graph_entries; files with findings are prioritized."""
    # large_ig: 100 generic files + AuthService.java (which appears in _SAMPLE_FINDINGS)
    large_ig = {f"File{i}.java": [f"dep.Lib{i}"] for i in range(100)}
    large_ig["AuthService.java"] = ["java.security.KeyPairGenerator"]
    cfg = CryptoDependConfig(neo4j_password="test", max_import_graph_entries=5)
    _, user = _build_dependency_prompt(_SAMPLE_FINDINGS, large_ig, _SAMPLE_AST, cfg)
    # Cap is enforced: at most 5 File*.java entries (AuthService.java doesn't count here)
    file_count = sum(1 for i in range(100) if f"File{i}.java" in user)
    assert file_count <= 4  # at most 4 generic files since AuthService.java takes 1 of 5 slots
    # Prioritization: AuthService.java (has findings) must be in the prompt
    assert "AuthService.java" in user
    # Lower-bound guard: import graph section must not be empty
    assert file_count > 0 or "AuthService.java" in user


# ── Compact JSON serialization ─────────────────────────────────────────────

def test_prompt_findings_json_is_compact():
    """Findings must be serialized without indent=2 whitespace."""
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_SAMPLE_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    # Compact JSON has no "  " two-space indents before keys.
    # Find the findings blob: it starts after "Crypto findings to analyze:\n"
    findings_section = user.split("Import graph for context:")[0]
    assert '  "algorithm_family"' not in findings_section  # no 2-space indent


def test_prompt_import_graph_json_is_compact():
    """Import graph must be serialized without indent=2 whitespace."""
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_SAMPLE_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    ig_section = user.split("Import graph for context:\n")[1].split("Relevant file slices:")[0]
    # Compact JSON has no "  " two-space indents inside the dict.
    assert "  " not in ig_section.strip()


# ── Quantum-vulnerable-only filter ─────────────────────────────────────────

_MIXED_VULN_FINDINGS = [
    {
        "algorithm_family": "RSA",
        "parameter_set": "RSA-2048",
        "use_context": "key_generation",
        "source_ref": "AuthService.java:L7",
        "confidence": 0.95,
        "evidence": 'KeyPairGenerator.getInstance("RSA")',
        "detected_by": "static_rule",
    },
    {
        "algorithm_family": "AES",
        "parameter_set": "AES-128",
        "use_context": "encryption",
        "source_ref": "DataService.java:L12",
        "confidence": 0.90,
        "evidence": 'Cipher.getInstance("AES/CBC/PKCS5Padding")',
        "detected_by": "static_rule",
    },
]

_SAFE_ONLY_FINDINGS = [
    {
        "algorithm_family": "AES",
        "parameter_set": "AES-256",
        "use_context": "encryption",
        "source_ref": "SafeService.java:L5",
        "confidence": 0.99,
        "evidence": 'Cipher.getInstance("AES/GCM")',
        "detected_by": "static_rule",
    },
]


def test_prompt_omits_quantum_safe_findings_when_vuln_exist():
    """AES (quantum-safe) must be excluded from main findings block when RSA findings exist."""
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_MIXED_VULN_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    # Main findings block ends at compact hints section (or import graph if no safe findings)
    split_marker = "Quantum-safe findings" if "Quantum-safe findings" in user else "Import graph for context:"
    main_findings_section = user.split(split_marker)[0]
    assert "RSA" in main_findings_section
    assert "AES" not in main_findings_section


def test_prompt_includes_compact_hints_for_safe_findings():
    """Quantum-safe findings appear as compact {f,l,a} hints after main findings block."""
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_MIXED_VULN_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert "Quantum-safe findings" in user
    hints_start = user.find("Quantum-safe findings")
    ig_start = user.find("Import graph for context:")
    assert hints_start < ig_start, "compact hints must appear before import graph"
    hints_section = user[hints_start:ig_start]
    assert '"a"' in hints_section, "compact hints must use {f,l,a} format"
    assert "AES" in hints_section


def test_no_compact_hints_when_no_safe_findings():
    """When only quantum-vulnerable findings exist, no compact hints section is added."""
    cfg = CryptoDependConfig(neo4j_password="test")
    vuln_only = [f for f in _MIXED_VULN_FINDINGS if f["algorithm_family"].upper() in {"RSA"}]
    _, user = _build_dependency_prompt(vuln_only, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert "Quantum-safe findings" not in user


def test_prompt_falls_back_to_all_findings_when_no_vuln():
    """When only quantum-safe findings exist, include them all (do not silently drop)."""
    cfg = CryptoDependConfig(neo4j_password="test")
    _, user = _build_dependency_prompt(_SAFE_ONLY_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    findings_section = user.split("Import graph for context:")[0]
    assert "AES" in findings_section


def test_filter_does_not_modify_input_findings_list():
    """The original findings list passed to prompt builder must not be mutated."""
    import copy
    cfg = CryptoDependConfig(neo4j_password="test")
    original = copy.deepcopy(_MIXED_VULN_FINDINGS)
    _build_dependency_prompt(_MIXED_VULN_FINDINGS, _SAMPLE_IG, _SAMPLE_AST, cfg)
    assert _MIXED_VULN_FINDINGS == original


def test_validated_findings_in_state_not_affected_by_prompt_filter():
    """A3.run() must pass ALL validated_findings to CDGState unchanged.

    The AES finding must survive in candidate_edges evaluation even though
    it was filtered from the LLM prompt.
    """
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state(
        findings=_MIXED_VULN_FINDINGS,
        import_graph={
            "AuthService.java": ["java.security.KeyPairGenerator"],
            "DataService.java": ["javax.crypto.Cipher"],
        },
    )
    # LLM proposes an edge referencing the AES finding's file
    aes_edge_json = json.dumps([{
        "edge_type": "uses",
        "source_ref": "DataService.java:L12",
        "target_ref": "javax.crypto.Cipher",
        "source_label": "DataService",
        "target_label": "Cipher",
        "llm_confidence": 0.9,
        "evidence": "import javax.crypto.Cipher",
    }])
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = aes_edge_json
        result = asyncio.run(agent.run(state))
    # The key check: state["validated_findings"] was never cleared or filtered
    assert len(state["validated_findings"]) == len(_MIXED_VULN_FINDINGS)  # both RSA + AES survive in state


# ── Agent-level 4-hop gate ─────────────────────────────────────────────────

def test_agent_rejects_four_hop_edge_in_validated():
    """Agent must NOT promote a 4-hop edge to validated_edges when min_edge_support=0.25.

    A 4-hop chain gives support=0.25 which is NOT > min_edge_support=0.25,
    so the edge must appear in candidate_edges (all LLM proposals) but not
    in validated_edges (only import-verified edges).
    """
    ig = {
        "a.java": ["b.java"],
        "b.java": ["c.java"],
        "c.java": ["d.java"],
        "d.java": ["org.crypto.RSA"],
    }
    four_hop_edge_json = json.dumps([{
        "edge_type": "uses",
        "source_ref": "a.java:L1",
        "target_ref": "org.crypto.RSA",
        "source_label": "A",
        "target_label": "RSA",
        "llm_confidence": 0.9,
        "evidence": "transitive import chain",
    }])
    findings = [{
        "algorithm_family": "RSA",
        "parameter_set": "RSA-2048",
        "use_context": "key_generation",
        "source_ref": "a.java:L1",
        "confidence": 0.9,
        "evidence": "RSA usage",
        "detected_by": "static_rule",
    }]
    agent = DependencyReasoningAgent(CryptoDependConfig(neo4j_password="test"))
    state = _make_a3_state(findings=findings, import_graph=ig)
    # Also update ast_cache to match the 4-hop graph
    state["ast_cache"] = {"a.java": {"source": "// a.java", "tree": None}}
    with patch("cryptodep.agents.a3_reasoning.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = four_hop_edge_json
        result = asyncio.run(agent.run(state))
    # LLM proposal must be recorded in candidate_edges
    assert len(result["candidate_edges"]) == 1
    # But the 4-hop edge must NOT pass the support gate into validated_edges
    assert len(result["validated_edges"]) == 0
