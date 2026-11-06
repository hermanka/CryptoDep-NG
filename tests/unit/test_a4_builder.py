from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch

from cryptodep.agents.a4_builder import (
    _findings_to_algo_nodes,
    _build_pqc_nodes,
    _compute_centrality,
    _build_cdg_document,
    _dedup_by_family,
    _extract_class_name,
    _is_library_ref,
    _is_test_file,
    _normalize_lib_name,
    _synthesize_component_library_edges,
    _augment_edges_from_import_graph,
)
from cryptodep.schema.cdg_models import (
    CDGEdge,
    CDGEdgeType,
    CryptoAlgorithmNode,
    MigrationPlan,
    NistQuantumVulnClass,
    MigrationPriority,
)
from cryptodep.state import CryptoFinding


def _rsa_finding() -> CryptoFinding:
    return {
        "algorithm_family": "RSA",
        "parameter_set": "RSA-2048",
        "use_context": "key_exchange",
        "source_ref": "src/auth/JwtService.java:L42",
        "confidence": 0.95,
        "evidence": "KeyPairGenerator.getInstance(\"RSA\", 2048)",
        "detected_by": "static_rule",
    }


def _aes_finding() -> CryptoFinding:
    return {
        "algorithm_family": "AES",
        "parameter_set": "AES-256",
        "use_context": "encryption",
        "source_ref": "src/crypto/CipherUtil.java:L10",
        "confidence": 0.90,
        "evidence": "Cipher.getInstance(\"AES/GCM/NoPadding\")",
        "detected_by": "static_rule",
    }


# ── _findings_to_algo_nodes ───────────────────────────────────────────────────

def test_findings_to_algo_nodes_single_finding():
    nodes = _findings_to_algo_nodes([_rsa_finding()])
    assert len(nodes) == 1
    node = list(nodes.values())[0]
    assert node.algorithm_family == "RSA"
    assert node.parameter_set == "RSA-2048"


def test_findings_to_algo_nodes_deduplication():
    """Two RSA-2048 findings from different files → single node."""
    f2 = dict(_rsa_finding())
    f2["source_ref"] = "src/other/AuthService.java:L99"
    nodes = _findings_to_algo_nodes([_rsa_finding(), f2])
    assert len(nodes) == 1


def test_findings_to_algo_nodes_different_algos():
    nodes = _findings_to_algo_nodes([_rsa_finding(), _aes_finding()])
    assert len(nodes) == 2


def test_findings_quantum_vulnerable_annotated():
    nodes = _findings_to_algo_nodes([_rsa_finding()])
    node = list(nodes.values())[0]
    assert node.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE


def test_findings_quantum_safe_annotated():
    nodes = _findings_to_algo_nodes([_aes_finding()])
    node = list(nodes.values())[0]
    assert node.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC


def test_findings_to_algo_nodes_empty():
    assert _findings_to_algo_nodes([]) == {}


def test_findings_to_algo_nodes_uses_parameter_set():
    f1 = _aes_finding()
    f1["parameter_set"] = "AES-CBC"
    nodes = _findings_to_algo_nodes([f1])
    node = list(nodes.values())[0]
    assert node.label == "AES-CBC"


def test_label_numeric_keysize_combines_family_and_param():
    f = {
        "algorithm_family": "RSA",
        "parameter_set": "2048",
        "use_context": "key_exchange",
        "source_ref": "src/auth/JwtService.java:L42",
        "confidence": 0.95,
        "evidence": "KeyPairGenerator.getInstance(\"RSA\", 2048)",
        "detected_by": "static_rule",
    }
    nodes = _findings_to_algo_nodes([f])
    node = list(nodes.values())[0]
    assert node.label == "RSA-2048"


def test_label_aes_compound_kept_or_normalized():
    f = {
        "algorithm_family": "AES",
        "parameter_set": "AES/CBC/PKCS5Padding",
        "use_context": "encryption",
        "source_ref": "src/crypto/CipherUtil.java:L10",
        "confidence": 0.90,
        "evidence": 'Cipher.getInstance("AES/CBC/PKCS5Padding")',
        "detected_by": "static_rule",
    }
    nodes = _findings_to_algo_nodes([f])
    node = list(nodes.values())[0]
    # Accept either normalized form (AES-CBC) or the raw param containing slashes
    assert node.label in ("AES-CBC", "AES/CBC/PKCS5Padding")


def test_label_jwt_alg_preserved():
    f = {
        "algorithm_family": "JWT",
        "parameter_set": "HS256",
        "use_context": "token",
        "source_ref": "src/auth/JwtService.java:L10",
        "confidence": 0.9,
        "evidence": 'Algorithm.HMAC256("secret")',
        "detected_by": "static_rule",
    }
    nodes = _findings_to_algo_nodes([f])
    node = list(nodes.values())[0]
    assert node.label == "HS256"


def test_classify_vuln_bcrypt_quantum_safe():
    from cryptodep.agents.a4_builder import _classify_vuln
    assert _classify_vuln("BCRYPT") == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC
    assert _classify_vuln("SCRYPT") == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC


# ── _build_pqc_nodes ─────────────────────────────────────────────────────────

def test_build_pqc_nodes_creates_pqc_for_vulnerable():
    algo_nodes = _findings_to_algo_nodes([_rsa_finding()])
    pqc_nodes, migrates_edges = _build_pqc_nodes(algo_nodes)
    assert len(pqc_nodes) >= 1
    assert len(migrates_edges) >= 1
    assert all(e.edge_type == CDGEdgeType.MIGRATES_TO for e in migrates_edges)


def test_build_pqc_nodes_skips_safe():
    """AES-256 is quantum-safe — no PQC node or migrates_to edge created."""
    algo_nodes = _findings_to_algo_nodes([_aes_finding()])
    pqc_nodes, migrates_edges = _build_pqc_nodes(algo_nodes)
    assert len(migrates_edges) == 0


def test_build_pqc_nodes_deduplicates_pqc():
    """RSA + ECDH both map to ML-KEM-768 — only one PQC node created."""
    ecdh_finding: CryptoFinding = {
        "algorithm_family": "ECDH",
        "parameter_set": "ECDH-P256",
        "use_context": "key_exchange",
        "source_ref": "src/tls/TLSConfig.java:L5",
        "confidence": 0.9,
        "evidence": "KeyAgreement.getInstance(\"ECDH\")",
        "detected_by": "static_rule",
    }
    algo_nodes = _findings_to_algo_nodes([_rsa_finding(), ecdh_finding])
    pqc_nodes, _ = _build_pqc_nodes(algo_nodes)
    # Both map to ML-KEM-768 → deduplicated to 1 PQC node
    algo_ids = {n.algorithm_id for n in pqc_nodes}
    assert len(algo_ids) == len(pqc_nodes)  # no duplicate PQC algo_id


def test_all_vulnerable_have_migrates_to():
    findings = [_rsa_finding(), _aes_finding()]
    algo_nodes = _findings_to_algo_nodes(findings)
    _, migrates_edges = _build_pqc_nodes(algo_nodes)
    vuln_ids = {nid for nid, n in algo_nodes.items()
                if n.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE}
    edge_sources = {e.source_id for e in migrates_edges}
    assert vuln_ids == edge_sources


# ── _compute_centrality ───────────────────────────────────────────────────────

def test_compute_centrality_returns_dict():
    algo_nodes = _findings_to_algo_nodes([_rsa_finding()])
    node_ids = list(algo_nodes.keys())
    edges: list[CDGEdge] = []
    centrality = _compute_centrality(node_ids, edges)
    assert isinstance(centrality, dict)
    for nid in node_ids:
        assert nid in centrality
        assert 0.0 <= centrality[nid] <= 1.0


def test_compute_centrality_hub_higher():
    """A node with more connections should have higher centrality."""
    n1 = "cdg:node:n1"
    n2 = "cdg:node:n2"
    n3 = "cdg:node:n3"
    edges = [
        CDGEdge(edge_type=CDGEdgeType.USES, source_id=n1, target_id=n2),
        CDGEdge(edge_type=CDGEdgeType.USES, source_id=n2, target_id=n3),
    ]
    centrality = _compute_centrality([n1, n2, n3], edges)
    # n2 is the intermediary — should have highest betweenness
    assert centrality[n2] >= centrality[n1]
    assert centrality[n2] >= centrality[n3]


# ── _build_cdg_document ───────────────────────────────────────────────────────

def test_build_cdg_document_passes_pydantic_validation():
    from cryptodep.schema.cdg_models import CDGDocument
    algo_nodes = _findings_to_algo_nodes([_rsa_finding()])
    pqc_nodes, migrates_edges = _build_pqc_nodes(algo_nodes)
    all_node_dicts = (
        [n.model_dump(mode="python") for n in algo_nodes.values()]
        + [n.model_dump(mode="python") for n in pqc_nodes]
    )
    doc = _build_cdg_document(
        node_dicts=all_node_dicts,
        edges=migrates_edges,
        migration_plan=MigrationPlan(),
        repo_path="test/repo",
        run_id="test-run-1",
    )
    # Pydantic validation happens at construction — if we get here, it passed
    assert doc.schema_version == "1.0.0"
    assert len(doc.nodes) == len(all_node_dicts)
    assert len(doc.edges) == len(migrates_edges)


# ── CDGBuilderAgent.run() ─────────────────────────────────────────────────────

from cryptodep.agents.a4_builder import CDGBuilderAgent
from cryptodep.config import CryptoDependConfig


def _make_config() -> CryptoDependConfig:
    return CryptoDependConfig(neo4j_password="test")


def _make_state_with_findings() -> dict:
    return {
        "repo_path": "/test/repo",
        "config": _make_config(),
        "run_id": "test-run-001",
        "file_index": {},
        "ast_cache": {},
        "import_graph": {},
        "repo_stats": {"total_files": 1, "total_loc": 100, "languages": {}},
        "raw_crypto_findings": [],
        "validated_findings": [
            {
                "algorithm_family": "RSA",
                "parameter_set": "RSA-2048",
                "use_context": "key_exchange",
                "source_ref": "src/auth/JwtService.java:L42",
                "confidence": 0.95,
                "evidence": 'KeyPairGenerator.getInstance("RSA", 2048)',
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


def _patched_run(state, findings_override=None):
    """Helper: run CDGBuilderAgent with Neo4j + CBOM patched out."""
    if findings_override is not None:
        state["validated_findings"] = findings_override
    config = _make_config()
    agent = CDGBuilderAgent(config)

    import neo4j as _neo4j_mod
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=False)
    mock_session.run.return_value.single.return_value = {"n": 2, "e": 1}
    mock_driver.session.return_value = mock_session

    return agent, mock_driver, mock_session


@pytest.mark.asyncio
async def test_run_produces_cdg_document():
    state = _make_state_with_findings()
    agent = CDGBuilderAgent(_make_config())
    with patch("neo4j.GraphDatabase.driver", return_value=MagicMock(
            session=MagicMock(return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(
                    run=MagicMock(return_value=MagicMock(single=MagicMock(return_value={"n": 2, "e": 1})))
                )),
                __exit__=MagicMock(return_value=False),
            ))
        )), \
         patch("cryptodep.tools.cbom_tools.Path"):
        result = await agent.run(state)
    assert result["cdg_document"] is not None
    assert result["cdg_document"].schema_version == "1.0.0"


@pytest.mark.asyncio
async def test_run_populates_migration_plan():
    state = _make_state_with_findings()
    agent = CDGBuilderAgent(_make_config())
    with patch("neo4j.GraphDatabase.driver"), \
         patch("cryptodep.tools.cbom_tools.Path"):
        result = await agent.run(state)
    assert result["migration_plan"] is not None
    assert result["migration_plan"].total_vulnerable_assets >= 1


@pytest.mark.asyncio
async def test_run_records_timing():
    state = _make_state_with_findings()
    agent = CDGBuilderAgent(_make_config())
    with patch("neo4j.GraphDatabase.driver"), \
         patch("cryptodep.tools.cbom_tools.Path"):
        result = await agent.run(state)
    assert "A4:CDGBuilder" in result["agent_timings"]


@pytest.mark.asyncio
async def test_run_empty_findings():
    """Pipeline with no validated findings → empty CDGDocument, no crash."""
    state = _make_state_with_findings()
    state["validated_findings"] = []
    agent = CDGBuilderAgent(_make_config())
    with patch("neo4j.GraphDatabase.driver"), \
         patch("cryptodep.tools.cbom_tools.Path"):
        result = await agent.run(state)
    assert result["cdg_document"] is not None
    assert result["cdg_document"].nodes == []


# ── _extract_class_name ───────────────────────────────────────────────────────

def test_extract_class_name_java_with_line():
    assert _extract_class_name("src/main/java/CryptoUtil.java:L42") == "CryptoUtil"

def test_extract_class_name_python_no_line():
    assert _extract_class_name("src/auth/jwt_service.py") == "jwt_service"

def test_extract_class_name_basename_only():
    assert _extract_class_name("HashingAssignment.java") == "HashingAssignment"

def test_extract_class_name_nested_path():
    assert _extract_class_name("src/main/java/org/example/SecurityConfig.java:L10") == "SecurityConfig"


# ── _is_library_ref ───────────────────────────────────────────────────────────

def test_is_library_ref_java_stdlib():
    assert _is_library_ref("java.security") is True
    assert _is_library_ref("javax.crypto") is True
    assert _is_library_ref("org.bouncycastle.jce") is True

def test_is_library_ref_rejects_file_path():
    assert _is_library_ref("src/main/java/Foo.java") is False
    assert _is_library_ref("Foo.java") is False

def test_is_library_ref_rejects_unknown():
    assert _is_library_ref("unknown") is False
    assert _is_library_ref("") is False

def test_is_library_ref_rejects_deep_local_app_fqn():
    """FQNs with 5+ dot-separated components are local app classes, not external libs."""
    # WebGoat-style local class FQNs must be rejected
    assert _is_library_ref("org.owasp.webgoat.lessons.cryptography.CryptoUtil") is False
    assert _is_library_ref("org.owasp.webgoat.lessons.jwt.JWTSecretKeyEndpoint") is False
    assert _is_library_ref("org.owasp.webgoat.lessons.cryptography.HashingAssignment") is False
    # Shallow external library refs must still be accepted
    assert _is_library_ref("java.security.KeyPairGenerator") is True   # 3 dots → shallow
    assert _is_library_ref("io.jsonwebtoken.SignatureAlgorithm") is True  # 2 dots → shallow
    assert _is_library_ref("org.jose4j.jws.JsonWebSignature") is True    # 3 dots → shallow


# ── _is_test_file ─────────────────────────────────────────────────────────────

def test_is_test_file_rejects_main_source():
    assert _is_test_file("src/main/java/org/example/CryptoUtil.java") is False
    assert _is_test_file("src/main/java/org/example/HashingAssignment.java") is False

def test_is_test_file_detects_test_directory():
    assert _is_test_file("src/test/java/org/example/CryptoUtilTest.java") is True
    assert _is_test_file("src/it/java/org/example/CryptoIntegrationTest.java") is True

def test_is_test_file_detects_test_suffix():
    assert _is_test_file("src/main/java/org/example/CryptoUtilTest.java") is True
    assert _is_test_file("src/main/java/org/example/JWTLessonIntegrationTest.java") is True

def test_synthesize_excludes_test_appcomponents():
    """AppComponent nodes must NOT be created for test/IT source files."""
    main_finding = _make_finding_with_lib(src="src/main/java/CryptoUtil.java:L42")
    test_finding = _make_finding_with_lib(src="src/test/java/CryptoUtilTest.java:L10")
    it_finding = _make_finding_with_lib(src="src/it/java/CryptoIntegrationTest.java:L5")
    algo_nodes = _findings_to_algo_nodes([main_finding, test_finding, it_finding])
    app_nodes, _, _ = _synthesize_component_library_edges(
        [main_finding, test_finding, it_finding], [], algo_nodes
    )
    app_labels = {n.label for n in app_nodes}
    assert "CryptoUtil" in app_labels, "Main source AppComponent must be kept"
    assert "CryptoUtilTest" not in app_labels, "Test file AppComponent must be filtered"
    assert "CryptoIntegrationTest" not in app_labels, "IT file AppComponent must be filtered"


# ── _synthesize_component_library_edges ───────────────────────────────────────

def _make_finding_with_lib(algo_family="RSA", param="RSA-2048",
                            src="src/auth/JwtService.java:L42") -> "CryptoFinding":
    return {
        "algorithm_family": algo_family,
        "parameter_set": param,
        "use_context": "key_exchange",
        "source_ref": src,
        "confidence": 0.9,
        "evidence": "test",
        "detected_by": "static_rule",
    }

def test_synthesize_creates_app_and_lib_nodes():
    finding = _make_finding_with_lib()
    algo_nodes = _findings_to_algo_nodes([finding])
    lib_edge = CDGEdge(
        edge_type=CDGEdgeType.USES,
        source_id="src/auth/JwtService.java:L42",
        target_id="java.security",
        confidence=0.9,
        evidence="import java.security.*",
    )
    app_nodes, lib_nodes, edges = _synthesize_component_library_edges(
        [finding], [lib_edge], algo_nodes
    )
    assert any(n.label == "JwtService" for n in app_nodes)
    assert any(n.label == "java.security" for n in lib_nodes)

def test_synthesize_uses_and_implements_edges():
    finding = _make_finding_with_lib()
    algo_nodes = _findings_to_algo_nodes([finding])
    lib_edge = CDGEdge(
        edge_type=CDGEdgeType.USES,
        source_id="src/auth/JwtService.java:L42",
        target_id="java.security",
        confidence=0.9,
        evidence="import java.security.*",
    )
    app_nodes, lib_nodes, edges = _synthesize_component_library_edges(
        [finding], [lib_edge], algo_nodes
    )
    edge_types = {e.edge_type for e in edges}
    assert CDGEdgeType.USES in edge_types
    assert CDGEdgeType.IMPLEMENTS in edge_types

def test_synthesize_empty_inputs():
    app_nodes, lib_nodes, edges = _synthesize_component_library_edges([], [], {})
    assert app_nodes == []
    assert lib_nodes == []
    assert edges == []


def test_synthesize_normalizes_class_level_library_ref_to_package():
    """A3 produces 'java.security.KeyPair' but label must be normalized to 'java.security'."""
    finding = _make_finding_with_lib(algo_family="RSA", param="RSA-2048",
                                     src="src/auth/CryptoUtil.java:L42")
    algo_nodes = _findings_to_algo_nodes([finding])
    # A3 edge has a class-level target (java.security.KeyPair), not package-level
    lib_edge = CDGEdge(
        edge_type=CDGEdgeType.USES,
        source_id="src/auth/CryptoUtil.java:L42",
        target_id="java.security.KeyPair",
        confidence=0.9,
        evidence="new KeyPair()",
    )
    app_nodes, lib_nodes, edges = _synthesize_component_library_edges(
        [finding], [lib_edge], algo_nodes
    )
    lib_labels = {n.label for n in lib_nodes}
    assert "java.security" in lib_labels, (
        f"Expected normalized label 'java.security', got {lib_labels}"
    )
    assert "java.security.KeyPair" not in lib_labels, (
        "Class-level ref must be normalized to package level"
    )


def test_synthesize_infers_uses_from_findings_when_a3_edges_miss_main_source():
    """When A3 validated_edges come only from test files, USES edges must still be
    inferred from findings for main-source AppComponents.

    Scenario:
      - CryptoUtil.java (main source) has an RSA finding
      - A3 validated_edge is from CryptoUtilTest.java → java.security.KeyPair
      - Synthesis should create: CryptoUtil → java.security (USES)
    """
    main_finding = _make_finding_with_lib(algo_family="RSA", param="RSA-2048",
                                          src="src/main/CryptoUtil.java:L42")
    algo_nodes = _findings_to_algo_nodes([main_finding])

    # A3 edge comes from TEST file (not main source)
    test_lib_edge = CDGEdge(
        edge_type=CDGEdgeType.USES,
        source_id="src/test/CryptoUtilTest.java:L25",
        target_id="java.security.KeyPair",
        confidence=0.9,
        evidence="KeyPair kp",
    )
    # Include both files in findings so file_to_class maps both
    test_finding = _make_finding_with_lib(algo_family="RSA", param="RSA-2048",
                                          src="src/test/CryptoUtilTest.java:L25")
    app_nodes, lib_nodes, edges = _synthesize_component_library_edges(
        [main_finding, test_finding], [test_lib_edge], algo_nodes
    )
    uses_edges = [(e.source_id, e.target_id) for e in edges if e.edge_type == CDGEdgeType.USES]
    app_by_id = {n.node_id: n.label for n in app_nodes}
    lib_by_id = {n.node_id: n.label for n in lib_nodes}
    uses_labels = [
        (app_by_id.get(src, src), lib_by_id.get(tgt, tgt))
        for src, tgt in uses_edges
    ]
    assert ("CryptoUtil", "java.security") in uses_labels, (
        f"Expected USES(CryptoUtil, java.security) inferred from findings, "
        f"got uses_labels={uses_labels}"
    )


# ── _build_pqc_nodes dual-context (RSA without use_context) ──────────────────

def test_build_pqc_nodes_rsa_key_exchange_context_still_yields_both_replacements():
    """RSA with use_context='key_exchange' must STILL produce BOTH ML-KEM-768 AND ML-DSA-65.

    RSA is dual-use: it serves as KEM (key encapsulation) AND digital signature.
    Even when A2 labels the finding as 'key_exchange', the migration plan must include
    both PQC replacements — the evaluator GT expects both migrates_to edges.
    """
    from cryptodep.schema.cdg_models import PQCAlgorithmId
    finding = {
        "algorithm_family": "RSA",
        "parameter_set": "RSA-2048",
        "use_context": "key_exchange",  # explicitly set — must NOT suppress ML-DSA-65
        "source_ref": "src/auth/JwtService.java:L42",
        "confidence": 0.9,
        "evidence": "KeyPairGenerator.getInstance(\"RSA\", 2048)",
        "detected_by": "static_rule",
    }
    algo_nodes = _findings_to_algo_nodes([finding])
    pqc_nodes, migrates_edges = _build_pqc_nodes(algo_nodes)
    algo_ids = {n.algorithm_id for n in pqc_nodes}
    assert PQCAlgorithmId.ML_KEM_768 in algo_ids, "Expected ML-KEM-768 for RSA key_exchange"
    assert PQCAlgorithmId.ML_DSA_65 in algo_ids, "Expected ML-DSA-65 even with key_exchange context"
    assert len(migrates_edges) == 2, f"Expected 2 migrates_to edges, got {len(migrates_edges)}"


def test_build_pqc_nodes_rsa_no_context_yields_both_replacements():
    """RSA with use_context=None must produce both ML-KEM-768 and ML-DSA-65."""
    from cryptodep.schema.cdg_models import PQCAlgorithmId
    finding = {
        "algorithm_family": "RSA",
        "parameter_set": "RSA-2048",
        "use_context": None,  # no context set
        "source_ref": "src/auth/AuthService.java:L10",
        "confidence": 0.9,
        "evidence": "RSA usage",
        "detected_by": "static_rule",
    }
    algo_nodes = _findings_to_algo_nodes([finding])
    pqc_nodes, migrates_edges = _build_pqc_nodes(algo_nodes)
    algo_ids = {n.algorithm_id for n in pqc_nodes}
    assert PQCAlgorithmId.ML_KEM_768 in algo_ids, "Expected ML-KEM-768 for RSA key_exchange context"
    assert PQCAlgorithmId.ML_DSA_65 in algo_ids, "Expected ML-DSA-65 for RSA digital_signature context"
    assert len(migrates_edges) == 2, f"Expected 2 migrates_to edges for dual-context RSA, got {len(migrates_edges)}"


# ── _dedup_by_family: compound label → RSA-2048 via _KEY_SIZE_RE ──────────────

def test_dedup_by_family_extracts_key_size_from_compound_label():
    """When parameter_set is compound (e.g. 'SHA256 + RSA 2048-bit'), dedup must
    extract the key size via _KEY_SIZE_RE and produce label='RSA-2048'."""
    finding = {
        "algorithm_family": "RSA",
        "parameter_set": "SHA256 + RSA 2048-bit",
        "use_context": "digital_signature",
        "source_ref": "src/auth/CryptoUtil.java:L10",
        "confidence": 0.9,
        "evidence": "Signature.getInstance(\"SHA256withRSA\")",
        "detected_by": "static_rule",
    }
    raw_nodes = _findings_to_algo_nodes([finding])
    deduped = _dedup_by_family(raw_nodes)
    assert len(deduped) == 1
    node = list(deduped.values())[0]
    assert node.label == "RSA-2048", (
        f"Expected label 'RSA-2048' from compound param, got '{node.label}'"
    )
    assert node.parameter_set == "2048", (
        f"Expected parameter_set '2048', got '{node.parameter_set}'"
    )
    assert node.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE


def test_dedup_by_family_picks_largest_key_size_among_multiple():
    """When multiple RSA nodes have different key sizes, dedup picks the largest."""
    f2048 = {
        "algorithm_family": "RSA",
        "parameter_set": "RSA 2048-bit",
        "use_context": "key_exchange",
        "source_ref": "src/auth/A.java:L1",
        "confidence": 0.9,
        "evidence": "RSA 2048",
        "detected_by": "static_rule",
    }
    f4096 = {
        "algorithm_family": "RSA",
        "parameter_set": "RSA 4096-bit",
        "use_context": "key_exchange",
        "source_ref": "src/auth/B.java:L1",
        "confidence": 0.9,
        "evidence": "RSA 4096",
        "detected_by": "static_rule",
    }
    raw_nodes = _findings_to_algo_nodes([f2048, f4096])
    deduped = _dedup_by_family(raw_nodes)
    assert len(deduped) == 1
    node = list(deduped.values())[0]
    assert node.parameter_set == "4096"
    assert node.label == "RSA-4096"


# ── _findings_to_algo_nodes: compound signature noise families ────────────────

@pytest.mark.parametrize("compound_family", [
    "SHA256withRSA",
    "SHA1withRSA",
    "SHA384withRSA",
    "SHA512withRSA",
    "SHA256withECDSA",
    "SHA384withECDSA",
    "SHA512withECDSA",
])
def test_compound_signature_families_are_noise_filtered(compound_family: str):
    """Compound signature algorithm families must be filtered out as noise.

    The underlying key algorithm (RSA, ECDSA) is captured separately via
    direct key-generation findings, so these compound labels create FP nodes.
    """
    finding = {
        "algorithm_family": compound_family,
        "parameter_set": None,
        "use_context": "digital_signature",
        "source_ref": "src/auth/Signer.java:L5",
        "confidence": 0.9,
        "evidence": f'Signature.getInstance("{compound_family}")',
        "detected_by": "static_rule",
    }
    nodes = _findings_to_algo_nodes([finding])
    assert len(nodes) == 0, (
        f"Expected compound family '{compound_family}' to be filtered as noise, "
        f"but got {len(nodes)} node(s)"
    )


# ── _augment_edges_from_import_graph: files_with_real_findings filter ─────────

def test_augment_skips_files_without_real_findings():
    """Files not in files_with_real_findings must not get augmented edges."""
    import_graph = {
        "src/CryptoUtil.java": ["java.security.KeyPairGenerator"],  # has real finding
        "src/Noise.java":      ["java.security.SecureRandom"],       # noise only
    }
    existing_edges: list = []
    files_with_real_findings = {"src/CryptoUtil.java"}   # Noise.java excluded

    result = _augment_edges_from_import_graph(
        existing_edges, import_graph, files_with_real_findings
    )
    result_sources = {e.source_id for e in result}

    assert "src/CryptoUtil.java" in result_sources, "real-finding file must be augmented"
    assert "src/Noise.java" not in result_sources, "noise-only file must NOT be augmented"


def test_augment_includes_all_when_no_filter():
    """Without files_with_real_findings filter, behavior unchanged (backward compat)."""
    import_graph = {
        "src/CryptoUtil.java": ["java.security.KeyPairGenerator"],
        "src/Other.java":      ["java.security.KeyPairGenerator"],
    }
    result = _augment_edges_from_import_graph([], import_graph, files_with_real_findings=None)
    result_sources = {e.source_id for e in result}
    assert "src/CryptoUtil.java" in result_sources
    assert "src/Other.java" in result_sources


def test_augment_spring_digest_utils_without_unrelated_utilities():
    result = _augment_edges_from_import_graph([], {
        "src/UserService.java": ["org.springframework.util.DigestUtils", "org.springframework.util.StringUtils"],
    }, {"src/UserService.java"})
    assert len(result) == 1
    assert result[0].target_id == "org.springframework.util.DigestUtils"
