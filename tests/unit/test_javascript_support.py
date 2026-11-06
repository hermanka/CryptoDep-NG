"""JavaScript ingestion, detection normalization, and CDG integration."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from cryptodep.config import CryptoDependConfig
from cryptodep.tools.ast_tools import (
    build_file_graph, extract_imports, filter_source_files, parse_file_ast, source_ref_path,
)
from cryptodep.tools.semgrep_tools import _ripgrep_prefilter, parse_semgrep_findings


@pytest.mark.parametrize("extension", [".js", ".mjs", ".cjs"])
def test_javascript_ingestion(extension, tmp_path):
    from cryptodep.agents.a1_ingestion import CodeIngestionAgent

    source = tmp_path / ("signer" + extension)
    source.write_text("import crypto from 'node:crypto'; export class Signer {}", encoding="utf-8")
    vendor = tmp_path / "node_modules" / "nested"
    vendor.mkdir(parents=True)
    (vendor / "vendor.js").write_text("export const ignored = true;", encoding="utf-8")
    config = CryptoDependConfig(neo4j_password="test")
    state = {"config": config, "repo_path": str(tmp_path)}
    result = asyncio.run(CodeIngestionAgent(config).run(state))
    assert list(result["file_index"]) == [str(source)]
    assert result["file_index"][str(source)]["language"] == "javascript"
    assert result["import_graph"][str(source)] == ["node:crypto"]
    assert not result["ast_cache"][str(source)]["tree"].root_node.has_error
    assert filter_source_files(str(tmp_path), ["java", "python"], []) == []


def test_javascript_imports_and_relative_resolution(tmp_path):
    source = tmp_path / "main.js"
    source.write_text("""
import crypto from 'node:crypto';
import { createHash as hash } from 'crypto';
const { generateKeyPairSync } = require('node:crypto');
export { encrypt } from './encryption';
const local = require('./helpers');
import('./dynamic.mjs');
require(variable);
// require('not-a-real-import');
const text = "import fake from 'also-not-an-import'";
""", encoding="utf-8")
    paths = [source, tmp_path / "encryption.js", tmp_path / "helpers" / "index.cjs", tmp_path / "dynamic.mjs"]
    for path in paths[1:]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export const encrypt = () => {};", encoding="utf-8")
    cache = {str(p): parse_file_ast(p, "javascript") for p in paths}
    imports = extract_imports(cache[str(source)]["tree"], cache[str(source)]["source"], "javascript")
    assert imports == ["node:crypto", "crypto", "./encryption", "./helpers", "./dynamic.mjs"]
    graph = build_file_graph({str(p): {"language": "javascript"} for p in paths}, cache)
    assert all(str(p) in graph[str(source)] for p in paths[1:])
    from cryptodep.agents.a3_reasoning import _build_import_graph_support
    assert _build_import_graph_support(str(source), "node:crypto", graph) == 1.0
    assert _build_import_graph_support(str(source), str(paths[1]), graph) == 1.0


@pytest.mark.parametrize("ref, expected", [
    ("D:/repo/signer.js:L42", "D:/repo/signer.js"),
    (r"D:\repo\signer.js:42", r"D:\repo\signer.js"),
    ("src/signer.js:L42-L45", "src/signer.js"),
    ("node:crypto", "node:crypto"),
])
def test_source_ref_preserves_windows_drive(ref, expected):
    from cryptodep.agents.a4_builder import _extract_class_name

    assert source_ref_path(ref) == expected
    if expected != "node:crypto":
        assert _extract_class_name(ref) == "signer"


@pytest.mark.parametrize("algorithm, method, family, parameter, context", [
    ("rsa", "generateKeyPairSync", "RSA", "RSA-2048", "other"),
    ("aes-128-gcm", "createCipheriv", "AES", "AES-128-GCM", "encryption"),
    ("sha256", "createHash", "SHA-256", None, "hashing"),
    ("sha256", "createHmac", "HMAC", None, "other"),
    ("RSA-PSS", "sign", "RSA", "RSA-2048", "digital_signature"),
    ("ECDSA", "sign", "ECDSA", None, "digital_signature"),
    ("ed25519", "generateKeyPairSync", "ECC", "ED25519", "digital_signature"),
    ("x25519", "generateKeyPairSync", "ECDH", "X25519", "key_exchange"),
])
def test_javascript_finding_normalization(algorithm, method, family, parameter, context):
    evidence = f"crypto.{method}('{algorithm}'" + (", { modulusLength: 2048 })" if family == "RSA" else ")")
    finding = parse_semgrep_findings([{
        "path": "src/signer.js", "start": {"line": 8},
        "extra": {"message": "Node crypto API", "lines": evidence,
                  "metadata": {"category": "crypto-javascript-api"},
                  "metavars": {"$ALG": {"abstract_content": repr(algorithm)},
                               "$METHOD": {"abstract_content": method}}},
    }])[0]
    assert finding["algorithm_family"] == family
    assert finding["parameter_set"] == parameter
    assert finding["use_context"] == context
    assert finding["confidence"] == 0.9
    assert finding["source_ref"] == "src/signer.js:L8"


def test_javascript_prefilter_keeps_lowercase_crypto(tmp_path):
    source = tmp_path / "hash.cjs"
    source.write_text("require('crypto').createHash('sha256');", encoding="utf-8")
    assert _ripgrep_prefilter([str(source)]) == [str(source)]


def test_semgrep_redacted_output_recovers_source_and_algorithm(tmp_path):
    import json
    from subprocess import CompletedProcess
    from cryptodep.tools.semgrep_tools import run_semgrep

    source = tmp_path / "hash.js"
    source.write_text("const c = require('crypto');\nc.createHash('sha256');\n", encoding="utf-8")

    def scan(cmd, **kwargs):
        return CompletedProcess(cmd, 0, json.dumps({"results": [{
            "path": cmd[-1], "start": {"line": 2}, "end": {"line": 2},
            "extra": {"message": "Node crypto API: createHash using 'sha256'", "lines": "requires login",
                      "metadata": {"category": "crypto-javascript-api"}},
        }]}))

    with patch("cryptodep.tools.semgrep_tools._is_windows", return_value=False), \
         patch("cryptodep.tools.semgrep_tools._find_semgrep_bin", return_value=["semgrep"]), \
         patch("cryptodep.tools.semgrep_tools._ripgrep_prefilter", return_value=[str(source)]), \
         patch("cryptodep.tools.semgrep_tools.subprocess.run", side_effect=scan):
        finding = parse_semgrep_findings(run_semgrep(["rules.yaml"], [str(source)]))[0]
    assert finding["evidence"] == "c.createHash('sha256');"
    assert finding["source_ref"] == str(source) + ":L2"
    assert finding["algorithm_family"] == "SHA-256"
    assert finding["use_context"] == "hashing"


def test_javascript_builds_connected_cdg(tmp_path, monkeypatch):
    from cryptodep.agents.a4_builder import CDGBuilderAgent

    monkeypatch.chdir(tmp_path)
    config = CryptoDependConfig(neo4j_password="test", sqlite_db_path=str(tmp_path / "cdg.db"))
    source = str(tmp_path / "signer.js")
    state = {
        "config": config, "repo_path": str(tmp_path), "run_id": "javascript-test",
        "validated_findings": [{
            "algorithm_family": "RSA", "parameter_set": "RSA-2048", "source_ref": source + ":L8",
            "confidence": 0.9, "evidence": "generateKeyPairSync('rsa')",
            "use_context": "key_exchange", "detected_by": "static_rule",
        }],
        "validated_edges": [], "import_graph": {source: ["node:crypto"]},
    }
    with patch("neo4j.GraphDatabase.driver", side_effect=RuntimeError("offline")):
        result = asyncio.run(CDGBuilderAgent(config).run(state))
    doc = result["cdg_document"]
    component = next(n for n in doc.nodes if n["node_type"] == "AppComponent")
    library = next(n for n in doc.nodes if n["node_type"] == "CryptoLibrary")
    assert component["label"] == "signer"
    assert component["language"] == library["language"] == "javascript"
    assert library["label"] == "node:crypto"
    assert {e.edge_type.value for e in doc.edges} >= {"uses", "implements", "migrates_to"}
    assert result["sqlite_db_path"] == str(tmp_path / "cdg.db")


@pytest.mark.parametrize("receiver", ["crypto.subtle", "window.crypto . subtle", "globalThis.crypto.subtle"])
def test_webcrypto_without_import_has_library(tmp_path, receiver):
    source = tmp_path / "browser.js"
    source.write_text(receiver + ".digest('SHA-256', data);", encoding="utf-8")
    parsed = parse_file_ast(source, "javascript")
    assert extract_imports(parsed["tree"], parsed["source"], "javascript") == ["webcrypto"]


def test_javascript_reachability_is_not_reported_as_unreachable():
    from cryptodep.agents.a6_reachability import ReachabilityAgent

    config = CryptoDependConfig(neo4j_password="test")
    result = asyncio.run(ReachabilityAgent(config).run({
        "validated_findings": [{"source_ref": "src/signer.js:L8"}],
    }))
    assert result["reachability_map"] == {}
    assert result["reachability_mode"] == "absent"
    assert result["errors"][0]["error_type"] == "unsupported_language"


def test_mixed_language_planning_keeps_baseline_weights_for_javascript():
    from cryptodep.agents.a5_planner import MigrationPlannerAgent, _compute_priority_score
    from cryptodep.schema.cdg_models import CDGDocument, CryptoAlgorithmNode, NistQuantumVulnClass
    from unittest.mock import AsyncMock

    config = CryptoDependConfig(neo4j_password="test")
    js = CryptoAlgorithmNode(label="RSA-js", algorithm_family="RSA", source_ref="signer.js:L8",
                             quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE)
    java = js.model_copy(update={"node_id": "java-node", "source_ref": "Signer.java:L8"})
    with patch("cryptodep.agents.a5_planner._compute_priority_score", wraps=_compute_priority_score) as score, \
         patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock(return_value="Report")):
        asyncio.run(MigrationPlannerAgent(config).run({
            "cdg_document": CDGDocument(nodes=[js.model_dump(), java.model_dump()]),
            "reachability_mode": "analyzed", "reachability_map": {java.source_ref: 1.0},
        }))
    assert score.call_args_list[0].args[1] == config.priority_weights
    assert score.call_args_list[0].kwargs["reachability_score"] is None
    assert score.call_args_list[1].args[1] == config.priority_weights_with_reachability
