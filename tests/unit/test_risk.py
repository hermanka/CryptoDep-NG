import copy
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from cryptodep.web import store
from cryptodep.web.app import create_app
from cryptodep.web.risk import annotate_risks, assess_node


def algorithm(family, quantum="quantum_safe_symmetric", **values):
    return {"node_type": "CryptoAlgorithm", "algorithm_family": family, "quantum_vuln_class": quantum, **values}


@pytest.mark.parametrize("family", ["MD5", "SHA-1", "SHA1"])
def test_weak_hashes_are_classical_warnings_not_pqc_migrations(family):
    risk = assess_node(algorithm(family))
    assert risk["level"] == "orange"
    assert risk["pqc_status"] == "not_flagged"
    assert risk["classical_warnings"][0]["code"] == "weak_hash"
    assert "password" in risk["classical_warnings"][0]["action"]
    assert "collision" in risk["classical_warnings"][0]["reason"]


def test_aes_ecb_warns_but_aes_gcm_does_not():
    assert assess_node(algorithm("AES", parameter_set="AES/ECB/PKCS5Padding"))["level"] == "orange"
    assert assess_node(algorithm("AES", parameter_set="AES-256-GCM"))["level"] == "gray"
    assert not assess_node(algorithm("HMAC", parameter_set="HMAC-MD5"))["classical_warnings"]


def test_parameter_review_and_unknown_are_distinct():
    assert assess_node(algorithm("AES", "grover_weakened"))["pqc_status"] == "parameter_review"
    assert assess_node(algorithm("AES", "grover_weakened"))["level"] == "orange"
    assert assess_node(algorithm("CUSTOM", "unknown"))["level"] == "unknown"
    assert assess_node({"node_type": "AppComponent"})["level"] == "gray"


def test_red_takes_precedence_without_hiding_classical_warnings():
    risk = assess_node(algorithm("MD5", "quantum_vulnerable"))
    assert risk["level"] == "red"
    assert risk["classical_warnings"]


def test_annotation_preserves_core_scores_and_is_idempotent():
    node = algorithm("RSA", "quantum_vulnerable", migration_urgency_score=90, confidence=.9)
    document = {"nodes": [node, algorithm("MD5")], "edges": [], "migration_plan": {"priority_queue": ["original"]}}
    original = copy.deepcopy(document)
    annotate_risks(document)
    assert document["risk_summary"]["red"] == document["risk_summary"]["orange"] == 1
    assert document["nodes"][0]["migration_urgency_score"] == original["nodes"][0]["migration_urgency_score"]
    assert document["migration_plan"] == original["migration_plan"]
    assert annotate_risks(copy.deepcopy(document)) == document


def test_old_history_and_download_gain_warnings_without_rescan(tmp_path):
    scan_id = str(uuid.uuid4())
    with TestClient(create_app(tmp_path)) as client:
        store.create_scan(tmp_path, scan_id, "https://github.com/a/b", {"model": "m", "endpoint": "http://localhost/v1"})
        folder = tmp_path / scan_id
        folder.mkdir()
        old = {"nodes": [algorithm("MD5")], "edges": []}
        (folder / "result.json").write_text(json.dumps(old))
        store.update(tmp_path, scan_id, status="completed")
        for route in ("graph", "download/cdg"):
            result = client.get(f"/api/scans/{scan_id}/{route}")
            assert result.status_code == 200
            assert result.json()["nodes"][0]["metadata"]["risk_assessment"]["level"] == "orange"
        assert json.loads((folder / "result.json").read_text()) == old
