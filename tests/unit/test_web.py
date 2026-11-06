"""Dashboard API contracts, persistence, and isolated pipeline execution."""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from cryptodep.web import store
from cryptodep.web.app import ai_config, create_app, repository_url
from cryptodep.tools.llm_tools import LLMEndpointError, call_llm


@pytest.fixture
def dashboard(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        yield client, tmp_path


@pytest.mark.parametrize("url", [
    "http://github.com/owner/repo", "https://github.com.evil.test/owner/repo", "file:///etc/passwd",
    "https://user:password@github.com/owner/repo", "https://github.com/owner/repo?token=secret",
    "https://github.com/owner/repo/tree/main", "https://github.com/owner/..", "https://127.0.0.1/owner/repo",
])
def test_reject_unsafe_repository_urls(url):
    with pytest.raises(ValueError):
        repository_url(url)


def test_canonical_repository_url():
    assert repository_url(" https://github.com/owner/repo.git/ ") == "https://github.com/owner/repo"


def test_settings_preserve_key_without_returning_it(dashboard):
    client, root = dashboard
    config = {"endpoint": "http://localhost:11434/v1", "model": "test-model", "api_key": "private-key"}
    response = client.put("/api/settings", json=config)
    assert response.status_code == 200
    assert response.json()["has_key"] is True
    assert "private-key" not in response.text
    assert "private-key" not in client.get("/api/settings").text
    config.pop("api_key")
    client.put("/api/settings", json=config)
    assert store.settings(root)["api_key"] == "private-key"
    client.put("/api/settings", json={**config, "api_key": ""})
    assert store.settings(root)["api_key"] == ""


def test_secret_is_not_echoed_in_validation_error(dashboard):
    client, _ = dashboard
    secret = "sensitive-value\ninvalid-header"
    response = client.put("/api/settings", json={"endpoint": "http://localhost/v1", "model": "m", "api_key": secret})
    assert response.status_code == 422
    assert "sensitive-value" not in response.text


def test_cross_origin_mutation_and_bad_host_are_rejected(dashboard):
    client, _ = dashboard
    assert client.post("/api/scans", json={"repo_url": "https://github.com/a/b"}, headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.get("/api/settings", headers={"Host": "evil.test"}).status_code == 400


def test_start_requires_settings_and_prevents_concurrent_scans(dashboard):
    client, root = dashboard
    assert client.post("/api/scans", json={"repo_url": "https://github.com/a/b"}).status_code == 422
    client.put("/api/settings", json={"endpoint": "http://localhost/v1", "model": "model-a", "api_key": "secret-a"})
    with patch("cryptodep.web.app.launch_scan", return_value=None) as launch:
        response = client.post("/api/scans", json={"repo_url": "https://github.com/a/b"})
        assert response.status_code == 202
        assert "secret-a" not in response.text
        client.put("/api/settings", json={"endpoint": "http://localhost/v1", "model": "model-b", "api_key": "secret-b"})
        assert launch.call_args.args[2]["api_key"] == "secret-a"
        assert launch.call_args.args[2]["model"] == "model-a"
        assert client.post("/api/scans", json={"repo_url": "https://github.com/c/d"}).status_code == 409
        assert "secret-a" not in client.get("/api/scans").text


def test_history_graph_and_files_survive_restart(tmp_path):
    scan_id = str(uuid.uuid4())
    with TestClient(create_app(tmp_path)) as client:
        store.create_scan(tmp_path, scan_id, "https://github.com/a/b", {"model": "m", "endpoint": "http://localhost/v1"})
        folder = tmp_path / scan_id
        folder.mkdir()
        (folder / "result.json").write_text(json.dumps({"nodes": [{"node_id": "test"}], "edges": []}))
        store.update(tmp_path, scan_id, status="completed", summary={"nodes": 1, "edges": 0})
    with TestClient(create_app(tmp_path)) as client:
        assert client.get("/api/scans").json()[0]["summary"]["nodes"] == 1
        assert client.get(f"/api/scans/{scan_id}/graph").json()["nodes"][0]["node_id"] == "test"
        assert client.get(f"/api/scans/{scan_id}/download/cdg").status_code == 200
        assert client.get(f"/api/scans/{scan_id}/download/worker.log").status_code == 404
        assert client.get("/api/scans/not-a-uuid/graph").status_code == 404


def test_delete_scan_removes_history_and_files_but_not_running(dashboard):
    client, root = dashboard
    done, running = str(uuid.uuid4()), str(uuid.uuid4())
    store.create_scan(root, done, "https://github.com/a/b", {"model": "m", "endpoint": "http://localhost/v1"})
    store.update(root, done, status="completed")
    (root / done).mkdir()
    (root / done / "result.json").write_text("{}")
    store.create_scan(root, running, "https://github.com/c/d", {"model": "m", "endpoint": "http://localhost/v1"})
    assert client.delete(f"/api/scans/{running}").status_code == 409
    assert client.delete(f"/api/scans/{done}").status_code == 204
    assert not (root / done).exists()
    assert [scan["id"] for scan in client.get("/api/scans").json()] == [running]
    assert client.delete(f"/api/scans/{done}").status_code == 404
    assert client.delete("/api/scans/not-a-uuid").status_code == 404


def test_ask_graph_validates_llm_ids_and_requires_graph(dashboard):
    from cryptodep.web.mock_ai import mock_reply
    from cryptodep.web.ask import build_messages

    client, root = dashboard
    client.put("/api/settings", json={"endpoint": "http://localhost/v1", "model": "m"})
    scan_id = str(uuid.uuid4())
    store.create_scan(root, scan_id, "https://github.com/a/b", {"model": "m", "endpoint": "http://localhost/v1"})
    question = {"question": "Komponen apa yang memakai RSA?"}
    assert client.post(f"/api/scans/{scan_id}/ask", json=question).status_code == 409
    store.update(root, scan_id, status="completed")
    (root / scan_id).mkdir()
    document = {"nodes": [{"node_id": "rsa", "node_type": "CryptoAlgorithm", "label": "RSA", "quantum_vuln_class": "quantum_vulnerable"},
                          {"node_id": "auth", "node_type": "AppComponent", "label": "Auth"}],
                "edges": [{"source_id": "auth", "target_id": "rsa", "edge_type": "uses"}]}
    (root / scan_id / "result.json").write_text(json.dumps(document))
    reply = json.dumps({"answer": "Auth memakai RSA.", "node_ids": ["auth", "invented"], "path": ["auth", "rsa", "ghost"]})
    with patch("cryptodep.web.app.call_llm", new=AsyncMock(return_value=reply)):
        result = client.post(f"/api/scans/{scan_id}/ask", json=question).json()
    assert result == {"answer": "Auth memakai RSA.", "node_ids": ["auth", "rsa"], "path": ["auth", "rsa"]}
    saved = client.get(f"/api/scans/{scan_id}/questions").json()
    assert [(q["question"], q["answer"], q["path"]) for q in saved] == [(question["question"], "Auth memakai RSA.", ["auth", "rsa"])]
    with patch("cryptodep.web.app.call_llm", new=AsyncMock(return_value='{"node_ids": []}')):
        assert client.post(f"/api/scans/{scan_id}/ask", json=question).status_code == 502
    assert client.post(f"/api/scans/{scan_id}/ask", json={"question": "x" * 501}).status_code == 422
    from cryptodep.web.risk import annotate_risks
    mock = json.loads(mock_reply(build_messages(annotate_risks(document), "?")))
    assert mock["node_ids"] == ["rsa"]
    assert len(client.get(f"/api/scans/{scan_id}/questions").json()) == 1  # failed answers are not saved
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert store.questions(root, scan_id) == []


def test_ask_context_carries_classical_fix_for_orange_nodes():
    from cryptodep.web.ask import build_messages
    from cryptodep.web.risk import annotate_risks

    document = annotate_risks({"nodes": [{"node_id": "sha1", "node_type": "CryptoAlgorithm", "label": "SHA-1",
                                          "algorithm_family": "SHA1", "quantum_vuln_class": "quantum_safe_symmetric"}], "edges": []})
    content = build_messages(document, "Pengganti SHA-1?")[0]["content"]
    graph = json.loads(content.split("Graph CDG:\n", 1)[1].split("\n\nPertanyaan:", 1)[0])
    node = graph["nodes"][0]
    assert node["risk"] == "orange" and "SHA-256" in node["warnings"][0]["action"] and "pqc_suggestions" not in node


def test_scan_log_is_shortened_and_redacted(dashboard):
    client, root = dashboard
    client.put("/api/settings", json={"endpoint": "http://localhost/v1", "model": "m", "api_key": "sk-secret-123"})
    scan_id = str(uuid.uuid4())
    store.create_scan(root, scan_id, "https://github.com/a/b", {"model": "m", "endpoint": "http://localhost/v1"})
    folder = root / scan_id
    folder.mkdir()
    (folder / "clone.log").write_text(f"Cloning into '{folder / 'repo'}'...\n")
    (folder / "worker.log").write_text(f"[info     ] a2 source={folder / 'repo'}/src/A.java:5 key=sk-secret-123\n"
                                       "\n[warning  ] call failed Authorization: Bearer abc.def\n")
    lines = client.get(f"/api/scans/{scan_id}/log").json()["lines"]
    assert lines[0] == "Cloning into 'repo'..."
    assert lines[1] == "[info ] a2 source=src/A.java:5 key=[disembunyikan]"
    assert "abc.def" not in lines[2] and len(lines) == 3
    assert client.get("/api/scans/not-a-uuid/log").status_code == 404


def test_restart_marks_active_scan_interrupted(tmp_path):
    scan_id = str(uuid.uuid4())
    store.initialize(tmp_path)
    store.create_scan(tmp_path, scan_id, "https://github.com/a/b", {"model": "m", "endpoint": "http://localhost/v1"})
    with TestClient(create_app(tmp_path)) as client:
        assert client.get(f"/api/scans/{scan_id}").json()["status"] == "interrupted"


def test_settings_connection_test(dashboard):
    client, _ = dashboard
    with patch("cryptodep.web.app.call_llm", new=AsyncMock(return_value='[{"ok":true}]')):
        response = client.post("/api/settings/test", json={"endpoint": "http://localhost/v1", "model": "m"})
    assert response.status_code == 200
    with patch("cryptodep.web.app.call_llm", new=AsyncMock(return_value='{}')):
        assert client.post("/api/settings/test", json={"endpoint": "http://localhost/v1", "model": "m"}).status_code == 400


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 503])
def test_provider_errors_are_distinct_and_redacted(dashboard, status):
    client, _ = dashboard
    original = httpx.AsyncClient
    def handler(request):
        return httpx.Response(status, json={"error": {"message": "private-provider-body"}})
    with patch("httpx.AsyncClient", side_effect=lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)):
        result = client.post("/api/settings/test", json={"endpoint": "http://localhost/v1", "model": "m", "api_key": "private-key"})
    assert result.status_code == 400
    assert f"HTTP {status}" in result.json()["detail"]
    assert "private-provider-body" not in result.text
    assert "private-key" not in result.text


def test_connection_probe_has_reasoning_token_budget(dashboard):
    client, _ = dashboard
    with patch("cryptodep.web.app.call_llm", new=AsyncMock(return_value='[{"ok":true}]')) as call:
        assert client.post("/api/settings/test", json={"endpoint": "http://localhost/v1", "model": "m"}).status_code == 200
    assert call.call_args.args[0].llm_max_tokens == 4096


@pytest.mark.parametrize("endpoint, model", [
    ("https://generativelanguage.googleapis.com/v1beta", "gemini-flash-latest"),
    ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-flash-latest:generateContent"),
])
def test_gemini_native_configuration_gives_actionable_validation(dashboard, endpoint, model):
    client, _ = dashboard
    response = client.post("/api/settings/test", json={"endpoint": endpoint, "model": model})
    assert response.status_code == 422
    assert "gemini" in response.json()["detail"].lower()


def test_empty_length_limited_response_has_specific_error():
    original = httpx.AsyncClient
    def handler(request):
        return httpx.Response(200, json={"choices": [{"finish_reason": "length", "message": {"content": None}}]})
    with patch("httpx.AsyncClient", side_effect=lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)):
        with pytest.raises(LLMEndpointError, match="batas token"):
            asyncio.run(call_llm(ai_config({"endpoint": "http://localhost/v1", "model": "m", "api_key": ""}), []))


def test_openai_compatible_request_and_safe_errors():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "[]"}}]})

    config = ai_config({"endpoint": "http://model.test/v1", "model": "test", "api_key": "private"})
    original = httpx.AsyncClient
    with patch("httpx.AsyncClient", side_effect=lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)):
        assert asyncio.run(call_llm(config, [{"role": "user", "content": "test"}])) == "[]"
    assert str(requests[0].url) == "http://model.test/v1/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer private"
    assert json.loads(requests[0].content)["model"] == "test"

    def failure(request):
        return httpx.Response(401, json={"error": "private-response-content"})

    with patch("httpx.AsyncClient", side_effect=lambda **kwargs: original(transport=httpx.MockTransport(failure), **kwargs)):
        with pytest.raises(RuntimeError) as error:
            asyncio.run(call_llm(config, []))
    assert "private-response-content" not in str(error.value)
    assert "private" not in str(config)


def test_worker_runs_pipeline_and_persists_review_details(tmp_path, monkeypatch):
    from cryptodep.web.worker import run_scan

    store.initialize(tmp_path)
    scan_id = str(uuid.uuid4())
    config = {"endpoint": "http://model.test/v1", "model": "test", "api_key": "secret"}
    store.create_scan(tmp_path, scan_id, "https://github.com/a/b", config)
    (tmp_path / scan_id).mkdir()

    def clone(url, repo, log):
        repo.mkdir()
        (repo / "signer.js").write_text("const crypto = require('node:crypto');\ncrypto.generateKeyPairSync('rsa', {modulusLength:2048});\n")
        return "a" * 40

    def scan(rules, files):
        return [{"path": files[0], "start": {"line": 2}, "extra": {
            "message": "Node crypto API: generateKeyPairSync using 'rsa'",
            "lines": "crypto.generateKeyPairSync('rsa', {modulusLength:2048});",
            "metadata": {"category": "crypto-javascript-api"},
        }}]

    monkeypatch.chdir(tmp_path)
    with patch("cryptodep.web.worker.clone_repository", side_effect=clone), \
         patch("cryptodep.agents.a2_detection.run_semgrep", side_effect=scan), \
         patch("cryptodep.agents.a3_reasoning.call_llm", new=AsyncMock(return_value="[]")), \
         patch("cryptodep.agents.a5_planner.call_llm", new=AsyncMock(return_value="Laporan")):
        run_scan(tmp_path, scan_id, config)
    result = store.get_scan(tmp_path, scan_id)
    assert result["status"] == "completed", result
    assert all(status == "completed" for status in result["progress"].values())
    document = json.loads((tmp_path / scan_id / "result.json").read_text())
    algorithm = next(node for node in document["nodes"] if node["node_type"] == "CryptoAlgorithm")
    assert algorithm["metadata"]["findings"][0]["file"] == "signer.js"
    assert "generateKeyPairSync" in algorithm["metadata"]["findings"][0]["evidence"]
    assert algorithm["metadata"]["migration_suggestions"]
    assert {edge["edge_type"] for edge in document["edges"]} >= {"uses", "implements", "migrates_to"}
    assert document["migration_plan"]["priority_queue"]
    assert (tmp_path / scan_id / "cbom.json").is_file()
    assert "secret" not in json.dumps(document)


def test_failed_clone_does_not_produce_clean_graph(dashboard):
    from cryptodep.web.worker import run_scan

    _, root = dashboard
    scan_id = str(uuid.uuid4())
    config = {"endpoint": "http://localhost/v1", "model": "m", "api_key": ""}
    store.create_scan(root, scan_id, "https://github.com/a/b", config)
    (root / scan_id).mkdir()
    with patch("cryptodep.web.worker.clone_repository", side_effect=RuntimeError("Clone gagal.")):
        run_scan(root, scan_id, config)
    result = store.get_scan(root, scan_id)
    assert result["status"] == "failed"
    assert result["progress"]["clone"] == "failed"
    assert not (root / scan_id / "result.json").exists()


def test_dashboard_and_assets_are_served(dashboard):
    client, _ = dashboard
    assert client.get("/").status_code == 200
    assert client.get("/vendor/cytoscape.min.js").status_code == 200
    assert client.get("/vendor/InterVariable.woff2").status_code == 200
