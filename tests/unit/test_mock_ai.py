from fastapi.testclient import TestClient

from cryptodep.web.mock_ai import MODEL, app


def test_mock_models_and_probe():
    with TestClient(app) as client:
        assert client.get("/health").json()["mock"] is True
        assert client.get("/v1/models").json()["data"][0]["id"] == MODEL
        response = client.post("/v1/chat/completions", json={
            "model": MODEL, "messages": [{"role": "user", "content": 'Return exactly this JSON array: [{"ok":true}]'}],
            "max_tokens": 4096, "temperature": 0,
        })
        assert response.status_code == 200
        assert response.json()["choices"][0]["message"]["content"] == '[{"ok":true}]'


def test_mock_is_explicit_and_does_not_invent_findings():
    with TestClient(app) as client:
        for prompt in ("Analyze source code", "Generate a PQC migration report"):
            response = client.post("/v1/chat/completions", json={"model": MODEL, "messages": [{"role": "user", "content": prompt}]})
            content = response.json()["choices"][0]["message"]["content"]
            if "report" in prompt:
                assert "mock" in content.lower()
            else:
                assert content == "[]"


def test_mock_rejects_unsupported_model_stream_and_invalid_body():
    with TestClient(app) as client:
        payload = {"model": MODEL, "messages": [{"role": "user", "content": "test"}]}
        assert client.post("/v1/chat/completions", json={**payload, "model": "not-a-model"}).status_code == 404
        assert client.post("/v1/chat/completions", json={**payload, "stream": True}).status_code == 400
        assert client.post("/v1/chat/completions", json={"model": MODEL, "messages": []}).status_code == 422
