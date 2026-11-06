"""Opt-in container smoke: real GitHub clone + Semgrep, local mock AI, isolated data.

Run inside the application image. Does not need a provider key or execute target code.
"""
from __future__ import annotations

import json
import argparse
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

from cryptodep.web.app import create_app
from cryptodep.web.mock_ai import mock_reply


class MockAI(BaseHTTPRequestHandler):
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        content = mock_reply(payload["messages"])
        body = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main(repo_url="https://github.com/adeyosemanputra/pygoat"):
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockAI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cryptodep-web-smoke-") as temporary:
            root = Path(temporary)
            with TestClient(create_app(root)) as client:
                config = {"endpoint": f"http://127.0.0.1:{server.server_port}/v1", "model": "integration-fixture", "api_key": ""}
                assert client.put("/api/settings", json=config).status_code == 200
                assert client.post("/api/settings/test", json=config).status_code == 200
                response = client.post("/api/scans", json={"repo_url": repo_url})
                assert response.status_code == 202, response.text
                scan_id = response.json()["id"]
                previous = None
                for _ in range(240):
                    result = client.get(f"/api/scans/{scan_id}").json()
                    active = next((name for name, status in result["progress"].items() if status == "running"), result["status"])
                    if active != previous:
                        print("Stage:", active, flush=True)
                        previous = active
                    if result["status"] != "running":
                        break
                    time.sleep(1)
                if result["status"] != "completed":
                    log = root / scan_id / "worker.log"
                    print(log.read_text(encoding="utf-8")[-5000:] if log.exists() else "No worker log", flush=True)
                assert result["status"] == "completed", result
                assert all(status == "completed" for status in result["progress"].values())
                graph = client.get(f"/api/scans/{scan_id}/graph").json()
                print("Result:", json.dumps(result["summary"]), flush=True)
                if not graph["nodes"] or not graph["edges"]:
                    print((root / scan_id / "worker.log").read_text(encoding="utf-8")[-8000:], flush=True)
                assert graph["nodes"] and graph["edges"]
                if repo_url == "https://github.com/appsecco/dvja":
                    md5 = [node for node in graph["nodes"] if node.get("algorithm_family") == "MD5"]
                    assert md5 and md5[0]["metadata"]["risk_assessment"]["level"] == "orange"
                    assert len(md5[0]["metadata"]["findings"]) == 2
                    assert all("md5DigestAsHex" in f["evidence"] for f in md5[0]["metadata"]["findings"])
                assert graph["target_repo"]["commit"]
                assert client.get(f"/api/scans/{scan_id}/download/report").status_code == 200
                assert client.get(f"/api/scans/{scan_id}/download/cbom").status_code == 200
            with TestClient(create_app(root)) as client:
                assert client.get("/api/scans").json()[0]["id"] == scan_id
                assert client.get(f"/api/scans/{scan_id}/graph").json()["nodes"] == graph["nodes"]
            print("PASS: clone, stage progress, real Semgrep, compatible AI, graph, downloads, persistent history", flush=True)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="https://github.com/adeyosemanputra/pygoat")
    main(parser.parse_args().repo)
