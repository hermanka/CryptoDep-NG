"""Single-user, local dashboard API. Run one Uvicorn worker."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from cryptodep.config import CryptoDependConfig
from cryptodep.tools.llm_tools import LLMEndpointError, call_llm
from cryptodep.web import ask as ask_graph
from cryptodep.web import store
from cryptodep.web.risk import annotate_risks


STATIC = Path(__file__).parent / "static"


def repository_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if (parts.scheme != "https" or parts.netloc.lower() != "github.com" or parts.query or parts.fragment
            or not re.fullmatch(r"/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/?", parts.path)):
        raise ValueError("Gunakan URL repository GitHub publik: https://github.com/owner/repo")
    path = parts.path.rstrip("/").removesuffix(".git")
    if path.rsplit("/", 1)[-1] in ("", ".", ".."):
        raise ValueError("Nama repository tidak valid.")
    return "https://github.com" + path


class ScanInput(BaseModel):
    repo_url: str = Field(max_length=2048)

    @field_validator("repo_url")
    @classmethod
    def validate_repo(cls, value):
        return repository_url(value)


class AskInput(BaseModel):
    question: str = Field(min_length=3, max_length=500)


class AISettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint: str = Field(max_length=2048)
    model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr | None = None

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value):
        parts = urlsplit(value.strip())
        if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or any(ord(c) < 32 for c in value)):
            raise ValueError("Endpoint harus URL HTTP(S), tanpa kredensial, query, atau fragment.")
        if parts.hostname == "generativelanguage.googleapis.com" and parts.path.rstrip("/") not in (
            "/v1beta/openai", "/v1beta/openai/chat/completions",
        ):
            raise ValueError("Untuk Gemini gunakan endpoint https://generativelanguage.googleapis.com/v1beta/openai")
        return value.strip().rstrip("/")

    @field_validator("model")
    @classmethod
    def validate_model(cls, value):
        if not value.strip():
            raise ValueError("Nama model wajib diisi.")
        if value.strip().endswith(":generateContent"):
            raise ValueError("Isi nama model tanpa :generateContent, misalnya gemini-flash-latest.")
        return value.strip()

    @field_validator("api_key")
    @classmethod
    def validate_key(cls, value):
        if value and (len(value.get_secret_value()) > 4096 or any(ord(c) < 32 for c in value.get_secret_value())):
            raise ValueError("API key tidak valid.")
        return value


def clean_log_line(line: str, folder: Path, secret: str) -> str:
    """Shorten scan paths and hide credentials before a log line reaches the browser."""
    line = line.replace(f"{folder / 'repo'}/", "").replace(str(folder / "repo"), "repo").replace(str(folder), "…")
    line = re.sub(r"/tmp/tmp\w+/\d{4}_", "", line)
    line = re.sub(r"(?i)(bearer\s+|api[_-]?key[=:]\s*)\S+", r"\1[disembunyikan]", line)
    if secret:
        line = line.replace(secret, "[disembunyikan]")
    return re.sub(r" {2,}", " ", line)[:500]


def merged_settings(root: Path, data: AISettings):
    current = store.settings(root)
    return {"endpoint": data.endpoint, "model": data.model,
            "api_key": current["api_key"] if data.api_key is None else data.api_key.get_secret_value()}


def ai_config(value: dict) -> CryptoDependConfig:
    return CryptoDependConfig(llm_provider="openai_compatible", llm_base_url=value["endpoint"],
                             llm_model=value["model"], llm_api_key=value["api_key"],
                             neo4j_password="", enable_neo4j=False, report_language="id")


def launch_scan(root: Path, scan_id: str, config: dict):
    directory = root / scan_id
    directory.mkdir(mode=0o700)
    env = dict(os.environ, CRYPTODEP_WEB_DATA_DIR=str(root), PYTHONUNBUFFERED="1", CRYPTODEP_DEBUG="0")
    with (directory / "worker.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([sys.executable, "-m", "cryptodep.web.worker", scan_id],
                                   stdin=subprocess.PIPE, stdout=log, stderr=log, env=env,
                                   start_new_session=os.name != "nt")
    try:
        process.stdin.write(json.dumps(config).encode("utf-8"))
        process.stdin.close()
    except (OSError, BrokenPipeError):
        process.terminate()
        process.wait(timeout=10)
        raise RuntimeError("Proses pemindaian tidak dapat dimulai.") from None

    def monitor():
        try:
            process.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            stop_scan(process)
        scan = store.get_scan(root, scan_id)
        if scan and scan["status"] == "running":
            steps = scan["progress"]
            steps = {stage: "failed" if status == "running" else status for stage, status in steps.items()}
            store.update(root, scan_id, status="failed", progress=steps,
                         error="Proses pemindaian berhenti atau melewati batas waktu 30 menit.")

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    return process, monitor_thread


def stop_scan(process):
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()


def create_app(data_dir: Path | None = None) -> FastAPI:
    root = (data_dir or Path(os.getenv("CRYPTODEP_WEB_DATA_DIR", "web_data"))).resolve()

    @asynccontextmanager
    async def lifespan(app):
        store.initialize(root)
        yield
        for running in app.state.processes.values():
            if running is not None:
                process, monitor_thread = running
                stop_scan(process)
                monitor_thread.join(timeout=20)

    app = FastAPI(title="CryptoDep", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.data_dir = root
    app.state.processes = {}
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        return JSONResponse({"detail": " ".join(error["msg"] for error in exc.errors())}, status_code=422)

    @app.middleware("http")
    async def same_origin(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD", "OPTIONS") and origin:
            if origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Origin tidak diizinkan."}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Permintaan lintas situs tidak diizinkan."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/settings")
    def get_settings():
        value = store.settings(root)
        return {"endpoint": value["endpoint"], "model": value["model"], "has_key": bool(value["api_key"])}

    @app.put("/api/settings")
    def put_settings(data: AISettings):
        store.save_settings(root, merged_settings(root, data))
        return get_settings()

    @app.post("/api/settings/test")
    async def test_settings(data: AISettings):
        config = ai_config(merged_settings(root, data))
        try:
            response = await call_llm(config, [{"role": "user", "content": 'Return exactly this JSON array: [{"ok":true}]'}])
            if json.loads(response) != [{"ok": True}]:
                raise ValueError("Unexpected JSON")
        except LLMEndpointError as exc:
            raise HTTPException(400, str(exc)) from None
        except (RuntimeError, ValueError):
            raise HTTPException(400, "Endpoint belum memberikan JSON yang sesuai untuk agent. Periksa dukungan respons JSON dan nama model.") from None
        return {"ok": True, "message": "Koneksi dan respons JSON berhasil diverifikasi."}

    @app.get("/api/scans")
    def scans():
        return store.history(root)

    @app.post("/api/scans", status_code=202)
    def start_scan(data: ScanInput):
        config = store.settings(root)
        if not config["endpoint"] or not config["model"]:
            raise HTTPException(422, "Isi endpoint dan nama model di Pengaturan terlebih dahulu.")
        scan_id = str(uuid.uuid4())
        try:
            store.create_scan(root, scan_id, data.repo_url, config)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        try:
            app.state.processes[scan_id] = launch_scan(root, scan_id, config)
        except (OSError, RuntimeError):
            store.update(root, scan_id, status="failed", error="Proses pemindaian tidak dapat dimulai.")
            raise HTTPException(500, "Proses pemindaian tidak dapat dimulai.") from None
        return store.get_scan(root, scan_id)

    def scan_or_404(scan_id: str):
        try:
            if str(uuid.UUID(scan_id)) != scan_id:
                raise ValueError()
        except ValueError:
            raise HTTPException(404, "Pemindaian tidak ditemukan.") from None
        scan = store.get_scan(root, scan_id)
        if scan is None:
            raise HTTPException(404, "Pemindaian tidak ditemukan.")
        return scan

    @app.get("/api/scans/{scan_id}")
    def scan_status(scan_id: str):
        return scan_or_404(scan_id)

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: str):
        scan_or_404(scan_id)
        try:
            store.delete_scan(root, scan_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        app.state.processes.pop(scan_id, None)
        # scan_id is a validated UUID, so this path stays inside root.
        shutil.rmtree(root / scan_id, ignore_errors=True)

    @app.get("/api/scans/{scan_id}/graph")
    def graph(scan_id: str):
        scan = scan_or_404(scan_id)
        path = root / scan_id / "result.json"
        if scan["status"] not in ("completed", "partial") or not path.is_file():
            raise HTTPException(409, "Graph belum tersedia untuk pemindaian ini.")
        return annotate_risks(json.loads(path.read_text(encoding="utf-8")))

    @app.post("/api/scans/{scan_id}/ask")
    async def ask(scan_id: str, data: AskInput):
        document = graph(scan_id)
        settings = store.settings(root)
        if not settings["endpoint"] or not settings["model"]:
            raise HTTPException(422, "Isi endpoint dan nama model di Pengaturan terlebih dahulu.")
        try:
            raw = await call_llm(ai_config(settings), ask_graph.build_messages(document, data.question),
                                 system_prompt=ask_graph.SYSTEM_PROMPT)
            result = ask_graph.parse_answer(raw, document)
        except LLMEndpointError as exc:
            raise HTTPException(400, str(exc)) from None
        except (RuntimeError, ValueError):
            raise HTTPException(502, "Model AI tidak memberikan jawaban yang dapat dibaca. Coba ulangi atau ganti pertanyaan.") from None
        store.add_question(root, scan_id, data.question, result)
        return result

    @app.get("/api/scans/{scan_id}/log")
    def scan_log(scan_id: str):
        scan_or_404(scan_id)
        folder = root / scan_id
        lines = []
        for name in ("clone.log", "worker.log"):
            if (folder / name).is_file():
                # shortcut: rereads the whole file per poll; fine for scan logs of a few thousand lines.
                lines += (folder / name).read_text(encoding="utf-8", errors="replace").splitlines()
        secret = store.settings(root)["api_key"]
        # "now" uses the same local-time format as worker log stamps, so the browser can measure silence without a TZ guess.
        return {"lines": [clean_log_line(line, folder, secret) for line in lines[-300:] if line.strip()],
                "now": time.strftime("%Y-%m-%d %H:%M:%S")}

    @app.get("/api/scans/{scan_id}/questions")
    def scan_questions(scan_id: str):
        scan_or_404(scan_id)
        return store.questions(root, scan_id)

    @app.get("/api/scans/{scan_id}/download/{kind}")
    def download(scan_id: str, kind: str):
        scan_or_404(scan_id)
        names = {"cdg": "result.json", "cbom": "cbom.json", "report": "report.md"}
        if kind not in names:
            raise HTTPException(404, "Berkas tidak ditemukan.")
        path = root / scan_id / names[kind]
        if not path.is_file():
            raise HTTPException(404, "Berkas belum tersedia.")
        if kind == "cdg":
            return JSONResponse(annotate_risks(json.loads(path.read_text(encoding="utf-8"))),
                                headers={"Content-Disposition": f'attachment; filename="cryptodep-{scan_id[:8]}-result.json"'})
        return FileResponse(path, filename=f"cryptodep-{scan_id[:8]}-{names[kind]}")

    app.mount("/", StaticFiles(directory=STATIC, html=True), name="dashboard")
    return app


app = create_app()
