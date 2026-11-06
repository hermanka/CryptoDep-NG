"""Small SQLite store for dashboard settings and durable scan history."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


STAGES = ["clone", "a1_ingestion", "a2_detection", "a3_reasoning", "a4_builder", "a5_planner"]
TERMINAL = {"completed", "partial", "failed", "interrupted"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection(root: Path):
    conn = sqlite3.connect(root / "dashboard.db", timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize(root: Path):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with connection(root) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK (id=1), value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, repo_url TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, progress TEXT NOT NULL,
                model TEXT NOT NULL, endpoint TEXT NOT NULL, commit_sha TEXT,
                summary TEXT NOT NULL DEFAULT '{}', error TEXT
            );
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
                created_at TEXT NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL
            );
        """)
        conn.execute("UPDATE scans SET status='interrupted', error=?, updated_at=? WHERE status='running'",
                     ("Pemindaian terputus saat aplikasi berhenti. Mulai pemindaian baru untuk mencoba kembali.", now()))
    os.chmod(root / "dashboard.db", 0o600)


def settings(root: Path) -> dict:
    with connection(root) as conn:
        row = conn.execute("SELECT value FROM settings WHERE id=1").fetchone()
    if row:
        return json.loads(row[0])
    return {"endpoint": os.getenv("CRYPTODEP_WEB_AI_URL", ""),
            "model": os.getenv("CRYPTODEP_WEB_AI_MODEL", ""),
            "api_key": os.getenv("CRYPTODEP_WEB_AI_KEY", "")}


def save_settings(root: Path, value: dict):
    with connection(root) as conn:
        conn.execute("INSERT INTO settings VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                     (json.dumps(value),))


def public_scan(row) -> dict:
    result = dict(row)
    result["progress"] = json.loads(result["progress"])
    result["summary"] = json.loads(result["summary"])
    return result


def get_scan(root: Path, scan_id: str) -> dict | None:
    with connection(root) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return public_scan(row) if row else None


def history(root: Path) -> list[dict]:
    with connection(root) as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    return [public_scan(row) for row in rows]


def create_scan(root: Path, scan_id: str, url: str, config: dict):
    with connection(root) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM scans WHERE status='running'").fetchone():
            raise ValueError("Pemindaian lain masih berjalan. Tunggu hingga selesai.")
        progress = {stage: "pending" for stage in STAGES}
        conn.execute("""INSERT INTO scans (id, repo_url, status, created_at, updated_at, progress, model, endpoint)
                        VALUES (?, ?, 'running', ?, ?, ?, ?, ?)""",
                     (scan_id, url, now(), now(), json.dumps(progress), config["model"], config["endpoint"]))


def delete_scan(root: Path, scan_id: str) -> bool:
    with connection(root) as conn:
        if conn.execute("SELECT 1 FROM scans WHERE id=? AND status='running'", (scan_id,)).fetchone():
            raise ValueError("Pemindaian yang masih berjalan tidak dapat dihapus.")
        conn.execute("DELETE FROM questions WHERE scan_id=?", (scan_id,))
        return conn.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount > 0


def add_question(root: Path, scan_id: str, question: str, answer: dict):
    with connection(root) as conn:
        conn.execute("INSERT INTO questions (scan_id, created_at, question, answer) VALUES (?, ?, ?, ?)",
                     (scan_id, now(), question, json.dumps(answer)))


def questions(root: Path, scan_id: str) -> list[dict]:
    with connection(root) as conn:
        rows = conn.execute("SELECT created_at, question, answer FROM questions WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
    return [{"created_at": row["created_at"], "question": row["question"], **json.loads(row["answer"])} for row in rows]


def update(root: Path, scan_id: str, **values):
    allowed = {"status", "progress", "summary", "error", "commit_sha"}
    if not values.keys() <= allowed:
        raise ValueError("Unknown scan fields")
    values["updated_at"] = now()
    values = {key: json.dumps(value) if isinstance(value, dict) else value for key, value in values.items()}
    with connection(root) as conn:
        conn.execute("UPDATE scans SET " + ", ".join(key + "=?" for key in values) + " WHERE id=?",
                     (*values.values(), scan_id))


def progress(root: Path, scan_id: str, stage: str, status: str):
    scan = get_scan(root, scan_id)
    steps = scan["progress"]
    steps[stage] = status
    update(root, scan_id, progress=steps)
