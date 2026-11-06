"""SQLite CDG store — primary local CDG persistence.

Operations:
  get_connection(db_path)                        → sqlite3.Connection
  init_schema(conn)                              → create tables if not exist (idempotent)
  save_cdg(conn, run_id, cdg_doc, repo_path)     → upsert CDGDocument atomically
  load_latest_cdg(conn, repo_path=None)          → CDGDocument (most recent)
  load_cdg_by_run_id(conn, run_id)               → CDGDocument
  list_runs(conn)                                → list[dict] ordered by created_at DESC
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import structlog

from cryptodep.schema.cdg_models import CDGDocument

log = structlog.get_logger().bind(module="sqlite_tools")

_DDL = """
CREATE TABLE IF NOT EXISTS cdg_runs (
    run_id      TEXT PRIMARY KEY,
    repo_path   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    node_count  INTEGER,
    edge_count  INTEGER,
    cdg_json    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cdg_nodes (
    run_id                  TEXT NOT NULL,
    node_id                 TEXT NOT NULL,
    node_type               TEXT NOT NULL,
    label                   TEXT,
    algorithm_family        TEXT,
    quantum_vuln_class      TEXT,
    migration_urgency_score REAL,
    source_ref              TEXT,
    confidence              REAL,
    node_json               TEXT NOT NULL,
    PRIMARY KEY (run_id, node_id),
    FOREIGN KEY (run_id) REFERENCES cdg_runs(run_id)
);

CREATE TABLE IF NOT EXISTS cdg_edges (
    run_id      TEXT NOT NULL,
    edge_id     TEXT NOT NULL,
    source_id   TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    edge_type   TEXT NOT NULL,
    confidence  REAL,
    evidence    TEXT,
    PRIMARY KEY (run_id, edge_id),
    FOREIGN KEY (run_id) REFERENCES cdg_runs(run_id)
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open (or create) the SQLite DB at db_path. Enables WAL mode."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create tables if they do not exist. Idempotent."""
    conn.executescript(_DDL)
    conn.commit()


def save_cdg(
    conn: sqlite3.Connection,
    run_id: str,
    cdg_doc: CDGDocument,
    repo_path: str,
) -> None:
    """Write CDGDocument to all three tables atomically (single transaction)."""
    doc_dict = cdg_doc.model_dump(mode="json")
    cdg_json = json.dumps(doc_dict, default=str)
    node_count = len(doc_dict.get("nodes", []))
    edge_count = len(doc_dict.get("edges", []))
    created_at = datetime.now(timezone.utc).isoformat()

    with conn:
        conn.execute(
            """INSERT INTO cdg_runs
               (run_id, repo_path, created_at, node_count, edge_count, cdg_json)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id) DO UPDATE SET
                 repo_path=excluded.repo_path,
                 created_at=excluded.created_at,
                 node_count=excluded.node_count,
                 edge_count=excluded.edge_count,
                 cdg_json=excluded.cdg_json""",
            (run_id, repo_path, created_at, node_count, edge_count, cdg_json),
        )
        conn.execute("DELETE FROM cdg_nodes WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM cdg_edges WHERE run_id = ?", (run_id,))

        for node in doc_dict.get("nodes", []):
            conn.execute(
                """INSERT INTO cdg_nodes
                   (run_id, node_id, node_type, label, algorithm_family,
                    quantum_vuln_class, migration_urgency_score, source_ref,
                    confidence, node_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    node.get("node_id", ""),
                    node.get("node_type", ""),
                    node.get("label", ""),
                    node.get("algorithm_family"),
                    node.get("quantum_vuln_class"),
                    node.get("migration_urgency_score"),
                    node.get("source_ref"),
                    node.get("confidence"),
                    json.dumps(node, default=str),
                ),
            )

        for edge in doc_dict.get("edges", []):
            conn.execute(
                """INSERT INTO cdg_edges
                   (run_id, edge_id, source_id, target_id, edge_type,
                    confidence, evidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    edge.get("edge_id", ""),
                    edge.get("source_id", ""),
                    edge.get("target_id", ""),
                    edge.get("edge_type", ""),
                    edge.get("confidence"),
                    edge.get("evidence"),
                ),
            )

    log.info("sqlite_cdg_saved", run_id=run_id, nodes=node_count, edges=edge_count)


def load_latest_cdg(
    conn: sqlite3.Connection,
    repo_path: Optional[str] = None,
) -> CDGDocument:
    """Load the most recent CDGDocument, optionally filtered by repo_path."""
    if repo_path:
        row = conn.execute(
            "SELECT cdg_json FROM cdg_runs WHERE repo_path = ?"
            " ORDER BY created_at DESC LIMIT 1",
            (repo_path,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT cdg_json FROM cdg_runs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

    if row is None:
        suffix = f" for repo {repo_path!r}" if repo_path else ""
        raise ValueError(f"No CDG runs found{suffix}.")
    return CDGDocument.model_validate(json.loads(row[0]))


def load_cdg_by_run_id(conn: sqlite3.Connection, run_id: str) -> CDGDocument:
    """Load a specific CDGDocument by run_id. Raises ValueError if not found."""
    row = conn.execute(
        "SELECT cdg_json FROM cdg_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"No CDG run found with run_id={run_id!r}.")
    return CDGDocument.model_validate(json.loads(row[0]))


def list_runs(conn: sqlite3.Connection) -> list[dict]:
    """Return run metadata ordered by created_at DESC."""
    rows = conn.execute(
        "SELECT run_id, repo_path, created_at, node_count, edge_count"
        " FROM cdg_runs ORDER BY created_at DESC"
    ).fetchall()
    return [dict(row) for row in rows]
