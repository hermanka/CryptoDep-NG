from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from cryptodep.cli import app

runner = CliRunner()


def _write_cdg(tmp_path: pathlib.Path, name: str, nodes: list, edges: list) -> pathlib.Path:
    p = tmp_path / name
    p.write_text(json.dumps({"nodes": nodes, "edges": edges}))
    return p


_NODE_RSA = {"node_id": "n1", "node_type": "CryptoAlgorithm", "label": "RSA-2048"}
_NODE_AES = {"node_id": "n2", "node_type": "CryptoAlgorithm", "label": "AES-CBC"}
_EDGE_USES = {
    "edge_type": "uses",
    "source_label": "AuthService",
    "target_label": "javax.crypto",
}


def test_diff_no_changes(tmp_path):
    old = _write_cdg(tmp_path, "old.json", [_NODE_RSA], [_EDGE_USES])
    new = _write_cdg(tmp_path, "new.json", [_NODE_RSA], [_EDGE_USES])
    result = runner.invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 0
    assert "No changes" in result.output


def test_diff_added_node(tmp_path):
    old = _write_cdg(tmp_path, "old.json", [_NODE_RSA], [])
    new = _write_cdg(tmp_path, "new.json", [_NODE_RSA, _NODE_AES], [])
    result = runner.invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 0
    assert "Added nodes" in result.output
    assert "AES-CBC" in result.output


def test_diff_removed_edge(tmp_path):
    old = _write_cdg(tmp_path, "old.json", [], [_EDGE_USES])
    new = _write_cdg(tmp_path, "new.json", [], [])
    result = runner.invoke(app, ["diff", str(old), str(new)])
    assert result.exit_code == 0
    assert "Removed edges" in result.output
    assert "uses" in result.output


def test_export_cbom_creates_output_file(tmp_path):
    cdg_file = _write_cdg(tmp_path, "cdg.json", [_NODE_RSA, _NODE_AES], [_EDGE_USES])
    out_file = tmp_path / "cdg.cdx.json"
    result = runner.invoke(app, ["export-cbom", str(cdg_file), "--output", str(out_file)])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    cbom_data = json.loads(out_file.read_text())
    assert "components" in cbom_data


def test_export_cbom_default_output_name(tmp_path):
    cdg_file = _write_cdg(tmp_path, "cdg.json", [_NODE_RSA], [])
    result = runner.invoke(app, ["export-cbom", str(cdg_file)])
    assert result.exit_code == 0, result.output
    default_out = cdg_file.parent / "cdg.cdx.json"
    assert default_out.exists()


# ── query tests ───────────────────────────────────────────────────────────────

def test_query_prints_records(monkeypatch):
    """query should print each Neo4j record as a JSON line."""
    from unittest.mock import MagicMock

    mock_record = MagicMock()
    mock_record.data.return_value = {"n": {"label": "RSA-2048"}}

    mock_session = MagicMock()
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=False)
    mock_session.run.return_value = [mock_record]

    mock_driver = MagicMock()
    mock_driver.__enter__ = MagicMock(return_value=mock_driver)
    mock_driver.__exit__ = MagicMock(return_value=False)
    mock_driver.session.return_value = mock_session

    monkeypatch.setattr("neo4j.GraphDatabase.driver", lambda *a, **kw: mock_driver)

    result = runner.invoke(app, ["query", "MATCH (n) RETURN n LIMIT 1"])
    assert result.exit_code == 0, result.output
    output_data = json.loads(result.output.strip())
    assert output_data == {"n": {"label": "RSA-2048"}}


def test_query_handles_connection_error(monkeypatch):
    """query should exit with code 1 and print error if Neo4j is unreachable."""
    from neo4j.exceptions import ServiceUnavailable

    def _bad_driver(*args, **kwargs):
        raise ServiceUnavailable("Connection refused")

    monkeypatch.setattr("neo4j.GraphDatabase.driver", _bad_driver)

    result = runner.invoke(app, ["query", "MATCH (n) RETURN n LIMIT 1"])
    assert result.exit_code == 1
    combined = result.output + result.stderr
    assert "Neo4j" in combined or "error" in combined.lower() or "Connection" in combined


def test_query_handles_neo4j_error(monkeypatch):
    """query should exit with code 1 on any Neo4jError (e.g. CypherSyntaxError)."""
    from neo4j.exceptions import Neo4jError

    def _bad_driver(*args, **kwargs):
        raise Neo4jError("Syntax error")

    monkeypatch.setattr("neo4j.GraphDatabase.driver", _bad_driver)

    result = runner.invoke(app, ["query", "INVALID CYPHER"])
    assert result.exit_code == 1
    combined = result.output + result.stderr
    assert "Neo4j" in combined or "error" in combined.lower()
