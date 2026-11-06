"""Unit tests for cryptodep/preflight.py — preflight dependency checks."""
from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock, patch


def _make_config(**kwargs):
    from cryptodep.config import CryptoDependConfig
    defaults = dict(
        neo4j_uri="bolt://localhost:7687",
        neo4j_password="test",
        llm_provider="anthropic",
    )
    defaults.update(kwargs)
    return CryptoDependConfig(**defaults)


# ── Neo4j checks ──────────────────────────────────────────────────────────


def test_neo4j_check_passes_when_connected():
    from cryptodep.preflight import check_neo4j

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.return_value = None

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        # Should not raise
        check_neo4j(_make_config())


def test_neo4j_check_aborts_when_service_unavailable(capsys):
    from cryptodep.preflight import check_neo4j
    from neo4j.exceptions import ServiceUnavailable

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = ServiceUnavailable("refused")

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with pytest.raises(SystemExit) as exc:
            check_neo4j(_make_config())
    assert exc.value.code == 1


def test_neo4j_check_aborts_when_auth_error(capsys):
    from cryptodep.preflight import check_neo4j
    from neo4j.exceptions import AuthError

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = AuthError("Unauthorized")

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with pytest.raises(SystemExit) as exc:
            check_neo4j(_make_config())
    assert exc.value.code == 1


def test_neo4j_check_error_includes_suggestion(capsys):
    from cryptodep.preflight import check_neo4j
    from neo4j.exceptions import ServiceUnavailable

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = ServiceUnavailable("refused")

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with pytest.raises(SystemExit):
            check_neo4j(_make_config())

    captured = capsys.readouterr()
    assert "docker" in captured.out.lower() or "docker" in captured.err.lower()


# ── LLM checks ────────────────────────────────────────────────────────────


def test_llm_check_passes_when_anthropic_key_set():
    from cryptodep.preflight import check_llm

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
        check_llm(_make_config(llm_provider="anthropic"))


def test_llm_check_aborts_when_anthropic_key_missing():
    from cryptodep.preflight import check_llm

    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            check_llm(_make_config(llm_provider="anthropic"))
    assert exc.value.code == 1


def test_llm_check_passes_when_openrouter_key_set():
    from cryptodep.preflight import check_llm

    with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-test"}):
        check_llm(_make_config(llm_provider="openrouter"))


def test_llm_check_aborts_when_openrouter_key_missing():
    from cryptodep.preflight import check_llm

    env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            check_llm(_make_config(llm_provider="openrouter"))
    assert exc.value.code == 1


def test_llm_check_passes_when_ollama_reachable():
    from cryptodep.preflight import check_llm
    import httpx

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch("httpx.get", return_value=mock_response):
        check_llm(_make_config(llm_provider="ollama"))


def test_llm_check_aborts_when_ollama_unreachable():
    from cryptodep.preflight import check_llm
    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
        with pytest.raises(SystemExit) as exc:
            check_llm(_make_config(llm_provider="ollama"))
    assert exc.value.code == 1


def test_llm_check_error_includes_suggestion(capsys):
    from cryptodep.preflight import check_llm

    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit):
            check_llm(_make_config(llm_provider="anthropic"))

    captured = capsys.readouterr()
    assert "ANTHROPIC_API_KEY" in captured.out or "ANTHROPIC_API_KEY" in captured.err


# ── run_preflight_checks (orchestrator) ───────────────────────────────────


def test_preflight_passes_silently_when_all_ok(capsys):
    from cryptodep.preflight import run_preflight_checks

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.return_value = None

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            run_preflight_checks(_make_config(llm_provider="anthropic"))

    captured = capsys.readouterr()
    assert "passed" in captured.out.lower()


def test_preflight_collects_all_failures_before_abort(capsys):
    from cryptodep.preflight import run_preflight_checks
    from neo4j.exceptions import ServiceUnavailable
    import httpx

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = ServiceUnavailable("refused")

    env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(SystemExit) as exc:
                run_preflight_checks(_make_config(llm_provider="openrouter"))

    assert exc.value.code == 1
    captured = capsys.readouterr()
    full_output = captured.out + captured.err
    # Both failures must be reported before abort
    assert "neo4j" in full_output.lower() or "bolt" in full_output.lower()
    assert "OPENROUTER_API_KEY" in full_output


# ── Repo checks ───────────────────────────────────────────────────────────


def test_repo_check_passes_when_directory_exists(tmp_path):
    from cryptodep.preflight import check_repo
    check_repo(tmp_path)  # should not raise


def test_repo_check_aborts_when_path_does_not_exist():
    from cryptodep.preflight import check_repo
    from pathlib import Path
    with pytest.raises(SystemExit) as exc:
        check_repo(Path("/nonexistent/repo/path"))
    assert exc.value.code == 1


def test_repo_check_aborts_when_path_is_a_file(tmp_path):
    from cryptodep.preflight import check_repo
    f = tmp_path / "not_a_dir.txt"
    f.write_text("hello")
    with pytest.raises(SystemExit) as exc:
        check_repo(f)
    assert exc.value.code == 1


def test_repo_check_error_includes_path_in_message(capsys, tmp_path):
    from cryptodep.preflight import check_repo
    from pathlib import Path
    missing = Path("/some/missing/repo")
    with pytest.raises(SystemExit):
        check_repo(missing)
    captured = capsys.readouterr()
    assert str(missing) in captured.out + captured.err


def test_run_preflight_includes_repo_check(tmp_path, capsys):
    from cryptodep.preflight import run_preflight_checks
    from pathlib import Path

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.return_value = None

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            with pytest.raises(SystemExit) as exc:
                run_preflight_checks(
                    _make_config(llm_provider="anthropic"),
                    repo_path=Path("/nonexistent/repo"),
                )
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "nonexistent" in captured.out + captured.err
