"""Session-scoped fixtures shared across unit tests.

Semgrep and tree-sitter are slow subprocess/parse invocations; running them
once per session rather than once per test eliminates redundant work and
prevents timeout flakiness on resource-constrained environments (e.g. WSL2).
"""
from __future__ import annotations

import asyncio
import pathlib
from unittest.mock import AsyncMock, patch

import pytest

from cryptodep.config import CryptoDependConfig

_FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"
_RULES_DIR = pathlib.Path("cryptodep/rules")

_A1_INITIAL: dict = {
    "repo_path": str(_FIXTURES),
    "file_index": {},
    "ast_cache": {},
    "import_graph": {},
    "repo_stats": {"total_files": 0, "total_loc": 0, "languages": {}},
    "raw_crypto_findings": [],
    "validated_findings": [],
    "candidate_edges": [],
    "validated_edges": [],
    "cdg_document": None,
    "neo4j_import_stats": {},
    "cbom_export_path": "",
    "migration_plan": None,
    "report_md": "",
    "errors": [],
    "agent_timings": {},
    "total_llm_tokens": 0,
}


# ── semgrep fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def java_semgrep_raw() -> list:
    """Run semgrep crypto-java.yaml against AuthService.java once per session."""
    from cryptodep.tools.semgrep_tools import run_semgrep

    return run_semgrep(
        [str(_RULES_DIR / "crypto-java.yaml")],
        [str(_FIXTURES / "AuthService.java")],
    )


@pytest.fixture(scope="session")
def python_semgrep_raw() -> list:
    """Run semgrep crypto-python.yaml against crypto_utils.py once per session."""
    from cryptodep.tools.semgrep_tools import run_semgrep

    return run_semgrep(
        [str(_RULES_DIR / "crypto-python.yaml")],
        [str(_FIXTURES / "crypto_utils.py")],
    )


# ── agent fixtures ────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def a1_state() -> dict:
    """Run A1 on sample_repo once per session; returns the A1 output state."""
    from cryptodep.agents.a1_ingestion import CodeIngestionAgent

    config = CryptoDependConfig(neo4j_password="test")
    a1 = CodeIngestionAgent(config)
    initial = dict(_A1_INITIAL)
    initial["config"] = config
    initial["run_id"] = "test-run-shared"
    return asyncio.run(a1.run(initial))


@pytest.fixture(scope="session")
def a2_result(a1_state: dict) -> dict:
    """Run A2 on A1 state once per session (LLM mocked to return empty list).

    Shared by tests that only *read* validated_findings / raw_crypto_findings.
    Tests that need mock call counts or a specific LLM response should use
    ``a1_state`` directly and run A2 themselves.
    """
    from cryptodep.agents.a2_detection import CryptoDetectionAgent

    config = CryptoDependConfig(neo4j_password="test")
    a2 = CryptoDetectionAgent(config)
    with patch("cryptodep.agents.a2_detection.call_llm", new_callable=AsyncMock) as mock:
        mock.return_value = "[]"
        return asyncio.run(a2.run(dict(a1_state)))
