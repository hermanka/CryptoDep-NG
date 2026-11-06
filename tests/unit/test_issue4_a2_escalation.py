"""Tests for Issue 4: A2 LLM escalation cap + deduplication.

RED tests — all should fail before the fix.
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from cryptodep.config import CryptoDependConfig


def _make_config(**kwargs) -> CryptoDependConfig:
    return CryptoDependConfig(neo4j_password="test", **kwargs)


def _low_conf_finding(alg: str, ref: str, confidence: float = 0.5) -> dict:
    return {
        "algorithm_family": alg,
        "parameter_set": None,
        "use_context": "encryption",
        "source_ref": ref,
        "confidence": confidence,
        "evidence": f"Cipher.getInstance({alg!r})",
        "detected_by": "static_rule",
    }


def _run_a2(config, findings, llm_call_counter: list):
    """Helper: run A2 with mocked Semgrep + LLM. Returns final state."""
    from cryptodep.agents.a2_detection import CryptoDetectionAgent

    agent = CryptoDetectionAgent(config)

    async def mock_call_llm(cfg, messages, system_prompt=None, **kwargs):
        llm_call_counter.append(1)
        return '[]'

    state = {
        "repo_path": "/tmp",
        "config": config,
        "file_index": {},
        "ast_cache": {},
        "errors": [],
        "agent_timings": {},
        "total_llm_tokens": 0,
        "raw_crypto_findings": [],
        "validated_findings": [],
    }

    with patch("cryptodep.agents.a2_detection.run_semgrep", return_value={}), \
         patch("cryptodep.agents.a2_detection.parse_semgrep_findings", return_value=findings), \
         patch("cryptodep.agents.a2_detection.build_cpg_slice", return_value="code snippet here"), \
         patch("cryptodep.agents.a2_detection.call_llm", side_effect=mock_call_llm):
        return asyncio.run(agent.run(state))


# ── Config has max_escalation_calls ──────────────────────────────────────────

def test_config_has_max_escalation_calls():
    """CryptoDependConfig must have max_escalation_calls with a default of 50."""
    config = _make_config()
    assert hasattr(config, "max_escalation_calls"), (
        "CryptoDependConfig must have max_escalation_calls field"
    )
    assert config.max_escalation_calls == 50, (
        f"Default must be 50, got {config.max_escalation_calls}"
    )


def test_config_max_escalation_calls_is_configurable():
    """max_escalation_calls must be overridable."""
    config = _make_config(max_escalation_calls=10)
    assert config.max_escalation_calls == 10


# ── Cap is enforced ───────────────────────────────────────────────────────────

def test_a2_escalation_capped_at_max():
    """A2 must make at most max_escalation_calls LLM calls regardless of finding count."""
    config = _make_config(max_escalation_calls=3, llm_confidence_threshold=0.75)

    # 10 findings of different families (each would normally get its own call)
    families = ["RSA", "ECDSA", "DH", "ECDH", "ElGamal", "DSA", "RC4", "DES", "MD5", "RSA2"]
    low_conf_findings = [
        _low_conf_finding(fam, f"File_{fam}.java:L1", confidence=0.5)
        for fam in families
    ]

    counter = []
    _run_a2(config, low_conf_findings, counter)

    assert len(counter) <= 3, (
        f"Expected at most 3 LLM calls (cap=3), got {len(counter)}"
    )


# ── Deduplication by algorithm_family ────────────────────────────────────────

def test_a2_deduplicates_by_algorithm_family():
    """A2 must make one LLM call per unique algorithm_family, not per finding."""
    config = _make_config(max_escalation_calls=50, llm_confidence_threshold=0.75)

    # 5 findings, all same algorithm_family "RSA" — expect only 1 LLM call
    low_conf_findings = [
        _low_conf_finding("RSA", f"Service_{i}.java:L10", confidence=0.5)
        for i in range(5)
    ]

    counter = []
    _run_a2(config, low_conf_findings, counter)

    assert len(counter) == 1, (
        f"Expected 1 LLM call for 5 RSA findings (deduped by family), got {len(counter)}"
    )


def test_a2_dedup_distinct_families_get_separate_calls():
    """Each unique algorithm_family below threshold must get its own LLM call."""
    config = _make_config(max_escalation_calls=50, llm_confidence_threshold=0.75)

    # 2 RSA + 3 AES findings — expect 2 LLM calls (one per family)
    low_conf_findings = (
        [_low_conf_finding("RSA", f"A_{i}.java:L1", confidence=0.5) for i in range(2)]
        + [_low_conf_finding("AES", f"B_{i}.java:L1", confidence=0.5) for i in range(3)]
    )

    counter = []
    _run_a2(config, low_conf_findings, counter)

    assert len(counter) == 2, (
        f"Expected 2 LLM calls (RSA + AES deduped families), got {len(counter)}"
    )


def test_a2_cap_applies_after_dedup():
    """Cap applies to the number of family groups, not individual findings."""
    config = _make_config(max_escalation_calls=2, llm_confidence_threshold=0.75)

    # 3 distinct families → normally 3 calls, but cap=2 → at most 2
    low_conf_findings = (
        [_low_conf_finding("RSA", f"RSA_{i}.java:L1", confidence=0.5) for i in range(3)]
        + [_low_conf_finding("ECDSA", f"EC_{i}.java:L1", confidence=0.5) for i in range(3)]
        + [_low_conf_finding("DH", f"DH_{i}.java:L1", confidence=0.5) for i in range(3)]
    )

    counter = []
    _run_a2(config, low_conf_findings, counter)

    assert len(counter) <= 2, (
        f"Expected at most 2 LLM calls (cap=2 after dedup), got {len(counter)}"
    )
