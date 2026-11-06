from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from cryptodep.config import CryptoDependConfig
from cryptodep.agents.a2_detection import CryptoDetectionAgent


# ── tests that share a single A2 run (LLM mocked → "[]") ─────────────────


def test_a2_populates_raw_findings(a2_result):
    assert len(a2_result["raw_crypto_findings"]) > 0


def test_a2_findings_have_required_fields(a2_result):
    for f in a2_result["validated_findings"]:
        assert "algorithm_family" in f
        assert "source_ref" in f
        assert "confidence" in f
        assert "detected_by" in f
        assert "evidence" in f
        assert isinstance(f["confidence"], float)


def test_a2_zero_false_negatives_on_rsa_dh(a2_result):
    """AC-A2-03: RSA and DH usages in fixtures must appear in validated_findings."""
    families = {f["algorithm_family"] for f in a2_result["validated_findings"]}
    assert "RSA" in families, f"RSA not found in {families}"
    assert "DH" in families, f"DH not found in {families}"


def test_a2_records_agent_timing(a2_result):
    assert "A2:CryptoDetection" in a2_result["agent_timings"]
    assert a2_result["agent_timings"]["A2:CryptoDetection"] > 0


# ── tests that need a fresh A2 run (different mock or mock call count) ────


def test_a2_no_llm_for_high_confidence_findings(a1_state):
    """Findings with confidence >= 0.75 must NOT call the LLM."""
    config = CryptoDependConfig(neo4j_password="test")
    a2 = CryptoDetectionAgent(config)

    with patch("cryptodep.agents.a2_detection.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "[]"
        result = asyncio.run(a2.run(dict(a1_state)))

    low_conf_count = sum(
        1 for f in result["raw_crypto_findings"] if f["confidence"] < 0.75
    )
    assert mock_llm.call_count <= low_conf_count
    high_conf = [f for f in result["validated_findings"] if f["confidence"] >= 0.75]
    assert len(high_conf) > 0


def test_a2_escalates_low_confidence_to_llm(a1_state):
    """Findings with confidence < 0.75 (crypto-constants) must trigger LLM call."""
    config = CryptoDependConfig(neo4j_password="test")
    a2 = CryptoDetectionAgent(config)

    promoted_finding = {
        "algorithm_family": "RSA",
        "parameter_set": "2048",
        "use_context": "digital_signature",
        "source_ref": "AuthService.java:L5",
        "confidence": 0.88,
        "evidence": 'KeyPairGenerator.getInstance("RSA")',
        "detected_by": "hybrid",
    }

    with patch("cryptodep.agents.a2_detection.call_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = json.dumps([promoted_finding])
        result = asyncio.run(a2.run(dict(a1_state)))

    hybrid = [f for f in result["validated_findings"] if f["detected_by"] == "hybrid"]
    low_conf_input = [f for f in result["raw_crypto_findings"] if f["confidence"] < 0.75]
    assert len(low_conf_input) > 0, "No low-confidence findings in fixtures — test is vacuous"
    assert len(hybrid) > 0


def test_a2_accepts_object_shaped_llm_reply(a1_state):
    """A single object or {"findings": [...]} must not raise 'str' object has no attribute 'get'."""
    finding = {"algorithm_family": "RSA", "source_ref": "AuthService.java:L5", "confidence": 0.88}
    for reply in (finding, {"findings": [finding, "noise"]}):
        a2 = CryptoDetectionAgent(CryptoDependConfig(neo4j_password="test"))
        with patch("cryptodep.agents.a2_detection.call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = json.dumps(reply)
            result = asyncio.run(a2.run(dict(a1_state)))
        assert not [e for e in result["errors"] if e["error_type"] == "llm_escalation_failed"]
        assert any(f["detected_by"] == "hybrid" for f in result["validated_findings"])
