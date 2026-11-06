from __future__ import annotations

import pathlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"


# ── build_cpg_slice ────────────────────────────────────────────────────────


def test_build_cpg_slice_returns_string():
    from cryptodep.tools.ast_tools import parse_file_ast
    from cryptodep.tools.llm_tools import build_cpg_slice

    result = parse_file_ast(FIXTURES / "AuthService.java", "java")
    ast_cache = {str(FIXTURES / "AuthService.java"): result}

    slc = build_cpg_slice(ast_cache, str(FIXTURES / "AuthService.java"), center_line=6)
    assert isinstance(slc, str)
    assert len(slc) > 0


def test_build_cpg_slice_contains_center_line_content():
    from cryptodep.tools.ast_tools import parse_file_ast
    from cryptodep.tools.llm_tools import build_cpg_slice

    result = parse_file_ast(FIXTURES / "AuthService.java", "java")
    ast_cache = {str(FIXTURES / "AuthService.java"): result}

    # Line 7 in AuthService.java contains "KeyPairGenerator"
    slc = build_cpg_slice(ast_cache, str(FIXTURES / "AuthService.java"), center_line=7)
    assert "KeyPairGenerator" in slc


def test_build_cpg_slice_cache_miss_returns_empty():
    from cryptodep.tools.llm_tools import build_cpg_slice

    slc = build_cpg_slice({}, "/nonexistent/file.java", center_line=1)
    assert slc == ""


def test_build_cpg_slice_respects_max_tokens():
    from cryptodep.tools.ast_tools import parse_file_ast
    from cryptodep.tools.llm_tools import build_cpg_slice

    result = parse_file_ast(FIXTURES / "AuthService.java", "java")
    ast_cache = {str(FIXTURES / "AuthService.java"): result}

    # max_tokens=10 should produce a very short slice
    slc = build_cpg_slice(ast_cache, str(FIXTURES / "AuthService.java"), center_line=6, max_tokens=10)
    assert len(slc) < 200


# ── call_anthropic ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_anthropic_returns_string():
    from cryptodep.tools.llm_tools import call_anthropic

    mock_content = MagicMock()
    mock_content.text = '[]'
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    with patch("anthropic.AsyncAnthropic") as MockClient:
        instance = MockClient.return_value
        instance.messages.create = AsyncMock(return_value=mock_response)

        result = await call_anthropic(
            model="claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": "test"}],
        )
        assert result == "[]"


@pytest.mark.asyncio
async def test_call_anthropic_passes_system_prompt():
    from cryptodep.tools.llm_tools import call_anthropic

    mock_content = MagicMock()
    mock_content.text = "response"
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    with patch("anthropic.AsyncAnthropic") as MockClient:
        instance = MockClient.return_value
        instance.messages.create = AsyncMock(return_value=mock_response)

        await call_anthropic(
            model="claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": "test"}],
            system_prompt="You are a cryptographer.",
        )
        call_kwargs = instance.messages.create.call_args.kwargs
        assert call_kwargs.get("system") == "You are a cryptographer."


# ── call_ollama ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_ollama_returns_string():
    from cryptodep.tools.llm_tools import call_ollama

    mock_response = MagicMock()
    mock_response.message.content = "[]"

    with patch("ollama.AsyncClient") as MockOllama:
        instance = MockOllama.return_value
        instance.chat = AsyncMock(return_value=mock_response)

        result = await call_ollama(
            model="qwen2.5-coder:7b",
            messages=[{"role": "user", "content": "test"}],
        )
        assert result == "[]"


# ── _extract_json ──────────────────────────────────────────────────────────


def test_extract_json_clean_object():
    from cryptodep.tools.llm_tools import _extract_json
    assert _extract_json('{"a": 1}') == '{"a": 1}'


def test_extract_json_clean_array():
    from cryptodep.tools.llm_tools import _extract_json
    assert _extract_json('[1, 2, 3]') == '[1, 2, 3]'


def test_extract_json_strips_markdown_fence():
    from cryptodep.tools.llm_tools import _extract_json
    raw = '```json\n{"a": 1}\n```'
    assert _extract_json(raw) == '{"a": 1}'


def test_extract_json_strips_markdown_fence_no_lang():
    from cryptodep.tools.llm_tools import _extract_json
    raw = '```\n{"a": 1}\n```'
    assert _extract_json(raw) == '{"a": 1}'


def test_extract_json_cot_preamble_before_object():
    from cryptodep.tools.llm_tools import _extract_json
    raw = 'Sure! Here is the JSON result:\n{"algorithms": ["RSA"]}'
    import json
    result = json.loads(_extract_json(raw))
    assert result == {"algorithms": ["RSA"]}


def test_extract_json_cot_preamble_before_array():
    from cryptodep.tools.llm_tools import _extract_json
    raw = 'Let me think about this...\n[{"type": "RSA"}, {"type": "AES"}]'
    import json
    result = json.loads(_extract_json(raw))
    assert len(result) == 2


def test_extract_json_text_after_object():
    from cryptodep.tools.llm_tools import _extract_json
    raw = '{"a": 1} some trailing explanation text'
    import json
    assert json.loads(_extract_json(raw)) == {"a": 1}


def test_extract_json_reasoning_model_output():
    from cryptodep.tools.llm_tools import _extract_json
    raw = (
        "I need to analyze the code carefully. "
        "The code uses RSA which is quantum vulnerable. "
        'My answer: {"findings": [{"algorithm": "RSA", "confidence": 0.9}]}'
    )
    import json
    result = json.loads(_extract_json(raw))
    assert result["findings"][0]["algorithm"] == "RSA"


def test_extract_json_raises_when_no_json():
    from cryptodep.tools.llm_tools import _extract_json
    import pytest
    with pytest.raises(ValueError, match="No JSON"):
        _extract_json("I cannot answer that question.")


def test_extract_json_raises_on_empty_string():
    from cryptodep.tools.llm_tools import _extract_json
    import pytest
    with pytest.raises(ValueError):
        _extract_json("")


# ── call_ollama ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_ollama_prepends_system_message():
    from cryptodep.tools.llm_tools import call_ollama

    mock_response = MagicMock()
    mock_response.message.content = "ok"

    with patch("ollama.AsyncClient") as MockOllama:
        instance = MockOllama.return_value
        instance.chat = AsyncMock(return_value=mock_response)

        await call_ollama(
            model="qwen2.5-coder:7b",
            messages=[{"role": "user", "content": "test"}],
            system_prompt="Be a cryptographer.",
        )
        call_kwargs = instance.chat.call_args.kwargs
        sent_messages = call_kwargs["messages"]
        assert sent_messages[0]["role"] == "system"
        assert sent_messages[0]["content"] == "Be a cryptographer."
