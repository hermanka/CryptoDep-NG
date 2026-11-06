"""LLM wrappers for Anthropic API and Ollama (PRD Section 4.2).

ALL LLM calls from agents must go through this module.
Never call anthropic.Anthropic() or ollama directly in agent files.

Operations:
  call_llm(config, messages, system_prompt, response_format) -> str (JSON)
  call_anthropic(model, messages, max_tokens, temperature)  -> str
  call_ollama(model, messages)                              -> str
  build_cpg_slice(ast_cache, file_path, center_line, max_tokens) -> str

Debug: set CRYPTODEP_DEBUG=1 to dump all prompts/responses to logs/
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import structlog

log = structlog.get_logger().bind(module="llm_tools")


class LLMEndpointError(RuntimeError):
    """Safe diagnostic generated locally, without upstream response bodies or credentials."""


def _extract_json(text: str) -> str:
    """Extract the first valid JSON object or array from an LLM response.

    Fallback chain (any model, any provider):
      1. Direct parse — clean JSON response
      2. Strip markdown fence — ```json ... ```
      3. Brace-match from first '{' — CoT preamble / trailing text
      4. Brace-match from first '[' — array responses
    Raises ValueError if no valid JSON is found.
    """
    if not text or not text.strip():
        raise ValueError("No JSON found in LLM response: empty string")

    text = text.strip()

    # Strategy 1: direct parse
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

    # Strategy 2: strip markdown code fence
    stripped = re.sub(r"^```(?:json)?\s*\n?", "", text)
    stripped = re.sub(r"\n?```\s*$", "", stripped).strip()
    try:
        json.loads(stripped)
        return stripped
    except json.JSONDecodeError:
        pass

    # Strategies 3 & 4: brace-match from first { or [, tried in order of appearance
    pairs = [('{', '}'), ('[', ']')]
    ordered = sorted(
        ((text.find(o), o, c) for o, c in pairs if text.find(o) != -1),
        key=lambda x: x[0],
    )
    for start, open_ch, close_ch in ordered:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        json.loads(candidate)
                        return candidate
                    except json.JSONDecodeError:
                        break

    raise ValueError(f"No JSON found in LLM response (preview={text[:200]!r})")


async def call_llm(
    config: Any,
    messages: List[Dict[str, str]],
    system_prompt: Optional[str] = None,
    response_format: Optional[str] = "json",
) -> str:
    """Route LLM call to Anthropic, Ollama, or OpenRouter based on config.llm_provider."""
    if config.llm_provider == "openai_compatible":
        raw = await call_openai_compatible(config, messages, system_prompt)
    elif config.llm_provider == "anthropic":
        raw = await call_anthropic(
            model=config.anthropic_model,
            messages=messages,
            system_prompt=system_prompt,
            max_tokens=config.llm_max_tokens,
            temperature=config.llm_temperature,
        )
    elif config.llm_provider == "openrouter":
        raw = await call_openrouter(
            model=config.openrouter_model,
            messages=messages,
            system_prompt=system_prompt,
            response_format=response_format,
            max_tokens=config.llm_max_tokens,
            temperature=config.llm_temperature,
        )
    elif config.llm_provider == "groq":
        raw = await call_groq(
            model=config.groq_model,
            messages=messages,
            system_prompt=system_prompt,
            response_format=response_format,
            max_tokens=config.llm_max_tokens,
            temperature=config.llm_temperature,
        )
    else:
        raw = await call_ollama(
            model=config.ollama_model,
            messages=messages,
            system_prompt=system_prompt,
            response_format=response_format,
        )

    if response_format == "json":
        return _extract_json(raw)
    return raw


async def call_openai_compatible(config: Any, messages: List[Dict[str, str]], system_prompt: Optional[str] = None) -> str:
    """Use a configurable Chat Completions endpoint without logging credentials or source."""
    import httpx

    base = config.llm_base_url.rstrip("/")
    url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    key = config.llm_api_key.get_secret_value()
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    all_messages = ([{"role": "system", "content": system_prompt}] if system_prompt else []) + list(messages)
    try:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=False) as client:
            response = await client.post(url, headers=headers, json={
                "model": config.llm_model, "messages": all_messages,
                "temperature": config.llm_temperature, "max_tokens": config.llm_max_tokens,
            })
        if response.status_code >= 300:
            reasons = {
                400: "Format permintaan atau parameter model tidak didukung.",
                401: "API key tidak valid atau belum diisi.",
                403: "Akses ditolak. Periksa izin API key, model, atau batasan wilayah.",
                404: "Endpoint atau nama model tidak ditemukan.",
                429: "Batas permintaan atau kuota provider tercapai. Coba kembali setelah kuota tersedia.",
                503: "Layanan/model sedang tidak tersedia atau sibuk. Coba kembali beberapa saat lagi.",
            }
            reason = reasons.get(response.status_code, "Provider menolak atau gagal memproses permintaan.")
            raise LLMEndpointError(f"Endpoint AI mengembalikan HTTP {response.status_code}. {reason}")
        choice = response.json()["choices"][0]
        result = choice["message"]["content"]
        if not isinstance(result, str) or not result.strip():
            if choice.get("finish_reason") == "length":
                raise LLMEndpointError("Respons AI kosong karena batas token tercapai. Model mungkin memakai token untuk reasoning.")
            raise ValueError("Empty content")
        return result
    except httpx.TimeoutException:
        raise LLMEndpointError("Endpoint AI melewati batas waktu respons 120 detik.") from None
    except httpx.RequestError:
        raise LLMEndpointError("Endpoint AI tidak dapat dihubungi. Periksa jaringan, DNS, dan sertifikat TLS.") from None
    except (ValueError, KeyError, IndexError, TypeError):
        raise LLMEndpointError("Endpoint AI mengembalikan format respons Chat Completions yang tidak valid.") from None


async def call_anthropic(
    model: str,
    messages: List[Dict[str, str]],
    system_prompt: Optional[str] = None,
    max_tokens: int = 4096,
    temperature: float = 0.0,
) -> str:
    """Call Anthropic API. Requires ANTHROPIC_API_KEY in environment."""
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if system_prompt:
        kwargs["system"] = system_prompt

    _debug_dump("anthropic_request", str({"model": model, "messages": messages}))
    response = await client.messages.create(**kwargs)
    result = response.content[0].text
    _debug_dump("anthropic_response", result)
    return result


async def call_ollama(
    model: str,
    messages: List[Dict[str, str]],
    system_prompt: Optional[str] = None,
    response_format: Optional[str] = "json",
) -> str:
    """Call Ollama API using the official ollama Python library.

    Local:  set OLLAMA_BASE_URL=http://localhost:11434 (default, no key needed)
    Cloud:  set OLLAMA_BASE_URL=https://ollama.com and OLLAMA_API_KEY=<your key>

    Reference: docs/ollama cloud API reference.md
    """
    from ollama import AsyncClient

    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    api_key = os.environ.get("OLLAMA_API_KEY", "")

    all_messages = list(messages)
    if system_prompt:
        all_messages = [{"role": "system", "content": system_prompt}] + all_messages

    client_kwargs: Dict[str, Any] = {"host": base_url}
    if api_key:
        client_kwargs["headers"] = {"Authorization": f"Bearer {api_key}"}

    _debug_dump("ollama_request", str({"model": model, "messages": all_messages}))
    client = AsyncClient(**client_kwargs)
    chat_kwargs: Dict[str, Any] = {"model": model, "messages": all_messages, "stream": False}
    if response_format == "json":
        chat_kwargs["format"] = "json"
    response = await client.chat(**chat_kwargs)
    result = response.message.content
    _debug_dump("ollama_response", result)
    return result


async def call_openrouter(
    model: str,
    messages: List[Dict[str, str]],
    system_prompt: Optional[str] = None,
    response_format: Optional[str] = "json",
    max_tokens: int = 4096,
    temperature: float = 0.0,
) -> str:
    """Call OpenRouter API using httpx."""
    import httpx

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        log.warning("OPENROUTER_API_KEY is missing in environment")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "CryptoDep-LLM",
    }

    all_messages = list(messages)
    if system_prompt:
        all_messages = [{"role": "system", "content": system_prompt}] + all_messages

    payload: Dict[str, Any] = {
        "model": model,
        "messages": all_messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    
    # json_object mode is not supported by all models (e.g. reasoning/thinking models).
    # Skip it — agents already instruct JSON output in their system prompts.

    _debug_dump("openrouter_request", str(payload))
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        message = response.json()["choices"][0]["message"]
        result = message.get("content")

        # Reasoning models (e.g. Nemotron) may return content=null when they
        # exhaust max_tokens on the thinking trace before producing output.
        if result is None:
            finish_reason = response.json()["choices"][0].get("finish_reason")
            raise RuntimeError(
                f"OpenRouter returned null content (finish_reason={finish_reason!r}). "
                f"Model may be a reasoning model that needs more max_tokens, "
                f"or does not support json_object response_format."
            )

    _debug_dump("openrouter_response", result)
    return result


async def call_groq(
    model: str,
    messages: List[Dict[str, str]],
    system_prompt: Optional[str] = None,
    response_format: Optional[str] = "json",
    max_tokens: int = 4096,
    temperature: float = 0.0,
) -> str:
    """Call Groq API (OpenAI-compatible). Requires GROQ_API_KEY in environment.

    Default model: llama-3.3-70b-versatile (fast, generous free tier).
    JSON mode enabled when response_format='json'.
    """
    import httpx

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        log.warning("GROQ_API_KEY is missing in environment")

    all_messages = list(messages)
    if system_prompt:
        all_messages = [{"role": "system", "content": system_prompt}] + all_messages

    payload: Dict[str, Any] = {
        "model": model,
        "messages": all_messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    # Do NOT set response_format=json_object — it forces dict output which breaks
    # prompts that ask for a JSON array. _extract_json handles both arrays and objects.

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    import asyncio

    _debug_dump("groq_request", str(payload))
    async with httpx.AsyncClient(timeout=120.0) as client:
        for attempt in range(4):  # up to 3 retries on 429
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if response.status_code == 429:
                # Honour Retry-After header if present, else back off 15s / 30s / 60s
                retry_after = int(response.headers.get("retry-after", [15, 30, 60][min(attempt, 2)]))
                log.warning("groq_rate_limit", attempt=attempt + 1, retry_after=retry_after)
                await asyncio.sleep(retry_after)
                continue
            response.raise_for_status()
            result = response.json()["choices"][0]["message"]["content"]
            break
        else:
            response.raise_for_status()  # will raise on the last 429
            result = ""  # unreachable but keeps type checker happy

    _debug_dump("groq_response", result)
    return result


def build_cpg_slice(
    ast_cache: Dict[str, Any],
    file_path: str,
    center_line: int,
    max_tokens: int = 2000,
) -> str:
    """Extract a source window centered on center_line, sized to fit within max_tokens."""
    if file_path not in ast_cache:
        log.warning("cpg_slice_cache_miss", file=file_path)
        return ""

    source: str = ast_cache[file_path]["source"]
    lines = source.splitlines()
    total_lines = len(lines)

    # Estimate: ~4 chars per token, split evenly above and below
    chars_budget = max_tokens * 4
    avg_line_len = max(1, len(source) // max(1, total_lines))
    raw_half = chars_budget // (2 * avg_line_len)
    # Apply minimum of 5 only when budget allows; for tiny budgets honour the budget
    window_half = raw_half if raw_half < 5 else max(5, raw_half)

    idx = center_line - 1  # convert 1-indexed to 0-indexed
    start = max(0, idx - window_half)
    end = min(total_lines, idx + window_half + 1)

    return "\n".join(lines[start:end])


def _debug_dump(label: str, content: str) -> None:
    """Dump prompt/response to logs/ if CRYPTODEP_DEBUG=1."""
    if os.environ.get("CRYPTODEP_DEBUG") == "1":
        import pathlib
        import time
        pathlib.Path("logs").mkdir(exist_ok=True)
        fname = f"logs/{label}_{int(time.time() * 1000)}.txt"
        pathlib.Path(fname).write_text(content)
        log.debug("llm_debug_dump", file=fname)
