"""
LLM client with ordered fallback chain.
Each agent calls call_llm_with_fallback() independently —
if one agent falls back to Claude, others still try GPT-4o first.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("threatwatch.llm")

# Ordered fallback chain — edit AGENT_PRIMARY_MODEL env var to change head
_DEFAULT_CHAIN = [
    ("gpt-4o",           "openai"),
    ("gpt-4o-mini",      "openai"),
    ("claude-3-5-haiku-20241022", "anthropic"),
]


def _get_chain(preferred_model: Optional[str] = None) -> list[tuple[str, str]]:
    primary = preferred_model or os.environ.get("AGENT_PRIMARY_MODEL", "gpt-4o")
    chain = [e for e in _DEFAULT_CHAIN if e[0] != primary]
    return [(primary, _provider_for(primary))] + chain


def _provider_for(model: str) -> str:
    if model.startswith("ollama/"):
        return "ollama"
    return "anthropic" if model.startswith("claude") else "openai"


async def call_llm_with_fallback(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 512,
    temperature: float = 0.1,
    json_mode: bool = True,
    timeout: int = 15,
    llm_config: Optional[dict] = None,
) -> tuple[str, str]:
    """
    Try each model in the fallback chain in order.

    Returns:
        (response_text, model_name_used)

    Raises:
        RuntimeError — all models failed (caller should use rule-only fallback)
    """
    llm_config = llm_config or {}
    chain = _get_chain(llm_config.get("preferred_model"))
    last_error: Optional[Exception] = None

    for model, provider in chain:
        request_timeout = settings.ollama_timeout if provider == "ollama" else timeout
        try:
            text = await asyncio.wait_for(
                _call(model, provider, system_prompt, user_prompt, max_tokens, temperature, json_mode, llm_config),
                timeout=request_timeout,
            )
            logger.info(f"[llm] {model} responded OK")
            return text, model

        except asyncio.TimeoutError:
            logger.warning(f"[llm] {model} timed out after {request_timeout}s")
            last_error = asyncio.TimeoutError(f"{model} timed out")

        except Exception as exc:
            logger.warning(f"[llm] {model} failed: {type(exc).__name__}: {exc}")
            last_error = exc

    raise RuntimeError(f"All LLM models failed. Last: {last_error}")


async def _call(
    model: str,
    provider: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
    llm_config: Optional[dict],
) -> str:
    if provider == "openai":
        return await _call_openai(model, system_prompt, user_prompt, max_tokens, temperature, json_mode, llm_config)
    elif provider == "anthropic":
        return await _call_anthropic(model, system_prompt, user_prompt, max_tokens, temperature, llm_config)
    elif provider == "ollama":
        return await _call_ollama(model, system_prompt, user_prompt, max_tokens, temperature, json_mode, llm_config)
    raise ValueError(f"Unknown provider: {provider}")


async def _call_openai(
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
    llm_config: Optional[dict],
) -> str:
    api_key = (llm_config or {}).get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    import openai
    client = openai.AsyncOpenAI(api_key=api_key)

    kwargs: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    response = await client.chat.completions.create(**kwargs)
    return response.choices[0].message.content or ""


async def _call_anthropic(
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    temperature: float,
    llm_config: Optional[dict],
) -> str:
    api_key = (llm_config or {}).get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set")

    import anthropic
    client = anthropic.AsyncAnthropic(api_key=api_key)

    # Anthropic has no native JSON mode — instruct via system prompt
    system = system_prompt + "\n\nCRITICAL: Respond with valid JSON only. No markdown, no explanation outside the JSON object."

    response = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return response.content[0].text


async def _call_ollama(
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
    llm_config: Optional[dict],
) -> str:
    base_url = (llm_config or {}).get("ollama_base_url") or settings.ollama_base_url
    if not base_url:
        raise ValueError("OLLAMA_BASE_URL not set")
    request_timeout = (llm_config or {}).get("ollama_timeout") or settings.ollama_timeout

    model_name = model.split("/", 1)[1] if model.startswith("ollama/") else model
    model_name = model_name or (llm_config or {}).get("ollama_model") or settings.ollama_model

    payload = {
        "model": model_name,
        "stream": False,
        "think": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
        },
    }
    if json_mode:
        payload["format"] = "json"

    async with httpx.AsyncClient(timeout=request_timeout + 5) as client:
        response = await client.post(f"{base_url.rstrip('/')}/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()

    message = data.get("message", {}) if isinstance(data, dict) else {}
    content = message.get("content", "")
    if not content:
        raise ValueError("Ollama returned an empty response")
    return content


def safe_parse_json(text: str) -> dict:
    """
    Parse LLM response as JSON.
    Handles models that wrap JSON in markdown code fences.
    """
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\nRaw: {text[:300]}")
