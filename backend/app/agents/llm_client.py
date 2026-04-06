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

logger = logging.getLogger("threatwatch.llm")

# Ordered fallback chain — edit AGENT_PRIMARY_MODEL env var to change head
_DEFAULT_CHAIN = [
    ("gpt-4o",           "openai"),
    ("gpt-4o-mini",      "openai"),
    ("claude-haiku-3-5-20241022", "anthropic"),
]


def _get_chain() -> list[tuple[str, str]]:
    primary = os.environ.get("AGENT_PRIMARY_MODEL", "gpt-4o")
    chain = [e for e in _DEFAULT_CHAIN if e[0] != primary]
    return [(primary, _provider_for(primary))] + chain


def _provider_for(model: str) -> str:
    return "anthropic" if model.startswith("claude") else "openai"


async def call_llm_with_fallback(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 512,
    temperature: float = 0.1,
    json_mode: bool = True,
    timeout: int = 15,
) -> tuple[str, str]:
    """
    Try each model in the fallback chain in order.

    Returns:
        (response_text, model_name_used)

    Raises:
        RuntimeError — all models failed (caller should use rule-only fallback)
    """
    chain = _get_chain()
    last_error: Optional[Exception] = None

    for model, provider in chain:
        try:
            text = await asyncio.wait_for(
                _call(model, provider, system_prompt, user_prompt, max_tokens, temperature, json_mode),
                timeout=timeout,
            )
            logger.info(f"[llm] {model} responded OK")
            return text, model

        except asyncio.TimeoutError:
            logger.warning(f"[llm] {model} timed out after {timeout}s")
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
) -> str:
    if provider == "openai":
        return await _call_openai(model, system_prompt, user_prompt, max_tokens, temperature, json_mode)
    elif provider == "anthropic":
        return await _call_anthropic(model, system_prompt, user_prompt, max_tokens, temperature)
    raise ValueError(f"Unknown provider: {provider}")


async def _call_openai(
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
) -> str:
    api_key = os.environ.get("OPENAI_API_KEY", "")
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
) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
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
