"""
Phase 2 assistant endpoints for the ThreatWatch copilot.
Provides:
- /api/v1/assistant/chat
- /api/v1/assistant/recommend
"""

from typing import Any, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.agents.llm_client import call_llm_with_fallback, safe_parse_json
from app.config import settings
from app.limiter import limiter

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])


class IncidentContext(BaseModel):
    scan_id: Optional[int] = None
    verdict: str = Field(default="safe", pattern="^(safe|suspicious|scam|uncertain)$")
    risk_percent: int = Field(default=0, ge=0, le=100)
    channel: str = Field(default="chat", pattern="^(email|sms|chat|url)$")
    threat_class: Optional[str] = Field(default=None, max_length=120)
    action_level: Optional[str] = Field(default=None, max_length=120)
    summary: Optional[str] = Field(default=None, max_length=3000)
    recommendation: Optional[str] = Field(default=None, max_length=3000)
    story: Optional[str] = Field(default=None, max_length=4000)
    reasons: list[str] = Field(default_factory=list, max_length=12)
    indicators: list[str] = Field(default_factory=list, max_length=12)
    pipeline_mode: Optional[str] = Field(default=None, max_length=60)
    agent_explanation: Optional[str] = Field(default=None, max_length=4000)
    message_excerpt: Optional[str] = Field(default=None, max_length=4000)


class AssistantChatRequest(BaseModel):
    prompt_kind: str = Field(default="summary", pattern="^(summary|action|exec|rule)$")
    incident: IncidentContext
    prompt_text: Optional[str] = Field(default=None, max_length=2000)
    preferred_model: Optional[str] = Field(default=None, max_length=120)
    openai_api_key: Optional[str] = Field(default=None, max_length=400)
    anthropic_api_key: Optional[str] = Field(default=None, max_length=400)


class AssistantRecommendRequest(BaseModel):
    incident: IncidentContext
    preferred_model: Optional[str] = Field(default=None, max_length=120)
    openai_api_key: Optional[str] = Field(default=None, max_length=400)
    anthropic_api_key: Optional[str] = Field(default=None, max_length=400)


@router.post("/chat")
@limiter.limit("10/minute")
async def assistant_chat(request: Request, req: AssistantChatRequest):
    fallback = _fallback_chat(req.prompt_kind, req.incident)
    llm_config = _llm_config(req.preferred_model, req.openai_api_key, req.anthropic_api_key)

    try:
        text, model_used = await call_llm_with_fallback(
            system_prompt=_assistant_system_prompt(),
            user_prompt=_assistant_user_prompt(req.prompt_kind, req.incident, req.prompt_text),
            max_tokens=_max_tokens_for(req.preferred_model, default_limit=420, ollama_limit=180),
            temperature=0.25,
            json_mode=True,
            timeout=settings.agent_llm_timeout,
            llm_config=llm_config,
        )
        data = safe_parse_json(text)
        return {
            "answer": data.get("answer", fallback),
            "model_used": model_used,
            "source": "llm",
        }
    except Exception:
        return {
            "answer": fallback,
            "model_used": "template-fallback",
            "source": "fallback",
        }


@router.post("/recommend")
@limiter.limit("10/minute")
async def assistant_recommend(request: Request, req: AssistantRecommendRequest):
    fallback = _fallback_recommend(req.incident)
    llm_config = _llm_config(req.preferred_model, req.openai_api_key, req.anthropic_api_key)

    try:
        text, model_used = await call_llm_with_fallback(
            system_prompt=_recommend_system_prompt(),
            user_prompt=_recommend_user_prompt(req.incident),
            max_tokens=_max_tokens_for(req.preferred_model, default_limit=520, ollama_limit=260),
            temperature=0.15,
            json_mode=True,
            timeout=settings.agent_llm_timeout,
            llm_config=llm_config,
        )
        data = safe_parse_json(text)
        return {
            "summary": data.get("summary", fallback["summary"]),
            "analyst_action": data.get("analyst_action", fallback["analyst_action"]),
            "user_action": data.get("user_action", fallback["user_action"]),
            "rule_suggestion": data.get("rule_suggestion", fallback["rule_suggestion"]),
            "confidence_note": data.get("confidence_note", fallback["confidence_note"]),
            "model_used": model_used,
            "source": "llm",
        }
    except Exception:
        fallback["model_used"] = "template-fallback"
        fallback["source"] = "fallback"
        return fallback


def _llm_config(preferred_model: Optional[str], openai_api_key: Optional[str], anthropic_api_key: Optional[str]) -> dict[str, Any]:
    return {
        "preferred_model": preferred_model.strip() if preferred_model else None,
        "openai_api_key": openai_api_key.strip() if openai_api_key else None,
        "anthropic_api_key": anthropic_api_key.strip() if anthropic_api_key else None,
        "ollama_base_url": settings.ollama_base_url,
        "ollama_model": settings.ollama_model,
    }


def _max_tokens_for(preferred_model: Optional[str], default_limit: int, ollama_limit: int) -> int:
    if preferred_model and preferred_model.startswith("ollama/"):
        return min(settings.agent_max_tokens, ollama_limit)
    return min(settings.agent_max_tokens, default_limit)


def _assistant_system_prompt() -> str:
    return (
        "You are ThreatWatch Copilot, a cybersecurity analyst assistant for a B2B threat operations dashboard. "
        "Be concise, operational, and executive-ready. "
        "Return valid JSON with exactly one field: answer."
    )


def _assistant_user_prompt(kind: str, incident: IncidentContext, prompt_text: Optional[str]) -> str:
    custom_block = (
        f"Analyst question:\n{prompt_text.strip()}\n\n"
        if prompt_text and prompt_text.strip()
        else ""
    )
    return (
        f"Prompt kind: {kind}\n"
        f"Incident context:\n{_incident_block(incident)}\n\n"
        f"{custom_block}"
        "Write a short response tailored to the prompt kind and the analyst question when present. "
        "If kind=summary, provide an analyst-ready summary. "
        "If kind=action, give the next best action. "
        "If kind=exec, write a leadership briefing. "
        "If kind=rule, suggest a practical rule improvement. "
        "When an analyst question is present, answer it directly using the incident context.\n"
        'Return JSON: {"answer":"..."}'
    )


def _recommend_system_prompt() -> str:
    return (
        "You are ThreatWatch Copilot producing structured threat recommendations for analysts and leadership. "
        "Be specific, calm, and business-ready. Return valid JSON only."
    )


def _recommend_user_prompt(incident: IncidentContext) -> str:
    return (
        f"Incident context:\n{_incident_block(incident)}\n\n"
        "Return JSON with exactly these fields: "
        "summary, analyst_action, user_action, rule_suggestion, confidence_note."
    )


def _incident_block(incident: IncidentContext) -> str:
    return (
        f"- verdict: {incident.verdict}\n"
        f"- risk_percent: {incident.risk_percent}\n"
        f"- channel: {incident.channel}\n"
        f"- threat_class: {incident.threat_class or 'unknown'}\n"
        f"- action_level: {incident.action_level or 'review'}\n"
        f"- summary: {incident.summary or ''}\n"
        f"- recommendation: {incident.recommendation or ''}\n"
        f"- story: {incident.story or ''}\n"
        f"- reasons: {', '.join(incident.reasons) or 'none'}\n"
        f"- indicators: {', '.join(incident.indicators) or 'none'}\n"
        f"- pipeline_mode: {incident.pipeline_mode or 'standard-only'}\n"
        f"- agent_explanation: {incident.agent_explanation or ''}\n"
        f"- message_excerpt: {incident.message_excerpt or ''}\n"
    )


def _fallback_chat(kind: str, incident: IncidentContext) -> str:
    reasons = ", ".join(incident.reasons[:3]) if incident.reasons else "limited evidence"
    if kind == "action":
        return (
            f"Recommended next step: {incident.recommendation or 'validate the sender, preserve evidence, and escalate if the pattern repeats.'} "
            f"Current drivers: {reasons}."
        )
    if kind == "exec":
        return (
            f"Leadership brief: this {incident.channel.upper()} incident was assessed as {incident.verdict.upper()} "
            f"at {incident.risk_percent}% estimated exposure. The main signals were {reasons}."
        )
    if kind == "rule":
        indicators = ", ".join(incident.indicators[:3]) if incident.indicators else "urgency language and suspicious destination patterns"
        return f"Suggested rule direction: improve coverage around {reasons}. Candidate indicators include {indicators}."
    return incident.summary or (
        f"This incident is currently classified as {incident.verdict.upper()} with {incident.risk_percent}% risk. "
        f"Primary drivers include {reasons}."
    )


def _fallback_recommend(incident: IncidentContext) -> dict[str, str]:
    reasons = ", ".join(incident.reasons[:3]) if incident.reasons else "limited evidence"
    indicators = ", ".join(incident.indicators[:3]) if incident.indicators else "urgency language and suspicious destination behavior"
    analyst_action = incident.recommendation or "Validate the sender, preserve message context, and escalate if corroborating signals appear."
    user_action = (
        "Do not click links or share credentials until the request is independently verified."
        if incident.verdict in {"scam", "suspicious"}
        else "No urgent user action is required at current confidence."
    )
    return {
        "summary": incident.summary or (
            f"ThreatWatch AI assesses this {incident.channel.upper()} incident as {incident.verdict.upper()} "
            f"with {incident.risk_percent}% estimated exposure, driven by {reasons}."
        ),
        "analyst_action": analyst_action,
        "user_action": user_action,
        "rule_suggestion": f"Strengthen detection around {reasons}. Candidate indicators: {indicators}.",
        "confidence_note": "This recommendation is template-based because no live LLM provider responded.",
    }
