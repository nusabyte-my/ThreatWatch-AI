"""
ClassifierAgent — primary LLM-based scam classification.
Always runs first in the pipeline (Step 1, sequential).
"""
from __future__ import annotations

import logging
from app.agents.base import AgentVerdict, ClassifierResult, ScanContext
from app.agents.llm_client import call_llm_with_fallback, safe_parse_json

logger = logging.getLogger("threatwatch.agents.classifier")

SYSTEM_PROMPT = """You are a specialist AI threat analyst for ThreatWatch AI, a scam and phishing \
detection system deployed in Malaysia.

CLASSIFICATION DEFINITIONS:
- "scam": High confidence (>70%) fraudulent. Indicators include fake authority impersonation \
(banks, government, courier), artificial urgency, OTP/credential requests, fake prizes, \
investment fraud, or malicious URLs.
- "suspicious": Ambiguous — some indicators present but insufficient to confirm fraud. Use \
this when uncertain rather than escalating to scam.
- "safe": No meaningful threat indicators. Normal communication.

HIGH-WEIGHT MALAYSIA-SPECIFIC PATTERNS:
- Banks: Maybank, CIMB, RHB, Public Bank, BSN, Bank Islam, Hong Leong, AmBank
- Government: LHDN (tax), PDRM (police), JPJ, KWSP/EPF, MySejahtera
- Courier: Pos Laju, DHL, FedEx, J&T — "customs fee" or "parcel on hold"
- Investment: guaranteed 20%+/month returns, Telegram/WhatsApp investment groups
- OTP theft: any request to share, forward, or "confirm" an OTP, TAC, or PIN code
- Gift card demands: Touch 'n Go, iTunes, Google Play cards as "payment"

OUTPUT — strict JSON, no other text:
{
  "verdict": "safe" | "suspicious" | "scam",
  "confidence": 0.0-1.0,
  "reasoning": "One sentence — primary threat signal or why it is safe.",
  "scam_categories": ["phishing","urgency","impersonation","otp","financial","url"]
}

RULES:
- Conservative: when genuinely uncertain, use "suspicious" not "scam"
- Confidence ≥ 0.90 only for textbook, multi-signal scam patterns
- Never hallucinate entities or URLs not present in the input
- Respond in English regardless of input language"""


def _build_user_prompt(ctx: ScanContext) -> str:
    parts = [f"Channel: {ctx.channel}", f"Message:\n{ctx.text}"]
    if ctx.url:
        parts.append(f"URL: {ctx.url}")
    if ctx.rule_flags:
        triggered = [f.get("description", f.get("rule_name", "")) for f in ctx.rule_flags[:5]]
        parts.append(f"Rule engine flags: {', '.join(triggered)}")
    parts.append(f"ML risk score: {ctx.ml_score:.2f}")
    return "\n\n".join(parts)


def _rule_only_fallback(ctx: ScanContext) -> ClassifierResult:
    blended = min(0.6 * ctx.rule_score + 0.4 * ctx.ml_score, 1.0)
    if blended >= 0.65:
        verdict = AgentVerdict.scam
    elif blended >= 0.35:
        verdict = AgentVerdict.suspicious
    else:
        verdict = AgentVerdict.safe

    categories = list({f.get("category", "") for f in ctx.rule_flags if f.get("category")})

    return ClassifierResult(
        agent_name="ClassifierAgent",
        success=True,
        llm_used="rule-only",
        verdict=verdict,
        confidence=round(blended, 3),
        label=verdict.value,
        reasoning="Classification derived from rule engine + ML signals (LLM unavailable).",
        scam_categories=categories,
    )


async def run(ctx: ScanContext) -> ClassifierResult:
    try:
        text, model = await call_llm_with_fallback(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=_build_user_prompt(ctx),
            max_tokens=256,
            temperature=0.1,
            json_mode=True,
        )
        data = safe_parse_json(text)

        raw_verdict = data.get("verdict", "safe").lower()
        verdict = AgentVerdict(raw_verdict) if raw_verdict in AgentVerdict._value2member_map_ else AgentVerdict.safe

        return ClassifierResult(
            agent_name="ClassifierAgent",
            success=True,
            llm_used=model,
            raw=text,
            verdict=verdict,
            confidence=float(data.get("confidence", 0.5)),
            label=verdict.value,
            reasoning=data.get("reasoning", ""),
            scam_categories=data.get("scam_categories", []),
        )

    except RuntimeError as e:
        logger.warning(f"[ClassifierAgent] All LLMs failed — rule-only fallback: {e}")
        return _rule_only_fallback(ctx)

    except Exception as e:
        logger.error(f"[ClassifierAgent] Unexpected error: {e}")
        result = _rule_only_fallback(ctx)
        result.error = str(e)
        return result
