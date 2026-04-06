"""
ExplainerAgent — generates plain-English user-facing explanation.
Runs last (Step 3, sequential) after all other agents have completed.
"""
from __future__ import annotations

import logging
from typing import Optional
from app.agents.base import (
    AgentVerdict, ClassifierResult, ExplainerResult,
    ScanContext, URLAnalystResult, VerifierResult,
)
from app.agents.llm_client import call_llm_with_fallback, safe_parse_json

logger = logging.getLogger("threatwatch.agents.explainer")

SYSTEM_PROMPT = """You are the user-facing explanation engine for ThreatWatch AI. \
Your audience is everyday Malaysian internet users — not security professionals. \
Translate technical threat findings into clear, empathetic, actionable English.

TONE GUIDELINES:
- "scam" verdict: direct, protective — tell the user exactly what NOT to do
- "suspicious" verdict: informative but not alarmist
- "safe" verdict: reassuring, brief — 1-2 sentences maximum
- Never condescending. Never blame the user for almost falling for a scam.

STRUCTURE (always this order):
1. Opening sentence: state verdict + primary reason
2. 1-2 sentences on specific signals found (or their absence)
3. One direct action instruction — be specific, not vague

CONTENT RULES:
- risk_factors: 2-4 most significant signals present (empty [] if safe)
- safe_indicators: 1-2 positive legitimacy signals (empty [] if scam)
- user_action must be specific. Examples:
  · SCAM: "Do NOT click the link. Report this to Maybank fraud at 1300-88-6688 \
or the National Scam Response Centre at 997."
  · SUSPICIOUS: "Do not share any personal details or click links until you verify \
this directly with the sender."
  · SAFE: "This message appears legitimate. No action needed."
- For OTP requests: ALWAYS include "Your bank will NEVER ask for your OTP."
- For investment scams: include SKIM warning (Securities Commission Malaysia)
- Mention specific Malaysian resources when relevant:
  · Maybank fraud: 1300-88-6688
  · CIMB fraud: 1300-88-2265
  · National Scam Response Centre (NSRC): 997
  · CCID Scam hotline: 03-2610-1559
  · Bank Negara Malaysia: 1300-88-5465

OUTPUT — strict JSON, no other text:
{
  "explanation": "2-3 sentences written for a non-technical user",
  "risk_factors": ["factor 1", "factor 2"],
  "safe_indicators": ["indicator 1"],
  "user_action": "Specific instruction for the user"
}"""


def _build_user_prompt(
    ctx: ScanContext,
    classifier: ClassifierResult,
    url_analyst: Optional[URLAnalystResult],
    verifier: VerifierResult,
) -> str:
    parts = [
        f"Channel: {ctx.channel}",
        f"Final verdict: {verifier.final_verdict.value}",
        f"ML risk score: {ctx.ml_score:.2f}",
        f"LLM classifier verdict: {classifier.verdict.value} (confidence: {classifier.confidence:.2f})",
        f"LLM reasoning: {classifier.reasoning}",
        f"Scam categories detected: {', '.join(classifier.scam_categories) or 'none'}",
        f"Agreement between ML and LLM: {verifier.agreement}",
    ]
    if verifier.flags_disagreement:
        parts.append(f"NOTE: disagreement detected — {verifier.adjudication_note}")

    if url_analyst and url_analyst.llm_used != "skipped":
        parts.append(f"URL analysis: domain={url_analyst.domain}, suspicious={url_analyst.is_suspicious}")
        if url_analyst.findings:
            parts.append(f"URL findings: {'; '.join(url_analyst.findings[:3])}")

    triggered_rules = [f.get("description", "") for f in ctx.rule_flags[:5] if f.get("description")]
    if triggered_rules:
        parts.append(f"Triggered rules: {'; '.join(triggered_rules)}")

    parts.append(f"\nMessage (first 400 chars):\n{ctx.text[:400]}")
    return "\n".join(parts)


def _rule_only_fallback(
    ctx: ScanContext,
    verifier: VerifierResult,
    url_analyst: Optional[URLAnalystResult],
) -> ExplainerResult:
    verdict = verifier.final_verdict
    rule_reasons = [f.get("description", "") for f in ctx.rule_flags[:3] if f.get("description")]
    url_findings = url_analyst.findings[:2] if url_analyst and url_analyst.findings else []

    if verdict == AgentVerdict.scam:
        explanation = (
            "This message shows multiple signs of a scam. "
            + (f"{rule_reasons[0]}. " if rule_reasons else "")
            + "Do not click any links or share personal information."
        )
        user_action = "Do NOT click any links. Report to the National Scam Response Centre at 997."
    elif verdict == AgentVerdict.suspicious:
        explanation = (
            "This message has some suspicious characteristics. "
            "Verify the sender's identity through an official channel before taking any action."
        )
        user_action = "Do not click links or share details until you independently verify the sender."
    elif verdict == AgentVerdict.uncertain:
        explanation = (
            "Our systems gave conflicting signals on this message. "
            "Treat it with caution and verify before acting."
        )
        user_action = "Verify directly with the purported sender through official contact details."
    else:
        explanation = "No significant threat indicators were detected in this message."
        user_action = "No action needed."

    return ExplainerResult(
        agent_name="ExplainerAgent",
        success=True,
        llm_used="rule-only",
        explanation=explanation,
        risk_factors=rule_reasons + url_findings,
        safe_indicators=[],
        user_action=user_action,
    )


async def run(
    ctx: ScanContext,
    classifier: ClassifierResult,
    url_analyst: Optional[URLAnalystResult],
    verifier: VerifierResult,
) -> ExplainerResult:
    if not ctx.include_explanation:
        return ExplainerResult(
            agent_name="ExplainerAgent",
            success=True,
            llm_used="skipped",
            explanation="",
        )

    try:
        text, model = await call_llm_with_fallback(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=_build_user_prompt(ctx, classifier, url_analyst, verifier),
            max_tokens=350,
            temperature=0.2,   # slightly higher for natural language
            json_mode=True,
        )
        data = safe_parse_json(text)

        return ExplainerResult(
            agent_name="ExplainerAgent",
            success=True,
            llm_used=model,
            raw=text,
            explanation=data.get("explanation", ""),
            risk_factors=data.get("risk_factors", []),
            safe_indicators=data.get("safe_indicators", []),
            user_action=data.get("user_action", ""),
        )

    except RuntimeError as e:
        logger.warning(f"[ExplainerAgent] All LLMs failed — rule-only fallback: {e}")
        return _rule_only_fallback(ctx, verifier, url_analyst)

    except Exception as e:
        logger.error(f"[ExplainerAgent] Unexpected error: {e}")
        result = _rule_only_fallback(ctx, verifier, url_analyst)
        result.error = str(e)
        return result
