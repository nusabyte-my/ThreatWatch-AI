"""
VerifierAgent — cross-checks ML score vs LLM verdict, flags sharp disagreements.
Runs in parallel with URLAnalystAgent (Step 2).
"""
from __future__ import annotations

import logging
from app.agents.base import AgentVerdict, ClassifierResult, ScanContext, VerifierResult
from app.agents.llm_client import call_llm_with_fallback, safe_parse_json

logger = logging.getLogger("threatwatch.agents.verifier")

SYSTEM_PROMPT = """You are a QA auditor for ThreatWatch AI. Cross-examine two independent \
assessments of the same message — one from a traditional ML classifier and one from an \
LLM classifier — then adjudicate the final verdict.

DISAGREEMENT TAXONOMY:
- "no_disagreement": Both align (both safe, or both scam/suspicious)
- "minor_disagreement": One says "suspicious", other says "safe" or "scam" → resolve to "suspicious"
- "major_disagreement": One says "safe", other says "scam" → flag as "uncertain", lower confidence
- "severity_gap": Same verdict label but confidence gap > 0.40 → note gap, use lower value

ADJUDICATION RULES:
1. ML scam (>0.65) + LLM safe → verdict "uncertain", flags_disagreement = true
2. LLM scam (>0.80) + ML safe (<0.35) → trust LLM, flags_disagreement = true
3. Both agree → agreement = true, average both scores
4. Both safe + high confidence → do NOT elevate verdict

OUTPUT — strict JSON, no other text:
{
  "ml_verdict": "safe" | "suspicious" | "scam",
  "llm_verdict": "safe" | "suspicious" | "scam",
  "agreement": true | false,
  "disagreement_severity": 0.0-1.0,
  "final_verdict": "safe" | "suspicious" | "scam" | "uncertain",
  "flags_disagreement": true | false,
  "adjudication_note": "One sentence explaining the decision."
}"""


def _ml_verdict_label(ml_score: float) -> str:
    if ml_score >= 0.65:
        return "scam"
    if ml_score >= 0.35:
        return "suspicious"
    return "safe"


def _build_user_prompt(ctx: ScanContext, classifier: ClassifierResult) -> str:
    return (
        f"ML risk score: {ctx.ml_score:.3f} (verdict: {_ml_verdict_label(ctx.ml_score)})\n"
        f"Rule engine score: {ctx.rule_score:.3f}\n"
        f"LLM verdict: {classifier.verdict.value} (confidence: {classifier.confidence:.3f})\n"
        f"LLM reasoning: {classifier.reasoning}\n"
        f"Triggered rule categories: {', '.join(set(f.get('category','') for f in ctx.rule_flags)) or 'none'}\n\n"
        f"Message (first 300 chars): {ctx.text[:300]}"
    )


def _rule_only_fallback(ctx: ScanContext, classifier: ClassifierResult) -> VerifierResult:
    ml_label = _ml_verdict_label(ctx.ml_score)
    llm_label = classifier.verdict.value
    agree = ml_label == llm_label
    severity = abs(ctx.ml_score - classifier.confidence)
    flags = not agree and severity > 0.3

    if flags:
        final = AgentVerdict.uncertain
    else:
        final = classifier.verdict

    return VerifierResult(
        agent_name="VerifierAgent",
        success=True,
        llm_used="rule-only",
        ml_verdict=ml_label,
        llm_verdict=llm_label,
        agreement=agree,
        disagreement_severity=round(severity, 3),
        final_verdict=final,
        flags_disagreement=flags,
        adjudication_note="Adjudication based on score comparison (LLM unavailable).",
    )


async def run(ctx: ScanContext, classifier: ClassifierResult) -> VerifierResult:
    try:
        text, model = await call_llm_with_fallback(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=_build_user_prompt(ctx, classifier),
            max_tokens=200,
            temperature=0.0,
            json_mode=True,
            llm_config=ctx.llm_config,
        )
        data = safe_parse_json(text)

        raw_final = data.get("final_verdict", "safe").lower()
        final_verdict = (
            AgentVerdict(raw_final)
            if raw_final in AgentVerdict._value2member_map_
            else AgentVerdict.safe
        )

        return VerifierResult(
            agent_name="VerifierAgent",
            success=True,
            llm_used=model,
            raw=text,
            ml_verdict=data.get("ml_verdict", _ml_verdict_label(ctx.ml_score)),
            llm_verdict=data.get("llm_verdict", classifier.verdict.value),
            agreement=bool(data.get("agreement", True)),
            disagreement_severity=float(data.get("disagreement_severity", 0.0)),
            final_verdict=final_verdict,
            flags_disagreement=bool(data.get("flags_disagreement", False)),
            adjudication_note=data.get("adjudication_note", ""),
        )

    except RuntimeError as e:
        logger.warning(f"[VerifierAgent] All LLMs failed — rule-only fallback: {e}")
        return _rule_only_fallback(ctx, classifier)

    except Exception as e:
        logger.error(f"[VerifierAgent] Unexpected error: {e}")
        result = _rule_only_fallback(ctx, classifier)
        result.error = str(e)
        return result
