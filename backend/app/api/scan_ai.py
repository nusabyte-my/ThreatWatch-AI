"""
POST /api/v1/scan/ai — multi-agent scan endpoint.
Runs existing ML + rule engine first, then the 4-agent LLM pipeline,
then blends both scores into a final result.
"""

import logging
from dataclasses import asdict
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import ScanContext
from app.agents.orchestrator import run_pipeline
from app.config import settings
from app.db.base import get_db
from app.db.models import Scan
from app.engine.scanner import scan as run_scan
from app.limiter import limiter

logger = logging.getLogger("threatwatch.api.scan_ai")

router = APIRouter(prefix="/api/v1", tags=["scan-ai"])


class AIScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    channel: str = Field(default="chat", pattern="^(email|sms|chat|url)$")
    url: Optional[str] = Field(default=None, max_length=2048)
    include_explanation: bool = Field(default=True)
    preferred_model: Optional[str] = Field(default=None, max_length=80)
    openai_api_key: Optional[str] = Field(default=None, max_length=400)
    anthropic_api_key: Optional[str] = Field(default=None, max_length=400)


@router.post("/scan/ai")
@limiter.limit("5/minute")
async def ai_scan(
    request: Request,
    req: AIScanRequest,
    db: AsyncSession = Depends(get_db),
):
    # ── Step 1: existing ML + rule engine (unchanged) ─────────────────────────
    try:
        base = await run_scan(
            text=req.text,
            channel=req.channel,
            url=req.url,
            db=db,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan engine failed: {exc}")

    # ── Step 2: agent pipeline (degrades gracefully if LLMs unavailable) ──────
    agent_block: dict[str, Any] = {
        "pipeline_mode": "disabled",
        "agents_used": [],
        "verdict": base["verdict"],
        "confidence": None,
        "explanation": None,
        "risk_factors": [],
        "safe_indicators": [],
        "user_action": None,
        "url_findings": [],
        "is_uncertain": False,
        "latency_ms": 0,
    }

    blended_score = base["risk_score"]
    blended_verdict = base["verdict"]

    if settings.agent_pipeline_enabled:
        try:
            ctx = ScanContext(
                text=req.text,
                channel=req.channel,
                url=req.url,
                ml_score=base["ml_score"],
                rule_score=base["rule_score"],
                rule_flags=base.get("flags", []),
                include_explanation=req.include_explanation,
                llm_config={
                    "preferred_model": req.preferred_model.strip() if req.preferred_model else None,
                    "openai_api_key": req.openai_api_key.strip() if req.openai_api_key else None,
                    "anthropic_api_key": req.anthropic_api_key.strip() if req.anthropic_api_key else None,
                },
            )

            pipeline = await run_pipeline(ctx)

            blended_score = pipeline.blended_risk_score
            blended_verdict = pipeline.final_verdict.value

            agent_block = {
                "pipeline_mode": pipeline.pipeline_mode,
                "agents_used": pipeline.agents_used,
                "verdict": pipeline.final_verdict.value,
                "confidence": pipeline.agent_confidence,
                "explanation": pipeline.explainer.explanation if pipeline.explainer else None,
                "risk_factors": pipeline.explainer.risk_factors if pipeline.explainer else [],
                "safe_indicators": pipeline.explainer.safe_indicators if pipeline.explainer else [],
                "user_action": pipeline.explainer.user_action if pipeline.explainer else None,
                "url_findings": pipeline.url_analyst.findings if pipeline.url_analyst else [],
                "is_uncertain": pipeline.verifier.flags_disagreement if pipeline.verifier else False,
                "latency_ms": pipeline.total_latency_ms,
                # Verifier detail
                "verifier": {
                    "ml_verdict": pipeline.verifier.ml_verdict,
                    "llm_verdict": pipeline.verifier.llm_verdict,
                    "agreement": pipeline.verifier.agreement,
                    "adjudication_note": pipeline.verifier.adjudication_note,
                } if pipeline.verifier else None,
            }

            # ── Persist agent_analysis to the scan record ─────────────────
            try:
                scan_record = await db.get(Scan, base["scan_id"])
                if scan_record:
                    scan_record.agent_analysis = _serialise(pipeline)
                    scan_record.risk_score = blended_score
                    await db.commit()
            except Exception as persist_err:
                logger.warning(f"[scan_ai] Failed to persist agent_analysis: {persist_err}")

        except Exception as exc:
            logger.error(f"[scan_ai] Agent pipeline error (returning base result): {exc}")
            agent_block["pipeline_mode"] = "error"
            agent_block["error"] = str(exc)

    return {
        "scan_id": base["scan_id"],
        "verdict": blended_verdict,
        "risk_score": blended_score,
        "risk_percent": int(blended_score * 100),
        "ml_score": base["ml_score"],
        "rule_score": base["rule_score"],
        "reasons": base["reasons"],
        "highlighted_tokens": base["highlighted_tokens"],
        "channel": req.channel,
        "agent": agent_block,
    }


def _serialise(pipeline) -> dict:
    """Convert AgentPipelineResult to a JSON-safe dict for PostgreSQL storage."""

    def _safe(obj):
        """Recursively convert enums to .value, drop 'raw' keys, handle nested dicts/lists."""
        if obj is None:
            return None
        if isinstance(obj, dict):
            return {k: _safe(v) for k, v in obj.items() if k != "raw"}
        if isinstance(obj, list):
            return [_safe(i) for i in obj]
        if hasattr(obj, "value"):   # Enum instance
            return obj.value
        return obj

    def _dc(obj):
        if obj is None:
            return None
        try:
            return _safe(asdict(obj))
        except Exception:
            return {}

    return {
        "pipeline_mode": pipeline.pipeline_mode,
        "final_verdict": pipeline.final_verdict.value,
        "agent_confidence": pipeline.agent_confidence,
        "llm_risk_score": pipeline.llm_risk_score,
        "blended_risk_score": pipeline.blended_risk_score,
        "agents_used": pipeline.agents_used,
        "total_latency_ms": pipeline.total_latency_ms,
        "classifier": _dc(pipeline.classifier),
        "url_analyst": _dc(pipeline.url_analyst),
        "verifier": _dc(pipeline.verifier),
        "explainer": _dc(pipeline.explainer),
    }
