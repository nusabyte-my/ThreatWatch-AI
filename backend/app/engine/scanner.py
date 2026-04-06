"""
Core scan orchestrator — combines ML score + rule score → final verdict.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from app.ml.predictor import predict_ml
from app.engine.rule_engine import evaluate as rule_evaluate
from app.db.models import Scan, ScanFlag, VerdictType, ChannelType


SCAM_THRESHOLD = 0.65
SUSPICIOUS_THRESHOLD = 0.35


def _blend(ml_score: float, rule_score: float) -> float:
    """
    Final risk = 60% rule engine + 40% ML.
    Rule engine is weighted higher because it's more interpretable and domain-specific.
    """
    return round(min(0.6 * rule_score + 0.4 * ml_score, 1.0), 4)


def _verdict(score: float) -> VerdictType:
    if score >= SCAM_THRESHOLD:
        return VerdictType.scam
    if score >= SUSPICIOUS_THRESHOLD:
        return VerdictType.suspicious
    return VerdictType.safe


async def scan(
    text: str,
    channel: str,
    url: str | None,
    db: AsyncSession,
) -> dict:
    # 1. ML prediction
    ml_result = predict_ml(text)
    ml_score = ml_result["scam_prob"]

    # 2. Rule engine
    rule_result = await rule_evaluate(text, url, db)
    rule_score = rule_result["rule_score"]

    # 3. Blend
    final_score = _blend(ml_score, rule_score)
    verdict = _verdict(final_score)

    # 4. Persist
    scan_obj = Scan(
        channel=ChannelType(channel),
        input_text=text[:4000],
        input_url=url,
        verdict=verdict,
        risk_score=final_score,
        ml_score=ml_score,
        rule_score=rule_score,
        reasons=rule_result["reasons"],
        highlighted_tokens=rule_result["highlighted_tokens"],
    )
    db.add(scan_obj)
    await db.flush()  # get scan_obj.id without committing

    for flag in rule_result["flags"]:
        db.add(ScanFlag(
            scan_id=scan_obj.id,
            flag_type=flag["flag_type"],
            value=flag["value"][:500],
            weight=flag["weight"],
            description=flag.get("description", ""),
        ))

    await db.commit()
    await db.refresh(scan_obj)

    return {
        "scan_id": scan_obj.id,
        "verdict": verdict.value,
        "risk_score": final_score,
        "risk_percent": int(final_score * 100),
        "ml_score": ml_score,
        "rule_score": rule_score,
        "reasons": rule_result["reasons"],
        "highlighted_tokens": rule_result["highlighted_tokens"],
        "channel": channel,
    }
