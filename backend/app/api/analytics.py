from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.db.models import Scan

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


def _iso_day(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date().isoformat()


@router.get("/summary")
async def get_analytics_summary(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(desc(Scan.created_at)).limit(250))
    scans = result.scalars().all()

    total = len(scans)
    verdict_counts = Counter(scan.verdict.value for scan in scans)
    channel_counts = Counter(scan.channel.value for scan in scans)
    feedback_counts = Counter(scan.user_feedback for scan in scans if scan.user_feedback)

    avg_risk = round(sum(scan.risk_score or 0 for scan in scans) / total, 3) if total else 0.0
    ai_usage = sum(1 for scan in scans if scan.agent_analysis)

    channel_breakdown = []
    for channel in ("email", "chat", "sms", "url"):
        matching = [scan for scan in scans if scan.channel.value == channel]
        channel_verdicts = Counter(scan.verdict.value for scan in matching)
        channel_breakdown.append(
            {
                "channel": channel,
                "total": len(matching),
                "safe": channel_verdicts.get("safe", 0),
                "suspicious": channel_verdicts.get("suspicious", 0),
                "scam": channel_verdicts.get("scam", 0),
            }
        )

    today = datetime.now(timezone.utc).date()
    trend_map: dict[str, dict[str, int]] = {}
    for offset in range(6, -1, -1):
        day = (today - timedelta(days=offset)).isoformat()
        trend_map[day] = {"date": day, "safe": 0, "suspicious": 0, "scam": 0, "total": 0}

    for scan in scans:
        day = _iso_day(scan.created_at)
        if day not in trend_map:
            continue
        trend_map[day][scan.verdict.value] += 1
        trend_map[day]["total"] += 1

    reason_counts: Counter[str] = Counter()
    token_counts: Counter[str] = Counter()
    threat_categories: Counter[str] = Counter()

    for scan in scans:
        for reason in (scan.reasons or [])[:6]:
            cleaned = str(reason).strip()
            if cleaned:
                reason_counts[cleaned] += 1
        for token in (scan.highlighted_tokens or [])[:10]:
            cleaned = str(token).strip()
            if cleaned:
                token_counts[cleaned] += 1
        agent_analysis = scan.agent_analysis or {}
        for category in agent_analysis.get("scam_categories", [])[:5]:
            cleaned = str(category).strip()
            if cleaned:
                threat_categories[cleaned] += 1

    recent_incidents = []
    for scan in scans[:8]:
        agent_analysis = scan.agent_analysis or {}
        recent_incidents.append(
            {
                "id": scan.id,
                "created_at": scan.created_at.isoformat(),
                "channel": scan.channel.value,
                "verdict": scan.verdict.value,
                "risk_percent": int((scan.risk_score or 0) * 100),
                "headline": (scan.input_text or "").replace("\n", " ").strip()[:140],
                "reasons": list(scan.reasons or [])[:3],
                "highlights": list(scan.highlighted_tokens or [])[:5],
                "recommendation": agent_analysis.get("user_action"),
                "explanation": agent_analysis.get("explanation"),
            }
        )

    return {
        "overview": {
            "total_scans": total,
            "safe": verdict_counts.get("safe", 0),
            "suspicious": verdict_counts.get("suspicious", 0),
            "scam": verdict_counts.get("scam", 0),
            "avg_risk_score": avg_risk,
            "ai_usage": ai_usage,
        },
        "channel_breakdown": channel_breakdown,
        "verdict_trend": list(trend_map.values()),
        "top_reasons": [{"label": label, "count": count} for label, count in reason_counts.most_common(6)],
        "top_tokens": [{"label": label, "count": count} for label, count in token_counts.most_common(8)],
        "threat_categories": [{"label": label, "count": count} for label, count in threat_categories.most_common(6)],
        "feedback": {
            "correct": feedback_counts.get("correct", 0),
            "false_positive": feedback_counts.get("false_positive", 0),
            "false_negative": feedback_counts.get("false_negative", 0),
        },
        "recent_incidents": recent_incidents,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
