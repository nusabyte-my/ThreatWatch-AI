from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.db.base import get_db
from app.db.models import Scan, VerdictType
from app.engine.scanner import scan as run_scan

router = APIRouter(prefix="/api/v1", tags=["scan"])


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    channel: str = Field(default="chat", pattern="^(email|sms|chat|url)$")
    url: Optional[str] = Field(default=None, max_length=2048)


class FeedbackRequest(BaseModel):
    feedback: str = Field(..., pattern="^(correct|false_positive|false_negative)$")


@router.post("/scan")
async def scan_message(req: ScanRequest, db: AsyncSession = Depends(get_db)):
    try:
        result = await run_scan(
            text=req.text,
            channel=req.channel,
            url=req.url,
            db=db,
        )
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/{scan_id}/feedback")
async def submit_feedback(scan_id: int, req: FeedbackRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.user_feedback = req.feedback
    await db.commit()
    return {"status": "ok", "scan_id": scan_id, "feedback": req.feedback}


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id,
        "verdict": scan.verdict.value,
        "risk_score": scan.risk_score,
        "risk_percent": int(scan.risk_score * 100),
        "ml_score": scan.ml_score,
        "rule_score": scan.rule_score,
        "reasons": scan.reasons,
        "highlighted_tokens": scan.highlighted_tokens,
        "channel": scan.channel.value,
        "user_feedback": scan.user_feedback,
        "created_at": scan.created_at.isoformat(),
    }


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count()).select_from(Scan))
    scam_count = await db.scalar(
        select(func.count()).select_from(Scan).where(Scan.verdict == VerdictType.scam)
    )
    suspicious_count = await db.scalar(
        select(func.count()).select_from(Scan).where(Scan.verdict == VerdictType.suspicious)
    )
    avg_score = await db.scalar(select(func.avg(Scan.risk_score)).select_from(Scan))

    recent_result = await db.execute(
        select(Scan).order_by(desc(Scan.created_at)).limit(5)
    )
    recent = recent_result.scalars().all()

    return {
        "total_scans": total or 0,
        "scam_detected": scam_count or 0,
        "suspicious": suspicious_count or 0,
        "safe": (total or 0) - (scam_count or 0) - (suspicious_count or 0),
        "avg_risk_score": round(float(avg_score or 0), 3),
        "recent_scans": [
            {
                "id": s.id,
                "verdict": s.verdict.value,
                "risk_percent": int(s.risk_score * 100),
                "channel": s.channel.value,
                "created_at": s.created_at.isoformat(),
            }
            for s in recent
        ],
    }


@router.get("/health")
async def health():
    return {"status": "ok", "service": "threatwatch-api"}
