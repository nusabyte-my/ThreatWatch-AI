"""Admin endpoints for managing rules — no auth for hackathon demo."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.base import get_db
from app.db.models import Rule

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


class RuleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    pattern: str = Field(..., min_length=1, max_length=500)
    pattern_type: str = Field(default="regex", pattern="^(keyword|regex|combo)$")
    weight: float = Field(default=0.2, ge=0.0, le=1.0)
    description: Optional[str] = None
    category: Optional[str] = None


@router.get("")
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Rule).order_by(Rule.category, Rule.name))
    rules = result.scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "pattern": r.pattern,
            "pattern_type": r.pattern_type,
            "weight": r.weight,
            "description": r.description,
            "category": r.category,
            "is_active": r.is_active,
        }
        for r in rules
    ]


@router.post("")
async def create_rule(req: RuleCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Rule).where(Rule.name == req.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Rule name already exists")
    rule = Rule(**req.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {"id": rule.id, "name": rule.name, "status": "created"}


@router.patch("/{rule_id}/toggle")
async def toggle_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.is_active = not rule.is_active
    await db.commit()
    return {"id": rule.id, "name": rule.name, "is_active": rule.is_active}


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    return {"status": "deleted", "id": rule_id}
