"""
Rule engine — loads active rules from PostgreSQL, evaluates them against input.
Returns list of triggered flags + cumulative rule score.
"""
import re
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Rule, SuspiciousDomain


async def evaluate(text: str, url: str | None, db: AsyncSession) -> dict:
    """
    Returns:
        {
            "rule_score": float,       # 0.0–1.0 (capped)
            "flags": List[dict],       # each triggered rule
            "reasons": List[str],      # human-readable
            "highlighted_tokens": List[str],
        }
    """
    result = await db.execute(select(Rule).where(Rule.is_active == True))
    rules: List[Rule] = result.scalars().all()

    flags = []
    reasons = []
    highlights = []
    cumulative = 0.0

    combined_input = (text + " " + (url or "")).lower()

    for rule in rules:
        matched = False
        matched_value = ""

        if rule.pattern_type in ("regex", "combo"):
            m = re.search(rule.pattern, combined_input, re.IGNORECASE)
            if m:
                matched = True
                matched_value = m.group(0)
        else:  # keyword
            if rule.pattern.lower() in combined_input:
                matched = True
                matched_value = rule.pattern

        if matched:
            flags.append({
                "flag_type": "pattern",
                "rule_name": rule.name,
                "value": matched_value,
                "weight": rule.weight,
                "description": rule.description,
                "category": rule.category,
            })
            reasons.append(rule.description)
            highlights.append(matched_value)
            cumulative += rule.weight

    # URL domain check
    if url:
        url_flags = await _check_url(url, db)
        flags.extend(url_flags)
        for f in url_flags:
            reasons.append(f["description"])
            highlights.append(f["value"])
            cumulative += f["weight"]

    return {
        "rule_score": min(round(cumulative, 4), 1.0),
        "flags": flags,
        "reasons": reasons[:10],          # cap for display
        "highlighted_tokens": list(set(highlights))[:15],
    }


async def _check_url(url: str, db: AsyncSession) -> list:
    import tldextract
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    full_domain = f"{ext.subdomain}.{domain}" if ext.subdomain else domain

    flags = []

    result = await db.execute(
        select(SuspiciousDomain).where(
            SuspiciousDomain.domain.in_([domain, full_domain, f"*.{ext.suffix}"])
        )
    )
    matches = result.scalars().all()
    for m in matches:
        flags.append({
            "flag_type": "url",
            "rule_name": f"domain_{m.reason}",
            "value": domain,
            "weight": m.risk_weight,
            "description": f"Domain flagged: {m.reason.replace('_', ' ')} ({domain})",
            "category": "url",
        })

    # IP address URL
    import re
    if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        flags.append({
            "flag_type": "url",
            "rule_name": "ip_address_url",
            "value": url[:80],
            "weight": 0.35,
            "description": "URL uses raw IP address — strong phishing indicator",
            "category": "url",
        })

    return flags
