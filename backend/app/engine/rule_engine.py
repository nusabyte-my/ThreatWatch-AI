"""
Rule engine — loads active rules from PostgreSQL, evaluates them against input.
Returns list of triggered flags + cumulative rule score.
"""
import logging
import re
from typing import List

import httpx
import tldextract
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models import Rule, SuspiciousDomain
from app.config import settings

logger = logging.getLogger("threatwatch.rule_engine")

# Compiled pattern cache — keyed by (rule_id, pattern) to avoid re-compiling on every request.
# Rules are DB-backed and change infrequently; this cache survives for the process lifetime.
_pattern_cache: dict[tuple[int, str], re.Pattern] = {}

_IP_URL_RE = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")


def _get_pattern(rule_id: int, pattern: str) -> re.Pattern:
    key = (rule_id, pattern)
    if key not in _pattern_cache:
        _pattern_cache[key] = re.compile(pattern, re.IGNORECASE)
    return _pattern_cache[key]


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
            m = _get_pattern(rule.id, rule.pattern).search(combined_input)
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
        url_flags.extend(await _check_google_safe_browsing(url))
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

    if _IP_URL_RE.match(url):
        flags.append({
            "flag_type": "url",
            "rule_name": "ip_address_url",
            "value": url[:80],
            "weight": 0.35,
            "description": "URL uses raw IP address — strong phishing indicator",
            "category": "url",
        })

    return flags


async def _check_google_safe_browsing(url: str) -> list:
    """
    Optional Google Safe Browsing v4 lookup.
    Returns zero flags when the API key is not configured or the lookup fails.
    """
    api_key = settings.google_safe_browsing_key.strip()
    if not api_key or not url:
        return []

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )
    payload = {
        "client": {
            "clientId": "threatwatch-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.google_safe_browsing_timeout) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning(f"[rule_engine] Safe Browsing lookup failed: {type(exc).__name__}: {exc}")
        return []

    matches = data.get("matches") or []
    if not matches:
        return []

    threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    threat_summary = ", ".join(t.lower().replace("_", " ") for t in threat_types[:3])

    return [{
        "flag_type": "url",
        "rule_name": "google_safe_browsing",
        "value": url[:500],
        "weight": 0.50,
        "description": (
            "Google Safe Browsing flagged this URL"
            + (f" ({threat_summary})" if threat_summary else "")
        ),
        "category": "url",
    }]
