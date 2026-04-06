"""
URLAnalystAgent — deep URL structural analysis.
Runs in parallel with VerifierAgent (Step 2).
Skipped entirely if ctx.url is None.
"""
from __future__ import annotations

import logging
import re
from typing import Optional
from app.agents.base import ScanContext, URLAnalystResult
from app.agents.llm_client import call_llm_with_fallback, safe_parse_json

logger = logging.getLogger("threatwatch.agents.url_analyst")

SYSTEM_PROMPT = """You are a cybersecurity URL analyst for ThreatWatch AI.

ANALYSIS FRAMEWORK:
1. Domain legitimacy
   - Lookalike domains: maybank2u-login.com vs maybank2u.com.my
   - Hyphen abuse: pay-dhl-customs.com
   - Subdomain abuse: maybank.evil.com (brand in subdomain, not root)
   - TLD mismatch: Malaysian legitimate services use .com.my / .gov.my — not .xyz/.top/.click/.tk

2. Structural red flags
   - Raw IP address as hostname (e.g. http://103.45.67.89/login)
   - Excessively encoded or obfuscated parameters
   - Suspicious keywords in path: /login /verify /secure /update /confirm when domain is not the real brand

3. URL shorteners — bit.ly, tinyurl.com, t.co, ow.ly, rb.gy, goo.gl, short.io
   - Always flag: destination hidden, high phishing risk

4. Legitimate signals (reduce suspicion)
   - HTTPS on a globally known domain (google.com, microsoft.com, shopee.com, lazada.com, gov.my)
   - Standard path matching known service

OUTPUT — strict JSON, no other text:
{
  "domain": "extracted root domain",
  "is_suspicious": true | false,
  "url_risk_score": 0.0-1.0,
  "redirect_detected": true | false,
  "lookalike_domain": true | false,
  "findings": ["up to 5 findings, most severe first, each ≤ 80 chars"]
}

RULES:
- url_risk_score ≥ 0.80 only for IP-address URLs or confirmed lookalike domains
- Known legitimate services get url_risk_score ≤ 0.10
- Base analysis on URL structure only — never fabricate external reputation data
- findings list: empty array [] if nothing suspicious"""


_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "short.io", "is.gd", "buff.ly", "tiny.cc",
}
_SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".online", ".tk", ".ml", ".ga", ".cf"}
_IP_URL_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")


def _extract_domain_signals(url: str) -> dict:
    try:
        import tldextract
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        is_shortener = domain in _SHORTENERS
        is_suspicious_tld = any(url.lower().endswith(t) or f"{t}/" in url.lower() for t in _SUSPICIOUS_TLDS)
        is_ip = bool(_IP_URL_RE.match(url))
        has_subdomain = bool(ext.subdomain) and ext.subdomain != "www"
        return {
            "domain": domain,
            "subdomain": ext.subdomain,
            "tld": ext.suffix,
            "is_shortener": is_shortener,
            "is_suspicious_tld": is_suspicious_tld,
            "is_ip": is_ip,
            "has_subdomain": has_subdomain,
        }
    except Exception:
        return {"domain": url[:50], "is_shortener": False, "is_suspicious_tld": False, "is_ip": False}


def _rule_only_fallback(ctx: ScanContext) -> URLAnalystResult:
    if not ctx.url:
        return URLAnalystResult(agent_name="URLAnalystAgent", success=True, llm_used="rule-only")

    signals = _extract_domain_signals(ctx.url)
    findings: list[str] = []
    score = 0.0

    if signals.get("is_shortener"):
        findings.append(f"{signals['domain']} is a URL shortener — destination hidden")
        score += 0.30
    if signals.get("is_ip"):
        findings.append("URL uses raw IP address — strong phishing indicator")
        score += 0.35
    if signals.get("is_suspicious_tld"):
        findings.append(f"Suspicious TLD: .{signals.get('tld', '')}")
        score += 0.25
    if signals.get("has_subdomain"):
        findings.append(f"Subdomain present: {signals.get('subdomain', '')} — check for brand abuse")
        score += 0.10

    score = min(score, 1.0)

    return URLAnalystResult(
        agent_name="URLAnalystAgent",
        success=True,
        llm_used="rule-only",
        domain=signals.get("domain"),
        is_suspicious=score >= 0.25,
        url_risk_score=round(score, 3),
        findings=findings,
        redirect_detected=signals.get("is_shortener", False),
        lookalike_domain=False,
    )


async def run(ctx: ScanContext) -> URLAnalystResult:
    if not ctx.url:
        return URLAnalystResult(agent_name="URLAnalystAgent", success=True, llm_used="skipped")

    signals = _extract_domain_signals(ctx.url)
    user_prompt = (
        f"URL: {ctx.url}\n\n"
        f"Pre-extracted signals:\n"
        f"  domain: {signals.get('domain')}\n"
        f"  subdomain: {signals.get('subdomain', 'none')}\n"
        f"  tld: .{signals.get('tld', '')}\n"
        f"  is_url_shortener: {signals.get('is_shortener')}\n"
        f"  is_ip_address: {signals.get('is_ip')}\n"
        f"  suspicious_tld: {signals.get('is_suspicious_tld')}\n\n"
        f"Channel: {ctx.channel}\n"
        f"Message context (first 200 chars): {ctx.text[:200]}"
    )

    try:
        text, model = await call_llm_with_fallback(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            max_tokens=256,
            temperature=0.0,
            json_mode=True,
            llm_config=ctx.llm_config,
        )
        data = safe_parse_json(text)

        return URLAnalystResult(
            agent_name="URLAnalystAgent",
            success=True,
            llm_used=model,
            raw=text,
            domain=data.get("domain", signals.get("domain")),
            is_suspicious=bool(data.get("is_suspicious", False)),
            url_risk_score=float(data.get("url_risk_score", 0.0)),
            findings=data.get("findings", []),
            redirect_detected=bool(data.get("redirect_detected", False)),
            lookalike_domain=bool(data.get("lookalike_domain", False)),
        )

    except RuntimeError as e:
        logger.warning(f"[URLAnalystAgent] All LLMs failed — rule-only fallback: {e}")
        return _rule_only_fallback(ctx)

    except Exception as e:
        logger.error(f"[URLAnalystAgent] Unexpected error: {e}")
        result = _rule_only_fallback(ctx)
        result.error = str(e)
        return result
