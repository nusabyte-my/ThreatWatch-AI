"""
POST /api/v1/scan/upload — parse a forwarded .eml file and scan it.
Uses Python's built-in `email` module — no extra dependency.
Extracts: Subject, From, body text, and any URLs found in body.
Then feeds into the standard scan engine.
"""
import email
import email.policy
import re
import logging
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.engine.scanner import scan as run_scan
from app.limiter import limiter

logger = logging.getLogger("threatwatch.api.upload")

router = APIRouter(prefix="/api/v1", tags=["upload"])

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
MAX_EML_SIZE = 2 * 1024 * 1024   # 2 MB


@router.post("/scan/upload")
@limiter.limit("10/minute")
async def scan_eml(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    # ── Validate file ─────────────────────────────────────────────────────────
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")

    raw = await file.read()
    if len(raw) > MAX_EML_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum 2 MB.")

    # ── Parse .eml ────────────────────────────────────────────────────────────
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse .eml file: {exc}")

    subject = str(msg.get("subject", "")).strip()
    sender  = str(msg.get("from", "")).strip()
    date    = str(msg.get("date", "")).strip()
    body    = _extract_body(msg)

    if not body and not subject:
        raise HTTPException(status_code=422, detail="Email has no readable text content.")

    # ── Build scan text ───────────────────────────────────────────────────────
    parts: list[str] = []
    if sender:
        parts.append(f"From: {sender}")
    if subject:
        parts.append(f"Subject: {subject}")
    if body:
        parts.append(body[:4000])   # cap at 4000 chars

    scan_text = "\n".join(parts)

    # Extract first URL found in body (passed to URL analyst)
    urls = _URL_RE.findall(body or "")
    first_url: Optional[str] = urls[0][:2048] if urls else None

    # ── Run scan engine ───────────────────────────────────────────────────────
    try:
        result = await run_scan(
            text=scan_text,
            channel="email",
            url=first_url,
            db=db,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")

    return {
        **result,
        "source": "eml_upload",
        "email_metadata": {
            "from": sender,
            "subject": subject,
            "date": date,
            "urls_found": len(urls),
            "first_url": first_url,
            "body_length": len(body or ""),
        },
    }


def _extract_body(msg) -> str:
    """
    Walk the MIME tree and return plain text body.
    Falls back to stripping HTML if no plain part exists.
    """
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get_content_disposition() or "")
            if "attachment" in disp:
                continue
            if ct == "text/plain":
                plain_parts.append(_decode_part(part))
            elif ct == "text/html":
                html_parts.append(_decode_part(part))
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            plain_parts.append(_decode_part(msg))
        elif ct == "text/html":
            html_parts.append(_decode_part(msg))

    if plain_parts:
        return "\n".join(plain_parts).strip()

    # Strip HTML tags as last resort
    if html_parts:
        raw_html = "\n".join(html_parts)
        return re.sub(r"<[^>]+>", " ", raw_html).strip()

    return ""


def _decode_part(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        return str(payload or "")
    except Exception:
        return ""
