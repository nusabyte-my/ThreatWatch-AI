"""
POST /api/v1/scan/upload — parse a forwarded email file (.eml, .msg, .mbox) and scan it.
Uses Python's built-in `email` / `mailbox` modules + `extract-msg` for Outlook .msg files.
Extracts: Subject, From, body text, and any URLs found in body.
Then feeds into the standard scan engine.
"""
import email
import email.policy
import mailbox
import io
import re
import logging
from typing import Optional

try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except ImportError:
    HAS_EXTRACT_MSG = False

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.engine.scanner import scan as run_scan
from app.limiter import limiter

logger = logging.getLogger("threatwatch.api.upload")

router = APIRouter(prefix="/api/v1", tags=["upload"])

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
MAX_EML_SIZE = 2 * 1024 * 1024   # 2 MB
MAX_MSG_SIZE = 5 * 1024 * 1024   # 5 MB (Outlook files can be larger)
MAX_MBOX_SIZE = 5 * 1024 * 1024  # 5 MB

SUPPORTED_EXTENSIONS = (".eml", ".msg", ".mbox")


@router.post("/scan/upload")
@limiter.limit("10/minute")
async def scan_email(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    # ── Validate file ─────────────────────────────────────────────────────────
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    ext = file.filename.lower().split(".")[-1]
    if f".{ext}" not in SUPPORTED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type .{ext}. Supported: {', '.join(SUPPORTED_EXTENSIONS)}")

    raw = await file.read()

    # ── Parse email based on format ───────────────────────────────────────────
    if ext == "msg":
        if len(raw) > MAX_MSG_SIZE:
            raise HTTPException(status_code=413, detail="File too large. Maximum 5 MB.")
        sender, subject, date, body = _parse_msg(raw)
    elif ext == "mbox":
        if len(raw) > MAX_MBOX_SIZE:
            raise HTTPException(status_code=413, detail="File too large. Maximum 5 MB.")
        sender, subject, date, body = _parse_mbox(raw)
    else:
        if len(raw) > MAX_EML_SIZE:
            raise HTTPException(status_code=413, detail="File too large. Maximum 2 MB.")
        sender, subject, date, body = _parse_eml(raw)

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
        "source": f"{ext}_upload",
        "email_metadata": {
            "from": sender,
            "subject": subject,
            "date": date,
            "urls_found": len(urls),
            "first_url": first_url,
            "body_length": len(body or ""),
            "file_format": ext,
        },
    }


def _parse_eml(raw: bytes) -> tuple[str, str, str, str]:
    """Parse .eml (RFC 822 / MIME) bytes → (from, subject, date, body)."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse .eml file: {exc}")

    subject = str(msg.get("subject", "")).strip()
    sender  = str(msg.get("from", "")).strip()
    date    = str(msg.get("date", "")).strip()
    body    = _extract_body(msg)
    return sender, subject, date, body


def _parse_msg(raw: bytes) -> tuple[str, str, str, str]:
    """Parse Outlook .msg file → (from, subject, date, body)."""
    if not HAS_EXTRACT_MSG:
        raise HTTPException(
            status_code=501,
            detail="Outlook .msg parsing requires the 'extract-msg' package. "
                   "Install it: pip install extract-msg",
        )
    try:
        msg = extract_msg.openMsg(io.BytesIO(raw))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse .msg file: {exc}")

    sender  = str(getattr(msg, "sender", "") or "").strip()
    subject = str(getattr(msg, "subject", "") or "").strip()
    date    = str(getattr(msg, "date", "") or "").strip()
    body    = str(getattr(msg, "body", "") or "").strip()

    # Fallback: try RTF / HTML body if plain body is empty
    if not body:
        html_body = str(getattr(msg, "htmlBody", "") or "")
        if html_body:
            body = re.sub(r"<[^>]+>", " ", html_body).strip()

    return sender, subject, date, body


def _parse_mbox(raw: bytes) -> tuple[str, str, str, str]:
    """Parse .mbox mailbox file → returns the FIRST email's metadata.

    .mbox can contain many emails; we extract the first one for scanning.
    """
    try:
        mbox = mailbox.mbox(io.BytesIO(raw))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse .mbox file: {exc}")

    if len(mbox) == 0:
        raise HTTPException(status_code=422, detail="The .mbox file contains no emails.")

    msg = mbox[0]  # first message in the mailbox

    subject = str(msg.get("subject", "")).strip()
    sender  = str(msg.get("from", "")).strip()
    date    = str(msg.get("date", "")).strip()
    body    = _extract_body(msg)
    return sender, subject, date, body


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
