import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Optional

import bcrypt

logger = logging.getLogger("threatwatch.auth")

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.config import settings

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(payload: dict) -> str:
    body = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = hmac.new(settings.secret_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(sig)}"


def _verify_token(token: str) -> Optional[dict]:
    try:
        body, sig = token.split(".", 1)
        expected_sig = _b64url(
            hmac.new(settings.secret_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        )
        if not secrets.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(_b64url_decode(body))
        if not isinstance(payload, dict):
            return None
        exp = int(payload.get("exp", 0))
        if exp < int(time.time()):
            return None
        role = str(payload.get("role", "")).lower()
        username = str(payload.get("sub", "")).strip().lower()
        if role not in ROLE_RANK or not username:
            return None
        return {"username": username, "role": role, "exp": exp}
    except Exception:
        return None


def _find_user(username: str) -> Optional[dict]:
    needle = username.strip().lower()
    for user in settings.auth_users:
        if user["username"] == needle:
            return user
    return None


def _verify_password(candidate: str, expected: str) -> bool:
    """
    Verify a password against a stored value.
    If `expected` is a bcrypt hash (starts with $2b$ or $2a$), use bcrypt.checkpw.
    Otherwise fall back to constant-time plaintext compare (legacy — log a warning).
    Passwords in AUTH_USERS_JSON should be bcrypt hashes:
        python -c "import bcrypt; print(bcrypt.hashpw(b'yourpass', bcrypt.gensalt()).decode())"
    """
    if expected.startswith(("$2b$", "$2a$", "$2y$")):
        try:
            return bcrypt.checkpw(candidate.encode("utf-8"), expected.encode("utf-8"))
        except Exception:
            return False
    # Plaintext fallback — warn so operators know to upgrade
    logger.warning(
        "AUTH: plaintext password comparison used — store bcrypt hashes in AUTH_USERS_JSON"
    )
    return secrets.compare_digest(candidate, expected)


@router.post("/login")
async def login(req: LoginRequest):
    user = _find_user(req.username)
    if not user or not _verify_password(req.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    issued_at = int(time.time())
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": issued_at,
        "exp": issued_at + max(60, settings.auth_token_ttl_minutes * 60),
    }
    token = _sign(payload)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": user["username"], "role": user["role"]},
        "expires_in": payload["exp"] - issued_at,
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict:
    if not settings.auth_enabled:
        return {"username": "local-admin", "role": "admin", "auth_type": "disabled"}

    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    payload = _verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    return {
        "username": payload["username"],
        "role": payload["role"],
        "auth_type": "bearer",
    }


async def require_api_key(x_api_key: str | None = Header(default=None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    return {"username": "legacy-api-key", "role": "admin", "auth_type": "api_key"}


def require_role(required_role: str):
    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(security),
        x_api_key: str | None = Header(default=None),
    ):
        user = None

        if credentials and credentials.scheme.lower() == "bearer":
            payload = _verify_token(credentials.credentials)
            if payload:
                user = {"username": payload["username"], "role": payload["role"], "auth_type": "bearer"}
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
        elif x_api_key:
            user = await require_api_key(x_api_key)
        elif not settings.auth_enabled:
            user = {"username": "local-admin", "role": "admin", "auth_type": "disabled"}
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

        if ROLE_RANK[user["role"]] < ROLE_RANK[required_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": user}
