import subprocess
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.scan import router as scan_router
from app.api.scan_ai import router as scan_ai_router
from app.api.upload import router as upload_router
from app.api.auth import router as auth_router
from app.api.rules import router as rules_router
from app.api.analytics import router as analytics_router
from app.api.assistant import router as assistant_router
from app.config import settings
from app.limiter import limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm ML model — trains from seed data if model.pkl missing
    from app.ml.predictor import _load
    try:
        _load()
    except FileNotFoundError:
        subprocess.run(
            [sys.executable, "-m", "app.ml.train", "--seed"],
            check=True,
        )
        _load()
    yield


app = FastAPI(
    title="ThreatWatch AI API",
    description="Multi-channel scam & phishing detection — ML + Rule engine",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
    allow_credentials=False,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)


@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request payload too large."},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid content-length header."},
            )

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

app.include_router(scan_router)
app.include_router(scan_ai_router)
app.include_router(upload_router)
app.include_router(auth_router)
app.include_router(rules_router)
app.include_router(analytics_router)
app.include_router(assistant_router)


@app.get("/")
async def root():
    return {"service": "ThreatWatch AI API", "version": "1.0.0"}
