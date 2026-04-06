import subprocess
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.api.scan import router as scan_router
from app.api.scan_ai import router as scan_ai_router
from app.api.upload import router as upload_router
from app.api.rules import router as rules_router
from app.config import settings


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


limiter = Limiter(key_func=get_remote_address)

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

app.include_router(scan_router)
app.include_router(scan_ai_router)
app.include_router(upload_router)
app.include_router(rules_router)


@app.get("/")
async def root():
    return {"service": "ThreatWatch AI API", "version": "1.0.0"}
