from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.scan import router as scan_router
from app.api.rules import router as rules_router

app = FastAPI(
    title="ThreatWatch AI API",
    description="Multi-channel scam & phishing detection — ML + Rule engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(rules_router)


@app.get("/")
async def root():
    return {"service": "ThreatWatch AI API", "version": "1.0.0", "docs": "/docs"}
