# ThreatWatch AI — Deployment & Enhancement Plan

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  USER BROWSER                                                    │
│  Vercel CDN  (frontend/index.html — static, global CDN)         │
│  URL: https://threatwatch-ai.vercel.app                              │
└─────────────────────────┬────────────────────────────────────────┘
                          │  HTTPS REST  /api/v1/*
                          │  (CORS locked to Vercel origin)
┌─────────────────────────▼────────────────────────────────────────┐
│  Railway (or Render)                                             │
│  FastAPI + Uvicorn inside Docker                                 │
│  URL: https://threatwatch-ai-api.up.railway.app                      │
│  Start: migrate → train (if no model.pkl) → uvicorn             │
└─────────────────────────┬────────────────────────────────────────┘
                          │  asyncpg / SQLAlchemy async
┌─────────────────────────▼────────────────────────────────────────┐
│  Supabase (recommended)  OR  Railway PostgreSQL                  │
│  PostgreSQL 15 · PgBouncer · pg_trgm · unaccent                 │
└──────────────────────────────────────────────────────────────────┘

GitHub Actions CI/CD:
  push to main → pytest → deploy backend (Railway) → deploy frontend (Vercel)
```

---

## Phase 1 — GitHub Setup

### .gitignore (critical)
```
__pycache__/
*.pyc
*.pyd
.venv/
venv/
*.pkl          # model.pkl is regenerated on boot — never commit
*.joblib
.env
.env.local
*.pem
*.key
.DS_Store
Thumbs.db
.vscode/
.idea/
pgdata/
.vercel/
```

### Branch Strategy
- `main` — production, CI/CD protected
- `dev` — integration branch, PRs merge here first
- `feature/*` — short-lived feature branches

### Steps
1. `git init` in `email-scanner/`
2. Add `.gitignore` above
3. Copy `.env.example` → `.env` (never commit `.env`)
4. `git add . && git commit -m "init: threatwatch-ai project"`
5. Push to GitHub

---

## Phase 2 — Backend Hardening

### 2a. CORS — tighten from `*`
Update `backend/app/main.py`:
- `allow_origins=settings.allowed_origins` (list from env)
- `docs_url="/docs" if settings.debug else None` — hide in prod

### 2b. Updated config.py
Add `allowed_origins: List[str]` and `api_key: str` to Settings.
Add `parse_origins` validator — Railway stores env vars as strings, comma-sep list must be parsed.

### 2c. Rate Limiting
Add `slowapi==0.1.9` to `requirements.txt`.
Limit `/api/v1/scan` to **20 requests/minute per IP** (in-memory, no Redis needed).
Decorator: `@limiter.limit("20/minute")` — requires `request: Request` param.

### 2d. API Key Auth on Admin Routes
Add `backend/app/api/auth.py`:
```python
async def require_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.api_key:
        raise HTTPException(403, "Invalid API key")
```
Apply as `dependencies=[Depends(require_api_key)]` on all `/api/v1/rules` routes.
Public routes (`/scan`, `/stats`, `/health`) stay open.

### 2e. Input Validation Fix
Add `ge=1` to scan_id path param:
```python
scan_id: int = Path(..., ge=1)
```

### 2f. Startup Pre-warm (lifespan event)
```python
@asynccontextmanager
async def lifespan(app):
    try:
        _load()
    except FileNotFoundError:
        subprocess.run([sys.executable, "-m", "app.ml.train", "--seed"], check=True)
        _load()
    yield
```
Prevents cold-start 503 on first request after container restart.

---

## Phase 3 — Database

### Recommendation: Supabase ✅

| Factor | Supabase Free | Railway PostgreSQL |
|--------|--------------|-------------------|
| Storage | 500 MB | 1 GB |
| Connections | 60 direct + PgBouncer | ~25 shared |
| Extensions | pg_trgm, unaccent pre-installed | Manual |
| Dashboard | SQL editor + table viewer | Basic |
| Inactivity | Pauses after 7 days (1-click resume) | Active while project alive |

**Gotcha**: Supabase pauses after 7 days inactivity. Log in and resume the night before judging. Takes ~30 seconds.

**Gotcha**: Use port `5432` (direct) for asyncpg with persistent connections. If `TooManyConnectionsError`, switch to port `6543` (PgBouncer).

### Setup Steps
1. Create Supabase project — region: Singapore (`ap-southeast-1`)
2. SQL Editor → run `init.sql` manually to enable extensions
3. Copy connection URI from Settings → Database → Connection String
4. Set as `DATABASE_URL` in Railway env vars
5. First Railway deploy runs `migrate.py` → creates all 4 tables + seeds 15 rules + 12 domains
6. Verify in Supabase Table Editor

---

## Phase 4 — Backend Deployment (Railway)

### Updated Dockerfile
Key changes from current:
- Add `punkt_tab` to NLTK downloads (required by newer NLTK)
- Add `RUN mkdir -p /app/ml`
- Add `CMD` instruction

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -c "import nltk; nltk.download('stopwords'); nltk.download('punkt'); nltk.download('punkt_tab')"
COPY . .
RUN mkdir -p /app/ml
EXPOSE 8100
CMD ["sh", "-c", "python -m app.db.migrate && python -m app.ml.train --seed && uvicorn app.main:app --host 0.0.0.0 --port 8100"]
```

Remove `psycopg2-binary` from requirements.txt — unused (app uses asyncpg only).

### Railway Setup Steps
1. railway.app → New Project → Deploy from GitHub → select `email-scanner`
2. Root directory: `backend/`
3. Start Command (override CMD): same as CMD above, but drop `--reload`
4. Health Check Path: `/api/v1/health`
5. Port: `8100`
6. Generate Domain → copy URL

### Railway Environment Variables
```
DATABASE_URL=postgresql://postgres:[PW]@db.[REF].supabase.co:5432/postgres
SECRET_KEY=[python -c "import secrets; print(secrets.token_hex(32))"]
MODEL_PATH=/app/ml/model.pkl
DEBUG=false
ALLOWED_ORIGINS=https://threatwatch-ai.vercel.app
API_KEY=[random key for rule admin]
```

### Railway Gotchas
- **Free tier**: 500 hrs/month execution. 720 hrs needed for 24/7 — exceeds free after ~20 days. Fine for hackathon.
- **Sleep**: Container sleeps after ~15 min inactivity. First request = 3-8s wake-up. Mitigated by `loadStats()` call on page load (already present).
- **No persistent disk**: Model is retrained on every restart (~10-15s). Acceptable — seed data is bundled.

### Render as Alternative
- Build Command: `pip install -r requirements.txt`
- Start Command: same as Railway
- Set `PORT=8100` or change uvicorn to `--port $PORT`
- Gotcha: Render free tier sleeps longer (30-60s wake-up vs Railway's 3-8s)

---

## Phase 5 — Frontend Deployment (Vercel)

### Fix: API URL Injection
Current code falls back to `''` (same-origin) on non-localhost. On Vercel this 404s.

Replace the `const API` block in `frontend/index.html`:
```javascript
const API = (function() {
  const host = window.location.hostname;
  if (host === 'localhost' || host === '127.0.0.1') return 'http://localhost:8100';
  return 'https://threatwatch-ai-api.up.railway.app';  // update after Railway deploy
})();
```

### vercel.json
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Cache-Control", "value": "public, max-age=3600, stale-while-revalidate=86400" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }
      ]
    }
  ],
  "cleanUrls": true
}
```

### Vercel Setup Steps
1. vercel.com → New Project → Import GitHub → select `email-scanner`
2. Root Directory: `frontend/`
3. Framework Preset: **Other**
4. Build Command: *(empty)*
5. Output Directory: `.`
6. Deploy
7. Add Vercel URL to Railway's `ALLOWED_ORIGINS`

### Vercel Free Tier
100 GB bandwidth/month · 100 deploys/day · unlimited static hosting. Will never be exceeded.

**Gotcha**: Vercel may auto-detect a wrong framework. Explicitly set to "Other" in UI.

---

## Phase 6 — CI/CD (GitHub Actions)

### .github/workflows/ci.yml — runs on every push/PR
- Spins up postgres:16 service container
- Installs Python deps (cached)
- Downloads NLTK data
- Runs `migrate.py` + `train.py`
- Runs `pytest tests/ -v`

### .github/workflows/deploy.yml — runs on push to main only
- `deploy-backend`: `railway up --service threatwatch-ai-api --detach`
- `deploy-frontend`: `vercel --prod --token $VERCEL_TOKEN` (depends on backend job)

### GitHub Secrets Required
| Secret | Source |
|--------|--------|
| `RAILWAY_TOKEN` | Railway → Account Settings → Tokens |
| `VERCEL_TOKEN` | vercel.com → Settings → Tokens |
| `VERCEL_ORG_ID` | `cat .vercel/project.json` after `vercel link` |
| `VERCEL_PROJECT_ID` | same file |

### Minimum Test (backend/tests/test_scan.py)
```python
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/health")
    assert r.status_code == 200

@pytest.mark.asyncio
async def test_scan_rejects_empty():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/scan", json={"text": "", "channel": "chat"})
    assert r.status_code == 422
```
Add `pytest==8.2.0` + `pytest-asyncio==0.23.6` to requirements.

---

## Phase 7 — Enhancements (Post-Deploy, Priority Order)

### P1 — .eml File Upload (High Impact, Medium Effort)
- Parse forwarded scam emails with Python's built-in `email` module (no new dep)
- Extract: `Subject`, `From`, `body (text/plain or text/html)`
- Feed extracted text + any URLs found into existing `scan()` engine
- New endpoint: `POST /api/v1/scan/upload` (multipart form)
- Frontend: add file input button below textarea
- **Demo value**: paste a real forwarded scam email → instant analysis

### P2 — URL Safety Check via Google Safe Browsing (Low Effort, High Demo Value)
- Free API, 10k lookups/day
- Add `GOOGLE_SAFE_BROWSING_KEY` env var
- In `rule_engine.py`, async HTTP call to Safe Browsing Lookup API v4
- If flagged: add `{"flag_type": "url", "weight": 0.5, "description": "Google Safe Browsing: known malicious URL"}`

### P3 — History / Recent Scans Panel
- Fetch `/api/v1/stats` returns `recent_scans[]` — already implemented
- Add a collapsible "Recent Scans" section below the result card
- Show last 5 scans: verdict chip + risk% + timestamp

### P4 — Rule Manager UI
- Simple table listing all rules from `GET /api/v1/rules`
- Toggle active/inactive per rule
- Add custom rule form (name, pattern, weight, category)
- Protected by API key (prompt for it once, store in sessionStorage)
- **Demo value**: live-edit rules during judging to show extensibility

### P5 — Chrome Extension Stub
- `manifest.json` (MV3) + `content_script.js` that scrapes Gmail message body
- Posts to ThreatWatch AI API on page load if URL matches `mail.google.com`
- Shows result as a badge overlay on the email subject line
- **Demo value**: extremely visual, shows real-world applicability

---

## How Users Utilize This

### User Journey

```
1. LAND on threatwatch-ai.vercel.app
   → Stats bar shows live scan counts (total / scams / suspicious / safe)

2. SELECT channel
   → Chat/SMS (default) | Email | URL

3. PASTE message
   → Any text: WhatsApp message, email body, SMS
   → Optional: paste a URL separately for domain analysis

4. CLICK "Analyze Now" (or Ctrl+Enter)
   → Loading spinner while API processes

5. SEE RESULT
   → Verdict banner: ✅ SAFE / ⚠️ SUSPICIOUS / 🚨 SCAM
   → Risk meter: 0–100%
   → ML Score + Rule Score breakdown
   → "Why flagged" — list of triggered rules in plain English
   → "Suspicious tokens" — highlighted matched patterns

6. GIVE FEEDBACK
   → Yes (correct) / False positive / Missed scam
   → Logged to PostgreSQL, used to improve future models

7. SCAN ANOTHER
   → Clear and repeat
```

### Supported Input Types
| What to paste | Channel to select |
|---------------|------------------|
| WhatsApp / Telegram message | Chat / SMS |
| SMS text | Chat / SMS |
| Email subject + body | Email |
| Suspicious link | URL |
| Any mix of the above | Chat / SMS (default) |

### What the Risk Score Means
| Score | Verdict | Meaning |
|-------|---------|---------|
| 0–34% | ✅ Safe | No significant indicators found |
| 35–64% | ⚠️ Suspicious | Some patterns detected — review carefully |
| 65–100% | 🚨 Scam | High confidence threat — do not click, do not share OTP |

---

## Demo Flow for Judges

**Duration**: 3-4 minutes

**Setup before demo**: Open `threatwatch-ai.vercel.app`. Pre-type the demo messages in a notes file so you can copy-paste fast.

**Step 1 — Show stats bar (30s)**
> "This is ThreatWatch AI. It's scanned X messages already. Let me show you what it does."

**Step 2 — Paste a scam message (60s)**
```
URGENT: Your Maybank account has been suspended.
Verify your identity now or lose access: http://bit.ly/mb-verify2026
```
Click "Analyze Now". Point to:
- 🚨 SCAM banner
- Risk score ~85%
- Reasons: "Bank impersonation", "URL shortener used", "Urgency pressure tactic"
- Highlighted tokens: `urgent`, `bit.ly`, `suspended`

> "In under a second, it identified three separate threat patterns: bank impersonation, urgency language, and a suspicious shortened URL."

**Step 3 — Paste a safe message (30s)**
```
Hi, your appointment is confirmed for Tuesday 10am. See you then!
```
> "Safe messages pass cleanly — no false positives."

**Step 4 — Show multi-channel (30s)**
Switch to Email channel. Paste email-style text. Show same detection.
> "Works across SMS, chat, and email — all channels a scammer uses."

**Step 5 — Show explainability (30s)**
Point to the reasons list and highlighted tokens.
> "It doesn't just say 'scam' — it tells you exactly why. This is what makes it useful for awareness, not just blocking."

**Step 6 — Show live database (30s)**
Open Supabase Table Editor in another tab. Show the `scans` table with the just-saved scan.
> "Every scan is logged to PostgreSQL. This powers audit trails, retraining, and analytics."

**Step 7 — Architecture slide (optional)**
> "FastAPI backend on Railway, PostgreSQL on Supabase, deployed on Vercel. Full CI/CD on GitHub Actions. Production-ready from day one."

---

## Checklist — Deploy Day

- [ ] `.gitignore` includes `*.pkl` and `.env`
- [ ] Supabase project created, extensions enabled, connection string copied
- [ ] Railway service created, env vars set, health check passing
- [ ] Vercel project created, root dir = `frontend/`, API URL hardcoded correctly
- [ ] `ALLOWED_ORIGINS` in Railway includes Vercel URL
- [ ] GitHub secrets set: `RAILWAY_TOKEN`, `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID`
- [ ] CI passes on `main` branch (green checkmark)
- [ ] Demo messages prepared in notes file
- [ ] Supabase project not paused (log in and click Resume if needed)
- [ ] Railway container warm (open the URL 5 min before demo)
