# ThreatWatch AI

> **Nexpert Hackathon 2026 · Team U · ThreatWatch Team**

Multi-channel AI scam and phishing detection — combining a machine learning ensemble, a live-editable rule engine, and a multi-agent LLM pipeline to protect users from fraud across email, SMS, and chat.

---

## Executive Summary

Digital scams in Malaysia have surged. In 2023 alone, Malaysians lost over **RM1.6 billion** to scams, with phishing, investment fraud, and bank impersonation accounting for the majority of cases. Existing tools either block blindly or explain nothing — leaving users unprotected and uninformed.

**ThreatWatch AI** is a real-time, explainable threat detection system that:

- Accepts any message — email, SMS, WhatsApp text, or URL — and returns a verdict in under 2 seconds
- Combines three independent detection layers: ML ensemble, rule engine, and multi-agent LLM analysis
- Explains *why* a message is flagged in plain language, with specific user action guidance
- Stores every scan in PostgreSQL for audit, retraining, and pattern analysis
- Degrades gracefully — if LLMs are unavailable, the ML + rule engine continues working independently

This is not a black-box classifier. Every decision is traceable, every rule is editable, and every verdict comes with a reason.

---

## Problem Statement

| Problem | Impact |
|---------|--------|
| Scam messages are increasingly convincing | Users cannot distinguish legitimate bank messages from phishing |
| Existing spam filters are binary — no explanation | Users click anyway because they don't understand the risk |
| Detection rules go stale | Scammers adapt; static rules fail within weeks |
| No Malaysia-specific tooling | Generic models miss local bank names, government agencies, courier brands |
| No feedback loop | False positives and missed scams are never corrected |

ThreatWatch AI addresses all five.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER  (browser / API client)                                       │
└───────────────────┬─────────────────────────────────────────────────┘
                    │  HTTPS
┌───────────────────▼─────────────────────────────────────────────────┐
│  Vercel CDN  — frontend/index.html  (static, global edge)           │
│  URL: https://threatwatch-ai.vercel.app                             │
└───────────────────┬─────────────────────────────────────────────────┘
                    │  REST  /api/v1/*
                    │  CORS locked · rate-limited 20 req/min
┌───────────────────▼─────────────────────────────────────────────────┐
│  Railway  — FastAPI + Uvicorn (Docker)                              │
│  Port 8100 · health check /api/v1/health                           │
│                                                                     │
│  Detection Pipeline                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: ML Engine                                         │   │
│  │  TF-IDF + Logistic Regression + Naive Bayes ensemble        │   │
│  │  Trained on Malaysia-specific scam seed data                │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │  Layer 2: Rule Engine                                       │   │
│  │  15+ regex/keyword rules, live-editable via admin API       │   │
│  │  Backed by PostgreSQL — no redeploy needed to update rules  │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │  Layer 3: Multi-Agent LLM Pipeline  (/scan/ai)             │   │
│  │  ClassifierAgent → [URLAnalystAgent + VerifierAgent]        │   │
│  │                  → ExplainerAgent → Aggregate               │   │
│  │  Primary: GPT-4o · Fallback: GPT-4o-mini → Claude Haiku    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Score Blend: 60% Rule + 40% ML  (standard)                        │
│  Score Blend: 50% Engine + 50% Agent  (AI endpoint)                │
└───────────────────┬─────────────────────────────────────────────────┘
                    │  asyncpg / SQLAlchemy
┌───────────────────▼─────────────────────────────────────────────────┐
│  Supabase — PostgreSQL 16                                           │
│  Tables: scans · scan_flags · rules · suspicious_domains           │
│  Extensions: pg_trgm · unaccent                                    │
│  PgBouncer connection pooler included                               │
└─────────────────────────────────────────────────────────────────────┘

CI/CD:  push to main → GitHub Actions → Railway (API) + Vercel (UI)
```

---

## Detection Layers

### Layer 1 — Machine Learning Engine

A three-model ensemble trained on Malaysia-focused scam and legitimate message data.

| Component | Detail |
|-----------|--------|
| Vectoriser | TF-IDF, unigrams + bigrams, 5,000 features, sublinear TF scaling |
| Model A | Logistic Regression, balanced class weights, L2 regularisation |
| Model B | Multinomial Naive Bayes, alpha=0.5 |
| Ensemble | Soft voting — 70% LR + 30% NB |
| Preprocessing | Stopword removal (scam-signal words preserved), URL/email tokenisation, punctuation stripping |
| Output | `scam_prob` (0.0–1.0), model used, ensemble confidence |

The model is trained from a seed dataset on container boot. It takes ~15 seconds and requires no external files. A retrain endpoint can be added to incorporate user feedback data from the `scans` table.

### Layer 2 — Rule Engine (PostgreSQL-backed)

15 default rules across 5 categories, stored in the `rules` table. Rules are evaluated as regex patterns against every scan. No redeploy is required to add, modify, or disable a rule.

| Category | Rules | Max Weight |
|----------|-------|-----------|
| `urgency` | "act now", "account suspended", artificial deadlines | 0.30 |
| `phishing` | Bank impersonation (8 major Malaysian banks), credential harvesting CTAs, fake prize | 0.40 |
| `otp` | OTP/TAC sharing requests | **0.45** (highest — nearly definitive) |
| `financial` | Money transfer requests, gift card demands, guaranteed investment returns | 0.40 |
| `url` | URL shorteners, suspicious TLDs (.xyz .top .tk .ml), raw IP address URLs | 0.35 |

12 suspicious domains are also seeded (known shorteners, free TLDs) for URL reputation checking via `tldextract`.

**Admin API** — Rules can be created, toggled, and deleted live via `POST /api/v1/rules` (API key required). This means a security analyst can respond to a new scam wave in seconds, without touching code.

### Layer 3 — Multi-Agent LLM Pipeline

Available at `POST /api/v1/scan/ai`. Four specialised agents run in a dependency-aware pipeline.

```
Step 1 (sequential):  ClassifierAgent      — LLM scam classification + categories
Step 2 (parallel):    URLAnalystAgent      — domain reputation + structural analysis
                      VerifierAgent        — cross-checks ML vs LLM, flags disagreements
Step 3 (sequential):  ExplainerAgent       — generates plain-English user explanation
Step 4 (in-process):  Orchestrator.aggregate() — blends all scores, resolves final verdict
```

**Fallback chain** (per agent, independent):
```
GPT-4o → GPT-4o-mini → Claude Haiku → rule-only (deterministic, zero latency)
```

The endpoint never returns a 500 due to LLM failure. If all models are unavailable, the pipeline degrades to the existing ML + rule engine transparently.

See [AGENTS_PLAN.md](AGENTS_PLAN.md) for full agent prompts, cost estimates, and implementation sequence.

---

## Risk Scoring

### Standard endpoint (`/api/v1/scan`)

```
Final Score = (60% × Rule Score) + (40% × ML Score)
```

### AI endpoint (`/api/v1/scan/ai`)

```
Engine Score = (60% × Rule Score) + (40% × ML Score)
Agent Score  = LLM ensemble confidence
Final Score  = (50% × Engine Score) + (50% × Agent Score)
```

### Verdict thresholds

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0 – 34% | Safe | No significant indicators |
| 35 – 64% | Suspicious | Review carefully — some patterns present |
| 65 – 100% | Scam | High confidence threat — do not proceed |

The rule engine carries 60% weight in the standard blend because it is more interpretable, domain-specific, and immediately updatable. The ML layer captures patterns outside the rule vocabulary.

---

## Security

| Control | Implementation |
|---------|---------------|
| CORS | Origin whitelist from env — no wildcard in production |
| Rate limiting | 20 req/min (standard), 5 req/min (AI endpoint) per IP via slowapi |
| Admin auth | `X-API-Key` header required on all `/api/v1/rules` endpoints |
| Input validation | Pydantic models — max text 5,000 chars, channel enum, URL max 2,048 chars, scan_id ≥ 1 |
| Secrets | All credentials via environment variables — never committed |
| Docs exposure | `/docs` only available when `DEBUG=true` |
| Container | Non-root Python image, minimal apt dependencies |

---

## API Reference

### Standard Scan

```
POST /api/v1/scan
Content-Type: application/json
```

**Request**
```json
{
  "text": "URGENT: Your Maybank account is locked. Verify now: http://bit.ly/mb-verify",
  "channel": "chat",
  "url": "http://bit.ly/mb-verify"
}
```
`channel`: `chat` | `sms` | `email` | `url`

**Response**
```json
{
  "scan_id": 42,
  "verdict": "scam",
  "risk_score": 0.87,
  "risk_percent": 87,
  "ml_score": 0.91,
  "rule_score": 0.85,
  "reasons": [
    "Bank impersonation",
    "Urgency pressure tactic",
    "URL shortener used"
  ],
  "highlighted_tokens": ["urgent", "bit.ly", "locked"],
  "channel": "chat"
}
```

### AI Scan (multi-agent)

```
POST /api/v1/scan/ai
Content-Type: application/json
```

**Request**
```json
{
  "text": "URGENT: Your Maybank account is locked. Verify now: http://bit.ly/mb-verify",
  "channel": "email",
  "url": "http://bit.ly/mb-verify",
  "include_explanation": true
}
```

**Response (additional `agent` block)**
```json
{
  "scan_id": 43,
  "verdict": "scam",
  "risk_score": 0.91,
  "risk_percent": 91,
  "agent": {
    "verdict": "scam",
    "confidence": 0.97,
    "pipeline_mode": "full",
    "agents_used": ["ClassifierAgent", "URLAnalystAgent", "VerifierAgent", "ExplainerAgent"],
    "explanation": "This message impersonates Maybank and uses a shortened URL to conceal a phishing destination. The urgency language and account-suspension threat are designed to force a hasty decision.",
    "risk_factors": [
      "Bank impersonation (Maybank)",
      "Shortened URL concealing destination",
      "Artificial urgency — account suspension threat"
    ],
    "safe_indicators": [],
    "user_action": "Do NOT click the link. Call Maybank fraud at 1300-88-6688 or the National Scam Response Centre at 997.",
    "url_findings": ["bit.ly is a URL shortener — real destination hidden"],
    "is_uncertain": false,
    "latency_ms": 1840
  }
}
```

### All Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/v1/scan` | — | Standard scan (ML + rules) |
| `POST` | `/api/v1/scan/ai` | — | AI scan (ML + rules + 4-agent LLM) |
| `GET` | `/api/v1/scan/{id}` | — | Retrieve scan by ID |
| `POST` | `/api/v1/scan/{id}/feedback` | — | Submit verdict feedback |
| `GET` | `/api/v1/stats` | — | Live totals + recent 5 scans |
| `GET` | `/api/v1/health` | — | Health check |
| `GET` | `/api/v1/rules` | API Key | List all rules |
| `POST` | `/api/v1/rules` | API Key | Create rule |
| `PATCH` | `/api/v1/rules/{id}/toggle` | API Key | Enable / disable rule |
| `DELETE` | `/api/v1/rules/{id}` | API Key | Delete rule |

---

## Database Schema

```sql
-- Every scan, regardless of channel or endpoint
CREATE TABLE scans (
    id              SERIAL PRIMARY KEY,
    channel         VARCHAR(10),           -- email | sms | chat | url
    input_text      TEXT,
    input_url       VARCHAR(2048),
    verdict         VARCHAR(15),           -- safe | suspicious | scam
    risk_score      FLOAT,                 -- 0.0–1.0
    ml_score        FLOAT,
    rule_score      FLOAT,
    reasons         JSONB,                 -- list of triggered rule descriptions
    highlighted_tokens JSONB,              -- matched suspicious tokens
    agent_analysis  JSONB,                 -- full agent pipeline result (AI endpoint only)
    user_feedback   VARCHAR(20),           -- correct | false_positive | false_negative
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- One row per triggered rule per scan — for analytics and rule weight tuning
CREATE TABLE scan_flags (
    id          SERIAL PRIMARY KEY,
    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    flag_type   VARCHAR(50),               -- pattern | url | ml
    value       VARCHAR(500),              -- matched string
    weight      FLOAT,
    description VARCHAR(300)
);

-- Live-editable detection rules
CREATE TABLE rules (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100) UNIQUE,
    pattern      VARCHAR(500),             -- regex or keyword
    pattern_type VARCHAR(20),              -- keyword | regex | combo
    weight       FLOAT DEFAULT 0.2,        -- added to risk score when matched
    description  VARCHAR(300),
    category     VARCHAR(50),              -- urgency | phishing | otp | financial | url
    is_active    BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Known bad domains and URL shorteners
CREATE TABLE suspicious_domains (
    id          SERIAL PRIMARY KEY,
    domain      VARCHAR(253) UNIQUE,
    reason      VARCHAR(100),              -- shortener | free_tld | known_phishing
    risk_weight FLOAT DEFAULT 0.3,
    added_at    TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Project Structure

```
ThreatWatch-AI/
│
├── .github/
│   └── workflows/
│       ├── ci.yml              — test on every push/PR (postgres service + pytest)
│       └── deploy.yml          — deploy on push to main (Railway → Vercel)
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py             — FastAPI app, CORS, rate limiter, lifespan pre-warm
│       ├── config.py           — pydantic-settings, all env vars, origin parser
│       ├── api/
│       │   ├── scan.py         — POST /scan, GET /stats, feedback, health
│       │   ├── scan_ai.py      — POST /scan/ai (agent pipeline endpoint) [planned]
│       │   ├── rules.py        — Rule CRUD, API-key protected
│       │   └── auth.py         — API key dependency
│       ├── db/
│       │   ├── base.py         — async engine, session factory, get_db dependency
│       │   ├── models.py       — SQLAlchemy ORM models
│       │   ├── migrate.py      — create_all + seed rules + seed domains on boot
│       │   └── init.sql        — pg_trgm, unaccent extensions
│       ├── ml/
│       │   ├── train.py        — TF-IDF + LR + NB ensemble training
│       │   ├── predictor.py    — lazy-loaded model singleton
│       │   └── preprocessor.py — tokenisation, stopwords, URL/email normalisation
│       ├── engine/
│       │   ├── scanner.py      — blend ML + rules → final verdict + DB persist
│       │   └── rule_engine.py  — regex eval against DB rules, URL domain check
│       └── agents/             — multi-agent LLM pipeline [planned — see AGENTS_PLAN.md]
│           ├── base.py
│           ├── llm_client.py
│           ├── orchestrator.py
│           ├── classifier_agent.py
│           ├── url_analyst_agent.py
│           ├── verifier_agent.py
│           └── explainer_agent.py
│
├── frontend/
│   ├── index.html              — single-page dark UI, live stats, feedback
│   └── vercel.json             — security headers, cache policy
│
├── nginx/
│   ├── proxy.conf              — routes / → UI, /api/ → FastAPI
│   └── frontend.conf           — nginx static server config
│
├── docker-compose.yml          — local dev: db + api + frontend + nginx proxy
├── PLAN.md                     — deployment plan: Supabase + Railway + Vercel
├── AGENTS_PLAN.md              — multi-agent pipeline design + prompts + cost estimates
├── deploy.sh                   — VPS deployment helper (on hold)
├── .env.example                — all required environment variables documented
└── .github/workflows/          — CI/CD
```

---

## Local Development

**Prerequisites:** Docker Desktop, Git

```bash
# Clone
git clone https://github.com/nusabyte-my/ThreatWatch-AI.git
cd ThreatWatch-AI

# Environment
cp .env.example .env
# Edit .env if needed — defaults work for local dev

# Start everything
docker compose up --build
```

| Service | URL |
|---------|-----|
| UI | http://localhost:3000 |
| API | http://localhost:8100 |
| API Docs | http://localhost:8100/docs |
| Database | localhost:5432 (user: `threatwatch`, db: `threatwatch`) |

**First boot sequence** (automatic, ~20–30s):
1. PostgreSQL healthcheck passes
2. `migrate.py` creates 4 tables, seeds 15 rules + 12 suspicious domains
3. `train.py` trains ML model from seed data, saves `model.pkl`
4. Uvicorn starts, lifespan pre-warms model into memory
5. All services ready

**Retrain model** (after adding feedback data):
```bash
docker exec threatwatch-api python -m app.ml.train --seed
```

---

## Production Deployment

Full step-by-step guide: [PLAN.md](PLAN.md)

### Infrastructure

| Component | Service | Plan | Cost |
|-----------|---------|------|------|
| Frontend | Vercel | Free | $0 |
| API | Railway | Hobby (500 hrs/mo) | ~$0–5/mo |
| Database | Supabase | Free (500 MB) | $0 |
| CI/CD | GitHub Actions | Free (2,000 min/mo) | $0 |

### Environment Variables (production)

```bash
# Database (Supabase connection string)
DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres

# App secrets
SECRET_KEY=<64-char hex — python -c "import secrets; print(secrets.token_hex(32))">
API_KEY=<random key for rule admin>

# CORS — add your Vercel domain
ALLOWED_ORIGINS=https://threatwatch-ai.vercel.app

# Agent pipeline (optional — degrades gracefully if not set)
OPENAI_API_KEY=sk-proj-...
ANTHROPIC_API_KEY=sk-ant-...

# Model
MODEL_PATH=/app/ml/model.pkl
DEBUG=false
```

### Deployment Steps (quick)

```bash
# 1. Push to main — GitHub Actions deploys automatically
git push origin main

# OR deploy manually:
# Backend → Railway CLI
railway up --service threatwatch-api

# Frontend → Vercel CLI
vercel --prod
```

---

## CI/CD Pipeline

```
push to main or PR
        │
        ▼
  ci.yml — GitHub Actions
  ├── Spin up postgres:16 service container
  ├── Install Python 3.11 deps (cached)
  ├── Download NLTK data
  ├── Run migrate.py (create tables, seed)
  ├── Run train.py --seed
  └── pytest tests/ -v
        │
        ▼ (main branch only, after CI passes)
  deploy.yml
  ├── railway up --service threatwatch-api  (backend)
  └── vercel --prod                          (frontend, after backend)
```

Required GitHub Secrets:

| Secret | Source |
|--------|--------|
| `RAILWAY_TOKEN` | Railway → Account Settings → Tokens |
| `VERCEL_TOKEN` | vercel.com → Settings → Tokens |
| `VERCEL_ORG_ID` | `cat .vercel/project.json` after `vercel link` |
| `VERCEL_PROJECT_ID` | same file |

---

## Operational Runbook

### Health Check
```bash
curl https://threatwatch-api.up.railway.app/api/v1/health
# {"status": "ok", "service": "threatwatch-api"}
```

### Add a New Detection Rule (live, no redeploy)
```bash
curl -X POST https://threatwatch-api.up.railway.app/api/v1/rules \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "name": "telegram_investment",
    "pattern": "\\b(telegram|whatsapp).{0,20}(invest|profit|return|join)\\b",
    "pattern_type": "regex",
    "weight": 0.35,
    "description": "Telegram/WhatsApp investment group recruitment",
    "category": "financial"
  }'
```

### Disable a Rule (without deleting)
```bash
curl -X PATCH https://threatwatch-api.up.railway.app/api/v1/rules/3/toggle \
  -H "X-API-Key: YOUR_API_KEY"
```

### View Live Stats
```bash
curl https://threatwatch-api.up.railway.app/api/v1/stats
```

### Pre-warm Container Before Demo
```bash
# Railway sleeps after ~15min inactivity. Hit health 5 min before demo:
curl https://threatwatch-api.up.railway.app/api/v1/health
# If slow (>5s), wait 10s and try again — container is waking
```

### Supabase Paused (free tier pauses after 7 days inactivity)
Log in to supabase.com → select project → click **Resume** → wait ~30 seconds.

---

## User Journey

```
1. Open ThreatWatch AI  →  Stats bar loads (total scans, scams caught, safe)

2. Select channel        →  Chat/SMS · Email · URL

3. Paste message         →  Any suspicious text, or paste a URL in the URL field

4. Click "Analyze Now"   →  (or Ctrl+Enter)
   or call /api/v1/scan  →  JSON API for integrations

5. Read result
   ├── Verdict banner:  ✅ SAFE  /  ⚠️ SUSPICIOUS  /  🚨 SCAM
   ├── Risk meter:      0–100%
   ├── Why flagged:     plain-English reasons per triggered rule
   └── Suspicious tokens: highlighted matched patterns

6. Submit feedback       →  "Was this correct?" → Yes / False positive / Missed scam
   └── Logged to DB for model improvement

7. Repeat
```

---

## Hackathon Demo Script

**Duration: 4 minutes**

**Before demo:** Open the live URL. Have these messages ready in a notes file.

**Step 1 — Stats (30s)**
> "ThreatWatch AI has already scanned [N] messages. Let me show you what it does."
Point to the stats bar.

**Step 2 — Scam detection (90s)**
Paste:
```
URGENT: Your Maybank account has been suspended.
Verify your identity now or lose access: http://bit.ly/mb-verify2026
```
Click Analyze. Walk through:
- 🚨 SCAM at 87% risk
- Reasons: Bank impersonation · Urgency pressure tactic · URL shortener used
- Highlighted tokens: `urgent`, `bit.ly`, `suspended`

> "Three independent signals — bank impersonation, urgency language, and a hidden URL. Detected in under 2 seconds."

**Step 3 — Safe message (30s)**
Paste:
```
Hi, your appointment is confirmed for Tuesday 10am. See you then!
```
> "Safe messages pass cleanly. No false positives."

**Step 4 — Multi-channel (30s)**
Switch to Email channel. Paste email-style text with sender and subject.
> "Works across SMS, chat, and email — every channel scammers use."

**Step 5 — Explainability (30s)**
Point to the reasons list and token highlights.
> "It doesn't just say scam. It tells you exactly why, in plain language a non-technical user understands."

**Step 6 — Live database (30s)**
Open Supabase Table Editor. Show the `scans` table with the scan just recorded.
> "Every scan is logged. This feeds the feedback loop — false positives and missed scams are tracked and used to improve the model."

**Step 7 — Architecture (30s)**
> "FastAPI on Railway, PostgreSQL on Supabase, deployed globally on Vercel. Full CI/CD on GitHub Actions. The rule engine is live-editable — a new scam wave can be responded to in seconds, no redeploy needed."

---

## Planned Enhancements

| Feature | Status | Description |
|---------|--------|-------------|
| Multi-agent pipeline | Planned | 4-agent LLM layer: Classifier + URL Analyst + Verifier + Explainer |
| `.eml` file upload | Planned | Parse forwarded scam emails directly |
| Google Safe Browsing | Planned | URL reputation via Google API (10k free lookups/day) |
| Rule Manager UI | Planned | In-browser rule editor with API key auth |
| Chrome Extension | Planned | Real-time detection overlay in Gmail |
| Model retraining API | Planned | Trigger retrain from accumulated feedback data |

See [AGENTS_PLAN.md](AGENTS_PLAN.md) for the full multi-agent implementation plan.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| API Framework | FastAPI + Uvicorn |
| ML | scikit-learn — TF-IDF, Logistic Regression, Multinomial Naive Bayes |
| NLP | NLTK — tokenisation, stopword removal |
| Database ORM | SQLAlchemy 2.0 async + asyncpg |
| Database | PostgreSQL 16 |
| Rate Limiting | slowapi (in-memory, per-IP) |
| Validation | Pydantic v2 + pydantic-settings |
| URL Analysis | tldextract |
| LLM — Primary | OpenAI GPT-4o / GPT-4o-mini |
| LLM — Fallback | Anthropic Claude Haiku 3.5 |
| Frontend | Vanilla HTML/JS, no framework |
| Container | Docker + docker-compose |
| Hosting — UI | Vercel (static CDN) |
| Hosting — API | Railway (Docker) |
| Hosting — DB | Supabase (managed PostgreSQL) |
| CI/CD | GitHub Actions |

---

## License

MIT — ThreatWatch Team · Team U · Nexpert Hackathon 2026
