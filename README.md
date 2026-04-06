# ThreatWatch AI ⚡

**Multi-channel AI scam & phishing detection** — ML + rule engine, built for real-world threat analysis across email, SMS, and chat.

> Hackathon project by [NusaByte](https://github.com/nusabyte-my)

---

## What It Does

Paste any message — email body, SMS, WhatsApp, or a suspicious URL — and ThreatWatch AI returns:

- **Verdict**: Safe / Suspicious / Scam
- **Risk Score**: 0–100%
- **Why it was flagged**: plain-English reasons from triggered rules
- **Suspicious tokens**: highlighted matched patterns

Detection combines a **TF-IDF + Logistic Regression + Naive Bayes ensemble** (ML layer) with a **PostgreSQL-backed rule engine** (regex + keyword patterns). Both layers run on every scan and are blended into a final risk score.

---

## Stack

| Layer | Tech |
|-------|------|
| Backend | FastAPI · Python 3.11 · asyncpg |
| ML | scikit-learn (TF-IDF + LR + NB ensemble) |
| Database | PostgreSQL 16 · SQLAlchemy async |
| Frontend | Vanilla HTML/JS · dark UI |
| Deploy | Vercel (frontend) · Railway (API) · Supabase (DB) |
| CI/CD | GitHub Actions |

---

## Project Structure

```
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              # FastAPI entry point
│       ├── config.py            # Settings (pydantic-settings)
│       ├── api/
│       │   ├── scan.py          # POST /scan, GET /stats, feedback
│       │   └── rules.py         # Rule CRUD (admin, API-key protected)
│       ├── db/
│       │   ├── models.py        # Scan, Rule, SuspiciousDomain tables
│       │   ├── migrate.py       # Auto-create tables + seed rules on boot
│       │   └── base.py          # Async SQLAlchemy engine
│       ├── ml/
│       │   ├── train.py         # Train TF-IDF + LR + NB ensemble
│       │   ├── predictor.py     # Lazy-loaded model singleton
│       │   └── preprocessor.py  # Text cleaning + tokenisation
│       └── engine/
│           ├── scanner.py       # Blend ML + rules → verdict
│           └── rule_engine.py   # Regex eval against DB rules
├── frontend/
│   └── index.html               # Single-page dark UI
├── nginx/                       # Proxy + frontend nginx configs
├── docker-compose.yml           # Local dev (all services)
├── PLAN.md                      # Full deployment & enhancement plan
└── deploy.sh                    # VPS deploy helper (on hold)
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scan` | Scan a message |
| `GET` | `/api/v1/scan/{id}` | Get scan result by ID |
| `POST` | `/api/v1/scan/{id}/feedback` | Submit feedback (correct / false_positive / false_negative) |
| `GET` | `/api/v1/stats` | Live scan stats + recent scans |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/rules` | List rules (API key required) |
| `POST` | `/api/v1/rules` | Add rule (API key required) |
| `PATCH` | `/api/v1/rules/{id}/toggle` | Enable/disable rule |
| `DELETE` | `/api/v1/rules/{id}` | Delete rule |

### Scan Request
```json
POST /api/v1/scan
{
  "text": "URGENT: Your Maybank account is locked. Verify: http://bit.ly/mb-verify",
  "channel": "chat",
  "url": "http://bit.ly/mb-verify"
}
```

### Scan Response
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

---

## Local Dev

```bash
# 1. Clone
git clone https://github.com/nusabyte-my/ThreatWatch-AI.git
cd ThreatWatch-AI

# 2. Set env
cp .env.example .env

# 3. Start all services
docker compose up --build

# App:  http://localhost:3000
# API:  http://localhost:8100
# Docs: http://localhost:8100/docs
```

First boot: migrations run, model trains from seed data, 15 rules + 12 suspicious domains seeded automatically. Takes ~20s.

---

## Deployment

See [PLAN.md](PLAN.md) for the full step-by-step guide.

**TL;DR:**
- Frontend → Vercel (root dir: `frontend/`)
- API → Railway (root dir: `backend/`, port `8100`)
- Database → Supabase (free tier, Singapore region)
- CI/CD → GitHub Actions (`.github/workflows/`)

---

## Detection Rules

15 default rules across 4 categories — all editable live via the rules API:

| Category | Examples |
|----------|---------|
| `urgency` | "act now", "account suspended", "limited time" |
| `phishing` | "verify your account", "click here", bank impersonation |
| `otp` | OTP sharing requests — highest weight (0.45) |
| `financial` | money transfer, gift card, fake investment returns |
| `url` | URL shorteners, suspicious TLDs, raw IP addresses |

---

## Risk Score Logic

```
Final Score = 60% × Rule Score + 40% × ML Score

Safe:        0–34%
Suspicious:  35–64%
Scam:        65–100%
```

Rule engine is weighted higher because it is more interpretable and domain-specific (Malaysia-focused patterns).

---

## License

MIT — NusaByte 2026
