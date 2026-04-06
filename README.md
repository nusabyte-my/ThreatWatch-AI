# ThreatWatch AI

ThreatWatch AI is a threat-operations platform for phishing, scam, and suspicious-message analysis across email, chat, SMS, and URLs.

It combines:
- a rule engine
- a machine-learning detection path
- optional AI-assisted analysis
- an executive dashboard
- a floating copilot
- self-hosted or BYOK LLM support

The local product is designed to run as a single operator surface on `http://localhost:5080`.

---

## Executive Summary

ThreatWatch AI helps teams move from suspicious content to a clear incident decision quickly.

Business value:
- reduces time to triage suspicious messages
- gives leadership-readable incident summaries instead of opaque scores
- keeps detection explainable through rules, signals, indicators, and timeline views
- supports local AI with Ollama/Gemma or hosted AI through BYOK
- provides a path to analyst workflow, governance, and reporting in one interface

What the platform does:
- scans pasted text, URLs, and `.eml` email files
- assigns a verdict: `safe`, `suspicious`, or `scam`
- shows evidence, indicators, and recommended action
- stores scans for analytics and recent-incident review
- supports AI copilot chat and AI recommendation enrichment
- includes mail-client integration stubs for Chrome/Gmail, Thunderbird, and Outlook Web

---

## What Is Included

Core platform:
- executive dashboard
- investigation workspace
- analytics view
- rules manager
- floating AI copilot
- branded incident print brief

Backend:
- FastAPI API
- PostgreSQL persistence
- route-level rate limiting
- security headers and request-size limits
- auth/RBAC foundation for rule operations
- Google Safe Browsing enrichment
- assistant endpoints for chat and recommendation

AI:
- standard engine: rules + ML
- AI pipeline: deeper analysis with model support
- BYOK support for OpenAI / Anthropic
- self-hosted Ollama support for Gemma

Integrations:
- Chrome extension stub
- Thunderbird extension stub
- Outlook Web extension stub

---

## Architecture

Local stack:
- `nginx` reverse proxy on `5080`
- `frontend` static dashboard
- `api` FastAPI service
- `db` PostgreSQL

Main user entry points:
- UI: `http://localhost:5080`
- API: `http://localhost:5080/api/v1/...`
- Health: `http://localhost:5080/api/v1/health`

---

## Install And Execute

### Prerequisites

- Docker Desktop
- Git
- optional: Ollama for self-hosted Gemma

### 1. Clone

```bash
git clone https://github.com/nusabyte-my/ThreatWatch-AI.git
cd ThreatWatch-AI
```

### 2. Configure environment

```bash
cp .env.example .env
```

For local development, the defaults are usually enough.

Important values you may want to set:
- `SECRET_KEY`
- `ADMIN_API_KEY`
- `AUTH_ENABLED`
- `AUTH_USERS_JSON`
- `GOOGLE_SAFE_BROWSING_KEY`
- `OLLAMA_BASE_URL`
- `OLLAMA_MODEL`

### 3. Start the platform

```bash
docker compose up --build -d
```

### 4. Open the app

- UI: `http://localhost:5080`
- Health: `http://localhost:5080/api/v1/health`

### 5. Stop the platform

```bash
docker compose down
```

---

## How To Use

### Dashboard

Use `Dashboard` for:
- threat posture overview
- KPI review
- recent incidents
- quick navigation into investigation

### Analyze

Use `Analyze` for active casework:
1. choose `Standard Engine` or `AI Pipeline`
2. choose the channel: `Chat`, `Email`, `SMS`, or `URL`
3. paste content or upload a `.eml`
4. click `Run threat assessment`
5. review:
   - verdict
   - risk
   - executive summary
   - recommended response
   - threat story
   - investigation timeline
   - evidence signals
   - indicators and intel
   - AI trace

### Analytics

Use `Analytics` for:
- incident mix
- detection quality snapshot
- categories and repeated reasons
- hot indicators
- channel concentration
- recent threat cards

### Rules

Use `Rules` to:
- sign in as `admin` / `analyst`
- review rules
- create rules
- toggle rules

### AI Copilot

Use the floating `AI Copilot` to:
- summarize a case
- get next-best action
- generate an exec briefing
- suggest rule direction
- ask custom case questions

---

## Self-Hosted Gemma

ThreatWatch AI supports self-hosted assistant responses through Ollama.

### Run Ollama

Example:

```bash
ollama serve
ollama pull gemma4:e2b
```

### Configure ThreatWatch AI

Set in `.env`:

```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=gemma4:e2b
```

In the dashboard:
- switch to `AI Pipeline`
- choose `ollama/gemma4:e2b`
- run a scan or use the copilot

If Ollama is unavailable, the platform falls back gracefully instead of crashing.

---

## Authentication

Rule operations support:
- bearer token auth
- roles: `viewer`, `analyst`, `admin`
- legacy `X-API-Key` fallback for admin workflows

Example local bootstrap account:
- username: `admin`
- password: `changeme_admin_password`

Change this immediately for any real environment.

---

## Key Endpoints

Core:
- `POST /api/v1/scan`
- `POST /api/v1/scan/ai`
- `POST /api/v1/scan/upload`
- `GET /api/v1/scan/{id}`
- `POST /api/v1/scan/{id}/feedback`
- `GET /api/v1/stats`
- `GET /api/v1/analytics/summary`
- `GET /api/v1/health`

Auth and rules:
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `GET /api/v1/rules`
- `POST /api/v1/rules`
- `PATCH /api/v1/rules/{id}/toggle`

Assistant:
- `POST /api/v1/assistant/chat`
- `POST /api/v1/assistant/recommend`

---

## Example API Calls

### Standard scan

```bash
curl -X POST http://localhost:5080/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"URGENT: Your account is locked. Verify now.\",\"channel\":\"email\"}"
```

### AI scan

```bash
curl -X POST http://localhost:5080/api/v1/scan/ai ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"URGENT: Your account is locked. Verify now.\",\"channel\":\"email\",\"include_explanation\":true}"
```

### Login

```bash
curl -X POST http://localhost:5080/api/v1/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":\"changeme_admin_password\"}"
```

---

## Extensions

Included stubs:
- `chrome-extension/README.md`
- `thunderbird-extension/README.md`
- `outlook-web-extension/README.md`

These use the same backend scan APIs and are intended as starting points for productized mail-client integrations.

---

## Security Notes

Current hardening includes:
- security headers at nginx
- trusted-host enforcement
- request-size limits
- route-level rate limits
- safer auth handling
- no-store API responses
- optional Safe Browsing enrichment

Still recommended for production:
- stronger user storage and password hashing
- audit logs
- secrets rotation
- production-specific CORS and origin tightening

---

## Repo Structure

```text
backend/                  FastAPI app, rules, auth, assistant, analytics
frontend/                 Dashboard UI and static assets
nginx/                    Reverse proxy config
chrome-extension/         Gmail/Chrome extension stub
thunderbird-extension/    Thunderbird extension stub
outlook-web-extension/    Outlook Web extension stub
docker-compose.yml        Local stack entry point
.env.example              Environment template
PLAN.md                   Build and roadmap plan
```

---

## Verification

After startup, verify:

```bash
curl http://localhost:5080/api/v1/health
```

Expected:

```json
{"status":"ok","service":"threatwatch-api"}
```

Then open:

```text
http://localhost:5080
```

---

## Current Status

Implemented:
- dashboard + investigation UI
- analytics summary API and frontend
- rules manager UI
- auth/RBAC foundation
- BYOK model path
- Ollama / Gemma support
- assistant APIs
- branded incident printing
- browser/mail integration stubs

Best next step:
- real browser QA and final runtime validation across the full UI and extensions
