# AGENTS_PLAN.md — ThreatWatch AI Multi-Agent Pipeline
## Nexpert Hackathon 2026 · Team U

---

## 1. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CLIENT  POST /api/v1/scan/ai                                               │
│  { text, channel, url, include_explanation? }                               │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────────┐
│  FastAPI  backend/app/api/scan_ai.py                                        │
│  · Validates input (same ScanRequest schema)                                │
│  · Runs existing ML + rule engine  (unchanged path)                         │
│  · Launches OrchestratorAgent.run()  [async, awaited]                       │
│  · Merges ML result + agent result → response                               │
│  · Persists to scans table (agent_analysis JSONB column)                    │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │
                    asyncio.gather (parallel where marked)
                                │
┌───────────────────────────────▼─────────────────────────────────────────────┐
│                         OrchestratorAgent                                   │
│  · Holds ScanContext (text, channel, url, ml_score, rule_score, flags)      │
│  · Decides which sub-agents to activate based on context                    │
│  · Aggregates sub-agent results → final agent_verdict + confidence          │
│                                                                             │
│   STEP 1 — SEQUENTIAL                                                       │
│   └── ClassifierAgent     (always — primary LLM classification)             │
│                                                                             │
│   STEP 2 — PARALLEL (after Step 1)                                          │
│   ├── URLAnalystAgent     (only if url present)                             │
│   └── VerifierAgent       (always — needs ClassifierAgent result)           │
│                                                                             │
│   STEP 3 — SEQUENTIAL                                                       │
│   └── ExplainerAgent      (runs last — synthesises all results)             │
│                                                                             │
│   STEP 4 — AGGREGATE (in-process, no LLM)                                  │
│   └── OrchestratorAgent.aggregate() → AgentPipelineResult                  │
└─────────────────────────────────────────────────────────────────────────────┘

LLM Fallback Chain (per agent, independent):

  Each Agent
    ├─ try: GPT-4o           (openai SDK)
    ├─ except: GPT-4o-mini   (openai SDK)
    ├─ except: Claude Haiku  (anthropic SDK)
    └─ except: rule-only     (deterministic, no LLM — zero latency)
```

---

## 2. Graceful Degradation Levels

| Level | Condition | Pipeline Mode | Latency |
|-------|-----------|--------------|---------|
| All LLMs responding | Normal | `full` | 1-4s |
| OpenAI down, Anthropic up | Claude handles all | `partial` | 2-5s |
| All LLMs down / no keys | Rule signals only | `rule-only` | <50ms |
| DB down too | ML prediction only | `ml-only` | <10ms |

The `/api/v1/scan/ai` endpoint **never returns 500** due to LLM failures — it always degrades gracefully.

---

## 3. File Structure

```
backend/app/agents/
├── __init__.py              # exports run_pipeline, ScanContext, AgentPipelineResult
├── base.py                  # all dataclasses: ScanContext, AgentVerdict, *Result types
├── llm_client.py            # call_llm_with_fallback() + FALLBACK_CHAIN
├── orchestrator.py          # run_pipeline() + aggregate()
├── classifier_agent.py      # ClassifierAgent — LLM scam classification
├── url_analyst_agent.py     # URLAnalystAgent — domain + URL structure analysis
├── verifier_agent.py        # VerifierAgent — ML vs LLM cross-check
└── explainer_agent.py       # ExplainerAgent — user-facing plain-English explanation

backend/app/api/
└── scan_ai.py               # POST /api/v1/scan/ai
```

Register in `main.py`:
```python
from app.api.scan_ai import router as scan_ai_router
app.include_router(scan_ai_router)
```

---

## 4. Shared Base — `backend/app/agents/base.py`

```python
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class AgentVerdict(str, Enum):
    scam      = "scam"
    suspicious = "suspicious"
    safe      = "safe"
    uncertain  = "uncertain"   # VerifierAgent sets on ML/LLM disagreement


@dataclass
class ScanContext:
    text: str
    channel: str
    url: Optional[str]
    ml_score: float
    rule_score: float
    rule_flags: list[dict]
    include_explanation: bool = True


@dataclass
class AgentResult:
    agent_name: str
    success: bool
    llm_used: Optional[str] = None   # "gpt-4o" | "gpt-4o-mini" | "claude-haiku-3-5" | "rule-only"
    error: Optional[str] = None
    raw: Optional[Any] = None


@dataclass
class ClassifierResult(AgentResult):
    verdict: AgentVerdict = AgentVerdict.safe
    confidence: float = 0.0
    label: str = "safe"
    reasoning: str = ""
    scam_categories: list[str] = field(default_factory=list)


@dataclass
class URLAnalystResult(AgentResult):
    domain: Optional[str] = None
    is_suspicious: bool = False
    url_risk_score: float = 0.0
    findings: list[str] = field(default_factory=list)
    redirect_detected: bool = False
    lookalike_domain: bool = False


@dataclass
class VerifierResult(AgentResult):
    ml_verdict: str = ""
    llm_verdict: str = ""
    agreement: bool = True
    disagreement_severity: float = 0.0
    final_verdict: AgentVerdict = AgentVerdict.safe
    flags_disagreement: bool = False


@dataclass
class ExplainerResult(AgentResult):
    explanation: str = ""
    risk_factors: list[str] = field(default_factory=list)
    safe_indicators: list[str] = field(default_factory=list)
    user_action: str = ""


@dataclass
class AgentPipelineResult:
    final_verdict: AgentVerdict
    agent_confidence: float
    llm_risk_score: float
    blended_risk_score: float
    classifier: Optional[ClassifierResult] = None
    url_analyst: Optional[URLAnalystResult] = None
    verifier: Optional[VerifierResult] = None
    explainer: Optional[ExplainerResult] = None
    pipeline_mode: str = "full"
    agents_used: list[str] = field(default_factory=list)
    total_latency_ms: int = 0
```

---

## 5. LLM Client — `backend/app/agents/llm_client.py`

```python
import os
import logging
logger = logging.getLogger("threatwatch.llm")

FALLBACK_CHAIN = [
    ("gpt-4o",           "openai"),
    ("gpt-4o-mini",      "openai"),
    ("claude-haiku-3-5", "anthropic"),
]


async def call_llm_with_fallback(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 512,
    temperature: float = 0.1,
    json_mode: bool = True,
) -> tuple[str, str]:
    """
    Returns (response_text, model_name_used).
    Raises RuntimeError if all models fail.
    """
    last_error = None

    for model, provider in FALLBACK_CHAIN:
        try:
            if provider == "openai":
                api_key = os.environ.get("OPENAI_API_KEY", "")
                if not api_key:
                    raise ValueError("OPENAI_API_KEY not set")
                import openai
                client = openai.AsyncOpenAI(api_key=api_key)
                kwargs = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                if json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = await client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content, model

            elif provider == "anthropic":
                api_key = os.environ.get("ANTHROPIC_API_KEY", "")
                if not api_key:
                    raise ValueError("ANTHROPIC_API_KEY not set")
                import anthropic
                client = anthropic.AsyncAnthropic(api_key=api_key)
                system = system_prompt + "\n\nIMPORTANT: Respond in valid JSON only."
                resp = await client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                return resp.content[0].text, model

        except Exception as e:
            logger.warning(f"[llm] {model} failed: {type(e).__name__}: {e}")
            last_error = e
            continue

    raise RuntimeError(f"All LLM models failed. Last error: {last_error}")
```

---

## 6. Orchestrator — `backend/app/agents/orchestrator.py`

```python
import asyncio
import time
from app.agents.base import *
from app.agents.classifier_agent import ClassifierAgent
from app.agents.url_analyst_agent import URLAnalystAgent
from app.agents.verifier_agent import VerifierAgent
from app.agents.explainer_agent import ExplainerAgent


async def run_pipeline(ctx: ScanContext) -> AgentPipelineResult:
    t0 = time.monotonic()
    agents_used = []

    # Step 1 — sequential
    classifier = await ClassifierAgent().run(ctx)
    if classifier.llm_used != "rule-only":
        agents_used.append("ClassifierAgent")

    # Step 2 — parallel
    tasks = [VerifierAgent().run(ctx, classifier)]
    if ctx.url:
        tasks.append(URLAnalystAgent().run(ctx))

    results = await asyncio.gather(*tasks, return_exceptions=False)
    verifier = results[0]
    url_analyst = results[1] if ctx.url else None

    if verifier and verifier.llm_used != "rule-only":
        agents_used.append("VerifierAgent")
    if url_analyst and url_analyst.llm_used != "rule-only":
        agents_used.append("URLAnalystAgent")

    # Step 3 — sequential
    explainer = await ExplainerAgent().run(ctx, classifier, url_analyst, verifier)
    if explainer and explainer.llm_used != "rule-only":
        agents_used.append("ExplainerAgent")

    # Step 4 — aggregate
    pipeline_result = _aggregate(ctx, classifier, url_analyst, verifier, explainer)
    pipeline_result.agents_used = agents_used
    pipeline_result.pipeline_mode = "full" if agents_used else "rule-only"
    pipeline_result.total_latency_ms = int((time.monotonic() - t0) * 1000)
    return pipeline_result


def _aggregate(ctx, classifier, url_analyst, verifier, explainer) -> AgentPipelineResult:
    # Agent-side risk score
    llm_risk = classifier.confidence if classifier.verdict in (AgentVerdict.scam, AgentVerdict.suspicious) else (1 - classifier.confidence)
    if url_analyst and url_analyst.is_suspicious:
        llm_risk = min(1.0, llm_risk + url_analyst.url_risk_score * 0.3)

    # Final blended score: existing engine 50% + agent 50%
    base = 0.6 * ctx.rule_score + 0.4 * ctx.ml_score
    blended = round(0.5 * base + 0.5 * llm_risk, 4)

    # Resolve verdict
    final = verifier.final_verdict if verifier else classifier.verdict

    return AgentPipelineResult(
        final_verdict=final,
        agent_confidence=classifier.confidence,
        llm_risk_score=round(llm_risk, 4),
        blended_risk_score=blended,
        classifier=classifier,
        url_analyst=url_analyst,
        verifier=verifier,
        explainer=explainer,
    )
```

---

## 7. Agent System Prompts

### ClassifierAgent
```
You are a specialist AI threat analyst for ThreatWatch AI, a scam and phishing detection
system deployed in Malaysia.

CLASSIFICATION DEFINITIONS:
- "scam": High confidence (>70%) fraudulent. Fake authority impersonation (banks, government,
  courier), urgency, OTP/credential requests, fake prizes, investment fraud, malicious URLs.
- "suspicious": Ambiguous — some indicators present but insufficient to confirm fraud.
- "safe": No meaningful threat indicators.

HIGH-WEIGHT MALAYSIA PATTERNS:
- Banks: Maybank, CIMB, RHB, Public Bank, BSN, Bank Islam, Hong Leong, AmBank
- Government: LHDN, PDRM, JPJ, KWSP/EPF, MySejahtera
- Courier: Pos Laju, DHL, J&T — "customs fee" or "parcel on hold"
- Investment: guaranteed 20%+/month returns, Telegram investment groups
- OTP theft: share/forward/confirm OTP, PIN, or TAC code
- Gift card: purchase Touch 'n Go, iTunes, Google Play as "payment"

OUTPUT (strict JSON):
{
  "verdict": "safe"|"suspicious"|"scam",
  "confidence": 0.0–1.0,
  "reasoning": "One sentence — primary threat signal or why safe.",
  "scam_categories": ["phishing","urgency","impersonation","otp","financial","url"]
}

RULES: Conservative — use "suspicious" not "scam" when uncertain. Never hallucinate.
```

### URLAnalystAgent
```
You are a cybersecurity URL analyst for ThreatWatch AI.

ANALYSIS FRAMEWORK:
1. Domain legitimacy — lookalike domains, hyphen abuse, subdomain abuse, TLD mismatch
   (Malaysia: legitimate banks use .com.my not .xyz/.top/.click)
2. Structural red flags — raw IP hostname, excessively long/encoded URLs, login/verify/update
   in path when domain is not the real brand
3. URL shorteners (bit.ly, tinyurl, t.co, ow.ly, rb.gy) — always flag, destination hidden
4. Legitimate patterns — HTTPS on known domains (google.com, gov.my) reduce suspicion

OUTPUT (strict JSON):
{
  "domain": "extracted root domain",
  "is_suspicious": true|false,
  "url_risk_score": 0.0–1.0,
  "redirect_detected": true|false,
  "lookalike_domain": true|false,
  "findings": ["max 5 findings, most severe first, each ≤80 chars"]
}

RULES: url_risk_score 0.8+ only for IP URLs or confirmed lookalike. Never fabricate data.
```

### VerifierAgent
```
You are a QA auditor for ThreatWatch AI. Cross-examine two independent assessments —
one from an ML classifier, one from an LLM classifier. Identify disagreements and adjudicate.

ADJUDICATION RULES:
1. ML says scam (>0.65) + LLM says safe → flag uncertain, score = 0.55
2. LLM says scam (>0.80) + ML says safe (<0.35) → trust LLM, flags_disagreement = true
3. Both agree → agreement = true, average both scores
4. Both safe + high confidence → do not elevate verdict

OUTPUT (strict JSON):
{
  "ml_verdict": "safe"|"suspicious"|"scam",
  "llm_verdict": "safe"|"suspicious"|"scam",
  "agreement": true|false,
  "disagreement_severity": 0.0–1.0,
  "final_verdict": "safe"|"suspicious"|"scam"|"uncertain",
  "flags_disagreement": true|false,
  "adjudication_note": "One sentence."
}
```

### ExplainerAgent
```
You are the user-facing explanation engine for ThreatWatch AI. Audience: everyday Malaysian
internet users — not security professionals. Translate findings into clear, empathetic,
actionable English.

TONE: Informative not alarmist (suspicious), direct + protective (scam), brief (safe).
Never condescending. Never blame the user.

STRUCTURE:
1. Opening: verdict + primary reason (1 sentence)
2. Specific signals found (1-2 sentences)
3. Direct action instruction (1 sentence, specific)

CONTENT RULES:
- OTP messages: always include "Your bank will NEVER ask for your OTP."
- user_action must be specific (include hotline numbers where relevant):
  · Maybank fraud: 1300-88-6688
  · CIMB fraud: 1300-88-2265
  · National Scam Response Centre (NSRC): 997
  · CCID Scam: 03-2610-1559

OUTPUT (strict JSON):
{
  "explanation": "2-3 sentences for the user",
  "risk_factors": ["factor 1", "factor 2"],
  "safe_indicators": ["indicator if any"],
  "user_action": "Specific action"
}
```

---

## 8. New API Endpoint — `backend/app/api/scan_ai.py`

### Request
```
POST /api/v1/scan/ai
```
```json
{
  "text": "URGENT: Your Maybank account has been suspended. Verify: http://bit.ly/mb-2026",
  "channel": "email",
  "url": "http://bit.ly/mb-2026",
  "include_explanation": true
}
```

### Response (full pipeline)
```json
{
  "scan_id": 42,
  "verdict": "scam",
  "risk_score": 0.91,
  "risk_percent": 91,
  "ml_score": 0.87,
  "rule_score": 0.95,
  "reasons": ["Bank impersonation", "URL shortener used", "Urgency pressure tactic"],
  "highlighted_tokens": ["urgent", "bit.ly", "suspended"],
  "channel": "email",
  "agent": {
    "verdict": "scam",
    "confidence": 0.97,
    "pipeline_mode": "full",
    "agents_used": ["ClassifierAgent", "URLAnalystAgent", "VerifierAgent", "ExplainerAgent"],
    "explanation": "This message impersonates Maybank and uses a shortened URL to hide a phishing destination. The urgency language and account-suspension threat are classic tactics designed to bypass rational decision-making.",
    "risk_factors": ["Bank impersonation (Maybank)", "Shortened URL concealing destination", "Artificial urgency — account suspension threat"],
    "safe_indicators": [],
    "user_action": "Do NOT click the link. Call Maybank fraud team immediately at 1300-88-6688 or the National Scam Response Centre at 997.",
    "url_findings": ["bit.ly is a URL shortener — destination hidden", "Redirect chain detected"],
    "is_uncertain": false,
    "latency_ms": 1840
  }
}
```

### Response (degraded — no LLM keys)
```json
{
  "agent": {
    "pipeline_mode": "rule-only",
    "agents_used": [],
    "explanation": null,
    "latency_ms": 12
  }
}
```

---

## 9. PostgreSQL Schema Changes

### Add `agent_analysis` JSONB column to `scans` table

In `backend/app/db/models.py`, add to `Scan` class:
```python
agent_analysis = Column(JSON, nullable=True, default=None)
```

In `backend/app/db/migrate.py`, add after `create_all()`:
```python
async def add_agent_analysis_column():
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE scans
            ADD COLUMN IF NOT EXISTS agent_analysis JSONB DEFAULT NULL;
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_scans_agent_verdict
            ON scans ((agent_analysis->>'agent_verdict'))
            WHERE agent_analysis IS NOT NULL;
        """))
    print("[migrate] agent_analysis column verified.")
```

No new tables needed for the hackathon. Post-hackathon: normalize into `agent_results` table.

---

## 10. Environment Variables (additions to `.env.example`)

```bash
# =============================================================================
# AGENT PIPELINE — ThreatWatch AI Multi-Agent Layer
# =============================================================================

# OpenAI — primary LLM (GPT-4o / GPT-4o-mini)
# Get from: https://platform.openai.com/api-keys
OPENAI_API_KEY=sk-proj-...

# Anthropic — Claude Haiku fallback
# Get from: https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-...

# Agent config
AGENT_LLM_TIMEOUT=15
AGENT_MAX_TOKENS=512
AGENT_PIPELINE_ENABLED=true
AGENT_PRIMARY_MODEL=gpt-4o      # switch to gpt-4o-mini to save cost during testing
AGENT_RATE_LIMIT=5/minute
```

---

## 11. Cost Estimate

| Model | Input (3,200 tok) | Output (590 tok) | Cost/scan |
|-------|------------------|-----------------|-----------|
| GPT-4o | $2.50/1M | $10.00/1M | ~$0.014 |
| GPT-4o-mini | $0.15/1M | $0.60/1M | ~$0.001 |
| Claude Haiku 3.5 | $0.80/1M | $4.00/1M | ~$0.005 |
| Rule-only | — | — | $0.000 |

**Hackathon budget for 500 demo scans:**
- GPT-4o: ~$7.00
- GPT-4o-mini: ~$0.42

**Latency (parallel pipeline):**
- GPT-4o: P50 ~3.5s, P95 ~7s
- GPT-4o-mini: P50 ~1.2s, P95 ~2.5s
- Rule-only fallback: <50ms

---

## 12. Implementation Sequence

| Phase | Tasks | Priority |
|-------|-------|----------|
| **1 — Foundation** | `base.py`, `agent_analysis` DB column, `config.py` updates, `requirements.txt` | Do first |
| **2 — LLM Infra** | `llm_client.py` + unit tests (mock all providers) | Do second |
| **3 — Agents** | `classifier_agent.py` → `verifier_agent.py` + `url_analyst_agent.py` (parallel) → `explainer_agent.py` | Can split across team |
| **4 — Wiring** | `orchestrator.py` → `scan_ai.py` → register router in `main.py` | After agents done |
| **5 — Test** | Integration tests with mocked + real keys, load test concurrent `/scan/ai` | Before demo |

---

## 13. Parallel Execution Summary

```
Step 1 (sequential):   ClassifierAgent           ~1.2s
                              │
Step 2 (parallel):     URLAnalystAgent            ~1.0s
                       VerifierAgent            ──── wall time = max(both) ~1.0s
                              │
Step 3 (sequential):   ExplainerAgent             ~1.0s
                              │
Step 4 (in-process):   aggregate()                <1ms
                              │
Total wall time (gpt-4o-mini): ~3.2s
Total wall time (gpt-4o):      ~5.5s
Savings from parallel Step 2:  ~1-2s vs naive sequential
```
