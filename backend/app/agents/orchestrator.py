"""
OrchestratorAgent — wires all agents into the dependency pipeline.

Execution order:
  Step 1 (sequential):  ClassifierAgent
  Step 2 (parallel):    URLAnalystAgent + VerifierAgent
  Step 3 (sequential):  ExplainerAgent
  Step 4 (in-process):  aggregate()
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from app.agents.base import (
    AgentPipelineResult, AgentVerdict,
    ClassifierResult, ExplainerResult,
    ScanContext, URLAnalystResult, VerifierResult,
)
from app.agents import classifier_agent, verifier_agent, url_analyst_agent, explainer_agent

logger = logging.getLogger("threatwatch.agents.orchestrator")


async def run_pipeline(ctx: ScanContext) -> AgentPipelineResult:
    t0 = time.monotonic()
    agents_used: list[str] = []

    # ── Step 1: classify ──────────────────────────────────────────��───────────
    classifier: ClassifierResult = await classifier_agent.run(ctx)
    if classifier.llm_used not in ("rule-only", "skipped", None):
        agents_used.append("ClassifierAgent")

    # ── Step 2: parallel — url analyst + verifier ────────────────────────────
    tasks: list = [verifier_agent.run(ctx, classifier)]
    has_url = bool(ctx.url)
    if has_url:
        tasks.append(url_analyst_agent.run(ctx))

    results = await asyncio.gather(*tasks, return_exceptions=False)

    verifier: VerifierResult = results[0]
    url_analyst: Optional[URLAnalystResult] = results[1] if has_url else None

    if verifier.llm_used not in ("rule-only", "skipped", None):
        agents_used.append("VerifierAgent")
    if url_analyst and url_analyst.llm_used not in ("rule-only", "skipped", None):
        agents_used.append("URLAnalystAgent")

    # ── Step 3: explain ───────────────────────────────────────────────────────
    explainer: ExplainerResult = await explainer_agent.run(ctx, classifier, url_analyst, verifier)
    if explainer.llm_used not in ("rule-only", "skipped", None):
        agents_used.append("ExplainerAgent")

    # ── Step 4: aggregate ─────────────────────────────────────────────────────
    pipeline = _aggregate(ctx, classifier, url_analyst, verifier, explainer)
    pipeline.agents_used = agents_used
    pipeline.pipeline_mode = "full" if agents_used else "rule-only"
    pipeline.total_latency_ms = int((time.monotonic() - t0) * 1000)

    logger.info(
        f"[orchestrator] done — verdict={pipeline.final_verdict.value} "
        f"score={pipeline.blended_risk_score:.3f} "
        f"mode={pipeline.pipeline_mode} "
        f"latency={pipeline.total_latency_ms}ms"
    )
    return pipeline


def _aggregate(
    ctx: ScanContext,
    classifier: ClassifierResult,
    url_analyst: Optional[URLAnalystResult],
    verifier: VerifierResult,
    explainer: ExplainerResult,
) -> AgentPipelineResult:
    # Agent-side risk score
    if classifier.verdict in (AgentVerdict.scam, AgentVerdict.suspicious):
        llm_risk = classifier.confidence
    else:
        llm_risk = 1.0 - classifier.confidence   # safe with high confidence → low risk

    # URL boost
    if url_analyst and url_analyst.is_suspicious:
        llm_risk = min(1.0, llm_risk + url_analyst.url_risk_score * 0.25)

    # Engine score (existing layers)
    engine_score = min(0.6 * ctx.rule_score + 0.4 * ctx.ml_score, 1.0)

    # Blended final: 50/50 engine vs agent
    blended = round(0.5 * engine_score + 0.5 * llm_risk, 4)

    # Final verdict: verifier wins (it cross-checks both layers)
    final = verifier.final_verdict

    return AgentPipelineResult(
        final_verdict=final,
        agent_confidence=round(classifier.confidence, 4),
        llm_risk_score=round(llm_risk, 4),
        blended_risk_score=blended,
        classifier=classifier,
        url_analyst=url_analyst,
        verifier=verifier,
        explainer=explainer,
    )
