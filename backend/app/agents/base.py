"""
Shared dataclasses and result types for the ThreatWatch AI agent pipeline.
All agents operate on ScanContext and return a subclass of AgentResult.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AgentVerdict(str, Enum):
    scam       = "scam"
    suspicious = "suspicious"
    safe       = "safe"
    uncertain  = "uncertain"   # VerifierAgent sets when ML and LLM disagree sharply


@dataclass
class ScanContext:
    """Immutable input passed to every agent."""
    text: str
    channel: str
    url: Optional[str]
    ml_score: float          # 0.0–1.0 from ML ensemble
    rule_score: float        # 0.0–1.0 from rule engine
    rule_flags: list[dict]   # triggered rule entries from rule_engine.py
    include_explanation: bool = True
    llm_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Base result — every agent returns this or a subclass."""
    agent_name: str
    success: bool
    llm_used: Optional[str] = None   # "gpt-4o" | "gpt-4o-mini" | "claude-haiku-3-5" | "rule-only"
    error: Optional[str] = None
    raw: Optional[Any] = None        # raw LLM response text (for debugging)


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
    adjudication_note: str = ""


@dataclass
class ExplainerResult(AgentResult):
    explanation: str = ""
    risk_factors: list[str] = field(default_factory=list)
    safe_indicators: list[str] = field(default_factory=list)
    user_action: str = ""


@dataclass
class AgentPipelineResult:
    """Final aggregated output from OrchestratorAgent."""
    final_verdict: AgentVerdict
    agent_confidence: float
    llm_risk_score: float           # 0.0–1.0 derived from agent pipeline
    blended_risk_score: float       # weighted blend of ML + rule + agent
    classifier: Optional[ClassifierResult] = None
    url_analyst: Optional[URLAnalystResult] = None
    verifier: Optional[VerifierResult] = None
    explainer: Optional[ExplainerResult] = None
    pipeline_mode: str = "full"     # "full" | "partial" | "rule-only"
    agents_used: list[str] = field(default_factory=list)
    total_latency_ms: int = 0
