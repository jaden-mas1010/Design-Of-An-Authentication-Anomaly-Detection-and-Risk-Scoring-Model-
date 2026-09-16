"""
api.schemas
===========
Pydantic models defining the HTTP contract for the AADRS API.

Field names deliberately mirror engine.models so that translating an
ECS-formatted authentication log line into a request body is close to
1:1. This is the contract David / PMS Ltd would integrate against.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AuthEventIn(BaseModel):
    """A single authentication event to be scored."""
    user_id: str = Field(..., examples=["u001"])
    event_time: datetime = Field(..., examples=["2026-07-08T09:30:00"])
    source_ip: str = Field(..., examples=["82.132.200.10"])
    provider: str = Field(..., examples=["azure_ad"])
    country_code: str = Field(..., examples=["GB"])
    outcome: str = Field(default="success", examples=["success", "failure"])
    mfa_used: bool = False
    recent_failure_count: int = 0
    device_fingerprint: Optional[str] = None


class UserBaselineIn(BaseModel):
    """Registers/updates a behavioural baseline for a user."""
    usual_countries: List[str] = Field(default_factory=list)
    usual_hours_utc: List[int] = Field(default_factory=list)


class DeviceProfileIn(BaseModel):
    """Registers/updates a known device for a user."""
    device_fingerprint: str
    is_trusted: bool = False
    total_logins: int = 0
    
class AskIn(BaseModel):
    """A free-text question about the current dashboard state, plus the context to answer it from."""
    question: str
    context: str  # compact summary built client-side from currently-visible events


class AskOut(BaseModel):
    answer: str
    source: str  # "groq" or "unavailable"

class RiskFactorOut(BaseModel):
    rule_id: str
    description: str
    points: int
    mitre_technique_id: Optional[str] = None


class ContributingFactorOut(BaseModel):
    """One rule's contribution to an alert, in both technical and plain language."""
    rule_id: str
    technical: str
    plain: str
    points: int
    mitre_technique_id: Optional[str] = None


class AlertExplanationOut(BaseModel):
    """
    Dual-audience explanation with prioritised remediation and an
    LLM-narrated (or safe-fallback) summary. See engine.explain and
    engine.groq_narrator for how this is built and grounded.
    """
    technical_summary: str
    plain_summary: str
    contributing_factors: List[ContributingFactorOut]
    recommended_actions: List[str]
    narrative: str
    narrative_source: str  # "groq" or "mock" - always know which one produced it


class RiskScoreOut(BaseModel):
    risk_score: int
    risk_tier: str
    risk_factors: List[str]
    risk_factor_details: List[RiskFactorOut]
    mitre_technique_id: List[str]
    baseline_used: bool
    device_used: bool
    explanation: Optional[AlertExplanationOut] = None


class MLScoreOut(BaseModel):
    anomaly_score: int
    risk_tier: str
    is_outlier: bool
    contributing_features: List[str]


class CompareScoreOut(BaseModel):
    rule_based: RiskScoreOut
    ml_based: MLScoreOut
    tiers_agree: bool
