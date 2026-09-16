"""
engine.models
=============
Core data structures for the AADRS engine.

Field choices are aligned with the Elastic Common Schema (ECS) authentication
fields where possible (source_ip, user, event), so that this schema can later
be mapped onto real SIEM data (Elastic / Sentinel) with minimal translation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


# ---------------------------------------------------------------------------
# Core entities
# ---------------------------------------------------------------------------

@dataclass
class User:
    """A directory identity that authentication events belong to."""
    user_id: str
    upn: str  # user principal name, e.g. alice@company.com


@dataclass
class UserBaseline:
    """
    Behavioural baseline for a user, built from historical authentication
    activity. In a production deployment this would be computed on a
    rolling window (e.g. last 30 days of successful logins); here it is
    supplied directly for prototyping and testing.
    """
    user_id: str
    usual_countries: List[str] = field(default_factory=list)
    usual_hours_utc: List[int] = field(default_factory=list)  # 0-23
    usual_devices: List[str] = field(default_factory=list)    # known device fingerprints


@dataclass
class DeviceProfile:
    """
    Known-device record. Absence of a DeviceProfile for an event (device=None)
    is itself a risk signal, since it means the device has never been
    enrolled/seen before.
    """
    device_id: str
    user_id: str
    device_fingerprint: str
    is_trusted: bool = False
    total_logins: int = 0
    first_seen: Optional[datetime] = None


@dataclass
class AuthEvent:
    """
    A single authentication event, aligned to ECS auth-event style fields.
    """
    user_id: str
    event_time: datetime
    source_ip: str
    provider: str                      # e.g. "azure_ad", "okta", "adfs"
    country_code: str                  # ISO 3166-1 alpha-2, from IP geolocation
    outcome: str = "success"           # "success" | "failure"
    mfa_used: bool = False
    recent_failure_count: int = 0      # failed attempts for this user in the preceding window
    device_fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# Scoring output
# ---------------------------------------------------------------------------

class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskFactor:
    """
    A single triggered detection rule, kept as a structured object (not just
    a string) so the result stays machine-readable and explainable —
    important for the transparency requirement PMS Ltd flagged.
    """
    rule_id: str
    description: str
    points: int
    mitre_technique_id: Optional[str] = None

    def __str__(self) -> str:
        return f"[{self.rule_id}] {self.description} (+{self.points})"


@dataclass
class RiskScoreResult:
    risk_score: int
    risk_tier: str
    risk_factors: List[str]                  # human-readable summaries (what main.py prints)
    risk_factor_details: List[RiskFactor]     # structured version, for programmatic use / UI
    mitre_technique_id: List[str]             # de-duplicated list of technique IDs triggered
