"""
engine.features
================
Shared feature engineering for the ML anomaly scorer (engine.ml_scorer).

Kept separate from ml_scorer so the same feature vector definition can be
reused by training-data generation, live scoring, and any future
evaluation scripts without drifting out of sync.

Feature vector (all numeric, order matters):
    [0] hour_of_day            0-23
    [1] country_is_usual       1 if country in baseline.usual_countries, else 0
    [2] country_is_high_risk   1 if country in the high-risk list, else 0
    [3] device_known           1 if a DeviceProfile exists, else 0
    [4] device_trusted         1 if device exists and is_trusted, else 0
    [5] device_total_logins    raw count (0 if unknown device)
    [6] recent_failure_count   raw count
    [7] mfa_used               1/0
    [8] outcome_is_failure     1/0

This is deliberately the same signal set the rule-based engine uses
(engine.rules), so the two approaches are evaluated on equal footing -
the comparison in Phase 6 is about detection *method*, not about one
model having access to richer features than the other.
"""

from __future__ import annotations

from typing import List, Optional

from .models import AuthEvent, UserBaseline, DeviceProfile
from .rules import HIGH_RISK_COUNTRIES

FEATURE_NAMES = [
    "hour_of_day",
    "country_is_usual",
    "country_is_high_risk",
    "device_known",
    "device_trusted",
    "device_total_logins",
    "recent_failure_count",
    "mfa_used",
    "outcome_is_failure",
]


def extract_features(
    event: AuthEvent,
    baseline: Optional[UserBaseline] = None,
    device: Optional[DeviceProfile] = None,
) -> List[float]:
    """Convert an AuthEvent + context into the numeric feature vector above."""
    country_is_usual = (
        1.0 if baseline and baseline.usual_countries and event.country_code in baseline.usual_countries
        else 0.0
    )
    country_is_high_risk = 1.0 if event.country_code in HIGH_RISK_COUNTRIES else 0.0
    device_known = 1.0 if device is not None else 0.0
    device_trusted = 1.0 if (device is not None and device.is_trusted) else 0.0
    device_total_logins = float(device.total_logins) if device is not None else 0.0

    return [
        float(event.event_time.hour),
        country_is_usual,
        country_is_high_risk,
        device_known,
        device_trusted,
        device_total_logins,
        float(event.recent_failure_count),
        1.0 if event.mfa_used else 0.0,
        1.0 if event.outcome == "failure" else 0.0,
    ]
