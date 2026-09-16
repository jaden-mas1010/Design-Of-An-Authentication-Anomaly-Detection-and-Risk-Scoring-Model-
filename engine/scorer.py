"""
engine.scorer
=============
Orchestrates the individual detection rules in engine.rules into a single
weighted, capped, tiered risk score (0-100).

This is intentionally simple and linear (sum of triggered rule weights,
capped at 100) rather than a black-box model, per the dissertation's core
design decision (Section 1.2 / 3.4): a transparent, explainable scoring
approach over an opaque one. Every point in the final score can be traced
back to a named rule via RiskScoreResult.risk_factor_details.
"""

from __future__ import annotations

from typing import List, Optional

from .models import AuthEvent, User, UserBaseline, DeviceProfile, RiskFactor, RiskScoreResult, RiskTier
from . import rules as rule_defs

MAX_SCORE = 100

# Score thresholds mapping a numeric score onto a qualitative tier.
# Tuned provisionally; intended to be revisited during Phase 6 evaluation
# against labelled CERT/LANL data (detection rate vs false positive rate).
TIER_THRESHOLDS = (
    (85, RiskTier.CRITICAL),
    (60, RiskTier.HIGH),
    (30, RiskTier.MEDIUM),
    (0, RiskTier.LOW),
)


def _score_to_tier(score: int) -> RiskTier:
    for threshold, tier in TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return RiskTier.LOW  # unreachable given 0 is the final threshold, kept for safety


def compute_risk_score(
    event: AuthEvent,
    user: User,
    baseline: Optional[UserBaseline] = None,
    device: Optional[DeviceProfile] = None,
) -> RiskScoreResult:
    """
    Compute a weighted risk score for a single authentication event.

    Parameters
    ----------
    event    : the authentication event being scored
    user     : the identity the event belongs to (kept for future rules,
               e.g. role-based weighting for privileged accounts)
    baseline : the user's behavioural baseline, if available
    device   : the device profile matching event.device_fingerprint, if known

    Returns
    -------
    RiskScoreResult with a 0-100 score, a qualitative tier, human-readable
    factor strings (for logging/printing), structured RiskFactor objects
    (for UI/API consumers), and any MITRE ATT&CK technique IDs implicated.
    """
    triggered: List[RiskFactor] = []

    context = {"event": event, "baseline": baseline, "device": device}

    for _name, rule_fn, arg_names in rule_defs.SIMPLE_RULES:
        args = [context[name] for name in arg_names]
        result = rule_fn(*args)
        if result is not None:
            triggered.append(result)

    # R009 depends on the score accumulated so far, so it runs after the
    # simple rules rather than being folded into SIMPLE_RULES.
    running_score = sum(rf.points for rf in triggered)
    mfa_rule = rule_defs.rule_no_mfa_on_risky_login(event, running_score)
    if mfa_rule is not None:
        triggered.append(mfa_rule)

    raw_score = sum(rf.points for rf in triggered)
    final_score = min(raw_score, MAX_SCORE)
    tier = _score_to_tier(final_score)

    technique_ids = sorted({
        rf.mitre_technique_id for rf in triggered if rf.mitre_technique_id is not None
    })

    return RiskScoreResult(
        risk_score=final_score,
        risk_tier=tier.value,
        risk_factors=[str(rf) for rf in triggered],
        risk_factor_details=triggered,
        mitre_technique_id=technique_ids,
    )
