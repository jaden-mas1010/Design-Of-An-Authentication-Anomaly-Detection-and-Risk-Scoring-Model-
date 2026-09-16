"""
engine.rules
============
Individual detection rules for the AADRS engine.

Design principle (per dissertation proposal, Section 3.4 / 4.1): favour
transparent, individually-documented rule-based logic over an opaque
black-box score, so that any triggered rule can be explained to an analyst
in one sentence. Each rule:

  - takes the event + context it needs,
  - returns a RiskFactor if it fires, or None if it doesn't,
  - is independently unit-testable (see tests/test_scorer.py).

Weights are provisional and intended to be tuned during Phase 5/6
evaluation against the CERT/LANL datasets, not treated as final.
"""

from __future__ import annotations

from typing import Optional

from .models import AuthEvent, UserBaseline, DeviceProfile, RiskFactor


# Simplified illustrative list of higher-risk source countries for
# credential-based attacks, per common threat intel reporting. In a
# production system this would be sourced from a maintained feed rather
# than hard-coded.
HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "SY"}

# Threshold below which a device is considered "newly enrolled" even if
# a profile exists.
LOW_HISTORY_LOGIN_THRESHOLD = 3

# Failure-count thresholds used to distinguish an isolated bad password
# entry from a brute-force / credential-stuffing pattern.
BRUTE_FORCE_THRESHOLD = 5
CREDENTIAL_STUFFING_THRESHOLD = 8
EXTREME_FAILURE_THRESHOLD = 50


def rule_unusual_country(event: AuthEvent, baseline: Optional[UserBaseline]) -> Optional[RiskFactor]:
    """R001: login from a country outside the user's established baseline."""
    if baseline and baseline.usual_countries and event.country_code not in baseline.usual_countries:
        return RiskFactor(
            rule_id="R001",
            description=f"Login from country ({event.country_code}) outside user's usual countries",
            points=15,
        )
    return None


def rule_high_risk_country(event: AuthEvent) -> Optional[RiskFactor]:
    """R002: login from a country on the high-risk source list, regardless of baseline."""
    if event.country_code in HIGH_RISK_COUNTRIES:
        return RiskFactor(
            rule_id="R002",
            description=f"Login from high-risk country ({event.country_code})",
            points=25,
            mitre_technique_id="T1078",  # Valid Accounts
        )
    return None


def rule_off_hours(event: AuthEvent, baseline: Optional[UserBaseline]) -> Optional[RiskFactor]:
    """R003: login outside the user's usual hours of activity (UTC)."""
    if baseline and baseline.usual_hours_utc and event.event_time.hour not in baseline.usual_hours_utc:
        return RiskFactor(
            rule_id="R003",
            description=f"Login at {event.event_time.hour:02d}:00 UTC, outside usual hours",
            points=10,
        )
    return None


def rule_unknown_device(event: AuthEvent, device: Optional[DeviceProfile]) -> Optional[RiskFactor]:
    """R004: no device profile at all — device has never been enrolled/seen."""
    if device is None:
        return RiskFactor(
            rule_id="R004",
            description="No known device profile for this login (unrecognised device)",
            points=15,
            mitre_technique_id="T1078",
        )
    return None


def rule_untrusted_device(device: Optional[DeviceProfile]) -> Optional[RiskFactor]:
    """R005: device profile exists but is explicitly marked as not trusted."""
    if device is not None and not device.is_trusted:
        return RiskFactor(
            rule_id="R005",
            description=f"Device {device.device_id} is not marked as trusted",
            points=10,
        )
    return None


def rule_low_history_device(device: Optional[DeviceProfile]) -> Optional[RiskFactor]:
    """R006: device exists but has very little login history (recently enrolled)."""
    if device is not None and device.total_logins < LOW_HISTORY_LOGIN_THRESHOLD:
        return RiskFactor(
            rule_id="R006",
            description=f"Device {device.device_id} has low login history ({device.total_logins} logins)",
            points=5,
        )
    return None


def rule_brute_force(event: AuthEvent) -> Optional[RiskFactor]:
    """R007: elevated recent failure count preceding this event (brute-force precursor)."""
    if event.recent_failure_count >= BRUTE_FORCE_THRESHOLD:
        return RiskFactor(
            rule_id="R007",
            description=f"{event.recent_failure_count} recent failed attempts before this login",
            points=20,
            mitre_technique_id="T1110",  # Brute Force
        )
    return None


def rule_credential_stuffing(event: AuthEvent) -> Optional[RiskFactor]:
    """R008: failure volume high enough to suggest automated/credential-stuffing activity."""
    if event.recent_failure_count >= CREDENTIAL_STUFFING_THRESHOLD:
        return RiskFactor(
            rule_id="R008",
            description=f"Failure volume ({event.recent_failure_count}) consistent with automated attack tooling",
            points=15,
            mitre_technique_id="T1110.004",  # Brute Force: Credential Stuffing
        )
    return None


def rule_extreme_failure_volume(event: AuthEvent) -> Optional[RiskFactor]:
    """
    R012: failure volume so high it indicates large-scale automated attack
    infrastructure (e.g. a botnet or distributed credential-stuffing run),
    not just a persistent individual attacker. Stacks on top of R007/R008
    rather than replacing them, so severity keeps scaling instead of
    plateauing once R008's threshold is crossed - without this, 10 failed
    attempts and 10,000 failed attempts would score identically.
    """
    if event.recent_failure_count >= EXTREME_FAILURE_THRESHOLD:
        return RiskFactor(
            rule_id="R012",
            description=f"Failure volume ({event.recent_failure_count}) indicates large-scale automated attack",
            points=20,
            mitre_technique_id="T1110.004",
        )
    return None


def rule_no_mfa_on_risky_login(event: AuthEvent, running_score_before_this_rule: int) -> Optional[RiskFactor]:
    """
    R009: MFA absent on a login that has already accumulated meaningful risk
    from other rules. Deliberately compounding rather than standalone -
    a normal login without MFA is common and not itself suspicious.

    Threshold set at >=15 to align with the weight of a single full-strength
    individual signal (R001/R004 each carry +15) - a login must already
    carry at least one independently-triggered risk factor before the
    absence of MFA is treated as compounding risk, rather than penalising
    no-MFA on an otherwise clean login. Provisional pending Phase 6
    evaluation against labelled data (see docs/evaluation_plan.md).
    """
    if not event.mfa_used and running_score_before_this_rule >= 15:
        return RiskFactor(
            rule_id="R009",
            description="No MFA used on a login with other risk indicators present",
            points=10,
        )
    return None


def rule_failed_outcome(event: AuthEvent) -> Optional[RiskFactor]:
    """R010: the event itself is a failed authentication attempt."""
    if event.outcome == "failure":
        return RiskFactor(
            rule_id="R010",
            description="Authentication outcome was a failure",
            points=5,
        )
    return None


def rule_new_provider_pattern(event: AuthEvent, baseline: Optional[UserBaseline]) -> Optional[RiskFactor]:
    """
    R011: placeholder for legacy/unusual-protocol detection (e.g. a user who
    normally authenticates via modern auth suddenly using a legacy IMAP/POP
    endpoint). Not exercised by current models but documented here as part
    of the >=10 rule requirement and left as an extension point.
    """
    return None


# Ordered list of all rules that take only (event, baseline, device) so the
# scorer can iterate them generically where possible. R009 is handled
# separately in scorer.py since it depends on the running score.
SIMPLE_RULES = (
    ("unusual_country", rule_unusual_country, ("event", "baseline")),
    ("high_risk_country", rule_high_risk_country, ("event",)),
    ("off_hours", rule_off_hours, ("event", "baseline")),
    ("unknown_device", rule_unknown_device, ("event", "device")),
    ("untrusted_device", rule_untrusted_device, ("device",)),
    ("low_history_device", rule_low_history_device, ("device",)),
    ("brute_force", rule_brute_force, ("event",)),
    ("credential_stuffing", rule_credential_stuffing, ("event",)),
    ("extreme_failure_volume", rule_extreme_failure_volume, ("event",)),
    ("failed_outcome", rule_failed_outcome, ("event",)),
)
