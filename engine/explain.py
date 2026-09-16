"""
engine.explain
===============
Turns a RiskScoreResult into a structured, prioritised, dual-audience
explanation with remediation steps - implementing the evidence chain
discussed with PMS Ltd (04.08.2026 meeting, Question 4 & 7):

    Authentication event -> detected anomaly -> contributing factors
    -> risk score -> evidence -> explanation -> recommended action

Every explanation is grounded in the RiskFactor objects the scorer
already produced - nothing here is generated freely; each sentence
traces back to a specific rule that actually fired. This is deliberate:
the meeting specifically flagged the risk of "unsupported or fabricated
AI responses" in a security context, so this module is a template/lookup
system, not a free-text generator, even though its output could later
feed an LLM-based NLP layer as structured evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .models import RiskFactor, RiskScoreResult


@dataclass
class RuleExplanation:
    """Static knowledge-base entry for one rule: how to explain and fix it."""
    technical: str          # for a SOC analyst / engineer
    plain: str               # for a non-technical stakeholder
    remediation: List[str]   # ordered, concrete steps
    urgency_note: str = ""   # optional extra context on why timing matters


# ---------------------------------------------------------------------------
# Knowledge base: one entry per rule ID. This is the part of the system a
# security SME should review/extend - it is intentionally separate from
# the scoring logic in rules.py so the two can evolve independently.
# ---------------------------------------------------------------------------
RULE_EXPLANATIONS: dict[str, RuleExplanation] = {
    "R001": RuleExplanation(
        technical="Login originated from a country outside the user's established baseline.",
        plain="This person signed in from a country they don't normally use.",
        remediation=[
            "Confirm with the user directly (via a separate channel, not email) whether they are travelling.",
            "If unconfirmed, treat as potential credential compromise and consider a forced password reset.",
        ],
    ),
    "R002": RuleExplanation(
        technical="Login originated from a country on the high-risk source list associated with credential-based attacks (MITRE T1078).",
        plain="This sign-in came from a location commonly linked to hacking attempts.",
        remediation=[
            "Escalate immediately - do not wait for user confirmation before restricting the session.",
            "Revoke active sessions for this account and force re-authentication with MFA.",
            "Check for other recent logins from this account for signs of broader compromise.",
        ],
        urgency_note="High-confidence threat-intel signal - treat as time-sensitive.",
    ),
    "R003": RuleExplanation(
        technical="Login occurred outside the user's established active hours (UTC).",
        plain="This person signed in at an unusual time for them.",
        remediation=[
            "Cross-check against known shift patterns or recent travel/time-zone changes.",
            "Weak signal alone - only act if combined with other flags on this alert.",
        ],
    ),
    "R004": RuleExplanation(
        technical="No device profile exists for this login - device has never been enrolled or seen (MITRE T1078).",
        plain="This sign-in came from a device we've never seen this person use before.",
        remediation=[
            "Prompt the user to verify the device via a trusted secondary channel.",
            "If unverified, block the session and require device registration before allowing access.",
        ],
    ),
    "R005": RuleExplanation(
        technical="Device profile exists but is explicitly marked as untrusted.",
        plain="This device is known to us but has not been approved for use.",
        remediation=[
            "Review why this device was never marked trusted - shared/kiosk device, BYOD policy gap, etc.",
            "Consider blocking untrusted devices from sensitive systems by policy.",
        ],
    ),
    "R006": RuleExplanation(
        technical="Device is trusted but has very limited login history (recently enrolled).",
        plain="This is a trusted device, but it's new - we don't have much history on it yet.",
        remediation=[
            "No immediate action required in isolation - monitor for repeat low-history flags on the same device.",
        ],
    ),
    "R007": RuleExplanation(
        technical="Elevated recent failure count preceding this login is consistent with brute-force activity (MITRE T1110).",
        plain="There were several failed sign-in attempts right before this one succeeded - a common sign of a guessed password.",
        remediation=[
            "Force an immediate password reset for this account.",
            "Check whether the failed attempts came from the same source as the eventual success.",
            "Review account lockout policy - this pattern may indicate lockout thresholds are too permissive.",
        ],
        urgency_note="Strong indicator of active credential-guessing - respond promptly.",
    ),
    "R008": RuleExplanation(
        technical="Failure volume is high enough to suggest automated credential-stuffing tooling rather than manual attempts (MITRE T1110.004).",
        plain="The number of failed attempts is far beyond what a person mistyping a password would produce - this looks automated.",
        remediation=[
            "Treat as a confirmed automated attack, not a user error.",
            "Force password reset and check if the same password is reused elsewhere (credential-stuffing implies a leaked password list).",
            "Consider CAPTCHA or rate-limiting on this account/endpoint going forward.",
        ],
        urgency_note="Automated attack tooling - escalate without waiting for user response.",
    ),
    "R009": RuleExplanation(
        technical="No MFA was used on a login that had already accumulated meaningful risk from other factors.",
        plain="This person didn't use extra sign-in verification (like a phone code), and other warning signs were already present.",
        remediation=[
            "This factor alone is not actionable - review it together with whichever other flags triggered on this alert.",
            "Longer-term: consider making MFA mandatory for this user/role to prevent this combination from recurring.",
        ],
    ),
    "R010": RuleExplanation(
        technical="This specific event's authentication outcome was a failure.",
        plain="This particular sign-in attempt didn't succeed.",
        remediation=[
            "Weak signal alone - a single failure is common and expected; only act if part of a larger pattern.",
        ],
    ),
    "R012": RuleExplanation(
        technical="Failure volume indicates large-scale automated attack infrastructure (e.g. botnet-driven), distinct in scale from R007/R008 (MITRE T1110.004).",
        plain="This is an extremely large number of failed attempts - consistent with a large-scale automated attack, not just one attacker.",
        remediation=[
            "Escalate to incident response immediately - this scale suggests infrastructure-level attack tooling.",
            "Block the source at the network/firewall level, not just the account level.",
            "Check whether other accounts are experiencing the same pattern (this may be a credential-stuffing campaign, not an isolated incident).",
        ],
        urgency_note="Largest-scale automated signal in the ruleset - highest response priority.",
    ),
}


@dataclass
class AlertExplanation:
    """Full, human-facing output for one scored event."""
    risk_score: int
    risk_tier: str
    priority_rank: int                       # 1 = highest priority among a batch; set by prioritize_alerts()
    technical_summary: str
    plain_summary: str
    contributing_factors: List[dict] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    mitre_technique_id: List[str] = field(default_factory=list)


def explain_result(result: RiskScoreResult) -> AlertExplanation:
    """
    Converts a RiskScoreResult into a dual-audience explanation with
    deduplicated, priority-ordered remediation steps.

    Every sentence here is grounded in an actual RiskFactor the scorer
    produced - if a rule fired, its explanation appears; if it didn't,
    it doesn't. Nothing is inferred beyond what the scorer already found.
    """
    factors: List[RiskFactor] = result.risk_factor_details

    contributing = []
    all_remediation: List[str] = []
    urgent_notes: List[str] = []

    for rf in factors:
        kb_entry = RULE_EXPLANATIONS.get(rf.rule_id)
        if kb_entry is None:
            contributing.append({
                "rule_id": rf.rule_id,
                "technical": rf.description,
                "plain": rf.description,
                "points": rf.points,
                "mitre_technique_id": rf.mitre_technique_id,
            })
            continue

        contributing.append({
            "rule_id": rf.rule_id,
            "technical": kb_entry.technical,
            "plain": kb_entry.plain,
            "points": rf.points,
            "mitre_technique_id": rf.mitre_technique_id,
        })

        for step in kb_entry.remediation:
            if step not in all_remediation:
                all_remediation.append(step)

        if kb_entry.urgency_note:
            urgent_notes.append(kb_entry.urgency_note)

    technical_summary = _build_technical_summary(result, factors)
    plain_summary = _build_plain_summary(result, factors, urgent_notes)

    return AlertExplanation(
        risk_score=result.risk_score,
        risk_tier=result.risk_tier,
        priority_rank=0,
        technical_summary=technical_summary,
        plain_summary=plain_summary,
        contributing_factors=contributing,
        recommended_actions=all_remediation,
        mitre_technique_id=result.mitre_technique_id,
    )


def _build_technical_summary(result: RiskScoreResult, factors: List[RiskFactor]) -> str:
    if not factors:
        return f"Score {result.risk_score}/100 ({result.risk_tier}). No rules triggered."
    rule_ids = ", ".join(rf.rule_id for rf in factors)
    return (
        f"Score {result.risk_score}/100 ({result.risk_tier}). "
        f"{len(factors)} rule(s) triggered: {rule_ids}."
    )


def _build_plain_summary(result: RiskScoreResult, factors: List[RiskFactor], urgent_notes: List[str]) -> str:
    if not factors:
        return "This sign-in looked normal - nothing unusual was detected."

    tier_language = {
        "LOW": "This sign-in had a minor unusual detail, but is not concerning on its own.",
        "MEDIUM": "This sign-in has a few unusual details worth a quick look.",
        "HIGH": "This sign-in shows multiple warning signs and should be reviewed soon.",
        "CRITICAL": "This sign-in shows strong signs of a real attack and needs immediate attention.",
    }
    base = tier_language.get(result.risk_tier, "This sign-in was flagged for review.")
    if urgent_notes:
        base += " " + urgent_notes[0]
    return base


def prioritize_alerts(results: List[RiskScoreResult]) -> List[AlertExplanation]:
    """
    Takes a batch of scored events and returns them as AlertExplanation
    objects ordered by priority (highest risk first), with priority_rank
    set. Ties are broken by number of contributing factors (more evidence
    = investigate first among equally-scored alerts), then by presence of
    any MITRE-mapped factor (a named technique outranks an unmapped one).
    """
    explanations = [explain_result(r) for r in results]

    def sort_key(exp: AlertExplanation):
        return (
            -exp.risk_score,
            -len(exp.contributing_factors),
            0 if exp.mitre_technique_id else 1,
        )

    explanations.sort(key=sort_key)
    for i, exp in enumerate(explanations, start=1):
        exp.priority_rank = i

    return explanations