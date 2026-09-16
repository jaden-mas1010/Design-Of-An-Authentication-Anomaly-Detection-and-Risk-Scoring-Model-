"""
engine.mock_narrator
======================
A free, offline narrator agent that conforms to BaseNarrator. Produces
natural-sounding prose from an AlertExplanation using templated variation,
with zero external dependencies and zero API cost - useful for development,
demos, and as a permanent safe fallback even after Groq is wired in.

Like engine.explain, this never invents a fact: it only ever rephrases
what AlertExplanation already computed from real triggered rules.
"""

from __future__ import annotations

import random

from .explain import AlertExplanation
from .narrator_base import BaseNarrator, NarrativeResult

_TIER_OPENERS = {
    "LOW": [
        "Nothing major here, but",
        "This one's mostly routine -",
        "Low concern overall, though",
    ],
    "MEDIUM": [
        "Worth a look:",
        "A few things stand out here -",
        "This one deserves a closer check:",
    ],
    "HIGH": [
        "This needs attention soon.",
        "Several warning signs stacked up on this one.",
        "This one's a genuine concern -",
    ],
    "CRITICAL": [
        "This needs immediate attention.",
        "Strong signs of a real attack here.",
        "This is the top priority right now -",
    ],
}

_NO_FACTOR_PHRASES = [
    "This sign-in looked completely normal - nothing unusual was detected.",
    "No unusual activity was found on this login.",
    "Everything about this sign-in matched expected behaviour.",
]


class MockNarrator(BaseNarrator):
    """
    Offline narrator - no API key, no network call, deterministic given a
    fixed random seed. Use this during development, in tests, and as the
    default fallback if a real LLM-backed narrator is unavailable.
    """

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    def generate_narrative(self, alert: AlertExplanation) -> NarrativeResult:
        if not alert.contributing_factors:
            narrative = self._rng.choice(_NO_FACTOR_PHRASES)
            return NarrativeResult(narrative=narrative, source="mock")

        opener = self._rng.choice(_TIER_OPENERS.get(alert.risk_tier, ["Flagged for review:"]))
        plain_facts = [f["plain"] for f in alert.contributing_factors]

        if len(plain_facts) == 1:
            body = plain_facts[0]
        else:
            body = plain_facts[0] + " On top of that, " + plain_facts[1].lower()
            if len(plain_facts) > 2:
                body += f" ({len(plain_facts) - 2} additional factor(s) also contributed.)"

        next_step = ""
        if alert.recommended_actions:
            next_step = f" Recommended next step: {alert.recommended_actions[0].lower()}"

        narrative = f"{opener} {body}.{next_step}"
        return NarrativeResult(narrative=narrative, source="mock")