"""
engine.groq_narrator
======================
Real LLM-backed narrator using Groq free API. Conforms to BaseNarrator.
Falls back to MockNarrator on any failure so the system degrades safely
rather than fabricating.
"""

from __future__ import annotations

import os
import re
from typing import Optional

import httpx

from .explain import AlertExplanation
from .narrator_base import BaseNarrator, NarrativeResult
from .mock_narrator import MockNarrator

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-20b"

SYSTEM_PROMPT = """You are explaining a cybersecurity alert to a non-technical business stakeholder.

STRICT RULES:
- You may ONLY use the facts provided below. Do not add, infer, or speculate about anything not explicitly stated.
- Do not invent additional risk factors, statistics, timestamps, or remediation steps.
- Do not use technical jargon (no "MITRE ATT&CK", "CVSS", rule IDs like R001, etc.) - translate everything into plain business language.
- Keep it to 2-3 short sentences plus a one-sentence recommended next step.
- If the facts describe a normal, non-risky login, say so plainly and briefly - do not manufacture urgency.
"""


def _build_user_prompt(alert: AlertExplanation) -> str:
    if not alert.contributing_factors:
        return "Facts: No unusual activity was detected on this sign-in. Risk score: 0/100."

    facts = [f"Risk score: {alert.risk_score}/100, severity level: {alert.risk_tier}."]
    for f in alert.contributing_factors:
        facts.append(f"- {f['plain']}")
    if alert.recommended_actions:
        facts.append("Recommended actions available: " + "; ".join(alert.recommended_actions[:3]))
    return "Facts:\n" + "\n".join(facts)


def _grounding_check(narrative: str) -> bool:
    if re.search(r"\bR0\d{2}\b", narrative):
        return False
    if len(narrative.strip()) == 0:
        return False
    return True


class GroqNarrator(BaseNarrator):
    def __init__(self, api_key: Optional[str] = None, timeout: float = 8.0):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.timeout = timeout
        self._fallback = MockNarrator()

    def generate_narrative(self, alert: AlertExplanation) -> NarrativeResult:
        if not self.api_key:
            return self._fallback.generate_narrative(alert)

        try:
            response = httpx.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": GROQ_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": _build_user_prompt(alert)},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 600,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            narrative = response.json()["choices"][0]["message"]["content"].strip()

            if not narrative:
                return self._fallback.generate_narrative(alert)

            if not _grounding_check(narrative):
                return self._fallback.generate_narrative(alert)

            return NarrativeResult(narrative=narrative, source="groq")

        except (httpx.HTTPError, KeyError, IndexError, TimeoutError):
            return self._fallback.generate_narrative(alert)
