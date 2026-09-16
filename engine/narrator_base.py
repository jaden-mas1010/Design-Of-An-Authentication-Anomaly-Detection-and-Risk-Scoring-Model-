"""
engine.narrator_base
======================
Defines the interface every "narrator" (explanation-generation agent) must
follow. This lets AADRS swap between a free, offline mock agent (for
development/demo, no API key needed) and a real LLM-backed agent (Groq)
later, without changing any calling code - only the object constructed
in one place changes.

This directly answers the meeting's Question 4/5 concern about controlled,
swappable AI components: the rest of the system depends on this interface,
never on a specific vendor's SDK.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .explain import AlertExplanation


@dataclass
class NarrativeResult:
    narrative: str
    source: str  # identifies which agent produced this - "mock", "groq", "fallback"


class BaseNarrator(ABC):
    """Every narrator implementation must produce a NarrativeResult from an AlertExplanation."""

    @abstractmethod
    def generate_narrative(self, alert: AlertExplanation) -> NarrativeResult:
        ...
        