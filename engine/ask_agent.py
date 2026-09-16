"""
engine.ask_agent
================

Answers free-text questions about the CURRENT dashboard state only.

The model receives a compact, explicit summary of what is currently on
the dashboard and is instructed not to answer beyond that information.

This is deliberately NOT a general chatbot:
- no direct database access
- no memory between questions
- no access to events that were not included in the supplied context
- no permission to invent missing information

If Groq is unavailable, GROQ_API_KEY is not configured, or the request
fails, the function returns a safe fallback response instead of guessing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import httpx


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-20b"


SYSTEM_PROMPT = """
You answer questions about a live authentication security dashboard.

STRICT RULES:
- Answer ONLY using the CONTEXT provided below.
- Do not use outside knowledge about security, companies, users, or events.
- If the context does not contain enough information to answer, say so plainly.
- Do not guess or estimate missing information.
- Do not invent statistics, user names, alerts, countries, IP addresses, or events.
- Keep answers concise: 1-4 sentences.
- Use plain business language unless the question itself uses technical language.
"""


@dataclass
class AskResult:
    answer: str
    source: str


def ask_question(
    question: str,
    context: str,
    api_key: Optional[str] = None,
    timeout: float = 8.0,
) -> AskResult:
    """
    Answer a dashboard question using only the provided dashboard context.

    Returns:
        AskResult:
            answer - generated or fallback answer
            source - "groq" or "unavailable"
    """

    resolved_api_key = api_key or os.environ.get("GROQ_API_KEY")

    if not question or not question.strip():
        return AskResult(
            answer="Please enter a question about the dashboard.",
            source="unavailable",
        )

    if not context or not context.strip():
        return AskResult(
            answer="There isn't enough dashboard information available to answer that question.",
            source="unavailable",
        )

    if not resolved_api_key:
        return AskResult(
            answer=(
                "AI question-answering isn't available right now "
                "(no API key configured)."
            ),
            source="unavailable",
        )

    try:
        response = httpx.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {resolved_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": (
                            f"CONTEXT:\n{context}\n\n"
                            f"QUESTION:\n{question}"
                        ),
                    },
                ],
                "temperature": 0.1,
                "max_tokens": 200,
            },
            timeout=timeout,
        )

        response.raise_for_status()

        data = response.json()

        answer = (
            data["choices"][0]["message"]["content"]
            .strip()
        )

        if not answer:
            return AskResult(
                answer=(
                    "The AI didn't return an answer. "
                    "Please try rephrasing your question."
                ),
                source="unavailable",
            )

        return AskResult(
            answer=answer,
            source="groq",
        )

    except httpx.TimeoutException:
        return AskResult(
            answer=(
                "The AI service took too long to respond. "
                "Please try again."
            ),
            source="unavailable",
        )

    except httpx.HTTPStatusError as exc:
       return AskResult(
            answer=(
              f"Groq HTTP {exc.response.status_code}: "
              f"{exc.response.text}"
            ),
            source="unavailable",
        )

    except httpx.HTTPError:
        return AskResult(
            answer=(
                "Couldn't reach the AI service right now. "
                "Please try again."
            ),
            source="unavailable",
        )

    except (KeyError, IndexError, TypeError, ValueError):
        return AskResult(
            answer=(
                "The AI service returned an unexpected response. "
                "Please try again."
            ),
            source="unavailable",
        )