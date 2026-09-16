"""
api.app
=======
HTTP API wrapping the AADRS scoring engine, so it can be integrated into
a real pipeline rather than run as a standalone script.

Run locally:
    uvicorn api.app:app --reload --port 8000

Then browse interactive docs at:
    http://127.0.0.1:8000/docs

Typical integration flow for a consuming system:
    1. POST /baselines/{user_id}          - register/update a user's behavioural baseline
    2. POST /devices/{device_fingerprint} - register/update a known device
    3. POST /score                        - score an incoming authentication event

Steps 1 and 2 are optional per event - /score works without them, it just
scores with less context (fewer rules can fire).

The dashboard "Ask AI" feature uses:
    POST /ask
"""

from __future__ import annotations

import uuid
from collections import deque
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score
from engine.ml_scorer import load_or_train
from engine.explain import explain_result
from engine.groq_narrator import GroqNarrator
from engine.ask_agent import ask_question
from engine.correlator import correlate_events

from api import store, db
from api.ws_manager import manager
from api.schemas import (
    AuthEventIn,
    UserBaselineIn,
    DeviceProfileIn,
    RiskScoreOut,
    RiskFactorOut,
    ContributingFactorOut,
    AlertExplanationOut,
    MLScoreOut,
    CompareScoreOut,
    AskIn,
    AskOut,
)

app = FastAPI(
    title="AADRS - Authentication Anomaly Detection and Risk Scoring API",
    description=(
        "Rule-based risk scoring for authentication events. "
        "Scores are transparent and explainable: every point in a score "
        "is traceable to a named, documented rule (see docs/detection_rules.md)."
    ),
    version="0.1.0",
)


_ml_scorer = None

# Bounded in-memory history used only for short-window correlation.
# The correlator itself looks back at most 30 minutes.
_recent_scored_events = deque(maxlen=1000)
_latest_investigations = []

# Constructed once at import time - it reads GROQ_API_KEY from the
# environment internally and always has a safe fallback.
_narrator = GroqNarrator()


@app.on_event("startup")
def on_startup() -> None:
    """Ensure the SQLite schema exists, and load/train the ML model, before serving requests."""
    global _ml_scorer
    db.init_db()
    _ml_scorer = load_or_train()


@app.get("/health")
def health() -> dict:
    """Basic liveness check for integration/monitoring purposes."""
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    """Serves the live monitoring dashboard (static/dashboard.html)."""
    dashboard_path = Path(__file__).parent.parent / "static" / "dashboard.html"
    return dashboard_path.read_text(encoding="utf-8")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    Dashboard clients connect here to receive a live feed of every scored
    event, as it happens.
    """
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/baselines/{user_id}")
def upsert_baseline(user_id: str, payload: UserBaselineIn) -> dict:
    """Register or update a user's behavioural baseline."""
    baseline = UserBaseline(
        user_id=user_id,
        usual_countries=payload.usual_countries,
        usual_hours_utc=payload.usual_hours_utc,
    )
    store.set_baseline(user_id, baseline)
    return {"status": "stored", "user_id": user_id}


@app.post("/devices/{device_fingerprint}")
def upsert_device(device_fingerprint: str, payload: DeviceProfileIn) -> dict:
    """Register or update a known device profile."""
    device = DeviceProfile(
        device_id=str(uuid.uuid4()),
        user_id="",
        device_fingerprint=device_fingerprint,
        is_trusted=payload.is_trusted,
        total_logins=payload.total_logins,
    )
    store.set_device(device_fingerprint, device)
    return {"status": "stored", "device_fingerprint": device_fingerprint}


@app.post("/ask", response_model=AskOut)
def ask_ai(payload: AskIn) -> AskOut:
    """
    Answer a natural-language question about the CURRENT dashboard state.

    The dashboard sends only:
      - the user's question
      - a compact summary of the dashboard's current state

    engine.ask_agent.ask_question() handles the Groq request and safe
    fallback behaviour.
    """
    if not payload.question or not payload.question.strip():
        raise HTTPException(status_code=400, detail="question is required")

    if not payload.context or not payload.context.strip():
        raise HTTPException(status_code=400, detail="dashboard context is required")

    result = ask_question(
        question=payload.question,
        context=payload.context,
    )

    return AskOut(
        answer=result.answer,
        source=result.source,
    )



def _serialize_investigation(case) -> dict:
    """
    Convert a CorrelationCase dataclass into JSON-safe data for the API
    and WebSocket clients.
    """
    data = asdict(case)
    data["started_at"] = case.started_at.isoformat()
    data["ended_at"] = case.ended_at.isoformat()
    return data


@app.get("/investigations")
def get_investigations() -> dict:
    """
    Return the currently correlated investigation cases.

    These cases are derived deterministically from the recent scored-event
    buffer; generative AI is not used to decide which events belong together.
    """
    return {
        "count": len(_latest_investigations),
        "investigations": [
            _serialize_investigation(case)
            for case in _latest_investigations
        ],
    }


@app.post("/score", response_model=RiskScoreOut)
async def score_event(payload: AuthEventIn) -> RiskScoreOut:
    """
    Score a single authentication event.

    Looks up any previously-registered baseline (by user_id) and device
    profile (by device_fingerprint) automatically.

    The response includes a dual-audience explanation (technical +
    plain-language) with prioritised remediation steps, and a narrated
    summary.
    """
    if not payload.user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    user = User(user_id=payload.user_id, upn=payload.user_id)

    event = AuthEvent(
        user_id=payload.user_id,
        event_time=payload.event_time,
        source_ip=payload.source_ip,
        provider=payload.provider,
        country_code=payload.country_code,
        outcome=payload.outcome,
        mfa_used=payload.mfa_used,
        recent_failure_count=payload.recent_failure_count,
        device_fingerprint=payload.device_fingerprint,
    )

    baseline = store.get_baseline(payload.user_id)
    device = store.get_device(payload.device_fingerprint)

    result = compute_risk_score(event, user, baseline, device)

    alert = explain_result(result)
    narrative_result = _narrator.generate_narrative(alert)

    explanation = AlertExplanationOut(
        technical_summary=alert.technical_summary,
        plain_summary=alert.plain_summary,
        contributing_factors=[
            ContributingFactorOut(**factor)
            for factor in alert.contributing_factors
        ],
        recommended_actions=alert.recommended_actions,
        narrative=narrative_result.narrative,
        narrative_source=narrative_result.source,
    )

    out = RiskScoreOut(
        risk_score=result.risk_score,
        risk_tier=result.risk_tier,
        risk_factors=result.risk_factors,
        risk_factor_details=[
            RiskFactorOut(
                rule_id=rf.rule_id,
                description=rf.description,
                points=rf.points,
                mitre_technique_id=rf.mitre_technique_id,
            )
            for rf in result.risk_factor_details
        ],
        mitre_technique_id=result.mitre_technique_id,
        baseline_used=baseline is not None,
        device_used=device is not None,
        explanation=explanation,
    )

    # ------------------------------------------------------------------
    # Correlation / investigation layer
    # ------------------------------------------------------------------

    global _latest_investigations

    scored_event = {
        "id": str(uuid.uuid4()),
        "user_id": payload.user_id,
        "event_time": payload.event_time,
        "source_ip": payload.source_ip,
        "outcome": payload.outcome,
        "risk_score": out.risk_score,
        "risk_tier": out.risk_tier,
        "country_code": payload.country_code,
        "device_fingerprint": payload.device_fingerprint,
        "mfa_used": payload.mfa_used,
    }

    _recent_scored_events.append(scored_event)

    _latest_investigations = correlate_events(
        list(_recent_scored_events),
        now=payload.event_time,
    )

    # Broadcast the original scored event.
    await manager.broadcast({
        "type": "score",
        "user_id": payload.user_id,
        "event_time": payload.event_time.isoformat(),
        "country_code": payload.country_code,
        "source_ip": payload.source_ip,
        "risk_score": out.risk_score,
        "risk_tier": out.risk_tier,
        "risk_factors": out.risk_factors,
        "mitre_technique_id": out.mitre_technique_id,
        "narrative": narrative_result.narrative,
        "narrative_source": narrative_result.source,
        "technical_summary": alert.technical_summary,
        "plain_summary": alert.plain_summary,
        "contributing_factors": alert.contributing_factors,
        "recommended_actions": alert.recommended_actions,
    })

    # Broadcast the complete current investigation set separately so the
    # dashboard can render/update an Investigations view.
    await manager.broadcast({
        "type": "investigations",
        "count": len(_latest_investigations),
        "investigations": [
            _serialize_investigation(case)
            for case in _latest_investigations
        ],
    })

    return out


@app.post("/score/compare", response_model=CompareScoreOut)
async def score_event_compare(payload: AuthEventIn) -> CompareScoreOut:
    """
    Score an event with BOTH the rule-based engine and the Isolation
    Forest model, returned side by side.
    """
    rule_result = await score_event(payload)

    user_id = payload.user_id

    event = AuthEvent(
        user_id=user_id,
        event_time=payload.event_time,
        source_ip=payload.source_ip,
        provider=payload.provider,
        country_code=payload.country_code,
        outcome=payload.outcome,
        mfa_used=payload.mfa_used,
        recent_failure_count=payload.recent_failure_count,
        device_fingerprint=payload.device_fingerprint,
    )

    baseline = store.get_baseline(user_id)
    device = store.get_device(payload.device_fingerprint)

    if _ml_scorer is None:
        raise HTTPException(
            status_code=503,
            detail="ML scorer is not initialized",
        )

    ml_result = _ml_scorer.score_event(event, baseline, device)

    ml_out = MLScoreOut(
        anomaly_score=ml_result.anomaly_score,
        risk_tier=ml_result.risk_tier,
        is_outlier=ml_result.is_outlier,
        contributing_features=ml_result.contributing_features,
    )

    return CompareScoreOut(
        rule_based=rule_result,
        ml_based=ml_out,
        tiers_agree=(rule_result.risk_tier == ml_out.risk_tier),
    )
