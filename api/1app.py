"""
api.app
=======
HTTP API wrapping the AADRS scoring engine, so it can be integrated into
a real pipeline (e.g. PMS Ltd's Cyber Security MVP) rather than run as a
standalone script.

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
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import FastAPI, HTTPException

from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score
from engine.ml_scorer import load_or_train

from api import store, db
from api.schemas import (
    AuthEventIn,
    UserBaselineIn,
    DeviceProfileIn,
    RiskScoreOut,
    RiskFactorOut,
    MLScoreOut,
    CompareScoreOut,
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
        user_id="",  # not strictly needed for scoring lookups keyed by fingerprint
        device_fingerprint=device_fingerprint,
        is_trusted=payload.is_trusted,
        total_logins=payload.total_logins,
    )
    store.set_device(device_fingerprint, device)
    return {"status": "stored", "device_fingerprint": device_fingerprint}


@app.post("/score", response_model=RiskScoreOut)
def score_event(payload: AuthEventIn) -> RiskScoreOut:
    """
    Score a single authentication event.

    Looks up any previously-registered baseline (by user_id) and device
    profile (by device_fingerprint) automatically - the caller does not
    need to resend that context on every event.
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

    return RiskScoreOut(
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
    )


@app.post("/score/compare", response_model=CompareScoreOut)
def score_event_compare(payload: AuthEventIn) -> CompareScoreOut:
    """
    Score an event with BOTH the rule-based engine and the Isolation
    Forest model, returned side by side. Intended for evaluation/research
    use (O4) rather than as the primary production endpoint - a real
    deployment would pick one method (or a documented blend of both).
    """
    rule_result = score_event(payload)  # reuses the /score logic above

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
