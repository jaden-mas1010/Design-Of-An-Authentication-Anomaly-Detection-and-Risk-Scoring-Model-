# AADRS API — Integration Guide

This document describes how an external system (e.g. PMS Ltd's Cyber
Security MVP) integrates with the AADRS scoring engine over HTTP, rather
than needing to embed the Python package directly.

## Running it

```bash
pip install fastapi uvicorn --break-system-packages
uvicorn api.app:app --reload --port 8000
```

Interactive API docs (auto-generated, try requests directly in browser):
`http://127.0.0.1:8000/docs`

## Integration flow

A consuming system typically does three things:

### 1. Register a user's behavioural baseline (periodic, e.g. nightly batch)

```
POST /baselines/{user_id}
{
  "usual_countries": ["GB"],
  "usual_hours_utc": [8,9,10,11,12,13,14,15,16,17]
}
```

### 2. Register known devices (on enrollment, or synced from device inventory)

```
POST /devices/{device_fingerprint}
{
  "device_fingerprint": "fp_alice_laptop",
  "is_trusted": true,
  "total_logins": 50
}
```

### 3. Score an authentication event (real-time, one call per login event)

```
POST /score
{
  "user_id": "u001",
  "event_time": "2026-07-08T09:30:00",
  "source_ip": "82.132.200.10",
  "provider": "azure_ad",
  "country_code": "GB",
  "outcome": "success",
  "mfa_used": true,
  "recent_failure_count": 0,
  "device_fingerprint": "fp_alice_laptop"
}
```

Response:

```json
{
  "risk_score": 0,
  "risk_tier": "LOW",
  "risk_factors": [],
  "risk_factor_details": [],
  "mitre_technique_id": [],
  "baseline_used": true,
  "device_used": true
}
```

Steps 1 and 2 are **optional per event** — `/score` still works without a
registered baseline or device, it simply has less context to work with
(fewer rules are able to evaluate, as shown by `baseline_used`/`device_used`
in the response). This matters for PMS's likely real-world case: a new
user or device with no history yet should still get scored, not rejected.

## Field mapping from raw logs

If PMS's log source is closer to raw ECS (Elastic Common Schema)
authentication events, the mapping is:

| ECS field | AADRS field |
|---|---|
| `user.id` | `user_id` |
| `@timestamp` | `event_time` |
| `source.ip` | `source_ip` |
| `event.provider` | `provider` |
| `source.geo.country_iso_code` | `country_code` |
| `event.outcome` | `outcome` |

`mfa_used`, `recent_failure_count`, and `device_fingerprint` are not
standard ECS fields and would need to be derived/enriched upstream
(e.g. `recent_failure_count` from a windowed aggregation over recent
failed-login events for the same user).

## Why HTTP rather than embedding the package directly

Per David's email (7 July 2026): PMS's interest is in the **framework,
methodology and scoring rationale** being reusable across future MVP
components, not necessarily this specific codebase being embedded
line-for-line into their stack. An HTTP boundary keeps the scoring logic
decoupled and independently versioned/testable, while still letting any
language/platform on PMS's side call it.

## Current limitations for a production integration

- The baseline/device store (`api/store.py`) is in-memory only — it
  resets on restart. Fine for testing and demoing; a real deployment
  would back this with PostgreSQL, as specified in the proposal (Section 4.1).
- No authentication on the API itself yet (no API key/token). Needed
  before this touches anything beyond a local test environment.
- Single-event scoring only — no batch endpoint yet. Worth adding if
  PMS wants to backfill/replay historical events.
