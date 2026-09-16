# AADRS — Engineering Hand-off

This document separates the academic dissertation output from what an
engineering team would actually need to implement this capability inside
the wider Cyber Security MVP. For the justification behind each rule's
weight, see docs/weighting_rationale.md — this file is deliberately terse
and implementation-focused.

## 1. Event Schema (Input)

The engine consumes `AuthEvent` objects. Minimum required fields, inferred
from engine/rules.py and engine/models.py:

| Field                 | Type     | Required | Notes                                      |
|------------------------|----------|----------|---------------------------------------------|
| user_id                | string   | yes      |                                              |
| event_time              | datetime | yes      | UTC assumed — see Open Question 3           |
| source_ip               | string   | yes      | Not currently used by any rule — see below  |
| provider                 | string   | yes      | e.g. azure_ad — not currently scored on     |
| country_code             | string   | yes      | ISO 3166-1 alpha-2, e.g. "GB", "RU"         |
| outcome                  | string   | no       | "success" / "failure" — used by R010        |
| mfa_used                 | boolean  | no       | defaults false-equivalent — used by R009    |
| recent_failure_count     | integer  | no       | defaults 0 — used by R007/R008/R012         |
| device_fingerprint       | string   | no       | used to resolve DeviceProfile               |

**Open question for engineering:** `source_ip` and `provider` are accepted
but not currently scored by any rule. Confirm whether these are intended
for a future rule (e.g. known-malicious-IP lookup) or are context-only
fields for logging/display.
**Resolved:** `source_ip` and `provider` are captured for logging and audit
purposes only and are not currently inputs to any scoring rule. If a future
IP-reputation rule is added, document it in docs/weighting_rationale.md
following the same template as R001–R012.
## 2. Supporting Context Objects

- **UserBaseline** — `usual_countries` (list), `usual_hours_utc` (list of ints).
  Set via `POST /baselines/{user_id}`.
- **DeviceProfile** — `device_id`, `device_fingerprint`, `is_trusted` (bool),
  `total_logins` (int). Set via `POST /devices/{fingerprint}`.
- Both are optional. Rules degrade gracefully when absent (verified in
  scratch_boundary_tests.py, case 8) rather than erroring.

## 3. Rule Engine (Detection Logic)

11 implemented rules (R001–R010, R012) plus one documented-but-unimplemented
placeholder (R011). Full logic in engine/rules.py; full rationale for each
weight in docs/weighting_rationale.md. Summary table:

| Rule | Trigger                                   | Weight | MITRE ATT&CK    |
|------|--------------------------------------------|--------|------------------|
| R001 | Country outside baseline                    | +15    | —                |
| R002 | Country on fixed high-risk list             | +25    | T1078            |
| R003 | Login outside usual hours                   | +10    | —                |
| R004 | No device profile at all                    | +15    | T1078            |
| R005 | Device profile exists, untrusted            | +10    | —                |
| R006 | Device trusted, <3 total logins             | +5     | —                |
| R007 | ≥5 recent failures                          | +20    | T1110            |
| R008 | ≥8 recent failures (stacks on R007)         | +15    | T1110.004        |
| R009 | No MFA AND running score ≥15                | +10    | —                |
| R010 | This event's outcome is "failure"           | +5     | —                |
| R011 | Legacy-provider pattern — NOT IMPLEMENTED   | —      | —                |
| R012 | ≥50 recent failures (stacks on R007+R008)   | +20    | T1110.004        |

Score is a simple capped sum (max 100). Tier thresholds:

| Score  | Tier     |
|--------|----------|
| ≥85    | CRITICAL |
| ≥60    | HIGH     |
| ≥30    | MEDIUM   |
| <30    | LOW      |

**Explicitly flagged as provisional** (per module docstrings): both rule
weights and tier thresholds are placeholder values pending Phase 5/6
evaluation against labelled CERT/LANL data. Do not treat as production-tuned.

## 4. API Surface

Implemented via FastAPI (api/app.py):

| Endpoint                        | Method | Purpose                          |
|-----------------------------------|--------|------------------------------------|
| /health                            | GET    | Liveness check                     |
| /score                             | POST   | Score a single AuthEvent           |
| /baselines/{user_id}               | POST   | Register/update a user baseline    |
| /devices/{device_fingerprint}      | POST   | Register/update a device profile   |
| /dashboard                          | GET    | Live HTML dashboard (demo only)    |

**Response shape from /score** (per test_api_integration.py):
`risk_score`, `risk_tier`, `risk_factors` (human-readable strings),
`mitre_technique_id` (list), `baseline_used` (bool), `device_used` (bool).

## 5. ML Comparison Layer (Not Production-Recommended Yet)

An Isolation Forest scorer (engine/ml_scorer.py) runs alongside the rule
engine for comparison purposes only (compare_scorers.py). Per the project's
core design decision, this is NOT the primary scoring path — the rule
engine is, specifically because its output is explainable per-factor and
the ML layer's is not (yet). Engineering should not treat the ML scorer as
production-ready without a separate explainability layer on top of it.

## 6. Test Coverage

- 34 pytest tests (automated suite — not included in files reviewed here,
  referenced in project history)
- Boundary-specific manual tests (scratch_boundary_tests.py) covering every
  rule threshold at the exact edge (e.g. 4 vs 5 failures, 07:59 vs 08:00)
- End-to-end HTTP integration test against the live API
  (test_api_integration.py)

## 7. Known Gaps / Open Questions for Engineering

1. `source_ip` and `provider` fields are accepted but unused by any current rule
2. Timezone handling assumes UTC only — no per-user timezone support
3. `HIGH_RISK_COUNTRIES` is a hard-coded set — needs a maintained threat-intel feed
4. R011 is a documented placeholder, not implemented
5. R009's compounding threshold (≥15) has no documented evidentiary basis yet
6. All weights and tier thresholds are pre-evaluation placeholders